"""
sync_service.py - Núcleo de comunicación P2P para KeyVault.
Implementa el servidor (Host) y el cliente (Móvil) con cifrado E2EE.
Utiliza únicamente la librería estándar y pyaes (vendoreado).
"""

import json
import socket
import threading
import base64
import os
import time
import hashlib
import hmac
import urllib.request
import queue
import asyncio
from fastapi import FastAPI, Request, Response, HTTPException
import uvicorn
from icecream import ic

# Importación de pyaes (asumiendo que está en el root)
import pyaes

# Configuración global
DEFAULT_PORT = 5005
MAC_SIZE = 32

# ------------------------------------------------------------------ #
#  Criptografía de Sesión (E2EE)
# ------------------------------------------------------------------ #
class SessionEncryptor:
    """Maneja el cifrado de datos en tránsito usando AES-256-CTR."""
    
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("La clave de sesión debe ser de 32 bytes.")
        self.key = key

    def encrypt(self, data: str) -> str:
        """Cifra una cadena y devuelve un paquete base64 [IV + HMAC + Ciphertext]."""
        raw_data = data.encode("utf-8")
        iv = os.urandom(16)
        
        # Cifrado AES-CTR
        counter = pyaes.Counter(initial_value=int.from_bytes(iv, "big"))
        aes = pyaes.AESModeOfOperationCTR(self.key, counter=counter)
        ciphertext = aes.encrypt(raw_data)
        
        # Firma HMAC para integridad
        mac = hmac.new(self.key, iv + ciphertext, hashlib.sha256).digest()
        
        # Empaquetado
        package = iv + mac + ciphertext
        return base64.b64encode(package).decode("utf-8")

    def decrypt(self, encrypted_b64: str) -> str | None:
        """Descifra un paquete base64 verificado por HMAC."""
        try:
            package = base64.b64decode(encrypted_b64)
            if len(package) < 16 + MAC_SIZE:
                return None
            
            iv = package[:16]
            mac = package[16:16+MAC_SIZE]
            ciphertext = package[16+MAC_SIZE:]
            
            # Verificar integridad
            expected_mac = hmac.new(self.key, iv + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(mac, expected_mac):
                return None
            
            # Descifrado AES-CTR
            counter = pyaes.Counter(initial_value=int.from_bytes(iv, "big"))
            aes = pyaes.AESModeOfOperationCTR(self.key, counter=counter)
            decrypted = aes.decrypt(ciphertext)
            return decrypted.decode("utf-8")
        except Exception:
            return None

# ------------------------------------------------------------------ #
class NoSignalServer(uvicorn.Server):
    """Sobreescribe Uvicorn para que no intente capturar señales de apagado en el hilo daemon."""
    def install_signal_handlers(self):
        pass

class BridgeServer:
    """Implementación del Servidor de Sincronización usando FastAPI y Uvicorn."""
    
    def __init__(self, port=DEFAULT_PORT):
        self.port = port
        self.uvicorn_server = None
        self.thread = None
        self.session_token = None
        self.session_key = None
        self.encryptor = None
        self.vault_data = None
        self.client_queues = {} # IP -> queue.Queue
        self.connected_clients = {} # IP -> Last Seen Timestamp
        self.is_running = False
        self.last_config = None
        self._pairing_file = None
        self.vault_provider = None  # callable() -> str (b64 fresco en cada request)
        
        self.app = FastAPI(docs_url=None, redoc_url=None) # Sin docs por seguridad
        self._setup_routes()

    def set_pairing_file(self, path: str):
        """Configura la ruta del archivo donde se persisten las credenciales del servidor."""
        self._pairing_file = path

    def _load_server_pairing(self) -> bool:
        """Carga token y clave guardados para reutilizarlos en reinicios."""
        if not self._pairing_file or not os.path.exists(self._pairing_file):
            return False
        try:
            with open(self._pairing_file) as f:
                data = json.load(f)
            self.session_token = data["token"]
            self.session_key = base64.b64decode(data["key_b64"])
            ic("Servidor: Token de pairing restaurado desde disco.")
            return True
        except Exception as e:
            ic(f"Servidor: No se pudo cargar el pairing: {e}")
            return False

    def _save_server_pairing(self):
        """Guarda token y clave actuales en disco para sobrevivir reinicios."""
        if not self._pairing_file:
            return
        os.makedirs(os.path.dirname(self._pairing_file), exist_ok=True)
        with open(self._pairing_file, "w") as f:
            json.dump({
                "token": self.session_token,
                "key_b64": base64.b64encode(self.session_key).decode(),
            }, f)

    def clear_pairing(self):
        """Borra el pairing guardado (para forzar re-emparejamiento)."""
        if self._pairing_file and os.path.exists(self._pairing_file):
            os.remove(self._pairing_file)

    def _setup_routes(self):
        @self.app.middleware("http")
        async def check_token(request: Request, call_next):
            if request.url.path == "/":
                return await call_next(request)
                
            # Auth global middleware
            token = request.query_params.get("token")
            if not token or token != self.session_token:
                return Response(status_code=403, content="Acceso no autorizado")
            
            client_ip = request.client.host
            self.connected_clients[client_ip] = time.time()
            return await call_next(request)

        @self.app.get("/sync")
        async def sync_vault():
            # Obtener bóveda fresca en cada petición (fuente de verdad siempre actualizada)
            fresh_vault = self.vault_provider() if self.vault_provider else self.vault_data
            if not fresh_vault:
                raise HTTPException(status_code=404, detail="Bóveda no preparada")
            encrypted_vault = self.encryptor.encrypt(fresh_vault)
            return Response(content=encrypted_vault.encode(), media_type="application/octet-stream")

        @self.app.get("/handshake")
        async def handshake():
            return {
                "status": "ok",
                "server_name": "KeyVault-PC",
                "version": "1.0.0"
            }

        @self.app.get("/clipboard/poll")
        async def clipboard_poll(request: Request):
            client_ip = request.client.host
            if client_ip not in self.client_queues:
                self.client_queues[client_ip] = queue.Queue()
            
            # Long-polling simple y thread-safe
            for _ in range(40): # 40 * 0.5s = 20s
                # Validar de nuevo por si se limpió el diccionario (reinicio server)
                q = self.client_queues.get(client_ip)
                if not q:
                    return Response(status_code=204)
                
                try:
                    msg = q.get_nowait()
                    encrypted_msg = self.encryptor.encrypt(msg)
                    return {"data": encrypted_msg}
                except queue.Empty:
                    await asyncio.sleep(0.5)
                    
            return Response(status_code=204) # No Content (indica que debe reintentar)
            
        @self.app.get("/")
        async def root_ping():
            return {"status": "ok", "message": "KeyVault Bridge Running"}

    def start(self, vault_provider: callable):
        """Inicia el servidor Uvicorn en un hilo daemon.
        vault_provider: callable sin argumentos que retorna el vault b64 fresco.
        """
        if not self._load_server_pairing():
            self.session_key = os.urandom(32)
            self.session_token = base64.b64encode(os.urandom(12)).decode("utf-8").replace("=", "")
        
        self.encryptor = SessionEncryptor(self.session_key)
        self._save_server_pairing()
        
        self.vault_provider = vault_provider
        self.vault_data = None  # Ya no se usa el snapshot estático
        self.is_running = True
        self.client_queues.clear()
        self.connected_clients.clear()
        
        # Log_level="error" para no ensuciar la consola de la UI
        # Usamos NoSignalServer para prevenir ValueError(signal) en el hilo de fondo
        config = uvicorn.Config(self.app, host="0.0.0.0", port=self.port, log_level="error")
        self.uvicorn_server = NoSignalServer(config=config)
        
        self.thread = threading.Thread(target=self.uvicorn_server.run, daemon=True)
        self.thread.start()
        
        # PIN de Respaldo: Derivado de la IP + Token
        ip = self.get_local_ip()
        pin = self.generate_pin(ip, self.session_token)
        
        self.last_config = {
            "ip": ip,
            "port": self.port,
            "token": self.session_token,
            "key_b64": base64.b64encode(self.session_key).decode(),
            "pin": pin
        }
        return self.last_config

    def stop(self):
        """Detiene grácilmente el servidor Uvicorn."""
        if self.uvicorn_server:
            self.uvicorn_server.should_exit = True
        self.is_running = False

    def push_clipboard(self, content: str):
        """Envía contenido al portapapeles de todos los clientes conectados de forma thread-safe."""
        for q in self.client_queues.values():
            q.put(content)

    def get_local_ip(self):
        """Intenta obtener la IP activa."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def generate_pin(self, ip: str, token: str) -> str:
        seed = f"{ip}:{token}".encode()
        h = hashlib.sha256(seed).hexdigest()
        return str(int(h[:8], 16))[:6].zfill(6)

# ------------------------------------------------------------------ #
#  Cliente de Puente (Móvil)
# ------------------------------------------------------------------ #
class BridgeClient:
    """Implementación del Cliente para descargar y escuchar eventos."""
    
    def __init__(self):
        self.base_url = None
        self.token = None
        self.key = None
        self.encryptor = None
        self.is_listening = False
        self.on_clipboard_global = None
        self.on_vault_sync = None
        self.on_disconnect = None   # callable() -> llamado cuando el servidor cae
        self._pairing_file = None

    @property
    def is_running(self):
        """Alias de is_listening para compatibilidad con vistas que usan is_running."""
        return self.is_listening

    def set_pairing_file(self, path: str):
        """Configura la ruta del archivo donde se guardan las credenciales de pairing."""
        self._pairing_file = path

    def save_pairing(self):
        """Persiste las credenciales de emparejamiento actuales en disco."""
        if not self._pairing_file or not self.base_url or not self.token:
            return
        data = {
            "base_url": self.base_url,
            "token": self.token,
            "key_b64": base64.b64encode(self.key).decode() if self.key else None,
        }
        os.makedirs(os.path.dirname(self._pairing_file), exist_ok=True)
        with open(self._pairing_file, "w") as f:
            json.dump(data, f)

    def try_reconnect(self) -> bool:
        """Intenta reconectar usando credenciales en memoria (sin leer archivo).
        Útil cuando el servidor se reinicia y el cliente quiere volver a conectar."""
        if not self.base_url or not self.token or not self.encryptor:
            return self.load_pairing()  # Fallback: intentar desde archivo
        try:
            handshake_url = f"{self.base_url}/handshake?token={self.token}"
            with urllib.request.urlopen(handshake_url, timeout=3) as resp:
                return resp.status == 200
        except Exception as e:
            # Si el error es 403 (token inválido), intentar desde archivo
            if "403" in str(e):
                return self.load_pairing()
            return False

    def load_pairing(self) -> bool:
        """Carga las credenciales guardadas e intenta reconectar. Devuelve True si OK."""
        if not self._pairing_file or not os.path.exists(self._pairing_file):
            return False
        try:
            with open(self._pairing_file) as f:
                data = json.load(f)
            base_url = data.get("base_url")
            token = data.get("token")
            key_b64 = data.get("key_b64")
            if not (base_url and token and key_b64):
                return False
            key = base64.b64decode(key_b64)
            # Verificar que el servidor sigue activo
            handshake_url = f"{base_url}/handshake?token={token}"
            with urllib.request.urlopen(handshake_url, timeout=3) as resp:
                if resp.status != 200:
                    return False
            # Restaurar estado
            self.base_url = base_url
            self.token = token
            self.key = key
            self.encryptor = SessionEncryptor(self.key)
            return True
        except Exception as e:
            ic(f"No se pudo restaurar el pairing: {e}")
            return False

    def clear_pairing(self):
        """Elimina las credenciales guardadas (solo llamar en desconexión manual)."""
        if self._pairing_file and os.path.exists(self._pairing_file):
            os.remove(self._pairing_file)

    def connect(self, ip, port, token, encryption_key, on_vault: callable, on_clipboard: callable) -> bool:
        """Configura el cliente y verifica la conexión real (Handshake)."""
        try:
            self.base_url = f"http://{ip}:{port}"
            self.token = token
            self.key = encryption_key
            self.encryptor = SessionEncryptor(self.key)
            
            # 1. VERIFICACIÓN REAL (Handshake)
            handshake_url = f"{self.base_url}/handshake?token={self.token}"
            with urllib.request.urlopen(handshake_url, timeout=5) as resp:
                if resp.status != 200:
                    return False
                ic("Handshake exitoso con PC")

            # 2. Descargar Bóveda inicial
            vault = self.download_vault()
            if vault:
                on_vault(vault)
            else:
                ic("Advertencia: No se pudo descargar la bóveda inicial, pero hay conexión.")
                
            # 3. Iniciar escucha de portapapeles
            self.start_clipboard_listener(on_clipboard)
            return True
        except Exception as e:
            ic(f"Fallo de conexión real: {e}")
            return False

    def download_vault(self) -> str | None:
        """Descarga la bóveda cifrada del PC."""
        try:
            url = f"{self.base_url}/sync?token={self.token}"
            with urllib.request.urlopen(url, timeout=10) as response:
                if response.status == 200:
                    encrypted_data = response.read().decode("utf-8")
                    return self.encryptor.decrypt(encrypted_data)
        except Exception as e:
            ic(f"Error al descargar vault: {e}")
        return None

    def start_clipboard_listener(self, on_receive: callable):
        """Inicia un ciclo de long-polling para recibir clipboard push."""
        self.is_listening = True
        _consecutive_errors = [0]  # contador mutable en closure
        
        def loop():
            url = f"{self.base_url}/clipboard/poll?token={self.token}"
            hb_url = f"{self.base_url}/handshake?token={self.token}"
            while self.is_listening:
                try:
                    with urllib.request.urlopen(url, timeout=35) as response:
                        _consecutive_errors[0] = 0  # reset en éxito
                        if response.status == 200:
                            raw_json = json.loads(response.read().decode())
                            decrypted = self.encryptor.decrypt(raw_json["data"])
                            if decrypted:
                                if self.on_clipboard_global:
                                    self.on_clipboard_global(decrypted)
                                elif on_receive:
                                    on_receive(decrypted)
                        elif response.status == 204:
                            pass # Reintento normal
                except Exception:
                    if not self.is_listening: break
                    _consecutive_errors[0] += 1
                    ic(f"Polling error #{_consecutive_errors[0]}")
                    
                    # Tras 3 errores consecutivos, verificar si el servidor sigue vivo
                    if _consecutive_errors[0] >= 3:
                        try:
                            with urllib.request.urlopen(hb_url, timeout=3):
                                pass  # Servidor vivo, continuar
                            _consecutive_errors[0] = 0
                        except Exception:
                            # Servidor caído — marcar desconectado y salir del loop
                            ic("Servidor no responde al heartbeat. Marcando desconectado.")
                            self.is_listening = False
                            if self.on_disconnect:
                                self.on_disconnect()
                            break
                    
                    time.sleep(2)
                    
        threading.Thread(target=loop, daemon=True).start()

    def stop_listener(self):
        """Detiene el ciclo de escucha."""
        self.is_listening = False

# ------------------------------------------------------------------ #
#  Prueba (Manual si se ejecuta directamente)
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    # Test rápido de cifrado
    enc = SessionEncryptor(os.urandom(32))
    original = "Secret Password 123"
    pkg = enc.encrypt(original)
    print(f"Encrypted: {pkg}")
    print(f"Decrypted: {enc.decrypt(pkg)}")
