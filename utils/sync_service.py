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
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import urllib.request
import queue

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
#  Servidor de Puente (PC Host)
# ------------------------------------------------------------------ #
class BridgeRequestHandler(BaseHTTPRequestHandler):
    """Manejador de peticiones para el servidor de sincronización."""
    
    def log_message(self, format, *args):
        # Silenciar logs automáticos para no saturar consola
        pass

    def do_GET(self):
        """Maneja peticiones de sincronización y eventos."""
        server = self.server  # type: BridgeServer
        
        # Verificar Token de Sesión (Query Parameter)
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        token = params.get("token", [None])[0]
        
        if not token or token != server.session_token:
            self.send_error(403, "Acceso no autorizado")
            return

        # Endpoint: /sync (Obtener bóveda cifrada)
        if parsed.path == "/sync":
            if not server.vault_data:
                self.send_error(404, "Bóveda no preparada")
                return
            
            # La bóveda ya viene cifrada por el sistema de backup interno (.vk)
            # Aquí la enviamos tal cual o la ciframos de nuevo con Session Key
            # para máxima seguridad en tránsito (E2EE real).
            encrypted_vault = server.encryptor.encrypt(server.vault_data)
            
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(encrypted_vault.encode())
            
        # Endpoint: /handshake (Validación inicial)
        elif parsed.path == "/handshake":
            # Registrar cliente
            client_ip = self.client_address[0]
            server.connected_clients[client_ip] = time.time()
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "ok",
                "server_name": "KeyVault-PC",
                "version": "1.0.0"
            }).encode())

        # Endpoint: /clipboard/poll (Long polling para portapapeles)
        elif parsed.path == "/clipboard/poll":
            client_ip = self.client_address[0]
            server.connected_clients[client_ip] = time.time()
            # Si no hay cola para este cliente, crearla
            if client_ip not in server.client_queues:
                server.client_queues[client_ip] = queue.Queue()
            
            try:
                # Esperar hasta 20 segundos para que sea más responsivo el refresco
                msg = server.client_queues[client_ip].get(timeout=20)
                encrypted_msg = server.encryptor.encrypt(msg)
                
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"data": encrypted_msg}).encode())
            except queue.Empty:
                self.send_response(204) # No Content (Reintento)
                self.end_headers()

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Servidor HTTP multi-hilo."""
    pass

class BridgeServer:
    """Implementación del Servidor de Sincronización."""
    
    def __init__(self, port=DEFAULT_PORT):
        self.port = port
        self.server = None
        self.thread = None
        self.session_token = None
        self.session_key = None
        self.encryptor = None
        self.vault_data = None # Almacena el binario .vk (en base64 o raw)
        self.client_queues = {} # Colas por IP para clipboard push
        self.connected_clients = {} # IP -> Last Seen Timestamp
        self.is_running = False
        self.last_config = None

    def start(self, vault_data: str):
        """Inicia el servidor en un hilo separado."""
        # Generar secretos de sesión
        self.session_key = os.urandom(32)
        self.session_token = base64.b64encode(os.urandom(12)).decode("utf-8").replace("=", "")
        self.encryptor = SessionEncryptor(self.session_key)
        self.vault_data = vault_data
        self.is_running = True
        
        self.server = ThreadedHTTPServer(("0.0.0.0", self.port), BridgeRequestHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        
        # PIN de Respaldo: Derivamos un PIN de 6 dígitos de la IP local + Token
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
        """Detiene el servidor."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        self.is_running = False

    def push_clipboard(self, content: str):
        """Envía contenido al portapapeles de todos los clientes conectados."""
        for q in self.client_queues.values():
            q.put(content)

    def get_local_ip(self):
        """Intenta obtener la IP de la interfaz activa (Hotspot o WiFi)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)) # No conecta realmente
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def generate_pin(self, ip: str, token: str) -> str:
        """Genera un PIN de 6 dígitos determinista para respaldo manual."""
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
        
        def loop():
            url = f"{self.base_url}/clipboard/poll?token={self.token}"
            while self.is_listening:
                try:
                    with urllib.request.urlopen(url, timeout=35) as response:
                        if response.status == 200:
                            raw_json = json.loads(response.read().decode())
                            decrypted = self.encryptor.decrypt(raw_json["data"])
                            if decrypted:
                                on_receive(decrypted)
                        elif response.status == 204:
                            pass # Reintento normal
                except Exception:
                    # Pausa exponencial o simple ante error de red
                    if not self.is_listening: break
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
