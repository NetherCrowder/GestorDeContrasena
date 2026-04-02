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
        """Maneja peticiones de sincronización y eventos con manejo de desconexión ruidosa."""
        try:
            self._do_GET_safe()
        except (ConnectionResetError, BrokenPipeError):
            # Cliente se desconectó a la fuerza, ignoramos para no ensuciar logs
            pass

    def _do_GET_safe(self):
        """Lógica real de GET protegida."""
        manager = getattr(self.server, 'manager', None)
        if not manager:
            self.send_error(500, "Error de configuración")
            return
        
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        token = params.get("token", [None])[0]

        # ---------------------------------------------------------
        # Paso 1: Auth Knock con PIN Numérico
        # ---------------------------------------------------------
        if parsed.path == "/auth/step1":
            # El token que envía el cliente debe ser Hash(PIN_NUMERICO)
            expected_h = hashlib.sha256(manager.numeric_pin.encode()).hexdigest()
            if not token or token != expected_h:
                self.send_error(403, "PIN Incorrecto")
                return
            
            # Registrar como 'pendiente de validación alpha'
            client_ip = self.client_address[0]
            if client_ip not in manager.pending_handshakers:
                manager.pending_handshakers.append(client_ip)
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "need_alpha", "msg": "PIN Correctos. Ingresa clave Alpha."}).encode())
            return

        # ---------------------------------------------------------
        # Paso 2: Verificación Alfanumérica y Entrega de Llaves
        # ---------------------------------------------------------
        elif parsed.path == "/auth/step2":
            client_ip = self.client_address[0]
            alpha_input = params.get("alpha", [None])[0]
            
            if client_ip not in manager.pending_handshakers:
                self.send_error(403, "Debes completar el Paso 1 primero")
                return
                
            if not alpha_input or alpha_input.upper() != manager.alpha_key.upper():
                # REGISTRAR FRACASO: PIN ALPHA INCORRECTO
                manager.auth_events.append(("failure", client_ip, time.time()))
                manager.regenerate_pins()
                self.send_error(401, "Clave Alfanumérica Incorrecta")
                return

            # ÉXITO: Entregar Token de Sesión Real y Clave Maestra cifrada
            transport_seed = (manager.numeric_pin + manager.alpha_key).encode()
            transport_key = hashlib.sha256(transport_seed).digest()
            transport_enc = SessionEncryptor(transport_key)
            
            key_b64 = base64.b64encode(manager.session_key).decode()
            credentials = json.dumps({"t": manager.session_token, "k": key_b64})
            encrypted_creds = transport_enc.encrypt(credentials)
            
            # REGISTRAR ÉXITO
            manager.auth_events.append(("success", client_ip, time.time()))
            
            manager.connected_clients[client_ip] = time.time()
            if client_ip in manager.pending_handshakers:
                manager.pending_handshakers.remove(client_ip)

            # ROTAR PINES tras éxito (seguridad máxima)
            manager.regenerate_pins()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"data": encrypted_creds}).encode())
            return

        # ---------------------------------------------------------
        # Endpoints de Sesión Activa (Requieren Token de Sesión Real)
        # ---------------------------------------------------------
        if not token or token != manager.session_token:
            self.send_error(403, "No autorizado (Sesion expirada o invalida)")
            return

        # Endpoint: /handshake (Ping de Sesión para BridgeClient)
        if parsed.path == "/handshake":
            client_ip = self.client_address[0]
            manager.connected_clients[client_ip] = time.time()
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "ok",
                "server_name": "KeyVault-PC",
                "version": "1.0.0"
            }).encode())
            return

        # Endpoint: /sync (Obtener bóveda cifrada)
        if parsed.path == "/sync":
            if not manager.vault_data:
                self.send_error(404, "Bóveda no preparada")
                return
            
            encrypted_vault = manager.encryptor.encrypt(manager.vault_data)
            
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(encrypted_vault.encode())
            
        # Endpoint: /clipboard/poll (Long polling)
        elif parsed.path == "/clipboard/poll":
            client_ip = self.client_address[0]
            manager.connected_clients[client_ip] = time.time()
            if client_ip not in manager.client_queues:
                manager.client_queues[client_ip] = queue.Queue()
            
            try:
                msg = manager.client_queues[client_ip].get(timeout=20)
                encrypted_msg = manager.encryptor.encrypt(msg)
                
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"data": encrypted_msg}).encode())
            except queue.Empty:
                self.send_response(204)
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
        self.pending_handshakers = [] # IPs que pasaron el PIN numérico
        self.auth_events = [] # (type, ip, timestamp) para feedback en UI
        self.is_running = False
        self.last_config = None
        self.numeric_pin = None
        self.alpha_key = None
        self.zeroconf = None
        self.zeroconf_info = None

    def start(self, vault_data: str):
        """Inicia el servidor en un hilo separado y emite el servicio mDNS."""
        import random
        from zeroconf import ServiceInfo, Zeroconf
        
        # Generar secretos de sesión
        self.session_key = os.urandom(32)
        self.session_token = base64.b64encode(os.urandom(12)).decode("utf-8").replace("=", "")
        self.encryptor = SessionEncryptor(self.session_key)
        self.vault_data = vault_data
        self.is_running = True
        
        self.server = ThreadedHTTPServer(("0.0.0.0", self.port), BridgeRequestHandler)
        self.server.manager = self # Facilitar acceso a datos en el handler
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        
        # Generar PIN Numérico (6 dígitos) y Alpha (7 chars)
        self.numeric_pin = str(random.randint(100000, 999999))
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        self.alpha_key = ''.join(random.choices(alphabet, k=7))
        
        # Cifrar carga Zeroconf solo con el PIN Numérico para el descubrimiento inicial
        # El contenido ya no tiene la llave maestra, solo confirma disponibilidad.
        ip = self.get_local_ip()
        pin_hash = hashlib.sha256(self.numeric_pin.encode()).digest()
        pin_enc = SessionEncryptor(pin_hash)
        
        invite = json.dumps({"status": "ready", "server": "KeyVault-PC"})
        encrypted_invite_b64 = pin_enc.encrypt(invite)
        
        # Publicar vía Zeroconf / mDNS de forma asíncrona por Flet
        desc = {b'v': b'1', b'p': encrypted_invite_b64.encode("utf-8")}
        self.zeroconf_info = ServiceInfo(
            "_keyvault._tcp.local.",
            f"KeyVault-{random.randint(1000, 9999)}._keyvault._tcp.local.",
            addresses=[socket.inet_aton(ip)],
            port=self.port,
            properties=desc,
            server=f"kv-{ip.replace('.', '-')}.local."
        )
        
        def _register_mdns():
            import asyncio
            # Crear un nuevo loop solo para este hilo, asegurando que zeroconf no interfiera con Flet
            asyncio.set_event_loop(asyncio.new_event_loop())
            try:
                self.zeroconf = Zeroconf()
                self.zeroconf.register_service(self.zeroconf_info)
                print("Zeroconf service broadcasted successfully.")
            except Exception as e:
                print(f"Fallo en hilo mdns: {e}")
                
        threading.Thread(target=_register_mdns, daemon=True).start()
        
        self.last_config = {
            "ip": ip,
            "port": self.port,
            "pin": self.numeric_pin,
            "alpha": self.alpha_key
        }
        return self.last_config

    def regenerate_pins(self):
        """Genera nuevos PINs y actualiza el anuncio Zeroconf."""
        import random
        from zeroconf import Zeroconf, ServiceInfo

        self.numeric_pin = str(random.randint(100000, 999999))
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        self.alpha_key = ''.join(random.choices(alphabet, k=7))
        
        # Limpiar handshakes pendientes previos al regenerar
        self.pending_handshakers.clear()
        
        # Cifrar carga Zeroconf solo con el PIN Numérico
        ip = self.get_local_ip()
        pin_hash = hashlib.sha256(self.numeric_pin.encode()).digest()
        pin_enc = SessionEncryptor(pin_hash)
        
        invite = json.dumps({"status": "ready", "server": "KeyVault-PC"})
        encrypted_invite_b64 = pin_enc.encrypt(invite)
        
        desc = {b'v': b'1', b'p': encrypted_invite_b64.encode("utf-8")}
        
        self.last_config = {
            "ip": ip,
            "port": self.port,
            "pin": self.numeric_pin,
            "alpha": self.alpha_key
        }

        # Actualizar Zeroconf si está vivo
        def _update_mdns():
            import asyncio
            if self.zeroconf:
                try:
                    # Zeroconf requiere unregister/register para actualizar propiedades
                    self.zeroconf.unregister_service(self.zeroconf_info)
                    
                    self.zeroconf_info = ServiceInfo(
                        "_keyvault._tcp.local.",
                        f"KeyVault-{random.randint(1000, 9999)}._keyvault._tcp.local.",
                        addresses=[socket.inet_aton(ip)],
                        port=self.port,
                        properties=desc,
                        server=f"kv-{ip.replace('.', '-')}.local."
                    )
                    self.zeroconf.register_service(self.zeroconf_info)
                    print(f"PINs rotados. Nuevo PIN: {self.numeric_pin}")
                except Exception as e:
                    print(f"Error rotando mdns: {e}")
                    
        threading.Thread(target=_update_mdns, daemon=True).start()

    def stop(self):
        """Detiene el servidor y elimina el anuncio mDNS."""
        if getattr(self, "zeroconf", None):
            try:
                self.zeroconf.unregister_service(self.zeroconf_info)
                self.zeroconf.close()
            except Exception as e:
                print(f"Error cerrando zeroconf: {e}")
            self.zeroconf = None
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
        """Método obsoleto."""
        pass

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
                print("Handshake exitoso con PC")

            # 2. Descargar Bóveda inicial
            vault = self.download_vault()
            if vault:
                on_vault(vault)
            else:
                print("Advertencia: No se pudo descargar la bóveda inicial, pero hay conexión.")
                
            # 3. Iniciar escucha de portapapeles
            self.start_clipboard_listener(on_clipboard)
            return True
        except Exception as e:
            print(f"Fallo de conexión real: {e}")
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
            print(f"Error al descargar vault: {e}")
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
