"""
sync_service.py - Núcleo de comunicación P2P para KeyVault.
Implementa el servidor (Host) y el cliente (Móvil) con cifrado E2EE.
Utilizar únicamente la librería estándar y pyaes (vendoreado).
"""

import json
import socket
import threading
import base64
import os
import time
import hashlib
import hmac
from icecream import ic
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
        
        # Inyectar DB si el manager la tiene
        db = getattr(manager, 'db', None)
        
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
            
            # Generar Token de Confianza Persistente para este dispositivo
            trust_token = base64.b64encode(os.urandom(24)).decode("utf-8")
            device_id = params.get("device_id", ["generic_device"])[0]
            device_name = params.get("device_name", ["Móvil"])[0]
            
            if db:
                db.register_trusted_device(device_id, device_name, trust_token)

            key_b64 = base64.b64encode(manager.session_key).decode()
            credentials = json.dumps({
                "t": manager.session_token, 
                "k": key_b64,
                "trust": trust_token
            })
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
        # Handshake Silencioso (Para dispositivos conocidos)
        # ---------------------------------------------------------
        elif parsed.path == "/auth/trust":
            d_id = params.get("device_id", [None])[0]
            d_token = params.get("trust_token", [None])[0]
            
            if not db or not d_id or not d_token:
                self.send_error(400, "Faltan parámetros de confianza")
                return
            
            trusted = db.get_trusted_device(d_id)
            if trusted and trusted["trust_token"] == d_token:
                # Dispositivo reconocido - Entregar secretos de sesión sin 2FA
                client_ip = self.client_address[0]
                manager.connected_clients[client_ip] = time.time()
                db.update_device_connection(d_id)
                
                credentials = json.dumps({
                    "t": manager.session_token, 
                    "k": base64.b64encode(manager.session_key).decode()
                })
                # Usamos el trust_token como llave de transporte temporal para este paquete
                transport_key = hashlib.sha256(d_token.encode()).digest()
                transport_enc = SessionEncryptor(transport_key)
                
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"data": transport_enc.encrypt(credentials)}).encode())
                return
            else:
                ic(f"TRUST: Intento fallido de {d_id} (Token inválido)")
                self.send_response(401)
                self.end_headers()
                self.wfile.write(json.dumps({"error": "trust_token_invalid"}).encode())
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
            
            # Obtener versión actual de la DB
            db_v = db.get_config("sync_version") if db else "0"
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "ok",
                "server_name": "KeyVault-PC",
                "db_version": db_v
            }).encode())
            return

        # Endpoint: /sync/status (Check de versión rápido)
        elif parsed.path == "/sync/status":
            db_v = db.get_config("sync_version") if db else "0"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"v": db_v}).encode())
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

    def do_POST(self):
        """Maneja recepción de datos (Sincronización reversa)."""
        manager = getattr(self.server, 'manager', None)
        db = getattr(manager, 'db', None)
        
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        token = params.get("token", [None])[0]

        if not token or token != manager.session_token:
            self.send_error(403, "Token inválido para POST")
            return

        if parsed.path == "/sync/upload":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                # Descifrar paquete
                decrypted_json = manager.encryptor.decrypt(post_data.decode("utf-8"))
                if not decrypted_json:
                    raise ValueError("Fallo de descifrado en upload")
                
                vault_data = json.loads(decrypted_json)
                # Notificar al manager que hay datos recibidos (el manager debe procesarlos)
                if hasattr(manager, 'on_vault_received') and manager.on_vault_received:
                    manager.on_vault_received(vault_data)

                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success"}).encode())
            except Exception as e:
                ic(f"Error on upload POST: {e}")
                self.send_error(400, str(e))

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Servidor HTTP multi-hilo."""
    pass

class BridgeServer:
    """Implementación del Servidor de Sincronización."""
    
    def __init__(self, port=DEFAULT_PORT, db_manager=None):
        self.port = port
        self.db = db_manager # Necesario para trust tokens y versionado
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
        self.on_vault_received = None # Callback para procesar subidas del móvil

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
        
        # Cifrar carga Zeroconf solo con el PIN Numérico
        ip = self.get_local_ip()
        pin_hash = hashlib.sha256(self.numeric_pin.encode()).digest()
        pin_enc = SessionEncryptor(pin_hash)
        
        invite = json.dumps({"status": "ready", "server": "KeyVault-PC"})
        encrypted_invite_b64 = pin_enc.encrypt(invite)
        
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
        
        self.pending_handshakers.clear()
        
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

        def _update_mdns():
            if self.zeroconf:
                try:
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
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

# ------------------------------------------------------------------ #
#  Cliente de Puente (Móvil)
# ------------------------------------------------------------------ #
class BridgeClient:
    """Implementación del Cliente para descargar y escuchar eventos."""
    
    def __init__(self, db_manager=None, auth_manager=None):
        self.base_url = None
        self.token = None # session_token
        self.key = None   # session_key
        self.trust_token = None
        self.device_id = None
        self.db = db_manager
        self.auth = auth_manager
        self.encryptor = None
        self.is_listening = False
        self.is_syncing = False
        self.last_db_version = "0"
        self.connected = False
        self.on_status_change = None # Callback (status: str)

    def connect(self, ip, port, token, encryption_key, trust_token=None, device_id=None, on_vault: callable = None, on_clipboard: callable = None) -> bool:
        """Configura el cliente y verifica la conexión real (Handshake)."""
        try:
            self.base_url = f"http://{ip}:{port}"
            self.token = token
            self.key = encryption_key if isinstance(encryption_key, bytes) else base64.b64decode(encryption_key)
            self.trust_token = trust_token
            # device_id: Usado para el registro en el Host
            self.encryptor = SessionEncryptor(self.key)
            
            # 1. VERIFICACIÓN REAL (Handshake)
            handshake_url = f"{self.base_url}/handshake?token={self.token}"
            with urllib.request.urlopen(handshake_url, timeout=5) as resp:
                if resp.status != 200:
                    return False
                data = json.loads(resp.read().decode())
                self.last_db_version = data.get("db_version", "0")
                print(f"Handshake exitoso con PC (v{self.last_db_version})")

            self.connected = True
            if self.on_status_change: self.on_status_change("online")

            # 2. Descargar Bóveda inicial si se requiere
            if on_vault:
                vault = self.download_vault()
                if vault: on_vault(vault)
                
            # 3. Iniciar hilos de monitoreo
            self.start_clipboard_listener(on_clipboard)
            self.start_auto_sync_loop(on_vault)
            return True
        except Exception as e:
            print(f"Fallo de conexión real: {e}")
            self.connected = False
            return False

    def attempt_silent_handshake(self, ip, port, device_id, trust_token) -> bool:
        """Intenta reconectar sin PIN usando el token de confianza."""
        try:
            url = f"http://{ip}:{port}/auth/trust?device_id={device_id}&trust_token={urllib.parse.quote(trust_token)}"
            with urllib.request.urlopen(url, timeout=3) as resp:
                if resp.status == 200:
                    raw_data = json.loads(resp.read().decode())
                    # Desencriptar respuesta de sesión (usando trust_token como llave temporal)
                    transport_key = hashlib.sha256(trust_token.encode()).digest()
                    transport_enc = SessionEncryptor(transport_key)
                    
                    creds_json = transport_enc.decrypt(raw_data["data"])
                    creds = json.loads(creds_json)
                    
                    self.base_url = f"http://{ip}:{port}"
                    self.token = creds["t"]
                    self.key = base64.b64decode(creds["k"])
                    self.trust_token = trust_token
                    self.device_id = device_id
                    self.encryptor = SessionEncryptor(self.key)
                    self.connected = True
                    ic(f"Reconexión silenciosa exitosa con {ip}")
                    return True
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            # Fallo silencioso (PC apagado o token expirado)
            if self.on_status_change: self.on_status_change("offline")
        except Exception as e:
            ic(f"Error inesperado en silent handshake: {e}")
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

    def start_auto_sync_loop(self, on_vault: callable):
        """Monitor de versiones para sincronización automática."""
        self.is_syncing = True
        
        def loop():
            while self.is_syncing:
                if not self.connected: 
                    time.sleep(5)
                    continue
                try:
                    # 1. Verificar versión en servidor
                    url = f"{self.base_url}/sync/status?token={self.token}"
                    with urllib.request.urlopen(url, timeout=10) as resp:
                        if resp.status == 200:
                            data = json.loads(resp.read().decode())
                            remote_v = data.get("v", "0")
                            if remote_v != self.last_db_version:
                                ic(f"SYNC: Cambio detectado! Local(v{self.last_db_version}) -> Remote(v{remote_v})")
                                vault = self.download_vault()
                                if vault:
                                    on_vault(vault)
                                    self.last_db_version = remote_v
                except Exception as e:
                    ic(f"Error in sync loop: {e}")
                    self.connected = False
                    if self.on_status_change: self.on_status_change("offline")
                
                time.sleep(4) # Polling cada 4 segundos

        threading.Thread(target=loop, daemon=True).start()

    def upload_vault(self, vault_data_b64: str) -> bool:
        """Envía la bóveda local al PC (Sincronización reversa)."""
        if not self.connected: return False
        try:
            url = f"{self.base_url}/sync/upload?token={self.token}"
            encrypted_data = self.encryptor.encrypt(vault_data_b64)
            
            req = urllib.request.Request(
                url, 
                data=encrypted_data.encode(),
                headers={'Content-Type': 'application/octet-stream'}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status == 200
        except Exception as e:
            ic(f"Error al subir cambios al PC: {e}")
            return False

    def stop_all(self):
        """Detiene todos los hilos de monitoreo."""
        self.is_listening = False
        self.is_syncing = False
        self.connected = False

if __name__ == "__main__":
    # Test rápido de cifrado
    enc = SessionEncryptor(os.urandom(32))
    original = "Secret Password 123"
    pkg = enc.encrypt(original)
    print(f"Encrypted: {pkg}")
    print(f"Decrypted: {enc.decrypt(pkg)}")
