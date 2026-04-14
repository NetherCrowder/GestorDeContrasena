"""
sync_service.py - Núcleo de comunicación P2P para KeyVault.
Implementa el servidor (Host/PC) con cifrado E2EE y autenticación en 2 pasos.
"""

import json
import socket
import threading
import base64
import os
import time
import hashlib
import hmac
import random
import string
import urllib.request
import urllib.parse
import queue
import asyncio
from icecream import ic

# Importación de pyaes (asumiendo que está en el root)
import pyaes

# Configuración global
DEFAULT_PORT = 5005
MAC_SIZE = 32
MAX_CLIENTS = 5
PIN_VALIDITY = 120  # segundos

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
        
        counter = pyaes.Counter(initial_value=int.from_bytes(iv, "big"))
        aes = pyaes.AESModeOfOperationCTR(self.key, counter=counter)
        ciphertext = aes.encrypt(raw_data)
        
        mac = hmac.new(self.key, iv + ciphertext, hashlib.sha256).digest()
        
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
            
            expected_mac = hmac.new(self.key, iv + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(mac, expected_mac):
                return None
            
            counter = pyaes.Counter(initial_value=int.from_bytes(iv, "big"))
            aes = pyaes.AESModeOfOperationCTR(self.key, counter=counter)
            decrypted = aes.decrypt(ciphertext)
            return decrypted.decode("utf-8")
        except Exception:
            return None

# ------------------------------------------------------------------ #
#  Servidor de Puente (PC/Windows)
# ------------------------------------------------------------------ #
class BridgeServer:
    """
    Servidor de Sincronización P2P con autenticación en 2 pasos.
    
    Flujo de vinculación:
      1. Cliente llama GET /auth/step1?pin_hash=<sha256(pin)>
         → Si pin correcto: responde {"status": "need_alpha"}
         → Rota el PIN en caso de fallo
      2. Cliente llama GET /auth/step2?alpha=<alpha>&device_id=<id>
         → Si alpha correcta: cifra credenciales (token+key) con SHA256(pin+alpha)
         → Emite trust_token y registra dispositivo
         → Rota PIN y Alpha después del éxito
      3. Reconexión: GET /auth/trust?device_id=<id>&trust_token=<token>
         → Si token válido: emite nuevas credenciales (el token no cambia)
    """
    
    def __init__(self, port=DEFAULT_PORT):
        from fastapi import FastAPI
        self.port = port
        self.uvicorn_server = None
        self.thread = None
        self.app = FastAPI(title="KeyVault Sync Server")
        
        # Gestión de sesiones (Multi-dispositivo)
        self.sessions = {}            # token -> {"device_id": str, "encryptor": SessionEncryptor}
        self.vault_provider = None
        
        # Sistema de PIN rotativo
        self.numeric_pin = None
        self.alpha_key = None
        self.pin_expires_at = 0
        self._pending_pin_hash = None  # Guardado tras Step1 exitoso
        
        # Gestión de clientes
        self.client_queues = {}       # ip -> queue.Queue
        self.connected_clients = {}   # device_id -> {ip, last_seen, device_name}
        self.trusted_devices = {}     # device_id -> trust_token
        
        # Estado y eventos
        self.is_running = False
        self.last_config = None
        self.auth_events = []         # lista de (tipo, ip, ts)
        self.on_vault_received = None # callback cuando móvil hace upload
        self.on_clipboard_push = None # callback cuando móvil envía al portapapeles del PC
        
        # Callbacks de UI
        self.on_pin_rotated = None    # callback() -> None para actualizar UI
        
        # Persistencia de dispositivos
        self._devices_file = os.path.join(
            os.getenv("LOCALAPPDATA", ""), "KeyVault", "bridge_devices.json"
        ) if os.name == "nt" else "bridge_devices.json"
        self._load_trusted_devices()

        self._setup_routes()
        
    def _load_trusted_devices(self):
        """Carga los tokens de confianza guardados desde el disco."""
        try:
            if os.path.exists(self._devices_file):
                with open(self._devices_file, "r") as f:
                    self.trusted_devices = json.load(f)
                ic(f"[{len(self.trusted_devices)}] Dispositivos de confianza cargados.")
        except Exception as e:
            ic(f"Error cargando dispositivos de confianza: {e}")

    def _save_trusted_devices(self):
        """Guarda los tokens de confianza al disco."""
        try:
            os.makedirs(os.path.dirname(self._devices_file), exist_ok=True)
            with open(self._devices_file, "w") as f:
                json.dump(self.trusted_devices, f)
        except Exception as e:
            ic(f"Error guardando dispositivos de confianza: {e}")
    
    # ------------------------------------------------------------------ #
    #  PIN Management
    # ------------------------------------------------------------------ #
    def _generate_pin(self) -> str:
        """Genera un PIN numérico de 6 dígitos."""
        return str(random.randint(100000, 999999))
    
    def _generate_alpha(self) -> str:
        """Genera una clave alfanumérica de 7 caracteres (mayúsculas + dígitos)."""
        chars = string.ascii_uppercase + string.digits
        return "".join(random.choices(chars, k=7))
    
    def rotate_credentials(self):
        """Genera nuevos PIN y Alpha, reinicia temporizador."""
        self.numeric_pin = self._generate_pin()
        self.alpha_key = self._generate_alpha()
        self.pin_expires_at = time.time() + PIN_VALIDITY
        self._pending_pin_hash = None
        ic(f"Credenciales rotadas → PIN: {self.numeric_pin} | Alpha: {self.alpha_key}")
        if self.on_pin_rotated:
            try:
                self.on_pin_rotated()
            except Exception:
                pass

    def _pin_rotation_loop(self):
        """Hilo daemon: rota el PIN cada PIN_VALIDITY segundos."""
        while self.is_running:
            now = time.time()
            remaining = self.pin_expires_at - now
            if remaining <= 0:
                self.rotate_credentials()
            time.sleep(1)
    
    @property
    def pin_remaining(self) -> int:
        """Segundos restantes para la rotación del PIN."""
        return max(0, int(self.pin_expires_at - time.time()))
    
    # ------------------------------------------------------------------ #
    #  Gestión de Dispositivos de Confianza
    # ------------------------------------------------------------------ #
    def _register_trusted_device(self, device_id: str, ip: str, name: str = "Móvil") -> str:
        """Registra un dispositivo y retorna su trust_token (máx. MAX_CLIENTS)."""
        # Si ya existe, reutilizar el mismo trust_token
        if device_id in self.trusted_devices:
            trust_token = self.trusted_devices[device_id]
        else:
            # Si superamos el máximo, eliminar el menos reciente o cualquiera inactivo
            if len(self.trusted_devices) >= MAX_CLIENTS:
                if self.connected_clients:
                    oldest = min(
                        self.connected_clients.items(),
                        key=lambda x: x[1].get("last_seen", 0)
                    )
                    old_id = oldest[0]
                else:
                    # Arbitrario si nadie está conectado (el primero del diccionario)
                    old_id = next(iter(self.trusted_devices.keys()))
                    
                self.trusted_devices.pop(old_id, None)
                self.connected_clients.pop(old_id, None)
                ic(f"Dispositivo antiguo removido del almacén en memoria: {old_id}")
            trust_token = base64.b64encode(os.urandom(24)).decode()
            self.trusted_devices[device_id] = trust_token
        
        self.connected_clients[device_id] = {
            "ip": ip,
            "last_seen": time.time(),
            "device_name": name
        }
        self._save_trusted_devices()
        return trust_token

    # ------------------------------------------------------------------ #
    #  Rutas HTTP (FastAPI)
    # ------------------------------------------------------------------ #
    def _setup_routes(self):
        from fastapi import Request, Response, HTTPException
        from fastapi.responses import JSONResponse

        # ----- Ruta de estado público (sin autenticación) -----
        @self.app.get("/")
        async def root_ping():
            return {"status": "ok", "message": "KeyVault Bridge Running"}

        # ----- Middleware de autenticación por token -----
        @self.app.middleware("http")
        async def auth_middleware(request: Request, call_next):
            # Rutas publicas (no requieren token de sesión)
            path = request.url.path
            public_paths = ["/", "/auth/step1", "/auth/step2", "/auth/trust", "/ping"]
            if path in public_paths:
                return await call_next(request)
            
            token = request.query_params.get("token")
            if not token or token not in self.sessions:
                return JSONResponse(status_code=403, content={"error": "unauthorized"})
            
            # Asociar sesión a la petición
            session = self.sessions[token]
            request.state.session = session
            
            # Actualizar actividad
            device_id = session.get("device_id")
            if device_id and device_id in self.connected_clients:
                self.connected_clients[device_id]["last_seen"] = time.time()
                if path in ["/sync", "/sync/upload"]:
                    self.connected_clients[device_id]["last_sync"] = time.time()
            
            return await call_next(request)

        # ----- PASO 1: Verificar PIN -----
        @self.app.get("/auth/step1")
        async def auth_step1(request: Request):
            pin_hash = request.query_params.get("pin_hash", "")
            client_ip = request.client.host
            
            expected_hash = hashlib.sha256(self.numeric_pin.encode()).hexdigest()
            
            if pin_hash == expected_hash and time.time() < self.pin_expires_at:
                # Guardar hash para verificar en Step 2
                self._pending_pin_hash = pin_hash
                self.auth_events.append(("step1_ok", client_ip, time.time()))
                return JSONResponse({"status": "need_alpha"})
            else:
                # PIN incorrecto o expirado: rotar
                self.auth_events.append(("step1_fail", client_ip, time.time()))
                self.rotate_credentials()
                return JSONResponse(status_code=401, content={"error": "pin_invalid"})

        # ----- PASO 2: Verificar Alpha Key + emitir credenciales -----
        @self.app.get("/auth/step2")
        async def auth_step2(request: Request):
            alpha = request.query_params.get("alpha", "").upper()
            device_id = request.query_params.get("device_id", "unknown")
            device_name = request.query_params.get("device_name", "Movil")
            client_ip = request.client.host
            
            # Verificar que el Step1 fue completado
            if not self._pending_pin_hash:
                return JSONResponse(status_code=403, content={"error": "step1_required"})
            
            # Verificar Alpha Key
            if alpha != self.alpha_key:
                self.auth_events.append(("step2_fail", client_ip, time.time()))
                self.rotate_credentials()
                return JSONResponse(status_code=401, content={"error": "alpha_invalid"})
            
            # Autenticación completa: generar credenciales de sesión
            session_key = os.urandom(32)
            session_token = os.urandom(16).hex()
            
            # Registrar dispositivo y obtener trust_token
            trust_token = self._register_trusted_device(device_id, client_ip, device_name)
            
            # Empaquetar credenciales
            credentials = json.dumps({
                "t": session_token,
                "k": base64.b64encode(session_key).decode(),
                "trust": trust_token
            })
            
            # Cifrar con llave derivada de PIN + Alpha (temporal, solo para el transporte)
            transport_seed = (self.numeric_pin + self.alpha_key).encode()
            transport_key = hashlib.sha256(transport_seed).digest()
            transport_enc = SessionEncryptor(transport_key)
            encrypted_creds = transport_enc.encrypt(credentials)
            
            # Limpiar sesiones antiguas de este mismo dispositivo
            old_tokens = [t for t, s in self.sessions.items() if s.get("device_id") == device_id]
            for t in old_tokens: self.sessions.pop(t, None)

            # Registrar nueva sesión
            self.sessions[session_token] = {
                "device_id": device_id,
                "encryptor": SessionEncryptor(session_key)
            }
            
            self.auth_events.append(("success", client_ip, time.time()))
            ic(f"Sesion creada para '{device_id}' desde {client_ip}")
            
            # Rotar PIN y Alpha después del éxito
            self.rotate_credentials()
            
            return JSONResponse({"data": encrypted_creds})

        # ----- Reconexión silenciosa por trust_token -----
        @self.app.get("/auth/trust")
        async def auth_trust(request: Request):
            device_id = request.query_params.get("device_id", "")
            trust_token = request.query_params.get("trust_token", "")
            client_ip = request.client.host
            
            known_token = self.trusted_devices.get(device_id)
            
            if not known_token or known_token != trust_token:
                return JSONResponse(status_code=401, content={"error": "trust_token_invalid"})
            
            # Emitir nuevas credenciales de sesión
            session_key = os.urandom(32)
            session_token = os.urandom(16).hex()
            
            credentials = json.dumps({
                "t": session_token,
                "k": base64.b64encode(session_key).decode()
            })
            
            # Cifrar con el trust_token como llave temporal
            transport_key = hashlib.sha256(trust_token.encode()).digest()
            transport_enc = SessionEncryptor(transport_key)
            encrypted_creds = transport_enc.encrypt(credentials)
            
            # Limpiar sesiones antiguas de este mismo dispositivo (Opcional, pero recomendado)
            old_tokens = [t for t, s in self.sessions.items() if s.get("device_id") == device_id]
            for t in old_tokens: self.sessions.pop(t, None)

            # Actualizar sesión
            self.sessions[session_token] = {
                "device_id": device_id,
                "encryptor": SessionEncryptor(session_key)
            }
            
            if device_id in self.connected_clients:
                self.connected_clients[device_id]["last_seen"] = time.time()
                self.connected_clients[device_id]["ip"] = client_ip
            else:
                # Recuperar de dispositivos de confianza si es que el servidor se reinició
                self.connected_clients[device_id] = {
                    "ip": client_ip,
                    "last_seen": time.time(),
                    "device_name": "Dispositivo Vinculado"
                }
            
            ic(f"Reconexion silenciosa de {device_id} desde {client_ip}")
            return JSONResponse({"data": encrypted_creds})

        # ----- Sincronización: descargar bóveda -----
        @self.app.get("/sync")
        async def sync_vault(request: Request):
            fresh_vault = self.vault_provider() if self.vault_provider else None
            if fresh_vault is None:
                raise HTTPException(status_code=404, detail="Boveda no preparada")
            
            session = request.state.session
            encryptor = session["encryptor"]
            
            # fresh_vault ya debería ser un string JSON (desde backup.py)
            encrypted = encryptor.encrypt(str(fresh_vault))
            return Response(content=encrypted.encode(), media_type="application/octet-stream")

        # ----- Sincronización: subir bóveda desde móvil -----
        @self.app.post("/sync/upload")
        async def sync_upload(request: Request):
            body = await request.body()
            session = request.state.session
            encryptor = session["encryptor"]
            
            try:
                payload = json.loads(body.decode())
                encrypted = payload.get("data", "")
                decrypted = encryptor.decrypt(encrypted)
                if decrypted and self.on_vault_received:
                    incoming = json.loads(decrypted)
                    # Soportar formato bridge_v1 o lista plana
                    if isinstance(incoming, dict) and incoming.get("fmt") == "bridge_v1":
                        data_list = incoming.get("data", [])
                    elif isinstance(incoming, list):
                        data_list = incoming
                    else:
                        raise ValueError("Formato de datos no soportado")
                        
                    self.on_vault_received(data_list)
                    return JSONResponse({"status": "ok"})
            except Exception as e:
                import traceback
                print(f"Error en sync/upload: {e}")
                traceback.print_exc()
                raise HTTPException(status_code=400, detail=f"Error procesando datos: {e}")

        # ----- Portapapeles: Long Polling (PC → Móvil) -----
        @self.app.get("/clipboard/poll")
        async def clipboard_poll(request: Request):
            client_ip = request.client.host
            if client_ip not in self.client_queues:
                self.client_queues[client_ip] = queue.Queue()
            
            for _ in range(40):  # 40 * 0.5s = 20s max espera
                q = self.client_queues.get(client_ip)
                if not q:
                    return Response(status_code=204)
                try:
                    msg = q.get_nowait()
                    session = request.state.session
                    encryptor = session["encryptor"]
                    encrypted_msg = encryptor.encrypt(msg)
                    return JSONResponse({"data": encrypted_msg})
                except queue.Empty:
                    await asyncio.sleep(0.5)
            
            return Response(status_code=204)

        # ----- Portapapeles: Push (Móvil → PC) -----
        @self.app.post("/clipboard/push")
        async def clipboard_push(request: Request):
            """Recibe texto del móvil, lo descifra y lo pone en el portapapeles del PC."""
            try:
                body = await request.body()
                session = request.state.session
                encryptor = session["encryptor"]
                payload = json.loads(body.decode())
                decrypted = encryptor.decrypt(payload.get("data", ""))
                if decrypted and self.on_clipboard_push:
                    self.on_clipboard_push(decrypted)
                return JSONResponse({"status": "ok"})
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Error: {e}")

        # ----- Estado de sincronización -----
        @self.app.get("/sync/status")
        async def sync_status():
            clients = []
            now = time.time()
            for did, info in list(self.connected_clients.items()):
                clients.append({
                    "device_id": did,
                    "ip": info.get("ip"),
                    "last_seen_ago": int(now - info.get("last_seen", now)),
                    "device_name": info.get("device_name", "Movil")
                })
            return JSONResponse({"clients": clients, "count": len(clients)})

        # ----- Handshake simple (para keep-alive del cliente) -----
        @self.app.get("/handshake")
        async def handshake():
            return JSONResponse({"status": "ok", "server": "KeyVault-PC"})

    # ------------------------------------------------------------------ #
    #  Ciclo de vida
    # ------------------------------------------------------------------ #
    def start(self, vault_provider: callable):
        """Inicia el servidor y el ciclo de rotación de PIN."""
        import uvicorn
        
        class NoSignalServer(uvicorn.Server):
            def install_signal_handlers(self):
                pass
        
        # Generar credenciales iniciales
        self.rotate_credentials()
        
        self.vault_provider = vault_provider
        self.is_running = True
        self.client_queues.clear()
        
        # Servidor Uvicorn
        config = uvicorn.Config(self.app, host="0.0.0.0", port=self.port, log_level="error")
        self.uvicorn_server = NoSignalServer(config=config)
        self.thread = threading.Thread(target=self.uvicorn_server.run, daemon=True)
        self.thread.start()
        
        # Hilo de rotación de PIN
        self._pin_thread = threading.Thread(target=self._pin_rotation_loop, daemon=True)
        self._pin_thread.start()
        
        ip = self.get_local_ip()

        # Iniciar zeroconf si está disponible
        self._zeroconf = None
        self._service_info = None
        try:
            from zeroconf import Zeroconf, ServiceInfo
            import socket
            self._zeroconf = Zeroconf()
            hostname = socket.gethostname()
            # Quitamos caracteres raros del hostname para evitar errores en zeroconf
            safe_name = "".join(c for c in hostname if c.isalnum() or c in "-")
            if not safe_name: safe_name = "PC"
            
            desc = {'app': 'keyvault', 'version': '2.0'}
            self._service_info = ServiceInfo(
                "_keyvault._tcp.local.",
                f"KeyVault_{safe_name}._keyvault._tcp.local.",
                addresses=[socket.inet_aton(ip)],
                port=self.port,
                properties=desc,
                server=f"{safe_name}.local."
            )
            self._zeroconf.register_service(self._service_info)
            ic("Zeroconf: Servicio publicado en la red local.")
        except Exception as e:
            ic(f"Zeroconf no disponible o falló al publicar: {e}")

        self.last_config = {
            "ip": ip,
            "port": self.port,
            "pin": self.numeric_pin,
            "alpha": self.alpha_key,
        }
        
        ic(f"BridgeServer iniciado en {ip}:{self.port}")
        return self.last_config

    def stop(self):
        """Detiene el servidor."""
        if hasattr(self, '_zeroconf') and self._zeroconf:
            try:
                if hasattr(self, '_service_info') and self._service_info:
                    self._zeroconf.unregister_service(self._service_info)
                self._zeroconf.close()
                ic("Zeroconf: Servicio des-registrado.")
            except Exception as e:
                pass
            self._zeroconf = None
            
        if self.uvicorn_server:
            self.uvicorn_server.should_exit = True
        self.is_running = False
        ic("BridgeServer detenido.")

    def push_clipboard(self, content: str):
        """Envía contenido al portapapeles de TODOS los clientes móviles conectados (PC → Móvil)."""
        for q in self.client_queues.values():
            q.put(content)
            
    def start_clipboard_listener(self, on_receive: callable):
        """Registra el callback que se dispara cuando el móvil envía texto al PC (Móvil → PC)."""
        self.on_clipboard_push = on_receive

    def push_to_device(self, device_id: str, content: str) -> bool:
        """Envía contenido al portapapeles de UN dispositivo específico.
        
        Returns True si el dispositivo está en línea, False si no se encontró.
        """
        info = self.connected_clients.get(device_id)
        if not info:
            return False
        ip = info.get("ip")
        q = self.client_queues.get(ip)
        if q:
            q.put(content)
            return True
        return False

    # --- Grupo B: Control y Seguridad ---
    
    def revoke_device(self, device_id: str):
        """Elimina el dispositivo de confianza y cierra sus sesiones activas."""
        self.trusted_devices.pop(device_id, None)
        self.connected_clients.pop(device_id, None)
        
        # Eliminar sesiones de este dispositivo
        tokens_to_remove = [t for t, s in self.sessions.items() if s.get("device_id") == device_id]
        for t in tokens_to_remove:
            self.sessions.pop(t, None)
            
        self._save_trusted_devices()
        ic(f"Dispositivo revocado: {device_id}")

    def revoke_all_devices(self):
        """Revoca todos los dispositivos y limpia todas las sesiones."""
        self.trusted_devices.clear()
        self.connected_clients.clear()
        self.sessions.clear()
        self._save_trusted_devices()
        ic("Todos los dispositivos han sido revocados.")

    def lock_device(self, device_id: str) -> bool:
        """Envía un comando de bloqueo remoto a un dispositivo específico."""
        return self.push_to_device(device_id, ":::KV_CMD_LOCK:::")
        
    def lock_all_devices(self):
        """Envía un comando de bloqueo remoto a todos los dispositivos."""
        self.push_clipboard(":::KV_CMD_LOCK:::")

    def get_connection_history(self) -> list:
        """Retorna el historial de eventos de autenticación."""
        return self.auth_events

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"


