"""
sync_service.py - Núcleo de comunicación P2P para KeyVault.
Implementa el cliente móvil con cifrado E2EE y conexión segura.
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
#  Cliente de Puente (Móvil)
# ------------------------------------------------------------------ #
class BridgeClient:
    """Cliente de sincronización para la versión móvil."""
    
    def __init__(self):
        self.base_url = None
        self.token = None
        self.key = None
        self.encryptor = None
        self.is_listening = False
        self.on_clipboard_global = None
        self.on_vault_sync = None
        self.on_disconnect = None
        self.connected = False
        self.trust_token = None
        self.device_id = None
        self._pairing_file = None

    @property
    def is_running(self):
        return self.is_listening

    def set_pairing_file(self, path: str):
        self._pairing_file = path

    def save_pairing(self):
        if not self._pairing_file or not self.base_url or not self.token:
            return
        data = {
            "base_url": self.base_url,
            "token": self.token,
            "key_b64": base64.b64encode(self.key).decode() if self.key else None,
            "trust_token": self.trust_token,
            "device_id": self.device_id,
        }
        os.makedirs(os.path.dirname(self._pairing_file), exist_ok=True)
        with open(self._pairing_file, "w") as f:
            json.dump(data, f)

    def load_pairing(self) -> bool:
        if not self._pairing_file or not os.path.exists(self._pairing_file):
            return False
        try:
            with open(self._pairing_file) as f:
                data = json.load(f)
            self.base_url = data.get("base_url")
            self.token = data.get("token")
            key_b64 = data.get("key_b64")
            self.trust_token = data.get("trust_token")
            self.device_id = data.get("device_id")
            if key_b64:
                self.key = base64.b64decode(key_b64)
                self.encryptor = SessionEncryptor(self.key)
            return bool(self.base_url and self.token)
        except Exception as e:
            ic(f"No se pudo cargar el pairing: {e}")
            return False

    def clear_pairing(self):
        if self._pairing_file and os.path.exists(self._pairing_file):
            os.remove(self._pairing_file)

    def attempt_silent_handshake(self, ip, port, device_id, trust_token) -> bool:
        """Intenta reconectar sin PIN usando el token de confianza."""
        try:
            url = f"http://{ip}:{port}/auth/trust?device_id={device_id}&trust_token={urllib.parse.quote(trust_token)}"
            with urllib.request.urlopen(url, timeout=3) as resp:
                if resp.status == 200:
                    raw_data = json.loads(resp.read().decode())
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
                    ic(f"Reconexion silenciosa exitosa con {ip}")
                    return True
        except (urllib.error.URLError, urllib.error.HTTPError):
            pass  # Servidor offline o token invalido — silencioso
        except Exception as e:
            ic(f"Error inesperado en silent handshake: {e}")
        return False

    def connect(self, ip, port, token, encryption_key,
                on_vault: callable, on_clipboard: callable,
                trust_token: str = None, device_id: str = None) -> bool:
        """Configura el cliente y verifica la conexión."""
        try:
            self.base_url = f"http://{ip}:{port}"
            self.token = token
            self.key = base64.b64decode(encryption_key) if isinstance(encryption_key, str) else encryption_key
            self.encryptor = SessionEncryptor(self.key)
            if trust_token:
                self.trust_token = trust_token
            if device_id:
                self.device_id = device_id
            
            # Verificar conexión
            handshake_url = f"{self.base_url}/handshake?token={self.token}"
            with urllib.request.urlopen(handshake_url, timeout=5) as resp:
                if resp.status != 200:
                    return False
                ic("Handshake exitoso con PC")
            
            # Descargar bóveda inicial
            vault = self.download_vault()
            if vault and on_vault:
                on_vault(vault)
            
            # Iniciar escucha de portapapeles
            self.start_clipboard_listener(on_clipboard)
            self.connected = True
            return True
        except Exception as e:
            ic(f"Fallo de conexion: {e}")
            return False

    def download_vault(self) -> str | None:
        try:
            url = f"{self.base_url}/sync?token={self.token}"
            with urllib.request.urlopen(url, timeout=10) as resp:
                if resp.status == 200:
                    encrypted = resp.read().decode("utf-8")
                    return self.encryptor.decrypt(encrypted)
        except Exception as e:
            ic(f"Error al descargar vault: {e}")
        return None

    def start_clipboard_listener(self, on_receive: callable):
        """Inicia long-polling para portapapeles y heartbeat."""
        self.is_listening = True
        _errors = [0]

        def loop():
            url = f"{self.base_url}/clipboard/poll?token={self.token}"
            hb_url = f"{self.base_url}/handshake?token={self.token}"
            while self.is_listening:
                try:
                    with urllib.request.urlopen(url, timeout=35) as resp:
                        _errors[0] = 0
                        if resp.status == 200:
                            raw = json.loads(resp.read().decode())
                            decrypted = self.encryptor.decrypt(raw["data"])
                            if decrypted:
                                if self.on_clipboard_global:
                                    self.on_clipboard_global(decrypted)
                                elif on_receive:
                                    on_receive(decrypted)
                except Exception:
                    if not self.is_listening:
                        break
                    _errors[0] += 1
                    if _errors[0] >= 3:
                        try:
                            urllib.request.urlopen(hb_url, timeout=3)
                            _errors[0] = 0
                        except Exception:
                            ic("Servidor no responde. Marcando desconectado.")
                            self.is_listening = False
                            self.connected = False
                            if self.on_disconnect:
                                self.on_disconnect()
                            break
                    time.sleep(2)

        threading.Thread(target=loop, daemon=True).start()

    def start_auto_sync_loop(self, db, auth_key, interval: int = 30):
        """Descarga cambios periódicamente y los fusiona."""
        if getattr(self, '_auto_sync_running', False):
            return
            
        self._auto_sync_running = True
        
        def loop():
            url = f"{self.base_url}/sync?token={self.token}"
            while self._auto_sync_running and self.connected:
                try:
                    # Traemos toda la bóveda periódicamente
                    import urllib.request
                    with urllib.request.urlopen(url, timeout=10) as resp:
                        if resp.status == 200:
                            encrypted = resp.read().decode("utf-8")
                            vault_str = self.encryptor.decrypt(encrypted)
                            if vault_str:
                                data_list = json.loads(vault_str)
                                ins, upd, skp = db.import_from_list(data_list, auth_key)
                                if (ins > 0 or upd > 0) and self.on_vault_sync:
                                    self.on_vault_sync(ins, upd)
                except Exception as e:
                    ic(f"Error en auto-sync background: {e}")
                
                # Dormimos el intervalo en picos pequeños para poder abortar si se desconecta
                for _ in range(interval * 2):
                    if not self._auto_sync_running or not self.connected:
                        break
                    time.sleep(0.5)

        threading.Thread(target=loop, daemon=True).start()

    def push_to_server_raw(self, data_list: list[dict]) -> bool:
        """Envía una lista de contraseñas descifradas al PC.
        
        El servidor espera: POST /sync/upload?token=<token>
        Body JSON: {"data": "<encrypted_json_string>"}
        """
        if not self.connected or not self.encryptor:
            ic("push_to_server_raw: sin conexión activa.")
            return False
        try:
            url = f"{self.base_url}/sync/upload?token={self.token}"
            payload_str = json.dumps(data_list, ensure_ascii=False)
            encrypted = self.encryptor.encrypt(payload_str)
            body = json.dumps({"data": encrypted}).encode("utf-8")

            req = urllib.request.Request(
                url, data=body,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status == 200
        except Exception as e:
            ic(f"Error en push_to_server_raw: {e}")
            return False

    def push_clipboard(self, text: str) -> bool:
        """Envía texto al portapapeles del PC de forma bidireccional."""
        if not self.connected or not self.encryptor:
            return False
        try:
            url = f"{self.base_url}/clipboard/push?token={self.token}"
            encrypted = self.encryptor.encrypt(text)
            body = json.dumps({"data": encrypted}).encode("utf-8")
            req = urllib.request.Request(
                url, data=body,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception as e:
            ic(f"Error en push_clipboard: {e}")
            return False

    def stop_listener(self):
        self.is_listening = False
        self._auto_sync_running = False
        self.connected = False


# ------------------------------------------------------------------ #
#  Test de cifrado
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    enc = SessionEncryptor(os.urandom(32))
    original = "Secret Password 123"
    pkg = enc.encrypt(original)
    print(f"Encrypted: {pkg}")
    print(f"Decrypted: {enc.decrypt(pkg)}")
