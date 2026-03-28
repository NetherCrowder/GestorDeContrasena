"""
backup.py - Utilidades para exportar e importar contraseñas usando el formato .vk.
Implementa el sistema de "Cerradura Binaria" (Contenido cifrado + Header bloqueado).
"""

import json
import base64
import os
import hashlib
from pathlib import Path
from datetime import datetime
import pyaes
import hmac
import hashlib
import os
from security.crypto import decrypt as decrypt_master

def get_base_data_path() -> Path:
    """Retorna la ruta base persistente operativa (Windows o Android)."""
    # En Android, flet provee esta variable para almacenamiento persistente de la app.
    app_storage = os.environ.get("FLET_APP_STORAGE_DATA")
    
    if app_storage:
        base = Path(app_storage)
    else:
        # Ruta persistente en Windows (AppData/Local/KeyVault)
        base = Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))) / "KeyVault"
        
    base.mkdir(parents=True, exist_ok=True)
    return base

# Clave interna para el bloqueo binario del archivo
APP_FIXED_KEY = hashlib.sha256(b"KeyVault_Internal_Binary_Lock_V1").digest()

# Parámetros técnicos
SALT_SIZE = 32
IV_SIZE   = 16   # Cambiado a 16 bytes para compatibilidad estándar con AES-CTR
MAC_SIZE  = 32   # Tamaño del HMAC-SHA256
KEY_SIZE  = 32
ITERATIONS = 50_000

# ------------------------------------------------------------------ #
#  Rutas y Descubrimiento
# ------------------------------------------------------------------ #
def get_backup_path(custom_name: str = "") -> str:
    """Genera una ruta en AppData/Local/KeyVault/backups con timestamp."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = get_base_data_path() / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    if custom_name:
        safe_name = "".join(c for c in custom_name if c.isalnum() or c in "._- ")
        filename = f"{safe_name}_{timestamp}.vk"
    else:
        filename = f"keyvault_{timestamp}.vk"
    return str(backup_dir / filename)

def list_backups() -> list[str]:
    """Lista todos los archivos .vk en la carpeta AppData/Local/KeyVault/backups."""
    backup_dir = get_base_data_path() / "backups"
    if not backup_dir.exists(): 
        return []
    return sorted([str(f) for f in backup_dir.glob("*.vk")], reverse=True)

# ------------------------------------------------------------------ #
#  Criptografía Interna
# ------------------------------------------------------------------ #
def derive_key(secret: str, salt: bytes) -> bytes:
    """Deriva una clave de 256 bits usando PBKDF2-HMAC-SHA256."""
    normalized = " ".join(secret.strip().lower().split())
    return hashlib.pbkdf2_hmac(
        "sha256", 
        normalized.encode("utf-8"), 
        salt, 
        iterations=ITERATIONS, 
        dklen=KEY_SIZE
    )

def encrypt_bytes(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """Cifra bytes usando AES-256-CTR + HMAC-SHA256."""
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    
    # Cifrado CTR
    counter = pyaes.Counter(initial_value=int.from_bytes(iv, "big"))
    aes = pyaes.AESModeOfOperationCTR(key, counter=counter)
    ciphertext = aes.encrypt(data)
    
    # Autenticación (Encrypt-then-MAC)
    mac = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()
    
    return salt, iv, mac + ciphertext

def decrypt_bytes(salt: bytes, iv: bytes, encrypted_payload: bytes, key: bytes) -> bytes | None:
    """Verifica el MAC y descifra la carga útil."""
    try:
        if len(encrypted_payload) < MAC_SIZE:
            return None
            
        mac = encrypted_payload[:MAC_SIZE]
        ciphertext = encrypted_payload[MAC_SIZE:]
        
        # Verificar integridad
        expected_mac = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            return None
            
        # Descifrado CTR
        counter = pyaes.Counter(initial_value=int.from_bytes(iv, "big"))
        aes = pyaes.AESModeOfOperationCTR(key, counter=counter)
        return aes.decrypt(ciphertext)
    except Exception:
        return None

# ------------------------------------------------------------------ #
#  Funciones Públicas
# ------------------------------------------------------------------ #
def export_passwords(file_path: str, passwords: list[dict], auth_key: bytes, question: str, answer: str) -> tuple[bool, int, int]:
    """
    Exporta las contraseñas a un archivo .vk cifrado y bloqueado.
    Retorna (True/False, items_exportados, items_saltados).
    """
    try:
        decrypted_passwords = []
        skipped_count = 0
        
        for pw in passwords:
            try:
                u_enc = pw.get("username")
                p_enc = pw.get("password")
                n_enc = pw.get("notes")

                item = {
                    "title": pw.get("title", ""),
                    "username": decrypt_master(u_enc, auth_key) if u_enc else "",
                    "password": decrypt_master(p_enc, auth_key) if p_enc else "",
                    "url": pw.get("url", ""),
                    "notes": decrypt_master(n_enc, auth_key) if n_enc else "",
                    "category_id": pw.get("category_id", 8),
                    "created_at": pw.get("created_at"),
                    "updated_at": pw.get("updated_at"),
                }
                decrypted_passwords.append(item)
            except Exception:
                skipped_count += 1
                continue
            
        if not decrypted_passwords and passwords:
            return False, 0, skipped_count

        # Capa 1: Cifrado con Respuesta de Seguridad
        i_salt = os.urandom(SALT_SIZE)
        i_key = derive_key(answer, i_salt)
        i_iv = os.urandom(IV_SIZE)
        
        # Codificar datos
        raw_inner = json.dumps(decrypted_passwords, ensure_ascii=False).encode("utf-8")
        
        # Cifrado de la capa interna con CTR y HMAC
        i_counter = pyaes.Counter(initial_value=int.from_bytes(i_iv, "big"))
        i_aes = pyaes.AESModeOfOperationCTR(i_key, counter=i_counter)
        i_ciphertext = i_aes.encrypt(raw_inner)
        i_mac = hmac.new(i_key, i_iv + i_ciphertext, hashlib.sha256).digest()
        
        # Ofuscar pregunta
        obfuscated_q = base64.b64encode(question.encode()).decode()
        
        # Paquete intermedio
        inner_package = {
            "h_meta": obfuscated_q,
            "s": base64.b64encode(i_salt).decode(),
            "n": base64.b64encode(i_iv).decode(),
            "t": base64.b64encode(i_mac).decode(),
            "d": base64.b64encode(i_ciphertext).decode()
        }
        
        # Capa 2: Bloqueo Binario de la Aplicación
        o_raw = json.dumps(inner_package).encode("utf-8")
        o_salt, o_iv, o_payload = encrypt_bytes(o_raw, APP_FIXED_KEY)
        
        with open(file_path, "wb") as f:
            f.write(o_salt)
            f.write(o_iv)
            f.write(o_payload)
            
        return True, len(decrypted_passwords), skipped_count
    except Exception as e:
        print(f"Error crítico al exportar: {e}")
        return False, 0, 0

def get_backup_metadata(file_path: str) -> dict | None:
    """Abre el binario y devuelve el paquete interno (incluye la pregunta desofuscada)."""
    try:
        with open(file_path, "rb") as f:
            o_salt = f.read(SALT_SIZE)
            o_iv = f.read(IV_SIZE)
            o_payload = f.read()
            
        o_raw = decrypt_bytes(o_salt, o_iv, o_payload, APP_FIXED_KEY)
        if not o_raw: 
            return None
        
        inner = json.loads(o_raw.decode("utf-8"))
        # Desofuscar pregunta para la UI
        inner["question_text"] = base64.b64decode(inner["h_meta"]).decode()
        return inner
    except Exception:
        return None

def import_passwords(inner_package: dict, answer: str) -> list[dict] | None:
    """Descifra el contenido del paquete usando la respuesta de seguridad."""
    try:
        i_salt = base64.b64decode(inner_package["s"])
        i_iv = base64.b64decode(inner_package["n"])
        i_mac = base64.b64decode(inner_package["t"])
        i_ciphertext = base64.b64decode(inner_package["d"])
        
        i_key = derive_key(answer, i_salt)
        
        # Verificar integridad de la capa interna
        expected_mac = hmac.new(i_key, i_iv + i_ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(i_mac, expected_mac):
            return None
            
        # Descifrar contenido
        i_counter = pyaes.Counter(initial_value=int.from_bytes(i_iv, "big"))
        i_aes = pyaes.AESModeOfOperationCTR(i_key, counter=i_counter)
        decrypted = i_aes.decrypt(i_ciphertext)
        return json.loads(decrypted.decode("utf-8"))
    except Exception:
        return None
