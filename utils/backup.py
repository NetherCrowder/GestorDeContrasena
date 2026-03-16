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
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from security.crypto import decrypt as decrypt_master

# Clave interna para el bloqueo binario del archivo
APP_FIXED_KEY = hashlib.sha256(b"KeyVault_Internal_Binary_Lock_V1").digest()

# Parámetros técnicos
SALT_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 50_000

# ------------------------------------------------------------------ #
#  Rutas y Descubrimiento
# ------------------------------------------------------------------ #
def get_backup_path(custom_name: str = "") -> str:
    """Genera una ruta en Documentos con timestamp."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    documents = Path.home() / "Documents"
    documents.mkdir(parents=True, exist_ok=True)
    if custom_name:
        safe_name = "".join(c for c in custom_name if c.isalnum() or c in "._- ")
        filename = f"{safe_name}_{timestamp}.vk"
    else:
        filename = f"keyvault_{timestamp}.vk"
    return str(documents / filename)

def list_backups() -> list[str]:
    """Lista todos los archivos .vk en la carpeta Documentos."""
    documents = Path.home() / "Documents"
    if not documents.exists(): 
        return []
    return sorted([str(f) for f in documents.glob("*.vk")], reverse=True)

# ------------------------------------------------------------------ #
#  Criptografía Interna
# ------------------------------------------------------------------ #
def derive_key(secret: str, salt: bytes) -> bytes:
    """Deriva una clave de 256 bits usando PBKDF2."""
    normalized = " ".join(secret.strip().lower().split())
    return PBKDF2(normalized.encode("utf-8"), salt, dkLen=KEY_SIZE, count=ITERATIONS)

def encrypt_bytes(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    salt = get_random_bytes(SALT_SIZE)
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return salt, nonce, tag + ciphertext

def decrypt_bytes(salt: bytes, nonce: bytes, encrypted_payload: bytes, key: bytes) -> bytes | None:
    try:
        tag = encrypted_payload[:TAG_SIZE]
        ciphertext = encrypted_payload[TAG_SIZE:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
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
        i_salt = get_random_bytes(SALT_SIZE)
        i_key = derive_key(answer, i_salt)
        i_nonce = get_random_bytes(NONCE_SIZE)
        i_cipher = AES.new(i_key, AES.MODE_GCM, nonce=i_nonce)
        
        raw_inner = json.dumps(decrypted_passwords, ensure_ascii=False).encode("utf-8")
        i_ciphertext, i_tag = i_cipher.encrypt_and_digest(raw_inner)
        
        # Ofuscar pregunta
        obfuscated_q = base64.b64encode(question.encode()).decode()
        
        # Paquete intermedio
        inner_package = {
            "h_meta": obfuscated_q,
            "s": base64.b64encode(i_salt).decode(),
            "n": base64.b64encode(i_nonce).decode(),
            "t": base64.b64encode(i_tag).decode(),
            "d": base64.b64encode(i_ciphertext).decode()
        }
        
        # Capa 2: Bloqueo Binario de la Aplicación
        o_raw = json.dumps(inner_package).encode("utf-8")
        o_salt, o_nonce, o_payload = encrypt_bytes(o_raw, APP_FIXED_KEY)
        
        with open(file_path, "wb") as f:
            f.write(o_salt)
            f.write(o_nonce)
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
            o_nonce = f.read(NONCE_SIZE)
            o_payload = f.read()
            
        o_raw = decrypt_bytes(o_salt, o_nonce, o_payload, APP_FIXED_KEY)
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
        i_nonce = base64.b64decode(inner_package["n"])
        i_tag = base64.b64decode(inner_package["t"])
        i_data = base64.b64decode(inner_package["d"])
        
        i_key = derive_key(answer, i_salt)
        i_cipher = AES.new(i_key, AES.MODE_GCM, nonce=i_nonce)
        decrypted = i_cipher.decrypt_and_verify(i_data, i_tag)
        return json.loads(decrypted.decode("utf-8"))
    except Exception:
        return None
