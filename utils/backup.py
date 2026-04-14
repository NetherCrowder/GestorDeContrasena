"""
backup.py - Utilidades para exportar e importar contraseñas usando el formato .vk.
Implementa el sistema de "Cerradura Binaria" (Contenido cifrado + Header bloqueado).
"""

import json
import base64
import os
from icecream import ic
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

def export_passwords_to_bytes(passwords: list[dict], auth_key: bytes, question: str, answer: str) -> bytes | None:
    """
    Versión de export_passwords que devuelve el contenido binario (.vk) directamente.
    Útil para la sincronización P2P sin tocar el disco.
    """
    try:
        decrypted_passwords = []
        for pw in passwords:
            try:
                u_enc = pw.get("username")
                p_enc = pw.get("password")
                n_enc = pw.get("notes")
                item = {
                    "sync_id": pw.get("sync_id") or "",
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
            except: continue

        # Capa 1: Cifrado con Respuesta de Seguridad
        i_salt = os.urandom(SALT_SIZE)
        i_key = derive_key(answer, i_salt)
        i_iv = os.urandom(IV_SIZE)
        raw_inner = json.dumps(decrypted_passwords, ensure_ascii=False).encode("utf-8")
        i_counter = pyaes.Counter(initial_value=int.from_bytes(i_iv, "big"))
        i_aes = pyaes.AESModeOfOperationCTR(i_key, counter=i_counter)
        i_ciphertext = i_aes.encrypt(raw_inner)
        i_mac = hmac.new(i_key, i_iv + i_ciphertext, hashlib.sha256).digest()
        
        inner_package = {
            "h_meta": base64.b64encode(question.encode()).decode(),
            "s": base64.b64encode(i_salt).decode(),
            "n": base64.b64encode(i_iv).decode(),
            "t": base64.b64encode(i_mac).decode(),
            "d": base64.b64encode(i_ciphertext).decode()
        }
        
        # Capa 2: Bloqueo Binario
        o_raw = json.dumps(inner_package).encode("utf-8")
        o_salt, o_iv, o_payload = encrypt_bytes(o_raw, APP_FIXED_KEY)
        return o_salt + o_iv + o_payload
    except:
        return None


def get_backup_metadata(file_path: str) -> dict | None:
    """Abre el binario y devuelve el paquete interno (incluye la pregunta desofuscada)."""
    try:
        with open(file_path, "rb") as f:
            full_data = f.read()
        return get_backup_metadata_from_bytes(full_data)
    except Exception:
        return None

def get_backup_metadata_from_bytes(data: bytes) -> dict | None:
    """Procesa un contenido binario (.vk) y devuelve el paquete interno."""
    try:
        if len(data) < SALT_SIZE + IV_SIZE:
            return None
            
        o_salt = data[:SALT_SIZE]
        o_iv = data[SALT_SIZE:SALT_SIZE+IV_SIZE]
        o_payload = data[SALT_SIZE+IV_SIZE:]
            
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

# ------------------------------------------------------------------ #
#  Funciones del Puente P2P (E2EE puro, sin capa de seguridad extra)
# ------------------------------------------------------------------ #
def export_passwords_bridge(passwords: list[dict], auth_key: bytes) -> str | None:
    """
    Serializa las contraseñas en JSON plano para transmisión via Bridge P2P.
    El canal ya es E2EE por lo que NO se aplica cifrado adicional aquí.
    Retorna un string JSON base64 listo para enviar.
    """
    try:
        decrypted_list = []
        for pw in passwords:
            try:
                u_enc = pw.get("username")
                p_enc = pw.get("password")
                n_enc = pw.get("notes")
                item = {
                    "sync_id": pw.get("sync_id") or "",
                    "title": pw.get("title", ""),
                    "username": decrypt_master(u_enc, auth_key) if u_enc else "",
                    "password": decrypt_master(p_enc, auth_key) if p_enc else "",
                    "url": pw.get("url", ""),
                    "notes": decrypt_master(n_enc, auth_key) if n_enc else "",
                    "category_id": pw.get("category_id", 8),
                    "is_favorite": pw.get("is_favorite", 0),
                    "created_at": pw.get("created_at"),
                    "updated_at": pw.get("updated_at"),
                }
                decrypted_list.append(item)
            except Exception:
                continue

        # Retornar JSON plano. El BridgeServer se encargará de cifrarlo con la SessionKey (AES-CTR)
        return json.dumps(decrypted_list, ensure_ascii=False)
    except Exception as e:
        ic(f"Error en export_passwords_bridge: {e}")
        return None


def apply_bridge_vault(vault_b64: str, db, auth_key: bytes) -> tuple[int, int, int]:
    """
    Aplica una bóveda recibida via Bridge al almacén local del móvil.
    Estrategia de fusión:
      - Si el registro (mismo title + username + category_id) NO existe → lo inserta.
      - Si EXISTE → compara updated_at y actualiza solo si el del PC es más reciente.
    Retorna (insertados, actualizados, saltados).
    """
    from icecream import ic
    try:
        raw = base64.b64decode(vault_b64).decode("utf-8")
        payload = json.loads(raw)
        ic(f"apply_bridge_vault: formato={payload.get('fmt')}, registros={len(payload.get('data', []))}")
        
        if payload.get("fmt") != "bridge_v1":
            ic("apply_bridge_vault: formato no reconocido, abortando")
            return 0, 0, 0
        
        incoming = payload["data"]
        from security.crypto import encrypt as encrypt_master
        
        inserted = 0
        updated = 0
        skipped = 0

        # Cargar TODOS los registros locales una sola vez (más eficiente)
        all_local = db.get_all_passwords()

        for item in incoming:
            title = item.get("title", "")
            username_plain = item.get("username", "")
            category_id = item.get("category_id", 8)
            updated_at_remote = item.get("updated_at") or ""
            sync_id = item.get("sync_id", "")

            # Buscar coincidencia local por sync_id, o (title + username)
            match = None
            if sync_id:
                for ex in all_local:
                    if ex.get("sync_id") == sync_id:
                        match = ex
                        break

            if not match:
                for ex in all_local:
                    try:
                        ex_username = decrypt_master(ex.get("username"), auth_key) if ex.get("username") else ""
                    except Exception:
                        ex_username = ""
                    if ex.get("title") == title and ex_username == username_plain:
                        match = ex
                        break

            # Re-cifrar con la clave del móvil
            u_enc = encrypt_master(item.get("username", ""), auth_key)
            p_enc = encrypt_master(item.get("password", ""), auth_key)
            n_enc = encrypt_master(item.get("notes", ""), auth_key) if item.get("notes") else b""

            local_ts = (match.get("updated_at") or "") if match else ""

            if match is None:
                # Nuevo: insertar preservando el timestamp del PC
                result = db.upsert_from_bridge(
                    title=title, username=u_enc, password=p_enc,
                    url=item.get("url", ""), category_id=category_id,
                    notes=n_enc, is_favorite=item.get("is_favorite", 0),
                    remote_updated_at=updated_at_remote,
                )
                inserted += 1
                ic(f"INSERT: {title!r} ts={updated_at_remote!r}")
            elif updated_at_remote > local_ts:
                # Actualizar: registro más nuevo en PC → reemplazar y guardar ts remoto
                result = db.upsert_from_bridge(
                    title=title, username=u_enc, password=p_enc,
                    url=item.get("url", ""), category_id=category_id,
                    notes=n_enc, is_favorite=item.get("is_favorite", 0),
                    remote_updated_at=updated_at_remote,
                    existing_id=match["id"],
                )
                updated += 1
                ic(f"UPDATE: {title!r} remote={updated_at_remote!r} > local={local_ts!r}")
            else:
                skipped += 1
                # ic(f"SKIP: {title!r} remote={updated_at_remote!r} local={local_ts!r}")

        ic(f"apply_bridge_vault: RESULTADO ins={inserted}, upd={updated}, skp={skipped}")
        return inserted, updated, skipped
    except Exception as e:
        from icecream import ic
        ic(f"apply_bridge_vault ERROR: {e}")
        import traceback; traceback.print_exc()
        return 0, 0, 0
