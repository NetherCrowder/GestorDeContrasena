"""
crypto.py - Módulo de cifrado AES-256-CTR + HMAC-SHA256 (Python Puro).

Esta versión utiliza una copia de 'pyaes' vendoreada directamente en el 
código fuente del proyecto para evitar incompatibilidades de compiladores 
y paquetes pre-compilados en entornos móviles como Android (Flet).

Esquema Criptográfico (Encrypt-then-MAC):
  - Algoritmo: AES-256 en modo CTR (pyaes puro, sin extensiones C)
  - Autenticación: HMAC con SHA-256 (stdlib hashlib/hmac)
  - KDF: PBKDF2-HMAC-SHA256 (stdlib hashlib)

Formato Binario del Almacenamiento:
[ IV (16 bytes) ] + [ HMAC (32 bytes) ] + [ Ciphertext (variable) ]
"""

import os
import hmac
import hashlib

# Importamos pyaes desde nuestra propia carpeta 'pyaes' vendoreada, 
# saltándonos la resolución de pip que falla en flet build apk.
import pyaes


# ── Parámetros Criptográficos ─────────────────────────────────────────────────
PBKDF2_ITERATIONS = 100_000
SALT_SIZE  = 32   # 256 bits para PBKDF2
KEY_SIZE   = 32   # 256 bits. Requerido para seguridad de grado AES-256
IV_SIZE    = 16   # 128 bits. Tamaño del Initialization Vector para CTR
MAC_SIZE   = 32   # 256 bits. Tamaño del digest HMAC-SHA256


# ── Generación y Derivación de Claves (KDF) ───────────────────────────────────

def generate_salt() -> bytes:
    """Genera 256 bits de secuencias pseudoaleatorias seguras criptográficamente."""
    return os.urandom(SALT_SIZE)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Deriva una clave maestra AES-256 usando la función estándar PBKDF2-HMAC-SHA256.
    Retorna exactamente 32 bytes derivados.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        iterations=PBKDF2_ITERATIONS,
        dklen=KEY_SIZE,
    )


# ── Modos Operativos: Cifrado y Autenticación ─────────────────────────────────

def _hmac(key: bytes, data: bytes) -> bytes:
    """Calcula la firma HMAC-SHA256 de los datos provistos."""
    return hmac.new(key, data, hashlib.sha256).digest()


def encrypt(data: str, key: bytes) -> bytes:
    """
    Cifra y autentica texto usando AES-256-CTR + HMAC-SHA256 (Encrypt-then-MAC).
    Si los datos están vacíos, devuelve un string de bytes vacío.
    """
    if not data:
        return b""

    # Generamos un nonce temporal de 16 bytes para este cifrado particular
    iv = os.urandom(IV_SIZE)

    # El modo CTR requiere un contador. pyaes lo inicializa pasándole el IV como un block int
    counter = pyaes.Counter(initial_value=int.from_bytes(iv, "big"))
    
    # Inicialización de la clase pura de pyaes
    aes = pyaes.AESModeOfOperationCTR(key, counter=counter)
    
    # pyaes en el modo CTR puede encriptar la cadena entera sin padding
    ciphertext = aes.encrypt(data.encode("utf-8"))

    # Firmamos el IV y el texto cifrado
    mac = _hmac(key, iv + ciphertext)

    # Concatenamos bajo la estructura IV | MAC | CIPHERTEXT
    return iv + mac + ciphertext


def decrypt(encrypted_data: bytes, key: bytes) -> str:
    """
    Verifica primero la autenticación del archivo (MAC) y, si tiene éxito, 
    descifra la carga útil AES-256-CTR devolviendo el texto claro original.
    Lanza ValueError si falla la verificación de autenticidad.
    """
    if not encrypted_data:
        return ""

    # Desempaquetamos la cápsula binaria
    iv         = encrypted_data[:IV_SIZE]  # type: ignore[index]
    stored_mac = encrypted_data[IV_SIZE:IV_SIZE + MAC_SIZE]  # type: ignore[index]
    ciphertext = encrypted_data[IV_SIZE + MAC_SIZE:]  # type: ignore[index]

    # Validamos el End-to-End verificando el MAC sobre el raw cifrado
    expected_mac = _hmac(key, iv + ciphertext)
    
    if not hmac.compare_digest(stored_mac, expected_mac):
        raise ValueError("MAC inválido: Corrupción de datos o clave incorrecta.")

    # Puesto que comprobamos integridad, procedemos a desencriptar seguro
    counter = pyaes.Counter(initial_value=int.from_bytes(iv, "big"))
    aes = pyaes.AESModeOfOperationCTR(key, counter=counter)
    plaintext = aes.decrypt(ciphertext)

    return plaintext.decode("utf-8")


# ── Utilidades Adicionales (Hashing simple) ───────────────────────────────────

def hash_password(password: str) -> str:
    """Devuelve un hash SHA-256 limpio de la contraseña de acceso (PIN/Master)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def hash_answer(answer: str) -> str:
    """Normaliza texto (respuestas de seguridad) removiendo excesos en espacios y devuelve el hash SHA-256."""
    normalized = " ".join(answer.strip().lower().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
