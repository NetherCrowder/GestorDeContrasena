"""
crypto.py - Módulo de cifrado AES-256-GCM con derivación PBKDF2.
Utiliza pycryptodome para todas las operaciones criptográficas.
"""

import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Parámetros de derivación
PBKDF2_ITERATIONS = 100_000
SALT_SIZE = 32          # 256 bits
KEY_SIZE = 32           # 256 bits (AES-256)
NONCE_SIZE = 12         # 96 bits recomendado para GCM
TAG_SIZE = 16           # 128 bits


def generate_salt() -> bytes:
    """Genera un salt aleatorio de 256 bits."""
    return get_random_bytes(SALT_SIZE)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Deriva una clave AES-256 a partir de la contraseña maestra usando PBKDF2."""
    return PBKDF2(
        master_password.encode("utf-8"),
        salt,
        dkLen=KEY_SIZE,
        count=PBKDF2_ITERATIONS,
        prf=lambda p, s: hashlib.new("sha256", p + s).digest(),
    )


def encrypt(data: str, key: bytes) -> bytes:
    """
    Cifra un texto con AES-256-GCM.
    Formato de salida: nonce (12 bytes) + tag (16 bytes) + ciphertext
    """
    if not data:
        return b""
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode("utf-8"))
    return nonce + tag + ciphertext


def decrypt(encrypted_data: bytes, key: bytes) -> str:
    """
    Descifra datos cifrados con AES-256-GCM.
    Espera formato: nonce (12) + tag (16) + ciphertext
    """
    if not encrypted_data:
        return ""
    nonce = encrypted_data[:NONCE_SIZE]
    tag = encrypted_data[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = encrypted_data[NONCE_SIZE + TAG_SIZE:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")


def hash_password(password: str) -> str:
    """Genera un hash SHA-256 de una contraseña (para almacenar en config)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def hash_answer(answer: str) -> str:
    """Normaliza y hashea una respuesta de seguridad."""
    normalized = " ".join(answer.strip().lower().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
