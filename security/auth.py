"""
auth.py - Módulo de autenticación: contraseña maestra, PIN, preguntas de
seguridad y rotación de contraseña.
"""

from datetime import datetime, timedelta
from database.db_manager import DatabaseManager
from security.crypto import (
    generate_salt, derive_key, encrypt, decrypt,
    hash_password, hash_answer,
)


class AuthManager:
    """Gestiona el ciclo de vida de autenticación del usuario."""

    def __init__(self, db: DatabaseManager):
        self.db = db
        self._key: bytes | None = None  # Clave AES derivada (en memoria)

    def get_user_questions(self) -> list[dict]:
        """Devuelve la lista de preguntas de seguridad del usuario."""
        return self.db.get_security_questions()

    @property
    def key(self) -> bytes | None:
        return self._key

    # ------------------------------------------------------------------ #
    #  Registro (primer uso)
    # ------------------------------------------------------------------ #
    def register(self, master_password: str, pin: str,
                 security_qa: list[tuple[str, str]],
                 rotation_days: int = 90) -> None:
        """
        Configura la bóveda por primera vez.
        - master_password: contraseña maestra
        - pin: PIN de 6 dígitos
        - security_qa: lista de (pregunta, respuesta)
        - rotation_days: días para rotación
        """
        salt = generate_salt()
        self._key = derive_key(master_password, salt)

        # Guardar config
        self.db.set_config("salt", salt.hex())
        self.db.set_config("master_password_hash", hash_password(master_password))
        self.db.set_config("pin_hash", hash_password(pin))
        # Cifrar la clave AES con el PIN para acceso rápido
        pin_key = derive_key(pin, salt)
        encrypted_master = encrypt(master_password, pin_key)
        self.db.set_config("pin_encrypted_master", encrypted_master.hex())
        self.db.set_config("password_rotation_days", str(rotation_days))
        self.db.set_config("last_password_change", datetime.now().isoformat())
        self.db.set_config("security_questions_configured", "true")

        # Guardar preguntas de seguridad
        questions = [(q, hash_answer(a)) for q, a in security_qa]
        self.db.save_security_questions(questions)

    def update_security_questions(self, security_qa: list[tuple[str, str]]) -> None:
        """
        Actualiza las preguntas de seguridad sin tocar la contraseña maestra o el PIN.
        security_qa: lista de (pregunta, respuesta)
        """
        questions = [(q, hash_answer(a)) for q, a in security_qa]
        self.db.save_security_questions(questions)

    # ------------------------------------------------------------------ #
    #  Login con contraseña maestra
    # ------------------------------------------------------------------ #
    def login_master(self, master_password: str) -> bool:
        """Intenta autenticar con la contraseña maestra."""
        stored_hash = self.db.get_config("master_password_hash")
        if stored_hash and hash_password(master_password) == stored_hash:
            salt = bytes.fromhex(self.db.get_config("salt"))
            self._key = derive_key(master_password, salt)
            return True
        return False

    # ------------------------------------------------------------------ #
    #  Login con PIN
    # ------------------------------------------------------------------ #
    def login_pin(self, pin: str) -> bool:
        """Intenta autenticar con el PIN de acceso rápido."""
        stored_hash = self.db.get_config("pin_hash")
        if stored_hash and hash_password(pin) == stored_hash:
            # Recuperar la contraseña maestra cifrada con el PIN
            salt = bytes.fromhex(self.db.get_config("salt"))
            pin_key = derive_key(pin, salt)
            encrypted_master_hex = self.db.get_config("pin_encrypted_master")
            try:
                master_password = decrypt(
                    bytes.fromhex(encrypted_master_hex), pin_key
                )
                self._key = derive_key(master_password, salt)
                return True
            except Exception:
                return False
        return False

    # ------------------------------------------------------------------ #
    #  Recuperación por preguntas de seguridad
    # ------------------------------------------------------------------ #
    def verify_security_answers(self, answers: dict[int, str]) -> bool:
        """
        Verifica respuestas de seguridad.
        answers = {question_id: respuesta_texto}
        Requiere al menos 3 correctas.
        """
        questions = self.db.get_security_questions()
        correct = 0
        for q in questions:
            if q["id"] in answers:
                if hash_answer(answers[q["id"]]) == q["answer_hash"]:
                    correct += 1
        return correct >= 3

    # ------------------------------------------------------------------ #
    #  Rotación de contraseña maestra
    # ------------------------------------------------------------------ #
    def needs_rotation(self) -> bool:
        """Verifica si la contraseña maestra necesita ser cambiada."""
        last_change = self.db.get_config("last_password_change")
        rotation_days = self.db.get_config("password_rotation_days")
        if not last_change or not rotation_days:
            return False
        last_dt = datetime.fromisoformat(last_change)
        return datetime.now() > last_dt + timedelta(days=int(rotation_days))

    def days_until_rotation(self) -> int:
        """Devuelve los días restantes para la próxima rotación."""
        last_change = self.db.get_config("last_password_change")
        rotation_days = self.db.get_config("password_rotation_days")
        if not last_change or not rotation_days:
            return 999
        last_dt = datetime.fromisoformat(last_change)
        expires = last_dt + timedelta(days=int(rotation_days))
        remaining = (expires - datetime.now()).days
        return max(0, remaining)

    def change_master_password(self, old_password: str,
                               new_password: str, new_pin: str) -> bool:
        """
        Cambia la contraseña maestra y re-cifra todos los datos.
        Retorna True si el cambio fue exitoso.
        """
        if not self.login_master(old_password):
            return False

        old_key = self._key
        salt = bytes.fromhex(self.db.get_config("salt"))

        # Generar nuevo salt y clave
        new_salt = generate_salt()
        new_key = derive_key(new_password, new_salt)

        # Re-cifrar todas las contraseñas
        all_passwords = self.db.get_all_passwords()
        for pw in all_passwords:
            decrypted_username = decrypt(pw["username"], old_key) if pw["username"] else ""
            decrypted_password = decrypt(pw["password"], old_key) if pw["password"] else ""
            decrypted_notes = decrypt(pw["notes"], old_key) if pw["notes"] else ""

            self.db.update_password(
                pw["id"],
                username=encrypt(decrypted_username, new_key),
                password=encrypt(decrypted_password, new_key),
                notes=encrypt(decrypted_notes, new_key),
            )

        # Actualizar config
        self.db.set_config("salt", new_salt.hex())
        self.db.set_config("master_password_hash", hash_password(new_password))
        self.db.set_config("pin_hash", hash_password(new_pin))
        pin_key = derive_key(new_pin, new_salt)
        encrypted_master = encrypt(new_password, pin_key)
        self.db.set_config("pin_encrypted_master", encrypted_master.hex())
        self.db.set_config("last_password_change", datetime.now().isoformat())

        self._key = new_key
        return True

    def force_change_password(self, new_password: str, new_pin: str) -> bool:
        """
        Cambio forzado de contraseña tras recuperación por preguntas.
        Requiere que _key ya esté establecida (no cifra datos porque no se tiene la anterior).
        En este caso se crea una nueva bóveda limpia.
        """
        new_salt = generate_salt()
        new_key = derive_key(new_password, new_salt)

        # Limpiar todas las contraseñas (no podemos re-cifrar sin la clave anterior)
        # NOTA: Esto es una limitación de seguridad - las contraseñas se pierden
        # al recuperar por preguntas de seguridad

        self.db.set_config("salt", new_salt.hex())
        self.db.set_config("master_password_hash", hash_password(new_password))
        self.db.set_config("pin_hash", hash_password(new_pin))
        pin_key = derive_key(new_pin, new_salt)
        encrypted_master = encrypt(new_password, pin_key)
        self.db.set_config("pin_encrypted_master", encrypted_master.hex())
        self.db.set_config("last_password_change", datetime.now().isoformat())

        self._key = new_key
        return True

    def lock(self):
        """Elimina la clave de memoria (cierra sesión)."""
        self._key = None
