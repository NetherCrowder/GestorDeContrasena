"""
db_manager.py - Capa de persistencia SQLite para el Gestor de Contraseñas.
Gestiona conexión, inicialización de esquema, y operaciones CRUD.
"""

import sqlite3
import os
import json
from datetime import datetime
from database.models import SCHEMA_SQL, DEFAULT_CATEGORIES
from icecream import ic
from utils.logging_config import register_error


class DatabaseManager:
    """Administrador central de la base de datos SQLite."""

    def __init__(self, db_path: str | None = None):
        ic("DATABASE INIT: Starting DatabaseManager initialization...")
        if db_path is None:
            # En Android (o empaquetado Flet), el directorio de la app es de SOLO LECTURA.
            # Debemos usar la variable garantizada de escritura de Flet:
            app_storage = os.environ.get("FLET_APP_STORAGE_DATA")
            if app_storage:
                db_path = os.path.join(app_storage, "vault.db")
                ic(f"DATABASE INIT: Android/Flet Storage Detected -> {db_path}")
            else:
                # Ruta persistente en Windows (AppData/Local/KeyVault)
                import sys
                from pathlib import Path
                base_dir = Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))) / "KeyVault"
                base_dir.mkdir(parents=True, exist_ok=True)
                
                # Aislamos la base de datos si estamos haciendo pruebas como celular local
                db_name = "vault_mobile_test.db" if "--mobile" in sys.argv else "vault.db"
                db_path = str(base_dir / db_name)
                ic(f"DATABASE INIT: Windows/Local Persistent Storage -> {db_path}")
        self.db_path = db_path
        self.conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------------ #
    #  Conexión y esquema
    # ------------------------------------------------------------------ #
    def connect(self):
        """Abre la conexión y crea las tablas si no existen."""
        ic(f"DATABASE CONNECT: Attempting to connect to SQLite at {self.db_path}")
        try:
            # Asegurarse de que el directorio padre exista (en Android a veces flet_app_data está vacío/inexistente)
            db_dir = os.path.dirname(self.db_path)
            if db_dir and not os.path.exists(db_dir):
                ic(f"DATABASE CONNECT: Directory {db_dir} does not exist. Creating it...")
                os.makedirs(db_dir, exist_ok=True)
                
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            ic("DATABASE CONNECT: Connection successful. Setting pragmas...")
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON")
            ic("DATABASE CONNECT: Executing schema script...")
            self.conn.executescript(SCHEMA_SQL)
            ic("DATABASE CONNECT: Migrating temp passwords...")
            self.migrate_temp_passwords()
            ic("DATABASE CONNECT: Seeding categories...")
            self.seed_categories()
            
            # Inicializar versión de sincronización si no existe
            if self.get_config("sync_version") is None:
                self.set_config("sync_version", "0")
                
            self.conn.commit()
            ic("DATABASE CONNECT: Database ready.")
        except sqlite3.OperationalError as e:
            register_error("DATABASE CRITICAL ERROR (Operational)", e)
            raise RuntimeError(f"Fallo crítico conectando a SQLite: {e}")
        except Exception as e:
            register_error("DATABASE CRITICAL ERROR (General)", e)
            raise RuntimeError(f"Fallo inesperado al inicializar la base de datos: {e}")

    def migrate_temp_passwords(self):
        """Añade la columna 'name' a temp_passwords si no existe."""
        try:
            self.conn.execute("ALTER TABLE temp_passwords ADD COLUMN name TEXT DEFAULT 'Sin nombre'")
        except sqlite3.OperationalError:
            # La columna ya existe
            pass

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def seed_categories(self):
        """Inserta las categorías predefinidas si la tabla está vacía."""
        cur = self.conn.execute("SELECT COUNT(*) FROM categories")
        if cur.fetchone()[0] == 0:
            self.conn.executemany(
                "INSERT INTO categories (name, icon, color, is_custom) VALUES (?, ?, ?, ?)",
                DEFAULT_CATEGORIES,
            )

    def _increment_version(self):
        """Incrementa la versión de la base de datos para notificar cambios por red."""
        try:
            v_str = self.get_config("sync_version") or "0"
            new_v = int(v_str) + 1
            self.set_config("sync_version", str(new_v))
            ic(f"DATABASE: Version incremented to {new_v}")
        except Exception as e:
            ic(f"Error incrementing sync version: {e}")

    # ------------------------------------------------------------------ #
    #  CRUD - Contraseñas
    # ------------------------------------------------------------------ #
    def add_password(self, title: str, username: bytes, password: bytes,
                     url: str = "", category_id: int = 8, notes: bytes = b"",
                     is_favorite: int = 0, password_rules: dict | None = None) -> int:
        """Crea un registro de contraseña. Devuelve el ID insertado."""
        now = datetime.now().isoformat()
        rules_json = json.dumps(password_rules or {})
        cur = self.conn.execute(
            """INSERT INTO passwords
               (title, username, password, url, category_id, notes,
                is_favorite, password_rules, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (title, username, password, url, category_id, notes,
             is_favorite, rules_json, now, now),
        )
        self.conn.commit()
        self._increment_version()
        return cur.lastrowid

    def get_all_passwords(self) -> list[dict]:
        """Devuelve todas las contraseñas como lista de diccionarios."""
        cur = self.conn.execute(
            "SELECT * FROM passwords ORDER BY updated_at DESC"
        )
        return [dict(row) for row in cur.fetchall()]

    def get_passwords_by_category(self, category_id: int) -> list[dict]:
        cur = self.conn.execute(
            "SELECT * FROM passwords WHERE category_id = ? ORDER BY updated_at DESC",
            (category_id,),
        )
        return [dict(row) for row in cur.fetchall()]

    def get_password_by_id(self, pw_id: int) -> dict | None:
        cur = self.conn.execute("SELECT * FROM passwords WHERE id = ?", (pw_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def update_password(self, pw_id: int, **fields) -> None:
        """Actualiza los campos indicados de una contraseña."""
        # Solo asignar updated_at automático si no viene en los fields
        if "updated_at" not in fields:
            fields["updated_at"] = datetime.now().isoformat()
        if "password_rules" in fields and isinstance(fields["password_rules"], dict):
            fields["password_rules"] = json.dumps(fields["password_rules"])
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [pw_id]
        self.conn.execute(
            f"UPDATE passwords SET {set_clause} WHERE id = ?", values
        )
        self.conn.commit()
        self._increment_version()

    def upsert_from_bridge(self, title: str, username: bytes, password: bytes,
                           url: str, category_id: int, notes: bytes,
                           is_favorite: int, remote_updated_at: str,
                           existing_id: int | None = None) -> str:
        """Inserta o actualiza una contraseña desde sincronización del Bridge.
        Preserva el updated_at original del PC para que las próximas sincronizaciones
        puedan comparar correctamente los timestamps.
        Devuelve: 'inserted' | 'updated' | 'skipped'
        """
        now = datetime.now().isoformat()
        remote_ts = remote_updated_at or now

        if existing_id is None:
            # Nuevo registro
            self.conn.execute(
                """INSERT INTO passwords
                   (title, username, password, url, category_id, notes,
                    is_favorite, password_rules, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (title, username, password, url, category_id, notes,
                 is_favorite, json.dumps({}), now, remote_ts),
            )
            self.conn.commit()
            return "inserted"
        else:
            # Actualizar — preservar el timestamp remoto para futuras comparaciones
            self.conn.execute(
                """UPDATE passwords
                   SET username=?, password=?, url=?, notes=?, is_favorite=?, updated_at=?
                   WHERE id=?""",
                (username, password, url, notes, is_favorite, remote_ts, existing_id),
            )
            self.conn.commit()
            return "updated"

    def delete_password(self, pw_id: int) -> None:
        self.conn.execute("DELETE FROM passwords WHERE id = ?", (pw_id,))
        self.conn.commit()
        self._increment_version()

    def search_passwords(self, query: str) -> list[dict]:
        """Busca contraseñas por título (texto plano)."""
        cur = self.conn.execute(
            "SELECT * FROM passwords WHERE title LIKE ? ORDER BY updated_at DESC",
            (f"%{query}%",),
        )
        return [dict(row) for row in cur.fetchall()]

    def get_favorites(self) -> list[dict]:
        cur = self.conn.execute(
            "SELECT * FROM passwords WHERE is_favorite = 1 ORDER BY updated_at DESC"
        )
        return [dict(row) for row in cur.fetchall()]

    def count_by_category(self) -> dict[int, int]:
        """Devuelve {category_id: count} para cada categoría."""
        cur = self.conn.execute(
            "SELECT category_id, COUNT(*) as cnt FROM passwords GROUP BY category_id"
        )
        return {row["category_id"]: row["cnt"] for row in cur.fetchall()}

    def import_from_list(self, data_list: list[dict], master_key: bytes) -> int:
        """Importación inteligente desde una lista de diccionarios (Sincronización)."""
        from security.crypto import encrypt, decrypt
        
        current_passwords = self.get_all_passwords()
        # Crear mapa de existencia: (título, usuario_plano, categoría) -> id
        existing_map = {}
        for lp in current_passwords:
            u_plain = ""
            try:
                u_plain = decrypt(lp["username"], master_key) if lp["username"] else ""
            except: pass
            existing_map[(lp["title"], u_plain, lp["category_id"])] = lp["id"]

        count = 0
        all_cats = self.get_all_categories()
        valid_ids = [c["id"] for c in all_cats]

        for item in data_list:
            cat_id = item.get("category_id", 8)
            if cat_id not in valid_ids: cat_id = 8

            title = item.get("title", "Sincronizado")
            u_plain = item.get("username", "")
            p_plain = item.get("password", "")
            n_plain = item.get("notes", "")
            url = item.get("url", "")

            enc_user = encrypt(u_plain, master_key)
            enc_pass = encrypt(p_plain, master_key)
            enc_note = encrypt(n_plain, master_key) if n_plain else b""

            key = (title, u_plain, cat_id)
            if key in existing_map:
                pw_id = existing_map[key]
                self.update_password(
                    pw_id,
                    password=enc_pass,
                    notes=enc_note,
                    url=url
                )
            else:
                self.add_password(
                    title=title,
                    username=enc_user,
                    password=enc_pass,
                    url=url,
                    notes=enc_note,
                    category_id=cat_id
                )
            count += 1
        
        self.conn.commit()
        self._increment_version()
        return count

    # ------------------------------------------------------------------ #
    #  CRUD - Categorías
    # ------------------------------------------------------------------ #
    def get_all_categories(self) -> list[dict]:
        cur = self.conn.execute("SELECT * FROM categories ORDER BY id")
        return [dict(row) for row in cur.fetchall()]

    def add_category(self, name: str, icon: str = "MORE_HORIZ",
                     color: str = "#607D8B") -> int:
        self.conn.execute(
            "INSERT INTO categories (name, icon, color, is_custom) VALUES (?, ?, ?, 1)",
            (name, icon, color),
        )
        self.conn.commit()
        self._increment_version()
        return cur.lastrowid

    def delete_category(self, cat_id: int) -> None:
        # Mover contraseñas huérfanas a "Otros" (id=8)
        self.conn.execute(
            "UPDATE passwords SET category_id = 8 WHERE category_id = ?", (cat_id,)
        )
        self.conn.execute("DELETE FROM categories WHERE id = ? AND is_custom = 1", (cat_id,))
        self.conn.commit()
        self._increment_version()

    # ------------------------------------------------------------------ #
    #  Preguntas de seguridad
    # ------------------------------------------------------------------ #
    def save_security_questions(self, questions: list[tuple[str, str]]) -> None:
        """Guarda preguntas con sus hashes. Reemplaza las existentes."""
        self.conn.execute("DELETE FROM security_questions")
        self.conn.executemany(
            "INSERT INTO security_questions (question, answer_hash) VALUES (?, ?)",
            questions,
        )
        self.conn.commit()

    def get_security_questions(self) -> list[dict]:
        cur = self.conn.execute("SELECT * FROM security_questions")
        return [dict(row) for row in cur.fetchall()]

    # ------------------------------------------------------------------ #
    #  Configuración
    # ------------------------------------------------------------------ #
    def get_config(self, key: str) -> str | None:
        cur = self.conn.execute("SELECT value FROM config WHERE key = ?", (key,))
        row = cur.fetchone()
        return row["value"] if row else None

    def set_config(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            (key, value),
        )
        self.conn.commit()

    def has_master_password(self) -> bool:
        return self.get_config("master_password_hash") is not None

    # ------------------------------------------------------------------ #
    #  Contraseñas Temporales (Almacén Generador)
    # ------------------------------------------------------------------ #
    def add_temp_password(self, password: bytes, name: str = "Sin nombre") -> None:
        now = datetime.now().isoformat()
        self.conn.execute(
            "INSERT INTO temp_passwords (password, name, created_at) VALUES (?, ?, ?)",
            (password, name, now)
        )
        self.conn.commit()

    def get_temp_passwords(self) -> list[dict]:
        cur = self.conn.execute("SELECT * FROM temp_passwords ORDER BY created_at DESC")
        return [dict(row) for row in cur.fetchall()]

    def cleanup_temp_passwords(self) -> None:
        """Mantiene solo las últimas 15 contraseñas (máx 24 horas)."""
        # Eliminar las más antiguas de 24h
        self.conn.execute(
            "DELETE FROM temp_passwords WHERE created_at < datetime('now', '-1 day')"
        )
        # Mantener solo las 15 más recientes
        self.conn.execute(
            """DELETE FROM temp_passwords 
               WHERE id NOT IN (
                   SELECT id FROM temp_passwords 
                   ORDER BY created_at DESC LIMIT 15
               )"""
        )
        self.conn.commit()

    def delete_temp_password(self, temp_id: int) -> None:
        """Elimina una contraseña temporal por su ID."""
        self.conn.execute("DELETE FROM temp_passwords WHERE id = ?", (temp_id,))
        self.conn.commit()

    # ------------------------------------------------------------------ #
    #  Gestión de Dispositivos de Confianza (Sync P2P)
    # ------------------------------------------------------------------ #
    def register_trusted_device(self, device_id: str, name: str, token: str):
        """Registra un dispositivo y mantiene solo los últimos 5."""
        now = datetime.now().isoformat()
        # Eliminar si ya existe para actualizar
        self.conn.execute("DELETE FROM trusted_sync_devices WHERE device_id = ?", (device_id,))
        
        # Insertar nuevo
        self.conn.execute(
            """INSERT INTO trusted_sync_devices 
               (device_id, device_name, trust_token, last_connected, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (device_id, name, token, now, now)
        )
        
        # Mantener solo 5 (los más recientes por conexión)
        self.conn.execute(
            """DELETE FROM trusted_sync_devices 
               WHERE id NOT IN (
                   SELECT id FROM trusted_sync_devices 
                   ORDER BY last_connected DESC LIMIT 5
               )"""
        )
        self.conn.commit()

    def get_trusted_device(self, device_id: str) -> dict | None:
        cur = self.conn.execute(
            "SELECT * FROM trusted_sync_devices WHERE device_id = ?", (device_id,)
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def list_trusted_devices(self) -> list[dict]:
        cur = self.conn.execute("SELECT * FROM trusted_sync_devices ORDER BY last_connected DESC")
        return [dict(row) for row in cur.fetchall()]

    def update_device_connection(self, device_id: str):
        now = datetime.now().isoformat()
        self.conn.execute(
            "UPDATE trusted_sync_devices SET last_connected = ? WHERE device_id = ?",
            (now, device_id)
        )
        self.conn.commit()
