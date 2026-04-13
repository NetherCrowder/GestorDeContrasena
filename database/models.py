"""
models.py - Esquema de base de datos SQLite para el Gestor de Contraseñas.
Define las tablas: passwords, categories, security_questions, config.
"""

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS categories (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    icon        TEXT    NOT NULL DEFAULT 'MORE_HORIZ',
    color       TEXT    NOT NULL DEFAULT '#607D8B',
    is_custom   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS passwords (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    title           TEXT    NOT NULL,
    username        BLOB,
    password        BLOB    NOT NULL,
    url             TEXT    DEFAULT '',
    category_id     INTEGER NOT NULL DEFAULT 8,
    notes           BLOB,
    is_favorite     INTEGER NOT NULL DEFAULT 0,
    password_rules  TEXT    DEFAULT '{}',
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    FOREIGN KEY (category_id) REFERENCES categories(id)
);

CREATE TABLE IF NOT EXISTS security_questions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    question    TEXT    NOT NULL,
    answer_hash TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS config (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS temp_passwords (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    password    BLOB    NOT NULL,
    name        TEXT    DEFAULT 'Sin nombre',
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS trusted_sync_devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       TEXT UNIQUE NOT NULL,
    device_name     TEXT    NOT NULL,
    trust_token     TEXT    NOT NULL,
    last_connected  TEXT    NOT NULL,
    created_at      TEXT    NOT NULL
);
"""

# Categorías predefinidas para insertar en la primera ejecución
DEFAULT_CATEGORIES = [
    ("Banca y Finanzas",  "ACCOUNT_BALANCE",  "#4CAF50", 0),
    ("Redes Sociales",    "PEOPLE",           "#E91E63", 0),
    ("Trabajo",           "WORK",             "#2196F3", 0),
    ("Entretenimiento",   "SPORTS_ESPORTS",   "#9C27B0", 0),
    ("Compras",           "SHOPPING_CART",     "#FF9800", 0),
    ("Email",             "EMAIL",            "#00BCD4", 0),
    ("Educación",         "SCHOOL",           "#795548", 0),
    ("Otros",             "MORE_HORIZ",       "#607D8B", 0),
]

# Banco de preguntas de seguridad predefinidas
SECURITY_QUESTIONS_BANK = [
    "¿Cuál es el nombre de tu pareja?",
    "¿Cuál es el nombre de tu mascota?",
    "¿En qué ciudad naciste?",
    "¿Cuál es el nombre de tu mejor amigo/a de infancia?",
    "¿Cuál fue tu primer trabajo?",
    "¿Cuál es el nombre de tu madre?",
    "¿Cuál es tu comida favorita?",
    "¿Cuál fue tu primer número de teléfono?",
]

# Perfiles de generación de contraseñas
PASSWORD_PROFILES = {
    "estandar": {
        "label": "🔐 Estándar",
        "min_length": 12,
        "max_length": 32,
        "allow_uppercase": True,
        "allow_lowercase": True,
        "allow_numbers": True,
        "allow_symbols": True,
        "allowed_symbols": "!@#$%^&*()_+-=[]{}|;:',.<>?/~`ñÑ",
        "pin_only": False,
    },
    "pin": {
        "label": "🏦 Solo PIN",
        "min_length": 4,
        "max_length": 8,
        "allow_uppercase": False,
        "allow_lowercase": False,
        "allow_numbers": True,
        "allow_symbols": False,
        "allowed_symbols": "",
        "pin_only": True,
    },
    "sin_especiales": {
        "label": "🔒 Sin especiales",
        "min_length": 8,
        "max_length": 20,
        "allow_uppercase": True,
        "allow_lowercase": True,
        "allow_numbers": True,
        "allow_symbols": False,
        "allowed_symbols": "",
        "pin_only": False,
    },

    "personalizado": {
        "label": "✏️ Personalizado",
        "min_length": 4,
        "max_length": 64,
        "allow_uppercase": True,
        "allow_lowercase": True,
        "allow_numbers": True,
        "allow_symbols": True,
        "allowed_symbols": "!@#$%^&*()_+-=[]{}|;:',.<>?/~`ñÑ",
        "pin_only": False,
    },
}
