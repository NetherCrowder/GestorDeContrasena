"""
helpers.py - Funciones auxiliares compartidas.
"""

import secrets
import string
import json


def generate_password(length: int = 16,
                      allow_uppercase: bool = True,
                      allow_lowercase: bool = True,
                      allow_numbers: bool = True,
                      allow_symbols: bool = True,
                      allowed_symbols: str = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`",
                      pin_only: bool = False) -> str:
    """
    Genera una contraseña criptográficamente segura.
    Respeta las restricciones del perfil/sitio.
    """
    if pin_only:
        return "".join(secrets.choice(string.digits) for _ in range(length))

    charset = ""
    required_chars = []

    if allow_lowercase:
        charset += string.ascii_lowercase
        required_chars.append(secrets.choice(string.ascii_lowercase))
    if allow_uppercase:
        charset += string.ascii_uppercase
        required_chars.append(secrets.choice(string.ascii_uppercase))
    if allow_numbers:
        charset += string.digits
        required_chars.append(secrets.choice(string.digits))
    if allow_symbols and allowed_symbols:
        charset += allowed_symbols
        required_chars.append(secrets.choice(allowed_symbols))

    if not charset:
        charset = string.ascii_letters + string.digits
        required_chars = [secrets.choice(charset)]

    # Generar el resto de caracteres
    remaining = length - len(required_chars)
    if remaining > 0:
        pw_chars = required_chars + [
            secrets.choice(charset) for _ in range(remaining)
        ]
    else:
        pw_chars = required_chars[:length]

    # Mezclar para evitar patrones predecibles
    result = list(pw_chars)
    secrets.SystemRandom().shuffle(result)
    return "".join(result)


def password_strength(password: str) -> tuple[int, str]:
    """
    Evalúa la fortaleza de una contraseña.
    Retorna (puntaje 0-100, etiqueta).
    """
    score = 0
    length = len(password)

    # Longitud
    if length >= 8:
        score += 15
    if length >= 12:
        score += 15
    if length >= 16:
        score += 10
    if length >= 20:
        score += 10

    # Variedad de caracteres
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in "!@#$%^&*()_+-=[]{}|;:',.<>?/~`" for c in password)

    if has_lower:
        score += 10
    if has_upper:
        score += 10
    if has_digit:
        score += 10
    if has_symbol:
        score += 15

    # Entropía por longitud única
    unique_chars = len(set(password))
    score += min(5, unique_chars // 3)

    score = min(100, score)

    if score < 30:
        return score, "Débil"
    elif score < 55:
        return score, "Media"
    elif score < 80:
        return score, "Fuerte"
    else:
        return score, "Muy fuerte"


def strength_color(score: int) -> str:
    """Color asociado al puntaje de fortaleza."""
    if score < 30:
        return "#F44336"  # Rojo
    elif score < 55:
        return "#FF9800"  # Naranja
    elif score < 80:
        return "#4CAF50"  # Verde
    else:
        return "#00E676"  # Verde brillante


def parse_rules(rules_json: str) -> dict:
    """Parsea las reglas de contraseña desde JSON."""
    try:
        return json.loads(rules_json) if rules_json else {}
    except (json.JSONDecodeError, TypeError):
        return {}
