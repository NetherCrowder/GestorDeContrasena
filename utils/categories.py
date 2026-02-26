"""
categories.py - Mapeo de nombres de íconos a objetos Flet icons.
"""

import flet as ft

# Mapeo de nombre de ícono (string) → ícono de Flet
ICON_MAP: dict[str, str] = {
    "ACCOUNT_BALANCE": ft.Icons.ACCOUNT_BALANCE,
    "PEOPLE": ft.Icons.PEOPLE,
    "WORK": ft.Icons.WORK,
    "SPORTS_ESPORTS": ft.Icons.SPORTS_ESPORTS,
    "SHOPPING_CART": ft.Icons.SHOPPING_CART,
    "EMAIL": ft.Icons.EMAIL,
    "SCHOOL": ft.Icons.SCHOOL,
    "MORE_HORIZ": ft.Icons.MORE_HORIZ,
    # Para categorías personalizadas
    "FOLDER": ft.Icons.FOLDER,
    "STAR": ft.Icons.STAR,
    "LOCK": ft.Icons.LOCK,
    "WIFI": ft.Icons.WIFI,
    "PHONE": ft.Icons.PHONE,
    "HOME": ft.Icons.HOME,
    "FLIGHT": ft.Icons.FLIGHT,
    "FITNESS_CENTER": ft.Icons.FITNESS_CENTER,
    "LOCAL_HOSPITAL": ft.Icons.LOCAL_HOSPITAL,
    "DIRECTIONS_CAR": ft.Icons.DIRECTIONS_CAR,
}


def get_icon(icon_name: str) -> str:
    """Obtiene el ícono de Flet a partir de su nombre string."""
    return ICON_MAP.get(icon_name, ft.Icons.MORE_HORIZ)
