"""
search_bar.py - Componente de barra de búsqueda.
"""

import flet as ft


def create_search_bar(on_search: callable) -> ft.Container:
    """Crea una barra de búsqueda estilizada."""
    return ft.Container(
        content=ft.TextField(
            hint_text="Buscar contraseñas...",
            hint_style=ft.TextStyle(color=ft.Colors.WHITE38),
            prefix_icon=ft.Icons.SEARCH,
            border=ft.InputBorder.NONE,
            bgcolor="#1e2a3a",
            color=ft.Colors.WHITE,
            cursor_color=ft.Colors.CYAN,
            text_size=14,
            content_padding=ft.padding.symmetric(horizontal=16, vertical=12),
            on_change=lambda e: on_search(e.control.value),
        ),
        border_radius=14,
        border=ft.border.all(1, ft.Colors.WHITE10),
        animate=ft.Animation(200, ft.AnimationCurve.EASE_IN_OUT),
    )
