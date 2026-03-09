"""
password_card.py - Componente de tarjeta de contraseña para la lista.
"""

import flet as ft
from utils.categories import get_icon


def create_password_card(
    pw_data: dict,
    category: dict,
    on_copy_user: callable,
    on_copy_pass: callable,
    on_edit: callable,
    on_delete: callable,
    on_favorite: callable,
    on_open_url: callable,
) -> ft.Container:
    """Crea una tarjeta visual para una contraseña."""

    cat_color = category.get("color", "#607D8B") if category else "#607D8B"
    cat_name = category.get("name", "Otros") if category else "Otros"

    return ft.Container(
        content=ft.Column(
            [
                # Título y favorito
                ft.Row(
                    [
                        ft.Icon(
                            get_icon(category.get("icon", "MORE_HORIZ") if category else "MORE_HORIZ"),
                            color=cat_color,
                            size=24,
                        ),
                        ft.Column(
                            [
                                ft.Text(
                                    pw_data.get("title", ""),
                                    size=16,
                                    weight=ft.FontWeight.W_600,
                                    color=ft.Colors.WHITE,
                                ),
                                ft.Text(
                                    cat_name,
                                    size=12,
                                    color=cat_color,
                                ),
                            ],
                            spacing=2,
                            expand=True,
                        ),
                        ft.IconButton(
                            icon=ft.Icons.STAR if pw_data.get("is_favorite") else ft.Icons.STAR_BORDER,
                            icon_color="#FFD700" if pw_data.get("is_favorite") else ft.Colors.WHITE54,
                            icon_size=20,
                            on_click=lambda e, pid=pw_data["id"]: on_favorite(pid),
                            tooltip="Favorito",
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.START,
                ),
                # Acciones rápidas
                ft.Column(
                    [
                        ft.TextButton(
                            "Mostrar y copiar usuario",
                            icon=ft.Icons.PERSON,
                            icon_color=ft.Colors.CYAN,
                            style=ft.ButtonStyle(color=ft.Colors.WHITE70),
                            on_click=lambda e, pid=pw_data["id"]: on_copy_user(e, pid),
                        ),
                        ft.TextButton(
                            "Mostrar y copiar clave",
                            icon=ft.Icons.KEY,
                            icon_color=ft.Colors.AMBER,
                            style=ft.ButtonStyle(color=ft.Colors.WHITE70),
                            on_click=lambda e, pid=pw_data["id"]: on_copy_pass(e, pid),
                        ),
                    ],
                    spacing=0,
                ),
                # Botones secundarios
                ft.Row(
                    [
                        ft.IconButton(
                            icon=ft.Icons.OPEN_IN_NEW,
                            icon_color=ft.Colors.CYAN,
                            icon_size=18,
                            tooltip="Abrir URL",
                            on_click=lambda e, pid=pw_data["id"]: on_open_url(pid),
                        ),
                        ft.IconButton(
                            icon=ft.Icons.EDIT,
                            icon_color=ft.Colors.BLUE_200,
                            icon_size=18,
                            tooltip="Editar",
                            on_click=lambda e, pid=pw_data["id"]: on_edit(pid),
                        ),
                        ft.IconButton(
                            icon=ft.Icons.DELETE_OUTLINE,
                            icon_color=ft.Colors.RED_300,
                            icon_size=18,
                            tooltip="Eliminar",
                            on_click=lambda e, pid=pw_data["id"]: on_delete(pid),
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.END,
                    spacing=0,
                ),
            ],
            spacing=4,
        ),
        bgcolor="#1e2a3a",
        border_radius=16,
        padding=ft.padding.all(16),
        border=ft.border.all(1, f"{cat_color}30"),
        animate=ft.Animation(300, ft.AnimationCurve.EASE_IN_OUT),
        on_hover=lambda e: _on_card_hover(e),
    )


def _on_card_hover(e: ft.ControlEvent):
    """Efecto hover en la tarjeta."""
    container: ft.Container = e.control
    if e.data == "true":
        container.bgcolor = "#253545"
        container.border = ft.border.all(1, ft.Colors.CYAN_700)
    else:
        container.bgcolor = "#1e2a3a"
        container.border = ft.border.all(1, "#60000000")
    container.update()
