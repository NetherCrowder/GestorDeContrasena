"""
category_tile.py - Tile visual para una categoría en el dashboard.
"""

import flet as ft
from utils.categories import get_icon


def create_category_tile(
    category: dict,
    count: int,
    on_click: callable,
) -> ft.Container:
    """Crea un tile de categoría con contador."""
    color = category.get("color", "#607D8B")
    icon_name = category.get("icon", "MORE_HORIZ")

    return ft.Container(
        content=ft.Column(
            [
                ft.Container(
                    content=ft.Icon(
                        get_icon(icon_name),
                        color=color,
                        size=32,
                    ),
                    bgcolor=f"{color}20",
                    border_radius=14,
                    width=56,
                    height=56,
                    alignment=ft.Alignment.CENTER,
                ),
                ft.Text(
                    category["name"],
                    size=13,
                    weight=ft.FontWeight.W_600,
                    color=ft.Colors.WHITE,
                    text_align=ft.TextAlign.CENTER,
                    max_lines=1,
                    overflow=ft.TextOverflow.ELLIPSIS,
                ),
                ft.Text(
                    f"{count} {'contraseña' if count == 1 else 'contraseñas'}",
                    size=11,
                    color=ft.Colors.WHITE54,
                    text_align=ft.TextAlign.CENTER,
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=6,
        ),
        bgcolor="#1e2a3a",
        border_radius=18,
        padding=ft.padding.all(16),
        border=ft.border.all(1, f"{color}30"),
        on_click=lambda e, cid=category["id"]: on_click(cid),
        ink=True,
        animate=ft.Animation(300, ft.AnimationCurve.EASE_IN_OUT),
        on_hover=lambda e, c=color: on_tile_hover(e, c),
    )


def on_tile_hover(e: ft.ControlEvent, color: str):
    container: ft.Container = e.control
    if e.data == "true":
        container.bgcolor = "#253545"
        container.border = ft.border.all(1.5, color)
        container.scale = 1.03
    else:
        container.bgcolor = "#1e2a3a"
        container.border = ft.border.all(1, f"{color}30")
        container.scale = 1.0
    container.update()
