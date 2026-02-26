"""
strength_bar.py - Indicador visual de fortaleza de contraseña.
"""

import flet as ft
from utils.helpers import password_strength, strength_color


def create_strength_bar(password: str) -> ft.Container:
    """Crea una barra de fortaleza visual para la contraseña dada."""
    score, label = password_strength(password)
    color = strength_color(score)

    return ft.Container(
        content=ft.Column(
            [
                ft.Row(
                    [
                        ft.Text("Fortaleza:", size=12, color=ft.Colors.WHITE54),
                        ft.Text(
                            label,
                            size=12,
                            weight=ft.FontWeight.W_600,
                            color=color,
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                ),
                ft.ProgressBar(
                    value=score / 100,
                    color=color,
                    bgcolor="#2a2a3e",
                    bar_height=6,
                    border_radius=3,
                ),
            ],
            spacing=4,
        ),
        padding=ft.padding.symmetric(vertical=4),
    )
