"""
Punto de entrada original de KeyVault (DEPRECADO).
Por favor, utiliza main_windows.py o main_mobile.py.
"""

import flet as ft
import sys

def main(page: ft.Page):
    print("=" * 60)
    print(" ATENCION: EL PUNTO DE ENTRADA HA CAMBIADO ")
    print("=" * 60)
    print("\nEl archivo 'main.py' esta obsoleto.")
    print("Para facilitar el desarrollo, se separaron las plataformas.\n")
    print("-> Para ejecutar la version de ESCRITORIO (Host):")
    print("   python main_windows.py\n")
    print("-> Para ejecutar la version SIMULADA MOVIL (Client):")
    print("   python main_mobile.py\n")
    print("=" * 60)

    page.title = "KeyVault — Archivo Obsoleto"
    page.bgcolor = "#0f172a"
    page.theme_mode = ft.ThemeMode.DARK
    page.window.width = 600
    page.window.height = 400
    
    async def close_app(e):
        await page.window.destroy()

    page.add(
        ft.Container(
            expand=True,
            content=ft.Column(
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                alignment=ft.MainAxisAlignment.CENTER,
                controls=[
                    ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, size=80, color=ft.Colors.AMBER),
                    ft.Text("ARCHIVO OBSOLETO", size=24, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE),
                    ft.Text(
                        "Has ejecutado main.py, el cual ya no es el punto de entrada.\n\n"
                        "-> Para escritorio: python main_windows.py\n"
                        "-> Para movil: python main_mobile.py",
                        size=16,
                        text_align=ft.TextAlign.CENTER,
                        color=ft.Colors.WHITE70
                    ),
                    ft.Container(height=20),
                    ft.FilledButton(
                        "Cerrar Aplicacion",
                        icon=ft.Icons.CLOSE,
                        style=ft.ButtonStyle(bgcolor=ft.Colors.RED_700, color=ft.Colors.WHITE),
                        on_click=close_app
                    )
                ]
            )
        )
    )
    page.update()

if __name__ == "__main__":
    # Mostrar advertencia en consola también directamente
    print("ATENCION: main.py esta obsoleto. Ejecutando aviso grafico...")
    ft.run(main)
