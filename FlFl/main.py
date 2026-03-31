import flet as ft
import requests

SERVER_IP = "http://127.0.0.1:8000"  # En Android cambia a la IP del PC

def main(page: ft.Page):
    page.title = "Prueba de conexión"
    page.vertical_alignment = ft.MainAxisAlignment.CENTER

    result_text = ft.Text(value="Presiona el botón para probar conexión")

    def test_connection(e):
        try:
            response = requests.get(f"{SERVER_IP}/ping")
            result_text.value = response.json()["message"]
        except Exception as ex:
            result_text.value = f"Error: {ex}"
        page.update()

    btn = ft.Button(content=ft.Text("Probar conexión"), on_click=test_connection)

    page.add(result_text, btn)

ft.run(main)
