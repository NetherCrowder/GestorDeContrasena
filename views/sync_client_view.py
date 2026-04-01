"""
sync_client_view.py - Vista de Cliente (Móvil) para sincronización local.
Permite escanear QR o introducir el PIN para vincularse al PC.
"""

import flet as ft
from utils.sync_service import BridgeClient
from icecream import ic
import json
import base64

class SyncClientView:
    def __init__(self, page: ft.Page, db_manager, auth_manager, bridge_client, on_back: callable):
        self.page = page
        self.db = db_manager
        self.auth = auth_manager
        self.client = bridge_client
        self.on_back = on_back
        
        # Componentes UI
        self.pin_input = ft.TextField(
            label="Introduce el PIN del PC",
            hint_text="000000",
            text_align=ft.TextAlign.CENTER,
            width=200,
            keyboard_type=ft.KeyboardType.NUMBER,
            password=True,
            can_reveal_password=True,
        )
        
        self.ip_input = ft.TextField(
            label="IP del PC (opcional si usas PIN)",
            hint_text="192.168.1.XX",
            width=250,
            keyboard_type=ft.KeyboardType.TEXT,
        )
        
        self.status_text = ft.Text("Listo para vincular", size=14, color=ft.Colors.WHITE54)
        self.loading_ring = ft.ProgressRing(visible=False, width=20, height=20, stroke_width=2)
        
        self.connect_btn = ft.ElevatedButton(
            "Vincular ahora",
            icon=ft.Icons.LINK,
            bgcolor=ft.Colors.CYAN_700,
            color=ft.Colors.WHITE,
            on_click=self.attempt_connect
        )

    def build(self):
        return ft.Container(
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.IconButton(ft.Icons.ARROW_BACK, on_click=lambda _: self.on_back()),
                            ft.Text("Vincular PC", size=20, weight=ft.FontWeight.BOLD),
                        ],
                    ),
                    ft.Divider(height=20, color=ft.Colors.WHITE10),
                    
                    ft.Icon(ft.Icons.PHONELINK_SETUP, size=60, color=ft.Colors.CYAN),
                    ft.Text("Conexión Segura", size=22, weight=ft.FontWeight.BOLD),
                    ft.Text(
                        "Introduce el PIN que aparece en la pantalla de tu PC.",
                        size=14, color=ft.Colors.WHITE38, text_align=ft.TextAlign.CENTER
                    ),
                    
                    ft.Container(height=20),
                    
                    self.pin_input,
                    ft.Text("O usa la IP directamente si conoces el token:", size=12, color=ft.Colors.WHITE24),
                    self.ip_input,
                    
                    ft.Container(height=10),
                    ft.Row([self.loading_ring, self.status_text], alignment=ft.MainAxisAlignment.CENTER),
                    
                    ft.Container(height=10),
                    self.connect_btn,
                    
                    ft.Container(height=30),
                    ft.Text(
                        "Nota: Ambos dispositivos deben estar en la misma red WiFi o el PC debe tener el Hotspot activo.",
                        size=12, color=ft.Colors.AMBER_200, text_align=ft.TextAlign.CENTER, italic=True
                    ),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            padding=20,
            expand=True,
            bgcolor="#0f172a",
        )

    def attempt_connect(self, e):
        code = self.pin_input.value.strip() # Puede ser el PIN o el código QR completo
        if not code:
            self.pin_input.error_text = "Introduce el PIN o escanea el QR"
            self.page.update()
            return
            
        self.status_text.value = "Conectando con PC..."
        self.loading_ring.visible = True
        self.connect_btn.disabled = True
        self.page.update()
        
        try:
            # Si el código es el del QR (formato: KV_SYNC|IP|PORT|TOKEN|KEY|QUEST)
            if code.startswith("KV_SYNC"):
                parts = code.split("|")
                ip = parts[1]
                port = int(parts[2])
                token = parts[3]
                key_b64 = parts[4]
                key = base64.b64decode(key_b64)
            else:
                # Si es un PIN, necesitamos la IP manual (MVP)
                ip = self.ip_input.value.strip()
                if not ip:
                    raise Exception("Si usas PIN, debes introducir la IP del PC")
                port = 5000
                token = code # Usamos el PIN como token temporal para el handshake
                key = b'00000000000000000000000000000000' # Clave debil para PIN (mejorar después)

            def on_vault_received(vault_data_b64):
                self.show_snackbar("📦 Bóveda recibida. Ve a Restaurar para aplicar.")

            def on_clipboard_received(text):
                self.page.set_clipboard(text)
                self.show_snackbar("📋 Portapapeles actualizado desde PC")

            # Iniciar conexión
            success = self.client.connect(
                ip=ip, 
                port=port, 
                token=token, 
                encryption_key=key, 
                on_vault=on_vault_received,
                on_clipboard=on_clipboard_received
            )
            
            if success:
                self.status_text.value = "🟢 Vinculado y escuchando PC"
                self.status_text.color = ft.Colors.CYAN
            else:
                raise Exception("El PC rechazó la conexión o no es visible")
                
        except Exception as ex:
            self.show_snackbar(f"Error: {ex}")
            self.status_text.value = f"❌ {str(ex)}"
            self.status_text.color = ft.Colors.RED
            self.connect_btn.disabled = False
            
        self.loading_ring.visible = False
        self.page.update()

    def show_snackbar(self, msg: str):
        self.page.snack_bar = ft.SnackBar(ft.Text(msg))
        self.page.snack_bar.open = True
        self.page.update()
