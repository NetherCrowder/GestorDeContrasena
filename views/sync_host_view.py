"""
sync_host_view.py - Vista de Servidor (PC) para sincronización local.
Permite iniciar el puente, mostrar QR/PIN y gestionar clientes.
"""

import flet as ft
import qrcode
import io
import base64
import os
from utils.sync_service import BridgeServer
from icecream import ic

class SyncHostView:
    def __init__(self, page: ft.Page, db_manager, auth_manager, bridge_server, on_back: callable):
        self.page = page
        self.db = db_manager
        self.auth = auth_manager
        self.server = bridge_server  # type: BridgeServer
        self.on_back = on_back
        
        # Estado local
        self.is_active = self.server.is_running
        
        # Componentes UI
        self.status_text = ft.Text("Puente Desconectado", size=16, color=ft.Colors.WHITE54)
        self.qr_image = ft.Image(
            src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
            width=250, height=250, border_radius=12, visible=False
        )
        self.pin_text = ft.Text("", size=40, weight=ft.FontWeight.BOLD, color=ft.Colors.CYAN)
        
        self.pin_area = ft.Column([
            ft.Text("PIN de Respaldo", size=12, color=ft.Colors.WHITE38),
            self.pin_text,
        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, visible=False)
        
        self.ip_text = ft.Text("", size=14, color=ft.Colors.WHITE38)
        self.clients_list = ft.Column(spacing=5)
        
        self.start_btn = ft.ElevatedButton(
            "Iniciar Puente Seguro",
            icon=ft.Icons.ROUTER,
            bgcolor=ft.Colors.CYAN_700,
            color=ft.Colors.WHITE,
            on_click=self.toggle_bridge
        )

    def build(self):
        # Si el servidor ya está activo, restaurar UI
        if self.is_active:
            self.restore_active_ui()

        return ft.Container(
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.IconButton(ft.Icons.ARROW_BACK, on_click=lambda _: self.on_back()),
                            ft.Text("Puente KeyVault", size=20, weight=ft.FontWeight.BOLD),
                        ],
                        alignment=ft.MainAxisAlignment.START,
                    ),
                    ft.Divider(height=20, color=ft.Colors.WHITE10),
                    
                    ft.Column(
                        [
                            ft.Icon(ft.Icons.CELL_WIFI, size=50, color=ft.Colors.CYAN),
                            ft.Text("Sincronización Local", size=24, weight=ft.FontWeight.W_700),
                            ft.Text(
                                "Activa el Hotspot de Windows si no estás en la misma red WiFi.",
                                size=13, color=ft.Colors.WHITE38, text_align=ft.TextAlign.CENTER
                            ),
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=10,
                        width=float("inf"),
                    ),
                    
                    ft.Container(height=20),
                    
                    # Área de Emparejamiento
                    ft.Container(
                        content=ft.Column(
                            [
                                self.status_text,
                                self.qr_image,
                                self.pin_area,
                                self.ip_text,
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=15,
                        ),
                        bgcolor="#1e2a3a",
                        padding=30,
                        border_radius=20,
                        border=ft.border.all(1, ft.Colors.WHITE10),
                        width=400,
                    ),
                    
                    ft.Container(height=10),
                    self.start_btn,
                    
                    ft.Container(height=20),
                    ft.Text("Dispositivos en línea:", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE54),
                    self.clients_list,
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                scroll=ft.ScrollMode.AUTO,
            ),
            padding=20,
            expand=True,
            bgcolor="#0f172a",
        )

    def generate_qr_base64(self, data):
        """Genera un código QR y devuelve su representación en Data URI."""
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        raw_b64 = base64.b64encode(buffered.getvalue()).decode()
        return f"data:image/png;base64,{raw_b64}"

    def toggle_bridge(self, e):
        if not self.is_active:
            self.start_bridge()
        else:
            self.stop_bridge()
        self.page.update()

    def start_bridge(self):
        try:
            # 1. Preparar datos de la bóveda (Exportación temporal)
            # Nota: Usamos la función de backup existente para generar el binario
            vault_bytes = self.db.export_vault_binary(self.auth.master_key)
            vault_b64 = base64.b64encode(vault_bytes).decode()
            
            # 2. Iniciar Servidor
            config = self.server.start(vault_b64)
            
            # 3. Generar QR (Data URI completo)
            qr_payload = f"KV_SYNC|{config['ip']}|{config['port']}|{config['token']}|{config['key_b64']}"
            self.qr_image.src = self.generate_qr_base64(qr_payload)
            self.qr_image.visible = True
            
            # 4. Actualizar UI
            self.pin_text.value = config["pin"]
            self.pin_area.visible = True
            self.ip_text.value = f"Servidor activo en: {config['ip']}"
            self.status_text.value = "🟢 Esperando conexión..."
            self.status_text.color = ft.Colors.CYAN
            self.start_btn.text = "Detener Puente"
            self.start_btn.bgcolor = ft.Colors.RED_700
            
            self.is_active = True
            ic("Servidor de sincronización iniciado")
            
        except Exception as ex:
            ic(f"Fallo al iniciar servidor: {ex}")
            self.show_snackbar(f"Error: {ex}")

    def stop_bridge(self):
        self.server.stop()
        self.qr_image.visible = False
        self.pin_area.visible = False
        self.ip_text.value = ""
        self.status_text.value = "Puente Desconectado"
        self.status_text.color = ft.Colors.WHITE54
        self.start_btn.text = "Iniciar Puente Seguro"
        self.start_btn.bgcolor = ft.Colors.CYAN_700
        self.is_active = False
        ic("Servidor de sincronización detenido")

    def show_snackbar(self, msg: str):
        self.page.snack_bar = ft.SnackBar(ft.Text(msg))
        self.page.snack_bar.open = True
        self.page.update()

    def restore_active_ui(self):
        """Restaura la UI si el servidor ya está corriendo."""
        if self.server.last_config:
            config = self.server.last_config
            # Re-generar QR
            qr_payload = f"KV_SYNC|{config['ip']}|{config['port']}|{config['token']}|{config['key_b64']}"
            self.qr_image.src = self.generate_qr_base64(qr_payload)
            self.qr_image.visible = True
            
            self.pin_text.value = config["pin"]
            self.pin_area.visible = True
            self.ip_text.value = f"Servidor activo en: {config['ip']}"
            self.status_text.value = "🟢 Puente Activo"
            self.status_text.color = ft.Colors.CYAN
            self.start_btn.text = "Detener Puente"
            self.start_btn.bgcolor = ft.Colors.RED_700
