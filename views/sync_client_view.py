"""
sync_client_view.py - Vista de Cliente (Móvil) para sincronización local.
Permite vincularse al PC mediante PIN/IP con validación en tiempo real.
"""

import flet as ft
from utils.sync_service import BridgeClient
from icecream import ic
import json
import base64
import hashlib

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
        
        self.paste_btn = ft.Row([
            ft.TextButton("Pegar desde Portapapeles", icon=ft.Icons.CONTENT_PASTE, on_click=self.paste_qr),
        ], alignment=ft.MainAxisAlignment.CENTER)
        
        self.ip_label = ft.Text("O usa la IP directamente:", size=12, color=ft.Colors.WHITE24)

        # Restaurar estado visual si la conexión persiste en segundo plano
        if self.client.is_listening:
            self.pin_input.visible = False
            self.ip_input.visible = False
            self.ip_label.visible = False
            self.paste_btn.visible = False
            
            self.status_text.value = "🟢 Vinculado correctamente"
            self.status_text.color = ft.Colors.CYAN
            self.connect_btn.text = "Cerrar Conexión"
            self.connect_btn.bgcolor = ft.Colors.RED_700
            self.connect_btn.on_click = self.disconnect

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
                    self.ip_label,
                    self.ip_input,
                    self.paste_btn,
                    
                    ft.Container(height=10),
                    ft.Row([self.loading_ring, self.status_text], alignment=ft.MainAxisAlignment.CENTER),
                    
                    ft.Container(height=10),
                    self.connect_btn,
                    
                    ft.Container(height=30),
                    ft.Text(
                        "Nota: Con Flet 0.83.0, asegúrate de dar permisos de Red en los ajustes de tu móvil si la app lo solicita.",
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
        code = self.pin_input.value.strip() 
        if not code:
            self.pin_input.error_text = "Introduce el PIN"
            self.page.update()
            return
            
        self.status_text.value = "Verificando conexión..."
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
                # Si es un PIN, necesitamos la IP manual
                ip = self.ip_input.value.strip()
                if not ip:
                    raise Exception("Si usas PIN, debes introducir la IP del PC")
                port = 5005 
                token = code 
                # Clave determinista basada en el PIN
                key = hashlib.sha256(code.encode()).digest() 

            def on_vault_received(vault_b64: str):
                """Aplica la bóveda del PC a la BD local con estrategia Merge."""
                try:
                    from utils.backup import apply_bridge_vault
                    ins, upd, skp = apply_bridge_vault(vault_b64, self.db, self.auth.key)
                    total = ins + upd
                    if total > 0:
                        self.show_snackbar(f"📦 {ins} nuevas, {upd} actualizadas, {skp} sin cambios.")
                        # Notificar al sistema global para refrescar la UI
                        if self.client.on_vault_sync:
                            self.client.on_vault_sync(ins, upd)
                    else:
                        self.show_snackbar("✅ Bóveda ya está sincronizada.")
                except Exception as ex:
                    self.show_snackbar(f"⚠️ Error aplicando bóveda: {ex}")

            def on_clipboard_received(text):
                try:
                    import subprocess
                    subprocess.run("clip", input=text.strip().encode("utf-16le"), check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    self.show_snackbar("📋 Portapapeles actualizado desde PC")
                except Exception as ex:
                    print("Error seteando clipboard local:", ex)

            # 1. INTENTAR CONEXIÓN REAL (HANDSHAKE)
            success = self.client.connect(
                ip=ip, 
                port=port, 
                token=token, 
                encryption_key=key, 
                on_vault=on_vault_received,
                on_clipboard=on_clipboard_received
            )
            
            if success:
                self.pin_input.visible = False
                self.ip_input.visible = False
                self.ip_label.visible = False
                self.paste_btn.visible = False
                
                # Guardar credenciales para reconexion automática futura
                self.client.save_pairing()
                
                self.status_text.value = "🟢 Vinculado correctamente"
                self.status_text.color = ft.Colors.CYAN
                self.connect_btn.text = "Cerrar Conexión"
                self.connect_btn.bgcolor = ft.Colors.RED_700
                self.connect_btn.on_click = self.disconnect
                self.connect_btn.disabled = False
                self.show_snackbar("🔒 Pairing guardado. La próxima vez se reconectará automáticamente.")
            else:
                raise Exception("El servidor no respondió o el PIN es incorrecto")
                
        except Exception as ex:
            self.show_snackbar(f"Error: {ex}")
            self.status_text.value = f"❌ {str(ex)}"
            self.status_text.color = ft.Colors.RED
            self.connect_btn.disabled = False
            
        self.loading_ring.visible = False
        self.page.update()

    def disconnect(self, e):
        self.client.stop_listener()
        self.client.clear_pairing()  # Borrar pairing guardado al desconectar manualmente
        
        self.pin_input.visible = True
        self.ip_input.visible = True
        self.ip_label.visible = True
        self.paste_btn.visible = True
        self.pin_input.value = ""
        
        self.status_text.value = "Desconectado"
        self.status_text.color = ft.Colors.WHITE54
        self.connect_btn.text = "Vincular ahora"
        self.connect_btn.bgcolor = ft.Colors.CYAN_700
        self.connect_btn.on_click = self.attempt_connect
        self.page.update()

    def paste_qr(self, e):
        # Obtener contenido del portapapeles usando PowerShell como bypass nativo
        try:
            import subprocess
            res = subprocess.run(["powershell", "-command", "Get-Clipboard"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            text = res.stdout.strip()
            
            if text:
                self.pin_input.value = text
                self.pin_input.update()
                self.show_snackbar("Contenido pegado")
                # Intentar conectar automáticamente si es un código de sincronización real
                if text.startswith("KV_SYNC"):
                    self.attempt_connect(None)
            else:
                self.show_snackbar("El portapapeles está vacío")
        except Exception as ex:
            self.show_snackbar(f"No se pudo acceder al portapapeles: {ex}")

    def show_snackbar(self, msg: str):
        self.page.snack_bar = ft.SnackBar(ft.Text(msg))
        self.page.snack_bar.open = True
        self.page.update()
