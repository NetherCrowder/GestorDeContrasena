"""
sync_host_view.py - Vista de Servidor (PC) para sincronización local.
Muestra el PIN rotativo y la Clave de Seguridad para vinculación en 2 pasos.
NO usa QR.
"""

import flet as ft
import asyncio
from utils.sync_service import BridgeServer
from icecream import ic


class SyncHostView:
    def __init__(self, page: ft.Page, db_manager, auth_manager, bridge_server: BridgeServer, on_back: callable):
        self.page = page
        self.db = db_manager
        self.auth = auth_manager
        self.server = bridge_server
        self.on_back = on_back

        self.is_active = self.server.is_running

        # --- Componentes de estado ---
        self.status_dot = ft.Icon(ft.Icons.CIRCLE, color=ft.Colors.RED_400, size=14)
        self.status_text = ft.Text("Puente Desconectado", size=15, color=ft.Colors.WHITE54)

        # --- PIN ---
        self.pin_display = ft.Text(
            "--- ---", size=46, weight=ft.FontWeight.BOLD,
            color=ft.Colors.CYAN, font_family="monospace"
        )
        self.timer_text = ft.Text("⏱ Renueva en: --s", size=12, color=ft.Colors.WHITE38)
        self.pin_copy_btn = ft.IconButton(
            icon=ft.Icons.COPY_OUTLINED, tooltip="Copiar PIN",
            icon_color=ft.Colors.WHITE38, visible=False,
            on_click=self.copy_pin
        )

        # --- Alpha Key ---
        self.alpha_display = ft.Text(
            "-------", size=28, weight=ft.FontWeight.BOLD,
            color=ft.Colors.AMBER_300, font_family="monospace"
        )

        # --- IP del servidor ---
        self.ip_text = ft.Text("", size=13, color=ft.Colors.WHITE38)

        # --- Lista de clientes ---
        self.clients_list = ft.Column(spacing=6)

        # --- Botón principal ---
        self.toggle_btn = ft.FilledButton(
            "Iniciar Puente Seguro",
            icon=ft.Icons.ROUTER,
            style=ft.ButtonStyle(bgcolor=ft.Colors.CYAN_700, color=ft.Colors.WHITE),
            on_click=self.toggle_bridge
        )

        self._ui_loop_running = False

    def build(self):
        if self.is_active:
            self._restore_active_ui()

        pin_card = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Column([
                        ft.Text("PIN de Conexión", size=12, color=ft.Colors.WHITE38),
                        ft.Row([
                            self.pin_display,
                            self.pin_copy_btn,
                        ], vertical_alignment=ft.CrossAxisAlignment.CENTER),
                        self.timer_text,
                    ], expand=True),
                ]),
                ft.Divider(color=ft.Colors.WHITE10),
                ft.Text("Clave de Seguridad", size=12, color=ft.Colors.WHITE38),
                self.alpha_display,
                ft.Text(
                    "Ingresa la clave en el móvil después de conectar el PIN.",
                    size=11, color=ft.Colors.WHITE30, italic=True
                ),
            ], spacing=10),
            bgcolor="#1e2a3a",
            padding=ft.padding.all(24),
            border_radius=16,
            border=ft.border.all(1, ft.Colors.WHITE10),
            width=420,
        )

        clients_card = ft.Container(
            content=ft.Column([
                ft.Text("Dispositivos Conectados", size=13, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE60),
                self.clients_list,
            ], spacing=8),
            bgcolor="#1a2332",
            padding=ft.padding.all(16),
            border_radius=12,
            border=ft.border.all(1, ft.Colors.WHITE10),
            width=420,
        )

        return ft.Container(
            content=ft.Column([
                # Header
                ft.Row([
                    ft.IconButton(ft.Icons.ARROW_BACK, on_click=lambda _: self.on_back()),
                    ft.Text("Puente KeyVault", size=20, weight=ft.FontWeight.BOLD),
                ], alignment=ft.MainAxisAlignment.START),
                ft.Divider(height=20, color=ft.Colors.WHITE10),

                # Ícono y título
                ft.Column([
                    ft.Icon(ft.Icons.CELL_WIFI, size=50, color=ft.Colors.CYAN),
                    ft.Text("Sincronización Local", size=22, weight=ft.FontWeight.W_700),
                    ft.Text(
                        "Ambos dispositivos deben estar en la misma red WiFi.",
                        size=13, color=ft.Colors.WHITE38, text_align=ft.TextAlign.CENTER
                    ),
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=8,
                   width=float("inf")),

                ft.Container(height=10),

                # Estado
                ft.Row([
                    self.status_dot,
                    self.status_text,
                    ft.Container(expand=True),
                    self.ip_text,
                ], width=420),

                ft.Container(height=5),
                pin_card,
                ft.Container(height=10),
                self.toggle_btn,
                ft.Container(height=16),
                clients_card,
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            scroll=ft.ScrollMode.AUTO,
            spacing=6),
            padding=24,
            expand=True,
            bgcolor="#0f172a",
        )

    # ------------------------------------------------------------------ #
    #  Acciones de UI
    # ------------------------------------------------------------------ #
    def copy_pin(self, e):
        """Copia el PIN al portapapeles."""
        try:
            import subprocess
            pin = self.server.numeric_pin or ""
            subprocess.run(
                "clip", input=pin.encode("utf-16le"),
                check=True, creationflags=subprocess.CREATE_NO_WINDOW
            )
            self._show_snackbar(f"PIN copiado: {pin}")
        except Exception as ex:
            ic(f"Error copiando PIN: {ex}")

    def toggle_bridge(self, e):
        if not self.is_active:
            self._start_bridge()
        else:
            self._stop_bridge()

    def _start_bridge(self):
        try:
            from utils.backup import export_passwords_bridge

            def vault_provider():
                return export_passwords_bridge(self.db.get_all_passwords(), self.auth.key)

            config = self.server.start(vault_provider)

            # Registrar callback para rotación de PIN
            self.server.on_pin_rotated = self._on_pin_updated

            self.is_active = True
            self._update_status_ui(active=True, config=config)

            if not self._ui_loop_running:
                self.page.run_task(self._ui_refresh_loop)

        except Exception as ex:
            ic(f"Error iniciando puente: {ex}")
            self._show_snackbar(f"Error: {ex}")

        self.page.update()

    def _stop_bridge(self):
        self.server.stop()
        self.server.on_pin_rotated = None
        self.is_active = False
        self._update_status_ui(active=False)
        self.page.update()

    def _on_pin_updated(self):
        """Llamado por el servidor cuando el PIN rota. Actualiza la UI."""
        try:
            self.pin_display.value = self._format_pin(self.server.numeric_pin)
            self.alpha_display.value = self.server.alpha_key or "-------"
            self.page.update()
        except Exception:
            pass

    def _format_pin(self, pin: str) -> str:
        """Formatea el PIN como '123 456' para mejor legibilidad."""
        if pin and len(pin) == 6:
            return f"{pin[:3]} {pin[3:]}"
        return pin or "--- ---"

    def _update_status_ui(self, active: bool, config: dict = None):
        if active and config:
            self.status_dot.color = ft.Colors.GREEN_400
            self.status_text.value = "🟢 Puente Activo — Esperando..."
            self.status_text.color = ft.Colors.GREEN_300
            self.pin_display.value = self._format_pin(config.get("pin", ""))
            self.alpha_display.value = config.get("alpha", "-------")
            self.ip_text.value = f"{config['ip']}:{config['port']}"
            self.pin_copy_btn.visible = True
            self.toggle_btn.text = "Detener Puente"
            self.toggle_btn.style = ft.ButtonStyle(bgcolor=ft.Colors.RED_700, color=ft.Colors.WHITE)
        else:
            self.status_dot.color = ft.Colors.RED_400
            self.status_text.value = "Puente Desconectado"
            self.status_text.color = ft.Colors.WHITE54
            self.pin_display.value = "--- ---"
            self.alpha_display.value = "-------"
            self.timer_text.value = "⏱ Renueva en: --s"
            self.ip_text.value = ""
            self.pin_copy_btn.visible = False
            self.clients_list.controls = []
            self.toggle_btn.text = "Iniciar Puente Seguro"
            self.toggle_btn.style = ft.ButtonStyle(bgcolor=ft.Colors.CYAN_700, color=ft.Colors.WHITE)

    def _restore_active_ui(self):
        """Restaura la UI cuando se entra a la vista con el servidor ya activo."""
        config = self.server.last_config
        if config:
            self._update_status_ui(active=True, config=config)
            self.server.on_pin_rotated = self._on_pin_updated
            # Arrancar el loop de refresco si no está corriendo
            if not self._ui_loop_running:
                self.page.run_task(self._ui_refresh_loop)

    # ------------------------------------------------------------------ #
    #  Loop de actualización de UI (temporizador + lista de clientes)
    # ------------------------------------------------------------------ #
    async def _ui_refresh_loop(self):
        self._ui_loop_running = True
        while self.is_active:
            try:
                # Actualizar temporizador
                remaining = self.server.pin_remaining
                self.timer_text.value = f"⏱ Renueva en: {remaining}s"

                # Actualizar PIN/Alpha por si rotaron
                self.pin_display.value = self._format_pin(self.server.numeric_pin)
                self.alpha_display.value = self.server.alpha_key or "-------"

                # Actualizar lista de clientes
                now = __import__("time").time()
                clients = list(self.server.connected_clients.items())
                
                # Filtrar clientes inactivos (>45s)
                active = [(did, info) for did, info in clients
                          if now - info.get("last_seen", 0) < 45]

                if active:
                    self.clients_list.controls = []
                    for did, info in active[:MAX_CLIENTS]:
                        ago = int(now - info.get("last_seen", now))
                        self.clients_list.controls.append(
                            ft.Row([
                                ft.Icon(ft.Icons.PHONELINK_LOCK, size=16, color=ft.Colors.GREEN_400),
                                ft.Text(
                                    f"{info.get('device_name', 'Móvil')} ({info.get('ip', '?')})",
                                    size=13, color=ft.Colors.WHITE70, expand=True
                                ),
                                ft.Text(
                                    f"Hace {ago}s", size=11, color=ft.Colors.WHITE38
                                ),
                                ft.IconButton(
                                    ft.Icons.LINK_OFF, icon_size=14, tooltip="Revocar",
                                    icon_color=ft.Colors.RED_300,
                                    data=did,
                                    on_click=self._revoke_device
                                ),
                            ])
                        )
                    count = len(active)
                    self.status_text.value = f"🟢 {count}/{MAX_CLIENTS} dispositivo{'s' if count != 1 else ''} conectado{'s' if count != 1 else ''}"
                else:
                    self.clients_list.controls = [
                        ft.Text("Esperando conexiones...", size=12, italic=True, color=ft.Colors.WHITE30)
                    ]
                    self.status_text.value = "🟢 Puente Activo — Esperando..."

                self.page.update()
            except Exception as ex:
                ic(f"Error en UI refresh loop: {ex}")

            await asyncio.sleep(1)

        self._ui_loop_running = False

    def _revoke_device(self, e):
        """Revoca el acceso de un dispositivo."""
        did = e.control.data
        self.server.trusted_devices.pop(did, None)
        self.server.connected_clients.pop(did, None)
        self._show_snackbar(f"Dispositivo {did} desconectado.")

    def _show_snackbar(self, msg: str):
        self.page.snack_bar = ft.SnackBar(ft.Text(msg), bgcolor=ft.Colors.BLUE_GREY_800)
        self.page.snack_bar.open = True
        self.page.update()


# Importar MAX_CLIENTS desde sync_service
try:
    from utils.sync_service import MAX_CLIENTS
except ImportError:
    MAX_CLIENTS = 5
