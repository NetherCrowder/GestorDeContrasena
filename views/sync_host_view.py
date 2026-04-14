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
        self.excluded_categories = set()

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

        self.filter_btn = ft.IconButton(
            ft.Icons.FILTER_LIST, tooltip="Filtro de Sincronización",
            icon_color=ft.Colors.WHITE54,
            on_click=self.open_filter_dialog
        )

        # --- Controles de Grupo B ---
        self.history_btn = ft.IconButton(
            ft.Icons.HISTORY, tooltip="Historial de Conexiones",
            icon_size=18, icon_color=ft.Colors.CYAN_300,
            on_click=self._show_history_dialog,
            visible=False
        )
        self.revoke_all_btn = ft.TextButton(
            "Desconectar Todos",
            icon=ft.Icons.BLOCK,
            icon_color=ft.Colors.RED_400,
            style=ft.ButtonStyle(color=ft.Colors.RED_400),
            on_click=self._revoke_all_devices,
            visible=False
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
                ft.Row([
                    ft.Text("Dispositivos Conectados", size=13, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE60),
                    ft.Container(expand=True),
                    self.history_btn
                ]),
                self.clients_list,
                ft.Row([self.revoke_all_btn], alignment=ft.MainAxisAlignment.END)
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
                ft.Row([self.toggle_btn, self.filter_btn], alignment=ft.MainAxisAlignment.CENTER),
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
                all_pw = self.db.get_all_passwords()
                if self.excluded_categories:
                    all_pw = [pw for pw in all_pw if pw.get("category_id") not in self.excluded_categories]
                return export_passwords_bridge(all_pw, self.auth.key)

            config = self.server.start(vault_provider)

            # Registrar callbacks
            self.server.on_pin_rotated = self._on_pin_updated
            self.server.on_vault_received = self._handle_vault_received

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
        self.server.on_vault_received = None
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
            self.history_btn.visible = True
            self.revoke_all_btn.visible = True
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
            self.history_btn.visible = False
            self.revoke_all_btn.visible = False
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
                        
                        # C2: Indicador de última sincronización
                        last_sync = info.get("last_sync")
                        if last_sync:
                            ls_secs = int(now - last_sync)
                            if ls_secs < 60: ls_str = f"{ls_secs}s"
                            elif ls_secs < 3600: ls_str = f"{ls_secs//60}m"
                            else: ls_str = f"{ls_secs//3600}h"
                            sync_info = f" | Sync: hace {ls_str}"
                        else:
                            sync_info = " | Sync: Nunca"

                        self.clients_list.controls.append(
                            ft.Row([
                                ft.Icon(ft.Icons.PHONELINK_LOCK, size=16, color=ft.Colors.GREEN_400),
                                ft.Column([
                                    ft.Text(f"{info.get('device_name', 'Móvil')}", size=13, weight=ft.FontWeight.W_500),
                                    ft.Text(f"IP: {info.get('ip', '?')}{sync_info} • Hace {ago}s", size=10, color=ft.Colors.WHITE38),
                                ], spacing=0, expand=True),
                                ft.IconButton(
                                    ft.Icons.LOCK_OUTLINE, icon_size=14, tooltip="Bloqueo Remoto",
                                    icon_color=ft.Colors.AMBER_400,
                                    data=did,
                                    on_click=self._lock_device
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
        """Revoca el acceso de un dispositivo secundario."""
        did = e.control.data
        self.server.revoke_device(did)
        self._show_snackbar(f"Dispositivo desconectado.")

    def _revoke_all_devices(self, e):
        """Revoca a todos los dispositivos."""
        self.server.revoke_all_devices()
        self._show_snackbar("Todos los dispositivos han sido desconectados.")

    def _lock_device(self, e):
        """Envía comando de bloqueo remoto."""
        did = e.control.data
        if self.server.lock_device(did):
            self._show_snackbar("Comando de bloqueo enviado al dispositivo.")
        else:
            self._show_snackbar("Error: el dispositivo no responde.")

    def _show_history_dialog(self, e):
        """Muestra el historial de conexiones."""
        events = self.server.get_connection_history()
        from datetime import datetime

        if not events:
            controls = [ft.Text("No hay eventos recientes.", size=13, color=ft.Colors.WHITE38)]
        else:
            controls = []
            for ev_type, ip, ts in reversed(events):
                dt = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
                color, icon, text = ft.Colors.WHITE54, ft.Icons.INFO_OUTLINE, "Evento desconocido"
                
                if ev_type == "success":
                    color, icon, text = ft.Colors.GREEN_400, ft.Icons.CHECK_CIRCLE, "Conexión exitosa"
                elif ev_type == "step1_ok":
                    color, icon, text = ft.Colors.CYAN_300, ft.Icons.LOCK_OPEN, "PIN aceptado (Paso 1)"
                elif ev_type == "step1_fail":
                    color, icon, text = ft.Colors.RED_300, ft.Icons.ERROR_OUTLINE, "Intento fallido (PIN)"
                elif ev_type == "step2_fail":
                    color, icon, text = ft.Colors.RED_300, ft.Icons.ERROR_OUTLINE, "Intento fallido (Clave)"

                controls.append(
                    ft.Row([
                        ft.Icon(icon, color=color, size=16),
                        ft.Text(f"[{dt}] {ip}", size=12, color=ft.Colors.WHITE70, expand=True),
                        ft.Text(text, size=12, color=color),
                    ])
                )

        dialog = ft.AlertDialog(
            title=ft.Text("Historial de Conexiones", size=16, weight=ft.FontWeight.BOLD),
            content=ft.Container(
                content=ft.Column(controls, spacing=10, scroll=ft.ScrollMode.AUTO),
                width=350, height=250
            ),
            bgcolor="#1e2a3a",
            actions=[
                ft.TextButton("Cerrar", on_click=lambda _: setattr(dialog, "open", False) or self.page.update())
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        self.page.overlay.append(dialog)
        dialog.open = True
        self.page.update()

    def _show_snackbar(self, msg: str, color: str = ft.Colors.BLUE_GREY_800):
        self.page.snack_bar = ft.SnackBar(ft.Text(msg), bgcolor=color)
        self.page.snack_bar.open = True
        self.page.update()

    # ------------------------------------------------------------------ #
    # Sincronización y Filtros
    # ------------------------------------------------------------------ #
    def _handle_vault_received(self, data_list: list[dict]):
        """Llamado por BridgeServer cuando recibe un empuje completo del móvil."""
        async def sync_worker():
            try:
                # La importación es síncrona, pero la envolvemos en el flujo de Flet
                inserted, updated, skipped = self.db.import_from_list(data_list, self.auth.key)
                # Incrementar versión para notificar por red
                self.db._increment_version()
                
                # Reportar en UI
                if inserted > 0 or updated > 0:
                    msg = f"Sincronización entrante: {inserted} nuevos, {updated} actualizados."
                    self._show_snackbar(msg, color=ft.Colors.GREEN_600)
                else:
                    self._show_snackbar("Sincronización entrante exitosa (sin cambios nuevos).", color=ft.Colors.LIGHT_BLUE_600)
                # page.update() debe ser llamado con await si estamos en un contexto async de Flet
                await self.page.update_async()
            except Exception as e:
                self._show_snackbar(f"Error importando sincronización: {e}", color=ft.Colors.RED_600)
                await self.page.update_async()

        # Lanzar la tarea asíncrona correctamente
        self.page.run_task(sync_worker)

    def open_filter_dialog(self, e):
        """Abre un diálogo para seleccionar qué categorías compartir en el Puente."""
        all_cats = self.db.get_all_categories()
        checkboxes = []

        def on_change(e, cid):
            if e.control.value:
                self.excluded_categories.discard(cid)
            else:
                self.excluded_categories.add(cid)

        for cat in all_cats:
            cid = cat["id"]
            checked = cid not in self.excluded_categories
            cb = ft.Checkbox(
                label=cat["name"],
                value=checked,
                on_change=lambda e, cid=cid: on_change(e, cid),
                fill_color=ft.Colors.CYAN_700
            )
            checkboxes.append(cb)

        def close_dg(e):
            d.open = False
            self.page.update()
            self._show_snackbar("Filtro actualizado. (Aplica a la próxima descarga desde el móvil)")

        d = ft.AlertDialog(
            title=ft.Text("Filtro de Sincronización"),
            content=ft.Column([
                ft.Text("Selecciona las categorías de contraseñas a exportar:", size=13, color=ft.Colors.WHITE54)
            ] + checkboxes, scroll=ft.ScrollMode.AUTO, tight=True, height=300),
            actions=[ft.TextButton("Listo", on_click=close_dg)],
            actions_alignment=ft.MainAxisAlignment.END,
            bgcolor="#1e293b"
        )
        self.page.overlay.append(d)
        d.open = True
        self.page.update()

# Importar MAX_CLIENTS desde sync_service
try:
    from utils.sync_service import MAX_CLIENTS
except ImportError:
    MAX_CLIENTS = 5
