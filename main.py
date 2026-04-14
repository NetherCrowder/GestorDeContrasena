"""
KeyVault — Gestor de Contraseñas Personal
Punto de entrada de la aplicación Flet (Ejecutable de Móvil).
"""

import traceback
import flet as ft
from icecream import ic
from utils.logging_config import setup_logging, register_error

# Inicializar logging
setup_logging()

def main(page: ft.Page):
    # ------------------------------------------------------------------ #
    #  Configuración de la página
    # ------------------------------------------------------------------ #
    page.title = "KeyVault — Gestor de Contraseñas"
    page.bgcolor = "#0f172a"
    page.theme_mode = ft.ThemeMode.DARK
    page.theme = ft.Theme(
        color_scheme_seed=ft.Colors.CYAN,
        font_family="Roboto",
    )
    page.padding = 0
    page.spacing = 0

    # Simulación de móvil en Escritorio o ejecución nativa
    page.window.width = 400
    page.window.height = 750
    page.window.resizable = False
    page.window.min_width = 400
    page.window.min_height = 600

    try:
        # ------------------------------------------------------------------ #
        #  Inicializar servicios
        # ------------------------------------------------------------------ #
        from database.db_manager import DatabaseManager
        from security.auth import AuthManager
        from views.login_view import LoginView
        from views.dashboard_view import DashboardView
        from views.passwords_view import PasswordsView
        from views.change_password import ChangePasswordView
        from utils.sync_service import BridgeClient
        
        # Instanciar managers de datos y seguridad
        db = DatabaseManager()
        db.connect()
        auth = AuthManager(db)
        
        # Servicios de Sincronización Globales (Solo Cliente/Móvil)
        bridge_client = BridgeClient()

        # Exponer estado y servicios globales en la página
        page.is_mobile = True
        page.kv_db = db
        page.kv_auth = auth
        page.kv_bridge = bridge_client

        # ------------------------------------------------------------------ #
        #  Navegación
        # ------------------------------------------------------------------ #
        def navigate(view_name: str, **kwargs):
            """Router central de la aplicación."""
            page.controls.clear()
            page.overlay.clear()

            if view_name == "login":
                login_view = LoginView(page, auth, on_login_success=lambda: post_login())
                page.add(login_view.build())

            elif view_name == "dashboard":
                dashboard = DashboardView(
                    page, db, auth, bridge_client,
                    on_navigate=lambda v, **kw: navigate(v, **kw),
                    on_logout=lambda: logout(),
                )
                page.add(dashboard.build())

            elif view_name == "sync_client":
                from views.sync_client_view import SyncClientView
                sync_view = SyncClientView(
                    page, db, auth, bridge_client,
                    on_back=lambda: navigate("dashboard")
                )
                page.add(sync_view.build())

            elif view_name == "passwords":
                category_id = kwargs.get("category_id", 8)
                categories = db.get_all_categories()
                category = next((c for c in categories if c["id"] == category_id), categories[-1])
                pw_view = PasswordsView(
                    page, db, auth, bridge_client,
                    category=category,
                    on_back=lambda: navigate("dashboard"),
                    on_refresh=lambda: navigate("passwords", category_id=category_id),
                )
                page.add(pw_view.build())

            elif view_name == "change_password":
                is_forced = kwargs.get("is_forced", False)
                change_view = ChangePasswordView(
                    page, auth,
                    is_forced=is_forced,
                    on_complete=lambda: navigate("dashboard"),
                )
                page.add(change_view.build())

            page.update()

        def post_login():
            """Acciones post-login: verificar rotación, reconectar sync y navegar."""
            # Intentar reconexión automática
            last_server_ip = db.get_config("last_sync_ip")
            trust_token = db.get_config("trust_token")
            device_id = db.get_config("device_id")
            
            if last_server_ip and trust_token and device_id:
                # Capturar en variables locales inmutables para el cierre (closure)
                _saved_ip = last_server_ip
                _saved_token = trust_token
                _saved_device = device_id

                def _try_reconnect():
                    # Usamos lista mutable para poder reasignar la IP dentro de la clausura
                    server_ip = [_saved_ip]

                    def on_remote_vault(v):
                        try:
                            import json
                            data_list = json.loads(v)
                            db.import_from_list(data_list, auth.key)
                        except Exception as e:
                            ic(f"Error importando bóveda remota silenciosa: {e}")

                    def _safe_clipboard(txt):
                        from utils.clipboard_helper import copy_to_clipboard
                        try:
                            copy_to_clipboard(page, txt)
                            page.snack_bar = ft.SnackBar(
                                ft.Text("📋 ¡Portapapeles del PC recibido!"),
                                bgcolor=ft.Colors.GREEN_400
                            )
                            page.snack_bar.open = True
                            page.update()
                        except Exception as ex:
                            ic(f"Clipboard UI error: {ex}")

                    # --- Intento 1: IP guardada ---
                    success = bridge_client.attempt_silent_handshake(
                        server_ip[0], 5005, _saved_device, _saved_token
                    )

                    # --- Intento 2: Fallback via mDNS si la IP cambió ---
                    if not success:
                        try:
                            from zeroconf import Zeroconf, ServiceBrowser
                            import socket, time

                            class SilentLocate:
                                def __init__(self): self.ip = None
                                def remove_service(self, z, t, n): pass
                                def update_service(self, z, t, n): pass
                                def add_service(self, zc, type_, name):
                                    info = zc.get_service_info(type_, name)
                                    if info and info.addresses:
                                        self.ip = socket.inet_ntoa(info.addresses[0])

                            zc = Zeroconf()
                            sl = SilentLocate()
                            sb = ServiceBrowser(zc, "_keyvault._tcp.local.", sl)
                            time.sleep(3)
                            try: sb.cancel()
                            except: pass
                            zc.close()

                            if sl.ip:
                                server_ip[0] = sl.ip
                                db.set_config("last_sync_ip", sl.ip)
                                success = bridge_client.attempt_silent_handshake(
                                    server_ip[0], 5005, _saved_device, _saved_token
                                )
                        except Exception as ex:
                            ic(f"Error en fallback Zeroconf móvil: {ex}")

                    # --- Conexión completa si el handshake fue exitoso ---
                    if success:
                        connected = bridge_client.connect(
                            server_ip[0], 5005,
                            bridge_client.token,
                            bridge_client.key,
                            on_vault=on_remote_vault,
                            on_clipboard=_safe_clipboard,
                            trust_token=_saved_token,
                            device_id=_saved_device
                        )
                        if connected:
                            bridge_client.start_auto_sync_loop(db, auth.key)
                            ic("Reconexión silenciosa completa. Clipboard y auto-sync activos.")
                    else:
                        ic("Reconexión silenciosa fallida. Necesita vinculación manual.")

                import threading
                threading.Thread(target=_try_reconnect, name="SilentReconnect", daemon=True).start()

            if auth.needs_rotation():
                navigate("change_password", is_forced=True)
            else:
                navigate("dashboard")

        def logout():
            """Cerrar sesión."""
            auth.lock()
            navigate("login")

        # Iniciar en la pantalla de login
        navigate("login")

    except Exception as e:
        register_error("CRITICAL ERROR IN INITIALIZATION", e)
        error_trace = traceback.format_exc()
        ic(f"CRITICAL ERROR:\n{error_trace}")

        page.controls.clear()
        page.add(
            ft.ListView(
                controls=[
                    ft.Text("⚠️ CRASH FATAL DE INICIALIZACIÓN", color="red", weight=ft.FontWeight.BOLD, size=20),
                    ft.Text("La aplicación falló al arrancar. Detalles en errors.log.", color="white70"),
                    ft.Text(error_trace, color="red", selectable=True, font_family="monospace", size=11)
                ],
                expand=True,
                padding=20,
                auto_scroll=True
            )
        )
        page.update()

if __name__ == "__main__":
    ft.run(main)
