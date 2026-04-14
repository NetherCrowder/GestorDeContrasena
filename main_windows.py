"""
KeyVault — Gestor de Contraseñas Personal
Punto de entrada de la aplicación Flet (Ejecutable de Windows).

El BridgeServer se inicia automáticamente tras el login y se mantiene
activo independientemente de la vista en pantalla.
"""

import traceback
import flet as ft
from icecream import ic
from utils.logging_config import setup_logging, register_error

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

    page.window.width = 1000
    page.window.height = 800
    page.window.resizable = True
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
        from utils.sync_service import BridgeServer
        from utils.backup import export_passwords_bridge

        db = DatabaseManager()
        db.connect()
        auth = AuthManager(db)

        # Instanciar el servidor (no iniciarlo aún, esperamos al login)
        bridge_server = BridgeServer()

        # Exponer servicios globalmente en la página
        page.is_mobile = False
        page.kv_db = db
        page.kv_auth = auth
        page.kv_bridge = bridge_server

        # ------------------------------------------------------------------ #
        #  Navegación
        # ------------------------------------------------------------------ #
        def navigate(view_name: str, **kwargs):
            """Router central de la aplicación."""
            page.controls.clear()
            page.overlay.clear()

            if view_name == "login":
                view = LoginView(page, auth, on_login_success=lambda: post_login())
                page.add(view.build())

            elif view_name == "dashboard":
                view = DashboardView(
                    page, db, auth, bridge_server,
                    on_navigate=lambda v, **kw: navigate(v, **kw),
                    on_logout=lambda: logout(),
                )
                page.add(view.build())

            elif view_name == "sync_host":
                from views.sync_host_view import SyncHostView
                view = SyncHostView(
                    page, db, auth, bridge_server,
                    on_back=lambda: navigate("dashboard")
                )
                page.add(view.build())

            elif view_name == "passwords":
                category_id = kwargs.get("category_id", 8)
                categories = db.get_all_categories()
                category = next(
                    (c for c in categories if c["id"] == category_id),
                    categories[-1]
                )
                view = PasswordsView(
                    page, db, auth, bridge_server,
                    category=category,
                    on_back=lambda: navigate("dashboard"),
                    on_refresh=lambda: navigate("passwords", category_id=category_id),
                )
                page.add(view.build())

            elif view_name == "change_password":
                is_forced = kwargs.get("is_forced", False)
                view = ChangePasswordView(
                    page, auth,
                    is_forced=is_forced,
                    on_complete=lambda: navigate("dashboard"),
                )
                page.add(view.build())

            page.update()

        def _start_bridge():
            """Inicia el puente en segundo plano si no está activo."""
            if not bridge_server.is_running:
                try:
                    def vault_provider():
                        return export_passwords_bridge(
                            db.get_all_passwords(), auth.key
                        )
                        
                    def _handle_incoming_vault(data_list):
                        ins, upd, skp = db.import_from_list(data_list, auth.key)
                        if ins > 0 or upd > 0:
                            ic(f"[Sync] Bóveda recibida. Insertadas: {ins}, Actualizadas: {upd}")
                            try:
                                page.snack_bar = ft.SnackBar(ft.Text("🔄 Sincronizado desde el Móvil"), bgcolor=ft.Colors.GREEN_800)
                                page.snack_bar.open = True
                                page.update()
                            except: pass
                            
                    bridge_server.on_vault_received = _handle_incoming_vault
                    bridge_server.start(vault_provider)
                    
                    # Recepción de portapapeles del móvil → puesto en el portapapeles de Windows
                    def _on_mobile_clipboard(txt: str):
                        ic(f"[Clipboard] Móvil → PC: {txt[:30]}...")
                        try:
                            import subprocess
                            subprocess.run(
                                ["powershell", "-command", f"Set-Clipboard -Value '{txt.replace(chr(39), '')}'"],
                                capture_output=True
                            )
                        except Exception:
                            pass
                        try:
                            page.snack_bar = ft.SnackBar(
                                ft.Text(f"📋 Portapapeles del Móvil: {txt[:40]}"),
                                bgcolor=ft.Colors.BLUE_800
                            )
                            page.snack_bar.open = True
                            page.update()
                        except: pass
                        
                    bridge_server.start_clipboard_listener(on_receive=_on_mobile_clipboard)
                    ic("BridgeServer iniciado automáticamente tras login.")
                except Exception as ex:
                    ic(f"Error iniciando bridge: {ex}")

        def post_login():
            """Acciones post-login: arrancar bridge y navegar."""
            _start_bridge()

            if auth.needs_rotation():
                navigate("change_password", is_forced=True)
            else:
                navigate("dashboard")

        def logout():
            """Cerrar sesión — el bridge se mantiene activo."""
            auth.lock()
            navigate("login")

        # Detener bridge al cerrar la ventana
        async def on_window_event(e):
            if e.data == "close":
                if bridge_server.is_running:
                    bridge_server.stop()

        page.window.on_event = on_window_event

        # Iniciar en login
        navigate("login")

    except Exception as e:
        register_error("CRITICAL ERROR IN INITIALIZATION", e)
        error_trace = traceback.format_exc()
        ic(f"CRITICAL ERROR:\n{error_trace}")

        page.controls.clear()
        page.add(
            ft.ListView(
                controls=[
                    ft.Text("CRASH FATAL DE INICIALIZACION", color="red",
                            weight=ft.FontWeight.BOLD, size=20),
                    ft.Text("La aplicacion fallo al arrancar. Detalles en errors.log.",
                            color="white70"),
                    ft.Text(error_trace, color="red", selectable=True,
                            font_family="monospace", size=11)
                ],
                expand=True, padding=20, auto_scroll=True
            )
        )
        page.update()


if __name__ == "__main__":
    ft.run(main)
