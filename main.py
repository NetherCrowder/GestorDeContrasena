"""
KeyVault — Gestor de Contraseñas Personal
Punto de entrada de la aplicación Flet con soporte híbrido PC/Móvil.
"""

import os
import sys
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

    # Dimensiones para escritorio
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
        from utils.sync_service import BridgeServer, BridgeClient

        db = DatabaseManager()
        db.connect()
        auth = AuthManager(db)

        # Servicios de Sincronización Globales (Persistentes)
        bridge_server = BridgeServer()
        bridge_client = BridgeClient()

        def global_clipboard_alert(text):
            try:
                import subprocess
                subprocess.run("clip", input=text.strip().encode("utf-16le"), check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                page.snack_bar = ft.SnackBar(ft.Text("📋 Sincronizado desde PC", color=ft.Colors.WHITE), bgcolor=ft.Colors.GREEN_700)
                page.snack_bar.open = True
                page.update()
            except Exception as e:
                ic(f"Error clipboard global: {e}")

        bridge_client.on_clipboard_global = global_clipboard_alert

        def _do_vault_sync_and_resume():
            """Helper: descarga vault, aplica merge, reanuda listener y guarda pairing."""
            v = bridge_client.download_vault()
            if v:
                try:
                    from utils.backup import apply_bridge_vault
                    ins, upd, _ = apply_bridge_vault(v, db, auth.key)
                    ic(f"Watcher sync: {ins} ins, {upd} upd")
                    if (ins + upd) > 0 and bridge_client.on_vault_sync:
                        bridge_client.on_vault_sync(ins, upd)
                except Exception as ex:
                    ic(f"Watcher vault merge error: {ex}")
            bridge_client.start_clipboard_listener(lambda _: None)
            bridge_client.save_pairing()

        def _refresh_ui(msg: str, color):
            """Refresca la UI desde un hilo background de forma segura."""
            try:
                page.snack_bar = ft.SnackBar(
                    ft.Text(msg, color=ft.Colors.WHITE), bgcolor=color
                )
                page.snack_bar.open = True
                navigate(_current_view["name"], **_current_view.get("kwargs", {}))
                page.update()
            except Exception as e:
                ic(f"_refresh_ui error: {e}")

        def _reconnect_watcher():
            """Loop de reconexión: reintenta cada 10s usando credenciales en memoria."""
            import time as _t
            ic("Watcher iniciado. Reintentando cada 10s...")
            while not bridge_client.is_listening:
                _t.sleep(10)
                if bridge_client.is_listening:
                    break
                try:
                    if bridge_client.try_reconnect():
                        ic("Servidor detectado. Reconectando...")
                        _do_vault_sync_and_resume()
                        _refresh_ui("🔗 Reconectado al PC automáticamente", ft.Colors.GREEN_800)
                        break
                except Exception as ex:
                    ic(f"Watcher retry: {ex}")
            ic("Watcher finalizado.")

        def global_disconnect_alert():
            """Llamado cuando el servidor PC deja de responder al heartbeat."""
            import threading as _th_dc
            try:
                # NO borrar pairing — credenciales siguen siendo válidas para reconectar
                _refresh_ui("🔴 Conexión con PC perdida", ft.Colors.RED_800)
            except Exception as e:
                ic(f"global_disconnect_alert error: {e}")
            _th_dc.Thread(target=_reconnect_watcher, daemon=True).start()

        bridge_client.on_disconnect = global_disconnect_alert

        # Configurar archivo de pairing (varía si estamos en modo mobile-test)
        import sys
        from pathlib import Path
        _kv_dir = Path(os.environ.get("FLET_APP_STORAGE_DATA", "") or 
                       os.environ.get("LOCALAPPDATA", "") or 
                       os.path.expanduser("~")) / "KeyVault"
        _kv_dir.mkdir(parents=True, exist_ok=True)
        _suffix = "_mobile_test" if "--mobile" in sys.argv else ""
        bridge_client.set_pairing_file(str(_kv_dir / f"pairing{_suffix}.json"))
        bridge_server.set_pairing_file(str(_kv_dir / "server_pairing.json"))

        # Estado compartido para el callback de sincronización global
        _current_view = {"name": "login"}

        def global_vault_sync(ins: int, upd: int):
            """Llamado desde el hilo de sync cuando hay cambios. Refresca la UI global."""
            try:
                if ins + upd == 0:
                    return
                # Mostrar bolita siempre
                msg = f"✅ Sincronizado: {ins} nuevas, {upd} actualizadas"
                page.snack_bar = ft.SnackBar(ft.Text(msg, color=ft.Colors.WHITE), bgcolor=ft.Colors.CYAN_800)
                page.snack_bar.open = True
                # Si el usuario está en el dashboard o passwords, refrescar esa vista
                if _current_view["name"] in ("dashboard", "passwords"):
                    navigate(_current_view["name"], **_current_view.get("kwargs", {}))
                else:
                    page.update()
            except Exception as e:
                ic(f"global_vault_sync error: {e}")

        bridge_client.on_vault_sync = global_vault_sync

        # ------------------------------------------------------------------ #
        #  Demonio de Sincronización Continua (Móvil)
        # ------------------------------------------------------------------ #
        import sys
        if "--mobile" in sys.argv:
            def _global_vault_polling_daemon():
                import time
                import threading
                ic("Daemon global de sincronización iniciado.")
                while True:
                    time.sleep(15)  # Verifica cada 15s
                    if bridge_client.is_listening:
                        try:
                            # Solo sincroniza si el sistema no está bloqueado (evitar spam si hay error)
                            new_vault = bridge_client.download_vault()
                            if new_vault:
                                from utils.backup import apply_bridge_vault
                                i2, u2, _ = apply_bridge_vault(new_vault, db, auth.key)
                                if (i2 + u2) > 0 and bridge_client.on_vault_sync:
                                    bridge_client.on_vault_sync(i2, u2)
                        except Exception as e:
                            ic(f"Global sync error: {e}")
            import threading as _th_glob
            _th_glob.Thread(target=_global_vault_polling_daemon, daemon=True).start()

        # ------------------------------------------------------------------ #
        #  Navegación
        # ------------------------------------------------------------------ #
        def navigate(view_name: str, **kwargs):
            """Router central de la aplicación."""
            page.controls.clear()
            page.overlay.clear()

            # Registrar vista activa para el callback de sincronización global
            _current_view["name"] = view_name
            _current_view["kwargs"] = kwargs

            # Determinar el servicio de bridge correcto según la plataforma o argumento CLI
            is_mobile = page.platform in [ft.PagePlatform.ANDROID, ft.PagePlatform.IOS]
            if "--mobile" in sys.argv:
                is_mobile = True

            current_bridge = bridge_client if is_mobile else bridge_server

            if view_name == "login":
                login_view = LoginView(page, auth, on_login_success=lambda: post_login())
                page.add(login_view.build())

            elif view_name == "dashboard":
                dashboard = DashboardView(
                    page, db, auth, current_bridge,
                    on_navigate=lambda v, **kw: navigate(v, **kw),
                    on_logout=lambda: logout(),
                )
                page.add(dashboard.build())

            elif view_name == "sync_host":
                from views.sync_host_view import SyncHostView
                sync_view = SyncHostView(
                    page, db, auth, bridge_server,
                    on_back=lambda: navigate("dashboard")
                )
                page.add(sync_view.build())

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
                    page, db, auth, current_bridge,
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
            """Acciones post-login: verificar rotación y navegar."""
            # Intentar reconectar automáticamente desde el pairing guardado (modo móvil)
            if "--mobile" in sys.argv and not bridge_client.is_listening:
                import threading
                def _try_reconnect():
                    ok = bridge_client.load_pairing()
                    if ok:
                        # Servidor disponible → sincronizar y reanudar
                        msg_prefix = "🔗 Reconectado"
                        try:
                            _do_vault_sync_and_resume()
                            bridge_client.save_pairing()
                        except Exception as ex:
                            ic(f"Error en auto-sync al inicio: {ex}")
                        _refresh_ui(f"{msg_prefix} · Bóveda al día", ft.Colors.GREEN_800)
                    else:
                        # Servidor no disponible al inicio → lanzar watcher unificado
                        ic("Servidor offline al inicio. Watcher en espera...")
                        import threading as _th4
                        _th4.Thread(target=_reconnect_watcher, daemon=True).start()

                threading.Thread(target=_try_reconnect, daemon=True).start()

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
