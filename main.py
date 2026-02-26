"""
KeyVault — Gestor de Contraseñas Personal
Punto de entrada de la aplicación Flet.
"""

import flet as ft
from database.db_manager import DatabaseManager
from security.auth import AuthManager
from views.login_view import LoginView
from views.dashboard_view import DashboardView
from views.passwords_view import PasswordsView
from views.change_password import ChangePasswordView


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

    # Dimensiones móviles
    page.window.width = 400
    page.window.height = 750
    page.window.resizable = True

    # ------------------------------------------------------------------ #
    #  Inicializar servicios
    # ------------------------------------------------------------------ #
    db = DatabaseManager()
    db.connect()
    auth = AuthManager(db)

    # ------------------------------------------------------------------ #
    #  Navegación
    # ------------------------------------------------------------------ #
    def navigate(view_name: str, **kwargs):
        """Router central de la aplicación."""
        page.controls.clear()
        page.overlay.clear()

        if view_name == "login":
            login_view = LoginView(page, auth, on_login_success=lambda: _post_login())
            page.add(login_view.build())

        elif view_name == "dashboard":
            dashboard = DashboardView(
                page, db, auth,
                on_navigate=lambda v, **kw: navigate(v, **kw),
                on_logout=lambda: _logout(),
            )
            page.add(dashboard.build())

        elif view_name == "passwords":
            category_id = kwargs.get("category_id", 8)
            categories = db.get_all_categories()
            category = next((c for c in categories if c["id"] == category_id), categories[-1])
            pw_view = PasswordsView(
                page, db, auth,
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

    def _post_login():
        """Acciones post-login: verificar rotación y navegar."""
        if auth.needs_rotation():
            navigate("change_password", is_forced=True)
        else:
            navigate("dashboard")

    def _logout():
        """Cerrar sesión."""
        auth.lock()
        navigate("login")

    # ------------------------------------------------------------------ #
    #  Iniciar en la pantalla de login
    # ------------------------------------------------------------------ #
    navigate("login")


# Punto de entrada
if __name__ == "__main__":
    ft.run(main)
