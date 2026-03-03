"""
dashboard_view.py - Vista principal con grid de categorías, búsqueda y favoritos.
"""

import flet as ft
from components.category_tile import create_category_tile
from components.search_bar import create_search_bar
from components.password_card import create_password_card
from security.crypto import decrypt


class DashboardView:
    """Pantalla principal del gestor de contraseñas."""

    def __init__(self, page: ft.Page, db_manager, auth_manager,
                 on_navigate: callable, on_logout: callable):
        self.page = page
        self.db = db_manager
        self.auth = auth_manager
        self.on_navigate = on_navigate
        self.on_logout = on_logout
        self.current_tab = 0

    def build(self) -> ft.Container:
        categories = self.db.get_all_categories()
        counts = self.db.count_by_category()
        total = sum(counts.values())

        # Grid de categorías
        cat_tiles = []
        for cat in categories:
            count = counts.get(cat["id"], 0)
            tile = create_category_tile(cat, count, self._on_category_click)
            cat_tiles.append(tile)

        self.categories_grid = ft.GridView(
            controls=cat_tiles,
            runs_count=2,
            max_extent=180,
            child_aspect_ratio=0.9,
            spacing=12,
            run_spacing=12,
            expand=True,
        )

        # Favoritos
        favorites = self.db.get_favorites()
        fav_cards = []
        cat_map = {c["id"]: c for c in categories}
        for pw in favorites[:5]:
            cat = cat_map.get(pw.get("category_id"), None)
            card = create_password_card(
                pw, cat,
                on_copy_user=self._copy_user,
                on_copy_pass=self._copy_pass,
                on_edit=self._edit_password,
                on_delete=self._delete_password,
                on_favorite=self._toggle_favorite,
                on_open_url=self._open_url,
            )
            fav_cards.append(card)

        # Búsqueda
        self.search_results = ft.Column([], spacing=8, visible=False)

        # Contenido por pestañas
        self.home_content = ft.Column(
            [
                # Header
                ft.Row(
                    [
                        ft.Column(
                            [
                                ft.Text("KeyVault", size=24, weight=ft.FontWeight.W_700,
                                        color=ft.Colors.WHITE),
                                ft.Text(f"{total} contraseñas guardadas", size=13,
                                        color=ft.Colors.WHITE54),
                            ],
                            expand=True,
                            spacing=2,
                        ),
                        ft.IconButton(
                            icon=ft.Icons.LOCK_OUTLINE,
                            icon_color=ft.Colors.RED_300,
                            tooltip="Cerrar sesión",
                            on_click=lambda e: self.on_logout(),
                        ),
                    ],
                ),
                ft.Container(height=4),
                create_search_bar(self._on_search),
                self.search_results,
                ft.Container(height=8),
                ft.Text("Categorías", size=16, weight=ft.FontWeight.W_600,
                         color=ft.Colors.WHITE),
                self.categories_grid,
            ],
            spacing=6,
            expand=True,
        )

        self.favorites_content = ft.Column(
            [
                ft.Text("Favoritos", size=20, weight=ft.FontWeight.W_700,
                         color=ft.Colors.WHITE),
                ft.Text(f"{len(favorites)} favoritos", size=13,
                         color=ft.Colors.WHITE54),
                ft.Container(height=8),
                *(fav_cards if fav_cards else [
                    ft.Container(
                        content=ft.Column(
                            [
                                ft.Icon(ft.Icons.STAR_BORDER, size=48, color=ft.Colors.WHITE24),
                                ft.Text("No tienes favoritos aún", size=14,
                                        color=ft.Colors.WHITE38),
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=8,
                        ),
                        padding=ft.padding.all(40),
                    ),
                ]),
            ],
            spacing=6,
            scroll=ft.ScrollMode.AUTO,
            expand=True,
        )

        self.settings_content = ft.Column(
            [
                ft.Text("Configuración", size=20, weight=ft.FontWeight.W_700,
                         color=ft.Colors.WHITE),
                ft.Container(height=12),
                self._settings_card(
                    ft.Icons.LOCK_RESET, "Cambiar contraseña maestra",
                    f"Próximo cambio en {self.auth.days_until_rotation()} días",
                    self._change_password,
                ),
                self._settings_card(
                    ft.Icons.HELP_OUTLINE, "Preguntas de seguridad",
                    "Configurar preguntas de recuperación",
                    self._edit_security_questions,
                ),
                self._settings_card(
                    ft.Icons.TIMER, "Rotación de contraseña",
                    f"Cada {self.db.get_config('password_rotation_days') or '90'} días",
                    self._change_rotation,
                ),
                ft.Container(height=20),
                ft.ElevatedButton(
                    "Cerrar sesión",
                    icon=ft.Icons.LOGOUT,
                    bgcolor="#F4433620",
                    color=ft.Colors.RED_300,
                    width=260,
                    style=ft.ButtonStyle(
                        shape=ft.RoundedRectangleBorder(radius=12),
                        side=ft.BorderSide(1, ft.Colors.RED_300),
                    ),
                    on_click=lambda e: self.on_logout(),
                ),
            ],
            spacing=10,
            scroll=ft.ScrollMode.AUTO,
            expand=True,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        )

        # Tab content
        self.tab_content = ft.Container(
            content=self.home_content,
            expand=True,
        )

        # Navigation bar
        nav_bar = ft.NavigationBar(
            destinations=[
                ft.NavigationBarDestination(
                    icon=ft.Icons.HOME_OUTLINED,
                    selected_icon=ft.Icons.HOME,
                    label="Inicio",
                ),
                ft.NavigationBarDestination(
                    icon=ft.Icons.STAR_BORDER,
                    selected_icon=ft.Icons.STAR,
                    label="Favoritos",
                ),
                ft.NavigationBarDestination(
                    icon=ft.Icons.AUTO_AWESOME,
                    selected_icon=ft.Icons.AUTO_AWESOME,
                    label="Generar",
                ),
                ft.NavigationBarDestination(
                    icon=ft.Icons.SETTINGS_OUTLINED,
                    selected_icon=ft.Icons.SETTINGS,
                    label="Ajustes",
                ),
            ],
            selected_index=0,
            on_change=self._on_tab_change,
            bgcolor="#16213e",
            indicator_color=ft.Colors.CYAN_700,
            label_behavior=ft.NavigationBarLabelBehavior.ALWAYS_SHOW,
        )

        # FAB
        fab = ft.FloatingActionButton(
            icon=ft.Icons.ADD,
            bgcolor=ft.Colors.CYAN_700,
            foreground_color=ft.Colors.WHITE,
            on_click=lambda e: self._add_password(),
            mini=False,
        )

        return ft.Container(
            content=ft.Column(
                [
                    ft.Container(
                        content=self.tab_content,
                        expand=True,
                        padding=ft.padding.symmetric(horizontal=16, vertical=12),
                    ),
                    nav_bar,
                ],
                spacing=0,
                expand=True,
            ),
            bgcolor="#0f172a",
            expand=True,
        )

    # ------------------------------------------------------------------ #
    #  Tabs
    # ------------------------------------------------------------------ #
    def _on_tab_change(self, e):
        idx = e.control.selected_index
        if idx == 0:
            self.tab_content.content = self.home_content
        elif idx == 1:
            self.tab_content.content = self.favorites_content
        elif idx == 2:
            from views.generator_view import GeneratorView
            gen = GeneratorView(self.page, db_manager=self.db, auth_manager=self.auth)
            self.tab_content.content = gen.build()
        elif idx == 3:
            self.tab_content.content = self.settings_content
        self.page.update()

    # ------------------------------------------------------------------ #
    #  Búsqueda
    # ------------------------------------------------------------------ #
    def _on_search(self, query: str):
        if not query or len(query) < 2:
            self.search_results.visible = False
            self.categories_grid.visible = True
            self.page.update()
            return

        results = self.db.search_passwords(query)
        categories = {c["id"]: c for c in self.db.get_all_categories()}

        self.search_results.controls.clear()
        self.search_results.controls.append(
            ft.Text(f"{len(results)} resultados", size=13, color=ft.Colors.WHITE54)
        )
        for pw in results[:10]:
            cat = categories.get(pw.get("category_id"))
            card = create_password_card(
                pw, cat,
                on_copy_user=self._copy_user,
                on_copy_pass=self._copy_pass,
                on_edit=self._edit_password,
                on_delete=self._delete_password,
                on_favorite=self._toggle_favorite,
                on_open_url=self._open_url,
            )
            self.search_results.controls.append(card)

        self.search_results.visible = True
        self.categories_grid.visible = False
        self.page.update()

    # ------------------------------------------------------------------ #
    #  Acciones de contraseñas
    # ------------------------------------------------------------------ #
    def _copy_user(self, pw_id):
        pw = self.db.get_password_by_id(pw_id)
        if pw and pw.get("username"):
            username = decrypt(pw["username"], self.auth.key)
            self.page.run_task(self.page.clipboard.set, username)
            snack = ft.SnackBar(
                content=ft.Text("Usuario copiado", color=ft.Colors.WHITE),
                bgcolor=ft.Colors.CYAN_700, duration=1500,
            )
            snack.open = True
            self.page.overlay.append(snack)
            self.page.update()

    def _copy_pass(self, pw_id):
        pw = self.db.get_password_by_id(pw_id)
        if pw and pw.get("password"):
            password = decrypt(pw["password"], self.auth.key)
            self.page.run_task(self.page.clipboard.set, password)
            snack = ft.SnackBar(
                content=ft.Text("Contraseña copiada", color=ft.Colors.WHITE),
                bgcolor=ft.Colors.GREEN_700, duration=1500,
            )
            snack.open = True
            self.page.overlay.append(snack)
            self.page.update()

    def _open_url(self, pw_id):
        pw = self.db.get_password_by_id(pw_id)
        if pw and pw.get("url"):
            self.page.launch_url(pw["url"])

    def _toggle_favorite(self, pw_id):
        pw = self.db.get_password_by_id(pw_id)
        if pw:
            self.db.update_password(pw_id, is_favorite=0 if pw["is_favorite"] else 1)
            self.on_navigate("dashboard")

    def _edit_password(self, pw_id):
        pw = self.db.get_password_by_id(pw_id)
        if pw:
            from views.password_form import PasswordFormView
            form = PasswordFormView(
                self.page, self.db, self.auth,
                categories=self.db.get_all_categories(),
                pw_data=pw,
                on_save=lambda: self.on_navigate("dashboard"),
                on_cancel=lambda: self.on_navigate("dashboard"),
            )
            self.page.controls.clear()
            self.page.add(form.build())
            self.page.update()

    def _delete_password(self, pw_id):
        def close_dialog():
            dialog.open = False
            self.page.update()

        def do_delete(e):
            self.db.delete_password(pw_id)
            close_dialog()
            
            async def refresh():
                import asyncio
                await asyncio.sleep(0.3)
                self.on_navigate("dashboard")
                
            self.page.run_task(refresh)

        dialog = ft.AlertDialog(
            title=ft.Text("¿Eliminar contraseña?", color=ft.Colors.WHITE),
            content=ft.Text("Esta acción no se puede deshacer.", color=ft.Colors.WHITE70),
            bgcolor="#1e2a3a",
            actions=[
                ft.TextButton("Cancelar", style=ft.ButtonStyle(color=ft.Colors.WHITE54),
                              on_click=lambda e: close_dialog()),
                ft.TextButton("Eliminar", style=ft.ButtonStyle(color=ft.Colors.RED),
                              on_click=do_delete),
            ],
        )
        dialog.open = True
        self.page.overlay.append(dialog)
        self.page.update()

    def _add_password(self):
        from views.password_form import PasswordFormView
        form = PasswordFormView(
            self.page, self.db, self.auth,
            categories=self.db.get_all_categories(),
            on_save=lambda: self.on_navigate("dashboard"),
            on_cancel=lambda: self.on_navigate("dashboard"),
        )
        self.page.controls.clear()
        self.page.add(form.build())
        self.page.update()

    def _on_category_click(self, category_id: int):
        self.on_navigate("passwords", category_id=category_id)

    # ------------------------------------------------------------------ #
    #  Settings
    # ------------------------------------------------------------------ #
    def _settings_card(self, icon, title, subtitle, on_click) -> ft.Container:
        return ft.Container(
            content=ft.ListTile(
                leading=ft.Icon(icon, color=ft.Colors.CYAN),
                title=ft.Text(title, color=ft.Colors.WHITE, size=14),
                subtitle=ft.Text(subtitle, color=ft.Colors.WHITE54, size=12),
                trailing=ft.Icon(ft.Icons.CHEVRON_RIGHT, color=ft.Colors.WHITE38),
                on_click=lambda e: on_click(),
            ),
            bgcolor="#1e2a3a",
            border_radius=14,
            border=ft.border.all(1, ft.Colors.WHITE10),
        )

    def _change_password(self):
        from views.change_password import ChangePasswordView
        view = ChangePasswordView(
            self.page, self.auth,
            on_complete=lambda: self.on_navigate("dashboard"),
        )
        self.page.controls.clear()
        self.page.add(view.build())
        self.page.update()

    def _edit_security_questions(self):
        from views.security_questions import SecurityQuestionsView
        view = SecurityQuestionsView(
            self.page, self.auth, mode="setup",
            on_complete=lambda: self.on_navigate("dashboard"),
            master_password="",  # No-op para re-configurar
        )
        self.page.controls.clear()
        self.page.add(view.build())
        self.page.update()

    def _change_rotation(self):
        current = self.db.get_config("password_rotation_days") or "90"

        dd = ft.Dropdown(
            label="Cambiar cada",
            label_style=ft.TextStyle(color=ft.Colors.CYAN),
            border_color=ft.Colors.WHITE24,
            color=ft.Colors.WHITE,
            value=current,
            options=[
                ft.dropdown.Option("30", "30 días"),
                ft.dropdown.Option("60", "60 días"),
                ft.dropdown.Option("90", "90 días"),
                ft.dropdown.Option("180", "180 días"),
            ],
        )

        def close_dialog():
            dialog.open = False
            self.page.update()

        def save_rotation(e):
            self.db.set_config("password_rotation_days", dd.value)
            close_dialog()
            
            async def refresh():
                import asyncio
                await asyncio.sleep(0.3)
                self.on_navigate("dashboard")
                
            self.page.run_task(refresh)

        dialog = ft.AlertDialog(
            title=ft.Text("Rotación de contraseña", color=ft.Colors.WHITE),
            content=dd,
            bgcolor="#1e2a3a",
            actions=[
                ft.TextButton("Cancelar", style=ft.ButtonStyle(color=ft.Colors.WHITE54),
                              on_click=lambda e: close_dialog()),
                ft.TextButton("Guardar", style=ft.ButtonStyle(color=ft.Colors.CYAN),
                              on_click=save_rotation),
            ],
        )
        dialog.open = True
        self.page.overlay.append(dialog)
        self.page.update()
