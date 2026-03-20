"""
passwords_view.py - Vista de lista de contraseñas filtrada por categoría.
"""

import flet as ft
from security.crypto import decrypt
from components.password_card import create_password_card
from icecream import ic
from utils.logging_config import register_error


class PasswordsView:
    """Lista de contraseñas de una categoría."""

    def __init__(self, page: ft.Page, db_manager, auth_manager,
                 category: dict, on_back: callable, on_refresh: callable):
        self.page = page
        self.db = db_manager
        self.auth = auth_manager
        self.category = category
        self.on_back = on_back
        self.on_refresh = on_refresh

    def build(self) -> ft.Container:
        passwords = self.db.get_passwords_by_category(self.category["id"])
        cat_color = self.category.get("color", "#607D8B")

        # Lista de tarjetas
        cards = []
        for pw in passwords:
            card = create_password_card(
                pw_data=pw,
                category=self.category,
                on_copy_user=self.show_and_copy_user,
                on_copy_pass=self.show_and_copy_pass,
                on_edit=self.edit_password,
                on_delete=self.delete_password,
                on_favorite=self.toggle_favorite,
                on_open_url=self.open_url,
            )
            cards.append(card)

        if not cards:
            cards = [
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Icon(ft.Icons.LOCK_OUTLINE, size=48, color=ft.Colors.WHITE24),
                            ft.Text(
                                "No hay contraseñas en esta categoría",
                                size=14, color=ft.Colors.WHITE38,
                                text_align=ft.TextAlign.CENTER,
                            ),
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=8,
                    ),
                    padding=ft.padding.all(40),
                ),
            ]

        self.cards_column = ft.Column(cards, spacing=10, scroll=ft.ScrollMode.AUTO, expand=True)

        return ft.Container(
            content=ft.Column(
                [
                    # Header
                    ft.Row(
                        [
                            ft.IconButton(
                                icon=ft.Icons.ARROW_BACK,
                                icon_color=ft.Colors.WHITE,
                                on_click=lambda e: self.on_back(),
                            ),
                            ft.Text(
                                self.category["name"],
                                size=20, weight=ft.FontWeight.W_700,
                                color=ft.Colors.WHITE, expand=True,
                            ),
                            ft.IconButton(
                                icon=ft.Icons.ADD_CIRCLE,
                                icon_color=cat_color,
                                icon_size=28,
                                tooltip="Agregar contraseña",
                                on_click=lambda e: self.add_password(),
                            ),
                        ],
                    ),
                    ft.Text(
                        f"{len(passwords)} {'contraseña' if len(passwords) == 1 else 'contraseñas'}",
                        size=13, color=ft.Colors.WHITE54,
                    ),
                    ft.Container(height=8),
                    self.cards_column,
                ],
                spacing=4,
            ),
            bgcolor="#0f172a",
            expand=True,
            padding=ft.padding.symmetric(horizontal=16, vertical=12),
        )

    def show_and_copy_user(self, e, pw_id):
        pw = self.db.get_password_by_id(pw_id)
        if pw and pw.get("username"):
            username = decrypt(pw["username"], self.auth.key)
            
            # Copiar al portapapeles
            self.page.run_task(self.page.clipboard.set, username)
            
            # Mostrar visualmente
            original_text = e.control.content
            original_icon = e.control.icon
            
            e.control.content = username
            e.control.icon = None
            e.control.update()

            async def restore_btn():
                import asyncio
                await asyncio.sleep(3)
                e.control.content = original_text
                e.control.icon = original_icon
                e.control.update()
                
            self.page.run_task(restore_btn)

    def show_and_copy_pass(self, e, pw_id):
        pw = self.db.get_password_by_id(pw_id)
        if pw and pw.get("password"):
            password = decrypt(pw["password"], self.auth.key)
            
            # Copiar al portapapeles
            self.page.run_task(self.page.clipboard.set, password)
            
            # Mostrar visualmente
            original_text = e.control.content
            original_icon = e.control.icon
            
            e.control.content = password
            e.control.icon = None
            e.control.update()

            async def restore_btn():
                import asyncio
                await asyncio.sleep(3)
                e.control.content = original_text
                e.control.icon = original_icon
                e.control.update()
                
            self.page.run_task(restore_btn)

    def open_url(self, pw_id):
        async def launch():
            pw = self.db.get_password_by_id(pw_id)
            if pw and pw.get("url"):
                url = pw["url"].strip()
                if url and not (url.startswith("http://") or url.startswith("https://")):
                    url = f"https://{url}"
                
                # En versiones modernas de Flet, launch_url es una coroutine
                res = self.page.launch_url(url)
                import asyncio
                if asyncio.iscoroutine(res):
                    await res
        
        self.page.run_task(launch)

    def toggle_favorite(self, pw_id):
        try:
            pw = self.db.get_password_by_id(pw_id)
            if pw:
                self.db.update_password(pw_id, is_favorite=0 if pw["is_favorite"] else 1)
                ic(f"Toggled favorite for {pw_id}")
                self.on_refresh()
        except Exception as ex:
            register_error(f"Error toggling favorite for {pw_id}", ex)

    def edit_password(self, pw_id):
        pw = self.db.get_password_by_id(pw_id)
        if pw:
            from views.password_form import PasswordFormView
            form = PasswordFormView(
                self.page, self.db, self.auth,
                categories=self.db.get_all_categories(),
                pw_data=pw,
                on_save=self.on_refresh,
                on_cancel=self.on_refresh,
            )
            self.page.controls.clear()
            self.page.add(form.build())
            self.page.update()

    def delete_password(self, pw_id):
        def close_dialog():
            dialog.open = False
            self.page.update()

        def do_delete(e):
            try:
                self.db.delete_password(pw_id)
                ic(f"Deleted password {pw_id}")
                close_dialog()
                
                async def refresh():
                    import asyncio
                    await asyncio.sleep(0.3)
                    self.on_refresh()
                    
                self.page.run_task(refresh)
            except Exception as ex:
                register_error(f"Error deleting password {pw_id}", ex)
                self.page.snack_bar = ft.SnackBar(ft.Text("Error al eliminar"))
                self.page.snack_bar.open = True
                self.page.update()

        dialog = ft.AlertDialog(
            title=ft.Text("¿Eliminar contraseña?", color=ft.Colors.WHITE),
            content=ft.Text(
                "Esta acción no se puede deshacer.",
                color=ft.Colors.WHITE70,
            ),
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

    def add_password(self):
        from views.password_form import PasswordFormView
        form = PasswordFormView(
            self.page, self.db, self.auth,
            categories=self.db.get_all_categories(),
            on_save=self.on_refresh,
            on_cancel=self.on_refresh,
            default_category_id=self.category["id"],
        )
        self.page.controls.clear()
        self.page.add(form.build())
        self.page.update()
