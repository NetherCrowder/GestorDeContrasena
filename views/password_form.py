"""
password_form.py - Formulario para crear/editar contraseñas con generador integrado.
"""

import flet as ft
import json
from database.models import PASSWORD_PROFILES
from utils.categories import get_icon
from utils.helpers import generate_password, password_strength, strength_color


class PasswordFormView:
    """Formulario modal para crear o editar una contraseña."""

    def __init__(self, page: ft.Page, db_manager, auth_manager,
                 categories: list[dict], pw_data: dict | None = None,
                 on_save: callable = None, on_cancel: callable = None,
                 default_category_id: int | None = None):
        self.page = page
        self.db = db_manager
        self.auth = auth_manager
        self.categories = categories
        self.pw_data = pw_data  # None para crear, dict para editar
        self.on_save = on_save
        self.on_cancel = on_cancel
        self.is_edit = pw_data is not None
        self.default_category_id = default_category_id

    def build(self) -> ft.Container:
        from security.crypto import decrypt

        # Valores para edición
        title_val = ""
        user_val = ""
        pass_val = ""
        url_val = ""
        notes_val = ""
        cat_id = str(self.default_category_id or 8)
        rules = {}

        if self.is_edit and self.pw_data:
            title_val = self.pw_data.get("title", "")
            key = self.auth.key
            user_val = decrypt(self.pw_data["username"], key) if self.pw_data.get("username") else ""
            pass_val = decrypt(self.pw_data["password"], key) if self.pw_data.get("password") else ""
            url_val = self.pw_data.get("url", "")
            cat_id = str(self.pw_data.get("category_id", 8))
            try:
                rules = json.loads(self.pw_data.get("password_rules", "{}"))
            except (json.JSONDecodeError, TypeError):
                rules = {}

        self.title_field = ft.TextField(
            label="Nombre del servicio", value=title_val,
            label_style=ft.TextStyle(color=ft.Colors.CYAN),
            hint_text="Ej: Instagram, Netflix, Banco...",
            hint_style=ft.TextStyle(color=ft.Colors.WHITE24),
            border_color=ft.Colors.WHITE24, focused_border_color=ft.Colors.CYAN,
            color=ft.Colors.WHITE, cursor_color=ft.Colors.CYAN, text_size=15,
            prefix_icon=ft.Icons.LABEL,
            content_padding=ft.padding.symmetric(horizontal=16, vertical=14),
        )
        self.user_field = ft.TextField(
            label="Usuario / Email", value=user_val,
            label_style=ft.TextStyle(color=ft.Colors.CYAN),
            hint_style=ft.TextStyle(color=ft.Colors.WHITE24),
            border_color=ft.Colors.WHITE24, focused_border_color=ft.Colors.CYAN,
            color=ft.Colors.WHITE, cursor_color=ft.Colors.CYAN, text_size=15,
            prefix_icon=ft.Icons.PERSON,
            content_padding=ft.padding.symmetric(horizontal=16, vertical=14),
        )
        self.pass_field = ft.TextField(
            label="Contraseña", value=pass_val,
            label_style=ft.TextStyle(color=ft.Colors.CYAN),
            hint_style=ft.TextStyle(color=ft.Colors.WHITE24),
            password=True, can_reveal_password=True,
            border_color=ft.Colors.WHITE24, focused_border_color=ft.Colors.CYAN,
            color=ft.Colors.WHITE, cursor_color=ft.Colors.CYAN, text_size=15,
            prefix_icon=ft.Icons.KEY,
            content_padding=ft.padding.symmetric(horizontal=16, vertical=14),
            on_change=self._on_pass_change,
        )

        # Fortaleza
        self.strength_bar = ft.ProgressBar(
            value=0, color="#4CAF50", bgcolor="#2a2a3e",
            bar_height=5, border_radius=3,
        )
        self.strength_label = ft.Text("", size=11, color=ft.Colors.WHITE54)
        if pass_val:
            self._update_strength(pass_val)

        self.url_field = ft.TextField(
            label="URL (opcional)", value=url_val,
            label_style=ft.TextStyle(color=ft.Colors.CYAN),
            hint_style=ft.TextStyle(color=ft.Colors.WHITE24),
            border_color=ft.Colors.WHITE24, focused_border_color=ft.Colors.CYAN,
            color=ft.Colors.WHITE, cursor_color=ft.Colors.CYAN, text_size=15,
            prefix_icon=ft.Icons.LINK,
            content_padding=ft.padding.symmetric(horizontal=16, vertical=14),
        )

        # Categoría
        self.cat_dropdown = ft.Dropdown(
            label="Categoría",
            label_style=ft.TextStyle(color=ft.Colors.CYAN),
            border_color=ft.Colors.WHITE24, focused_border_color=ft.Colors.CYAN,
            color=ft.Colors.WHITE, text_size=14,
            value=cat_id,
            options=[
                ft.dropdown.Option(str(c["id"]), c["name"])
                for c in self.categories
            ],
            content_padding=ft.padding.symmetric(horizontal=16, vertical=8),
        )

        self.error_text = ft.Text("", color=ft.Colors.RED_300, size=13, visible=False)

        return ft.Container(
            content=ft.Column(
                [
                    # Header
                    ft.Row(
                        [
                            ft.IconButton(
                                icon=ft.Icons.ARROW_BACK,
                                icon_color=ft.Colors.WHITE,
                                on_click=lambda e: self.on_cancel() if self.on_cancel else None,
                            ),
                            ft.Text(
                                "Editar contraseña" if self.is_edit else "Nueva contraseña",
                                size=20, weight=ft.FontWeight.W_700, color=ft.Colors.WHITE,
                                expand=True,
                            ),
                        ],
                    ),
                    ft.Container(height=8),
                    self.title_field,
                    self.user_field,
                    self.pass_field,
                    ft.Row(
                        [
                            self.strength_label,
                            ft.TextButton(
                                "Generar",
                                icon=ft.Icons.AUTO_AWESOME,
                                style=ft.ButtonStyle(color=ft.Colors.CYAN),
                                on_click=self._open_generator,
                            ),
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    ),
                    self.strength_bar,
                    self.url_field,
                    self.cat_dropdown,
                    self.error_text,
                    ft.Container(height=12),
                    ft.ElevatedButton(
                        "Guardar" if self.is_edit else "Crear contraseña",
                        icon=ft.Icons.SAVE,
                        bgcolor=ft.Colors.CYAN_700,
                        color=ft.Colors.WHITE,
                        width=260,
                        height=48,
                        style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=12)),
                        on_click=self._on_save,
                    ),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=10,
                scroll=ft.ScrollMode.AUTO,
            ),
            bgcolor="#0f172a",
            expand=True,
            padding=ft.padding.symmetric(horizontal=24, vertical=16),
        )

    def _on_pass_change(self, e):
        self._update_strength(e.control.value)

    def _update_strength(self, password: str):
        if password:
            score, label = password_strength(password)
            color = strength_color(score)
            self.strength_bar.value = score / 100
            self.strength_bar.color = color
            self.strength_label.value = f"{label} ({score}%)"
            self.strength_label.color = color
        else:
            self.strength_bar.value = 0
            self.strength_label.value = ""
        self.page.update()

    def _open_generator(self, e):
        """Abre el generador en un bottom sheet."""
        from views.generator_view import GeneratorView

        # Obtener reglas existentes o usar el perfil por defecto
        if self.is_edit and self.pw_data and self.pw_data.get("password_rules"):
            try:
                rules = json.loads(self.pw_data["password_rules"])
            except (json.JSONDecodeError, TypeError):
                rules = PASSWORD_PROFILES["estandar"].copy()
        else:
            rules = PASSWORD_PROFILES["estandar"].copy()

        gen = GeneratorView(
            self.page,
            initial_rules=rules,
            on_use_password=self._use_generated_password,
        )

        bs = ft.BottomSheet(
            content=ft.Container(
                content=gen.build(),
                height=520,
                bgcolor="#0f172a",
                border_radius=ft.border_radius.only(top_left=20, top_right=20),
            ),
            open=True,
        )
        self.page.overlay.append(bs)
        self._current_sheet = bs
        self.page.update()

    def _use_generated_password(self, password: str, rules: dict):
        self.pass_field.value = password
        self.current_rules = rules
        self._update_strength(password)
        # Cerrar bottom sheet
        if hasattr(self, '_current_sheet'):
            self._current_sheet.open = False
            self.page.update()

    def _on_save(self, e):
        from security.crypto import encrypt

        title = self.title_field.value
        if not title or not title.strip():
            self._show_error("El nombre del servicio es obligatorio")
            return

        password = self.pass_field.value
        if not password:
            self._show_error("La contraseña es obligatoria")
            return

        key = self.auth.key
        if not key:
            self._show_error("Error de autenticación. Reinicia la app.")
            return

        username_enc = encrypt(self.user_field.value or "", key)
        password_enc = encrypt(password, key)
        notes_enc = encrypt("", key)  # Dejar vacío al eliminar campo
        url = self.url_field.value or ""
        category_id = int(self.cat_dropdown.value or 8)

        # Obtener reglas del perfil
        rules = getattr(self, "current_rules", {})
        if not rules and self.is_edit and self.pw_data:
            try:
                rules = json.loads(self.pw_data.get("password_rules", "{}"))
            except (json.JSONDecodeError, TypeError):
                rules = {}

        if self.is_edit:
            self.db.update_password(
                self.pw_data["id"],
                title=title.strip(),
                username=username_enc,
                password=password_enc,
                url=url,
                category_id=category_id,
                notes=notes_enc,
                password_rules=rules,
            )
        else:
            self.db.add_password(
                title=title.strip(),
                username=username_enc,
                password=password_enc,
                url=url,
                category_id=category_id,
                notes=notes_enc,
                password_rules=rules,
            )

        if self.on_save:
            self.on_save()

    def _show_error(self, msg):
        self.error_text.value = msg
        self.error_text.visible = True
        self.page.update()
