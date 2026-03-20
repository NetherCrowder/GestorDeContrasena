"""
login_view.py - Vista de login/registro con contraseña maestra y PIN.
"""

import flet as ft
from icecream import ic
from utils.logging_config import register_error


class LoginView:
    """Pantalla de autenticación."""

    def __init__(self, page: ft.Page, auth_manager, on_login_success: callable):
        self.page = page
        self.auth = auth_manager
        self.on_login_success = on_login_success
        self.is_register = not self.auth.db.has_master_password()
        self.pin_attempts = 0
        self.max_pin_attempts = 3

    def build(self) -> ft.Container:
        if self.is_register:
            return self.build_register()
        else:
            return self.build_login()

    # ------------------------------------------------------------------ #
    #  Login
    # ------------------------------------------------------------------ #
    def build_login(self) -> ft.Container:
        self.pin_field = ft.TextField(
            hint_text="PIN de 6 dígitos",
            hint_style=ft.TextStyle(color=ft.Colors.WHITE38),
            password=True,
            can_reveal_password=True,
            max_length=6,
            keyboard_type=ft.KeyboardType.NUMBER,
            border_color=ft.Colors.WHITE24,
            focused_border_color=ft.Colors.CYAN,
            color=ft.Colors.WHITE,
            cursor_color=ft.Colors.CYAN,
            text_size=18,
            text_align=ft.TextAlign.CENTER,
            content_padding=ft.padding.symmetric(horizontal=20, vertical=16),
        )

        self.master_field = ft.TextField(
            hint_text="Contraseña maestra",
            hint_style=ft.TextStyle(color=ft.Colors.WHITE38),
            password=True,
            can_reveal_password=True,
            border_color=ft.Colors.WHITE24,
            focused_border_color=ft.Colors.CYAN,
            color=ft.Colors.WHITE,
            cursor_color=ft.Colors.CYAN,
            text_size=16,
            content_padding=ft.padding.symmetric(horizontal=20, vertical=16),
            visible=False,
        )

        self.error_text = ft.Text("", color=ft.Colors.RED_300, size=13, visible=False)
        self.show_master_btn = ft.TextButton(
            "Usar contraseña maestra",
            style=ft.ButtonStyle(color=ft.Colors.CYAN),
            on_click=self.toggle_login_mode,
        )
        self.forgot_btn = ft.TextButton(
            "¿Olvidaste tu contraseña?",
            style=ft.ButtonStyle(color=ft.Colors.AMBER),
            on_click=lambda e: self.show_recovery(),
            visible=False,
        )

        return ft.Container(
            content=ft.Column(
                [
                    ft.Container(height=40),
                    # Logo
                    ft.Container(
                        content=ft.Icon(ft.Icons.LOCK_ROUNDED, size=64, color=ft.Colors.CYAN),
                        bgcolor="#00BCD420",
                        border_radius=32,
                        width=100,
                        height=100,
                        alignment=ft.Alignment.CENTER,
                    ),
                    ft.Text(
                        "KeyVault",
                        size=28,
                        weight=ft.FontWeight.W_700,
                        color=ft.Colors.WHITE,
                    ),
                    ft.Text(
                        "Ingresa para acceder a tu bóveda",
                        size=14,
                        color=ft.Colors.WHITE54,
                    ),
                    ft.Container(height=20),
                    self.pin_field,
                    self.master_field,
                    self.error_text,
                    ft.Container(height=8),
                    ft.ElevatedButton(
                        "Desbloquear",
                        icon=ft.Icons.LOCK_OPEN,
                        bgcolor=ft.Colors.CYAN_700,
                        color=ft.Colors.WHITE,
                        width=280,
                        height=48,
                        style=ft.ButtonStyle(
                            shape=ft.RoundedRectangleBorder(radius=12),
                        ),
                        on_click=self.on_login,
                    ),
                    self.show_master_btn,
                    self.forgot_btn,
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=10,
                scroll=ft.ScrollMode.AUTO,
            ),
            bgcolor="#0f172a",
            expand=True,
            padding=ft.padding.symmetric(horizontal=32, vertical=16),
        )

    def toggle_login_mode(self, e):
        self.pin_field.visible = not self.pin_field.visible
        self.master_field.visible = not self.master_field.visible
        if self.master_field.visible:
            self.show_master_btn.text = "Usar PIN"
        else:
            self.show_master_btn.text = "Usar contraseña maestra"
        self.page.update()

    def on_login(self, e):
        self.error_text.visible = False

        if self.master_field.visible:
            # Login con contraseña maestra
            password = self.master_field.value
            if not password:
                self.show_error("Ingresa tu contraseña maestra")
                return
            try:
                if self.auth.login_master(password):
                    ic("Master Login successful")
                    self.on_login_success()
                else:
                    self.show_error("Contraseña incorrecta")
                    self.forgot_btn.visible = True
                    self.page.update()
            except Exception as ex:
                register_error("Error during Master Login", ex)
                self.show_error("Error inesperado al iniciar sesión")
        else:
            # Login con PIN
            pin = self.pin_field.value
            if not pin or len(pin) != 6:
                self.show_error("El PIN debe tener 6 dígitos")
                return
            try:
                if self.auth.login_pin(pin):
                    ic("PIN Login successful")
                    self.on_login_success()
                else:
                    self.pin_attempts += 1
                    remaining = self.max_pin_attempts - self.pin_attempts
                    if remaining <= 0:
                        self.show_error("PIN bloqueado. Usa la contraseña maestra.")
                        self.pin_field.visible = False
                        self.master_field.visible = True
                        self.show_master_btn.visible = False
                        self.forgot_btn.visible = True
                    else:
                        self.show_error(f"PIN incorrecto. {remaining} intentos restantes.")
                    self.page.update()
            except Exception as ex:
                register_error("Error during PIN Login", ex)
                self.show_error("Error inesperado al validar el PIN")

    def show_error(self, msg: str):
        self.error_text.value = msg
        self.error_text.visible = True
        self.page.update()

    def show_recovery(self):
        from views.security_questions import SecurityQuestionsView
        recovery_view = SecurityQuestionsView(
            self.page, self.auth, mode="recovery",
            on_complete=self.on_login_success,
        )
        self.page.controls.clear()
        self.page.add(recovery_view.build())
        self.page.update()

    # ------------------------------------------------------------------ #
    #  Registro
    # ------------------------------------------------------------------ #
    def build_register(self) -> ft.Container:
        self.reg_password = ft.TextField(
            label="Contraseña maestra",
            hint_text="Mín. 8 caracteres",
            hint_style=ft.TextStyle(color=ft.Colors.WHITE38),
            label_style=ft.TextStyle(color=ft.Colors.CYAN),
            password=True,
            can_reveal_password=True,
            border_color=ft.Colors.WHITE24,
            focused_border_color=ft.Colors.CYAN,
            color=ft.Colors.WHITE,
            cursor_color=ft.Colors.CYAN,
            text_size=16,
            content_padding=ft.padding.symmetric(horizontal=20, vertical=16),
        )
        self.reg_confirm = ft.TextField(
            label="Confirmar contraseña",
            hint_style=ft.TextStyle(color=ft.Colors.WHITE38),
            label_style=ft.TextStyle(color=ft.Colors.CYAN),
            password=True,
            can_reveal_password=True,
            border_color=ft.Colors.WHITE24,
            focused_border_color=ft.Colors.CYAN,
            color=ft.Colors.WHITE,
            cursor_color=ft.Colors.CYAN,
            text_size=16,
            content_padding=ft.padding.symmetric(horizontal=20, vertical=16),
        )
        self.reg_pin = ft.TextField(
            label="PIN de acceso rápido (6 dígitos)",
            hint_style=ft.TextStyle(color=ft.Colors.WHITE38),
            label_style=ft.TextStyle(color=ft.Colors.CYAN),
            password=True,
            can_reveal_password=True,
            max_length=6,
            keyboard_type=ft.KeyboardType.NUMBER,
            border_color=ft.Colors.WHITE24,
            focused_border_color=ft.Colors.CYAN,
            color=ft.Colors.WHITE,
            cursor_color=ft.Colors.CYAN,
            text_size=18,
            text_align=ft.TextAlign.CENTER,
            content_padding=ft.padding.symmetric(horizontal=20, vertical=16),
        )
        self.reg_rotation = ft.Dropdown(
            label="Cambiar contraseña cada",
            label_style=ft.TextStyle(color=ft.Colors.CYAN),
            border_color=ft.Colors.WHITE24,
            focused_border_color=ft.Colors.CYAN,
            color=ft.Colors.WHITE,
            text_size=14,
            value="90",
            options=[
                ft.dropdown.Option("30", "30 días"),
                ft.dropdown.Option("60", "60 días"),
                ft.dropdown.Option("90", "90 días"),
                ft.dropdown.Option("180", "180 días"),
            ],
            content_padding=ft.padding.symmetric(horizontal=20, vertical=8),
        )
        self.reg_error = ft.Text("", color=ft.Colors.RED_300, size=13, visible=False)

        return ft.Container(
            content=ft.Column(
                [
                    ft.Container(height=20),
                    ft.Icon(ft.Icons.SHIELD_ROUNDED, size=56, color=ft.Colors.CYAN),
                    ft.Text(
                        "Crear tu bóveda",
                        size=24,
                        weight=ft.FontWeight.W_700,
                        color=ft.Colors.WHITE,
                    ),
                    ft.Text(
                        "Configura tu contraseña maestra para proteger tus datos",
                        size=13,
                        color=ft.Colors.WHITE54,
                        text_align=ft.TextAlign.CENTER,
                    ),
                    ft.Container(height=12),
                    self.reg_password,
                    self.reg_confirm,
                    ft.Divider(color=ft.Colors.WHITE10, height=24),
                    self.reg_pin,
                    self.reg_rotation,
                    self.reg_error,
                    ft.Container(height=12),
                    ft.ElevatedButton(
                        "Continuar →",
                        bgcolor=ft.Colors.CYAN_700,
                        color=ft.Colors.WHITE,
                        width=280,
                        height=48,
                        style=ft.ButtonStyle(
                            shape=ft.RoundedRectangleBorder(radius=12),
                        ),
                        on_click=self.on_register_step1,
                    ),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=10,
                scroll=ft.ScrollMode.AUTO,
            ),
            bgcolor="#0f172a",
            expand=True,
            padding=ft.padding.symmetric(horizontal=32, vertical=16),
        )

    def on_register_step1(self, e):
        pw = self.reg_password.value
        confirm = self.reg_confirm.value
        pin = self.reg_pin.value

        if not pw or len(pw) < 8:
            self.show_reg_error("La contraseña debe tener al menos 8 caracteres")
            return
        if pw != confirm:
            self.show_reg_error("Las contraseñas no coinciden")
            return
        if not pin or len(pin) != 6 or not pin.isdigit():
            self.show_reg_error("El PIN debe ser de 6 dígitos numéricos")
            return

        # Ir al paso de preguntas de seguridad
        rotation = int(self.reg_rotation.value or "90")
        from views.security_questions import SecurityQuestionsView
        sq_view = SecurityQuestionsView(
            self.page, self.auth, mode="setup",
            on_complete=self.on_login_success,
            master_password=pw,
            pin=pin,
            rotation_days=rotation,
        )
        self.page.controls.clear()
        self.page.add(sq_view.build())
        self.page.update()

    def show_reg_error(self, msg: str):
        self.reg_error.value = msg
        self.reg_error.visible = True
        self.page.update()
