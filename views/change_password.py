"""
change_password.py - Vista para cambiar la contraseña maestra.
"""

import flet as ft


class ChangePasswordView:
    """Pantalla de cambio de contraseña maestra."""

    def __init__(self, page: ft.Page, auth_manager,
                 is_forced: bool = False, on_complete: callable = None):
        self.page = page
        self.auth = auth_manager
        self.is_forced = is_forced
        self.on_complete = on_complete

    def build(self) -> ft.Container:
        self.old_pw = ft.TextField(
            label="Contraseña anterior",
            label_style=ft.TextStyle(color=ft.Colors.CYAN),
            hint_style=ft.TextStyle(color=ft.Colors.WHITE24),
            password=True,
            can_reveal_password=True,
            border_color=ft.Colors.WHITE24,
            focused_border_color=ft.Colors.CYAN,
            color=ft.Colors.WHITE,
            cursor_color=ft.Colors.CYAN,
            text_size=16,
            content_padding=ft.padding.symmetric(horizontal=20, vertical=16),
            visible=not self.is_forced,
        )
        self.new_pw = ft.TextField(
            label="Nueva contraseña maestra",
            hint_text="Mín. 8 caracteres",
            label_style=ft.TextStyle(color=ft.Colors.CYAN),
            hint_style=ft.TextStyle(color=ft.Colors.WHITE24),
            password=True,
            can_reveal_password=True,
            border_color=ft.Colors.WHITE24,
            focused_border_color=ft.Colors.CYAN,
            color=ft.Colors.WHITE,
            cursor_color=ft.Colors.CYAN,
            text_size=16,
            content_padding=ft.padding.symmetric(horizontal=20, vertical=16),
        )
        self.confirm_pw = ft.TextField(
            label="Confirmar nueva contraseña",
            label_style=ft.TextStyle(color=ft.Colors.CYAN),
            hint_style=ft.TextStyle(color=ft.Colors.WHITE24),
            password=True,
            can_reveal_password=True,
            border_color=ft.Colors.WHITE24,
            focused_border_color=ft.Colors.CYAN,
            color=ft.Colors.WHITE,
            cursor_color=ft.Colors.CYAN,
            text_size=16,
            content_padding=ft.padding.symmetric(horizontal=20, vertical=16),
        )
        self.new_pin = ft.TextField(
            label="Nuevo PIN de 6 dígitos",
            label_style=ft.TextStyle(color=ft.Colors.CYAN),
            hint_style=ft.TextStyle(color=ft.Colors.WHITE24),
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
        self.error_text = ft.Text("", color=ft.Colors.RED_300, size=13, visible=False)
        self.success_text = ft.Text("", color=ft.Colors.GREEN_300, size=13, visible=False)

        title = "Cambio obligatorio" if self.is_forced else "Cambiar contraseña"
        subtitle = ("Tu contraseña ha expirado. Debes crear una nueva."
                     if self.is_forced
                     else "Ingresa tu contraseña actual y la nueva.")

        warning = None
        if self.is_forced:
            warning = ft.Container(
                content=ft.Row(
                    [
                        ft.Icon(ft.Icons.WARNING_AMBER, color=ft.Colors.AMBER, size=20),
                        ft.Text(
                            "Las contraseñas almacenadas se perderán tras la recuperación.",
                            color=ft.Colors.AMBER,
                            size=12,
                            expand=True,
                        ),
                    ],
                    spacing=8,
                ),
                bgcolor="#FF980020",
                border_radius=10,
                padding=ft.padding.all(12),
            )

        children = [
            ft.Container(height=20),
            ft.Icon(ft.Icons.LOCK_RESET, size=48, color=ft.Colors.CYAN),
            ft.Text(title, size=22, weight=ft.FontWeight.W_700, color=ft.Colors.WHITE),
            ft.Text(subtitle, size=13, color=ft.Colors.WHITE54, text_align=ft.TextAlign.CENTER),
        ]
        if warning:
            children.append(warning)
        children += [
            ft.Container(height=12),
            self.old_pw,
            self.new_pw,
            self.confirm_pw,
            ft.Divider(color=ft.Colors.WHITE10, height=16),
            self.new_pin,
            self.error_text,
            self.success_text,
            ft.Container(height=12),
            ft.ElevatedButton(
                "Cambiar contraseña",
                icon=ft.Icons.CHECK,
                bgcolor=ft.Colors.CYAN_700,
                color=ft.Colors.WHITE,
                width=280,
                height=48,
                style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=12)),
                on_click=self.on_change,
            ),
        ]

        return ft.Container(
            content=ft.Column(
                children,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=10,
                scroll=ft.ScrollMode.AUTO,
            ),
            bgcolor="#0f172a",
            expand=True,
            padding=ft.padding.symmetric(horizontal=32, vertical=16),
        )

    def on_change(self, e):
        new = self.new_pw.value
        confirm = self.confirm_pw.value
        pin = self.new_pin.value

        if not new or len(new) < 8:
            self.show_error("La contraseña debe tener al menos 8 caracteres")
            return
        if new != confirm:
            self.show_error("Las contraseñas no coinciden")
            return
        if not pin or len(pin) != 6 or not pin.isdigit():
            self.show_error("El PIN debe ser de 6 dígitos numéricos")
            return

        if self.is_forced:
            success = self.auth.force_change_password(new, pin)
        else:
            old = self.old_pw.value
            if not old:
                self.show_error("Ingresa tu contraseña actual")
                return
            success = self.auth.change_master_password(old, new, pin)

        if success:
            if self.on_complete:
                self.on_complete()
        else:
            self.show_error("La contraseña actual es incorrecta")

    def show_error(self, msg):
        self.error_text.value = msg
        self.error_text.visible = True
        self.success_text.visible = False
        self.page.update()
