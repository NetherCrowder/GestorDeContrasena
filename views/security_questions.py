"""
security_questions.py - Vista de configuración y recuperación por preguntas de seguridad.
"""

import flet as ft
from database.models import SECURITY_QUESTIONS_BANK
from security.crypto import hash_answer


class SecurityQuestionsView:
    """Configurar o responder preguntas de seguridad."""

    def __init__(self, page: ft.Page, auth_manager, mode: str = "setup",
                 on_complete: callable = None, master_password: str = "",
                 pin: str = "", rotation_days: int = 90, is_update: bool = False):
        """
        mode: "setup" (registro) o "recovery" (recuperación)
        """
        self.page = page
        self.auth = auth_manager
        self.mode = mode
        self.on_complete = on_complete
        self.master_password = master_password
        self.pin = pin
        self.rotation_days = rotation_days
        self.is_update = is_update

    def build(self) -> ft.Container:
        if self.mode == "setup":
            return self.build_setup()
        else:
            return self.build_recovery()

    # ------------------------------------------------------------------ #
    #  Configuración (Registro)
    # ------------------------------------------------------------------ #
    def build_setup(self) -> ft.Container:
        self.question_fields = []
        question_widgets = []

        for i, question in enumerate(SECURITY_QUESTIONS_BANK):
            cb = ft.Checkbox(
                label=question,
                label_style=ft.TextStyle(color=ft.Colors.WHITE70, size=13),
                check_color=ft.Colors.CYAN,
                active_color=ft.Colors.CYAN_700,
            )
            answer = ft.TextField(
                hint_text="Tu respuesta...",
                hint_style=ft.TextStyle(color=ft.Colors.WHITE24),
                border_color=ft.Colors.WHITE24,
                focused_border_color=ft.Colors.CYAN,
                color=ft.Colors.WHITE,
                cursor_color=ft.Colors.CYAN,
                text_size=14,
                content_padding=ft.padding.symmetric(horizontal=16, vertical=10),
                visible=False,
            )
            # Vincular checkbox con campo de respuesta
            cb.on_change = lambda e, a=answer: self.toggle_answer(e, a)
            self.question_fields.append((cb, answer, question))
            question_widgets.append(
                ft.Container(
                    content=ft.Column([cb, answer], spacing=4),
                    padding=ft.padding.only(bottom=8),
                )
            )

        self.setup_error = ft.Text("", color=ft.Colors.RED_300, size=13, visible=False)

        return ft.Container(
            content=ft.Column(
                [
                    ft.Container(height=16),
                    ft.Icon(ft.Icons.HELP_OUTLINE, size=48, color=ft.Colors.AMBER),
                    ft.Text(
                        "Preguntas de Seguridad",
                        size=22,
                        weight=ft.FontWeight.W_700,
                        color=ft.Colors.WHITE,
                    ),
                    ft.Text(
                        "Selecciona al menos 3 preguntas y respóndelas. "
                        "Las necesitarás si olvidas tu contraseña maestra.",
                        size=13,
                        color=ft.Colors.WHITE54,
                        text_align=ft.TextAlign.CENTER,
                    ),
                    ft.Container(height=8),
                    *question_widgets,
                    self.setup_error,
                    ft.Container(height=12),
                    ft.ElevatedButton(
                        "Guardar cambios ✓" if self.is_update else "Finalizar registro ✓",
                        bgcolor=ft.Colors.CYAN_700,
                        color=ft.Colors.WHITE,
                        width=280,
                        height=48,
                        style=ft.ButtonStyle(
                            shape=ft.RoundedRectangleBorder(radius=12),
                        ),
                        on_click=self.on_setup_complete,
                    ),
                    ft.TextButton(
                        "Regresar",
                        style=ft.ButtonStyle(color=ft.Colors.WHITE54),
                        on_click=lambda _: self.on_complete() if self.on_complete else None,
                        visible=self.is_update
                    ),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=6,
                scroll=ft.ScrollMode.AUTO,
            ),
            bgcolor="#0f172a",
            expand=True,
            padding=ft.padding.symmetric(horizontal=24, vertical=16),
        )

    def toggle_answer(self, e, answer_field: ft.TextField):
        answer_field.visible = e.control.value
        self.page.update()

    def on_setup_complete(self, e):
        selected = []
        for cb, answer, question in self.question_fields:
            if cb.value:
                if not answer.value or not answer.value.strip():
                    self.show_setup_error(f"Responde la pregunta: {question[:40]}...")
                    return
                selected.append((question, answer.value.strip()))

        if len(selected) < 3:
            self.show_setup_error("Debes seleccionar al menos 3 preguntas")
            return

        if self.is_update:
            # Solo actualizar preguntas
            self.auth.update_security_questions(selected)
        else:
            # Registrar usuario nuevo (Borrando lo anterior si existe)
            self.auth.register(
                master_password=self.master_password,
                pin=self.pin,
                security_qa=selected,
                rotation_days=self.rotation_days,
            )

        if self.on_complete:
            self.on_complete()

    def show_setup_error(self, msg):
        self.setup_error.value = msg
        self.setup_error.visible = True
        self.page.update()

    # ------------------------------------------------------------------ #
    #  Recuperación
    # ------------------------------------------------------------------ #
    def build_recovery(self) -> ft.Container:
        questions = self.auth.db.get_security_questions()
        self.recovery_fields = []
        question_widgets = []

        for q in questions:
            answer = ft.TextField(
                label=q["question"],
                label_style=ft.TextStyle(color=ft.Colors.WHITE70, size=13),
                hint_style=ft.TextStyle(color=ft.Colors.WHITE24),
                border_color=ft.Colors.WHITE24,
                focused_border_color=ft.Colors.AMBER,
                color=ft.Colors.WHITE,
                cursor_color=ft.Colors.AMBER,
                text_size=14,
                content_padding=ft.padding.symmetric(horizontal=16, vertical=12),
            )
            self.recovery_fields.append((q["id"], answer))
            question_widgets.append(answer)

        self.recovery_error = ft.Text("", color=ft.Colors.RED_300, size=13, visible=False)

        return ft.Container(
            content=ft.Column(
                [
                    ft.Container(height=20),
                    ft.Icon(ft.Icons.SECURITY, size=48, color=ft.Colors.AMBER),
                    ft.Text(
                        "Recuperar Acceso",
                        size=22,
                        weight=ft.FontWeight.W_700,
                        color=ft.Colors.WHITE,
                    ),
                    ft.Text(
                        "Responde correctamente al menos 3 preguntas para recuperar el acceso.",
                        size=13,
                        color=ft.Colors.WHITE54,
                        text_align=ft.TextAlign.CENTER,
                    ),
                    ft.Container(height=12),
                    *question_widgets,
                    self.recovery_error,
                    ft.Container(height=12),
                    ft.ElevatedButton(
                        "Verificar respuestas",
                        bgcolor=ft.Colors.AMBER_700,
                        color=ft.Colors.WHITE,
                        width=280,
                        height=48,
                        style=ft.ButtonStyle(
                            shape=ft.RoundedRectangleBorder(radius=12),
                        ),
                        on_click=self.on_recovery_verify,
                    ),
                    ft.TextButton(
                        "← Volver al login",
                        style=ft.ButtonStyle(color=ft.Colors.WHITE54),
                        on_click=lambda e: self.back_to_login(),
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

    def on_recovery_verify(self, e):
        answers = {}
        for qid, field in self.recovery_fields:
            if field.value and field.value.strip():
                answers[qid] = field.value.strip()

        if self.auth.verify_security_answers(answers):
            # Mostrar pantalla de cambio de contraseña
            from views.change_password import ChangePasswordView
            change_view = ChangePasswordView(
                self.page, self.auth,
                is_forced=True,
                on_complete=self.on_complete,
            )
            self.page.controls.clear()
            self.page.add(change_view.build())
            self.page.update()
        else:
            self.recovery_error.value = "Respuestas incorrectas. Necesitas al menos 3 correctas."
            self.recovery_error.visible = True
            self.page.update()

    def back_to_login(self):
        from views.login_view import LoginView
        login = LoginView(self.page, self.auth, self.on_complete)
        self.page.controls.clear()
        self.page.add(login.build())
        self.page.update()
