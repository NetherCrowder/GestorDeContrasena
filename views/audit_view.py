"""
audit_view.py - Vista de Auditoría y Salud de las contraseñas.
"""

import flet as ft
from utils.security_audit import PasswordAuditEngine
from utils.helpers import strength_color
from icecream import ic
from utils.logging_config import register_error

class AuditView:
    def __init__(self, page: ft.Page, db_manager, auth_manager, on_edit: callable = None):
        self.page = page
        self.db = db_manager
        self.auth = auth_manager
        self.on_edit = on_edit
        self.audit_engine = PasswordAuditEngine()

    def build(self) -> ft.Container:
        all_passwords = self.db.get_all_passwords()
        categories = self.db.get_all_categories()
        
        try:
            # Realizar auditoría
            audit_results = self.audit_engine.vault_wide_audit(
                all_passwords, categories, self.auth.key
            )
            ic("Vault-wide audit completed")
        except Exception as ex:
            register_error("Error during vault audit", ex)
            return ft.Container(
                content=ft.Column(
                    [
                        ft.Icon(ft.Icons.ERROR_OUTLINE, color=ft.Colors.RED, size=48),
                        ft.Text("Error al realizar la auditoría", size=16, color=ft.Colors.WHITE),
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER
                ),
                padding=40,
                expand=True
            )
        
        score = audit_results["overall_score"]
        
        # Header de Salud
        health_header = ft.Container(
            content=ft.Column(
                [
                    ft.Text("Puntuación de Salud", size=16, color=ft.Colors.WHITE70),
                    ft.Row(
                        [
                            ft.Text(f"{score}%", size=48, weight=ft.FontWeight.W_900, 
                                    color=strength_color(score)),
                            ft.Icon(
                                ft.Icons.SHIELD if score > 70 else ft.Icons.GPP_MAYBE,
                                size=40,
                                color=strength_color(score)
                            )
                        ],
                        alignment=ft.MainAxisAlignment.CENTER
                    ),
                    ft.Text(
                        self.get_score_msg(score),
                        size=14, color=ft.Colors.WHITE54, text_align=ft.TextAlign.CENTER
                    )
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=5
            ),
            padding=20,
            bgcolor="#1e293b",
            border_radius=20,
        )

        # Recomendación Top
        top_rec = self.get_top_recommendation(audit_results["processed_passwords"])
        top_rec_container = ft.Container(visible=False)
        if top_rec:
            top_rec_container = ft.Container(
                content=ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Icon(ft.Icons.LIGHTBULB_CIRCLE, color=ft.Colors.YELLOW_400, size=24),
                                ft.Text("Recomendación Prioritaria", size=16, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE)
                            ],
                            spacing=10
                        ),
                        ft.Text(top_rec, size=14, color=ft.Colors.WHITE70),
                    ],
                    spacing=8
                ),
                padding=16,
                bgcolor="#33415550",
                border=ft.border.all(1, ft.Colors.CYAN_700),
                border_radius=12,
                margin=ft.margin.symmetric(vertical=10)
            )
            top_rec_container.visible = True

        # Secciones de Problemas
        vulnerabilities_list = ft.Column(spacing=10, scroll=ft.ScrollMode.AUTO, expand=True)
        
        critical = []
        moderate = []
        minor = []

        for pw in audit_results["processed_passwords"]:
            for v in pw["analysis"]["vulnerabilities"]:
                card = self.create_issue_card(pw, v)
                if v["severity"] == "high": critical.append(card)
                elif v["severity"] == "medium": moderate.append(card)
                else: minor.append(card)

        if not critical and not moderate and not minor:
            vulnerabilities_list.controls.append(
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Icon(ft.Icons.CHECK_CIRCLE_OUTLINE, size=64, color=ft.Colors.GREEN_400),
                            ft.Text("Tu vault está saludable", size=18, weight=ft.FontWeight.W_600, color=ft.Colors.WHITE),
                            ft.Text("No se encontraron vulnerabilidades críticas.", color=ft.Colors.WHITE54)
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=10
                    ),
                    padding=40,
                    alignment=ft.alignment.Alignment(0, 0)
                )
            )
        else:
            if critical:
                vulnerabilities_list.controls.append(self.section_title("Riesgo Crítico", ft.Colors.RED_400))
                vulnerabilities_list.controls.extend(critical)
            if moderate:
                vulnerabilities_list.controls.append(self.section_title("Riesgo Moderado", ft.Colors.ORANGE_400))
                vulnerabilities_list.controls.extend(moderate)
            if minor:
                vulnerabilities_list.controls.append(self.section_title("Riesgo Menor", ft.Colors.CYAN_700))
                vulnerabilities_list.controls.extend(minor)

        return ft.Container(
            content=ft.Column(
                [
                    ft.Text("Auditoría y Salud", size=24, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE),
                    ft.Text("Analiza y fortalece tu seguridad", size=14, color=ft.Colors.WHITE54),
                    ft.Container(height=10),
                    health_header,
                    top_rec_container,
                    vulnerabilities_list
                ],
                spacing=5,
                expand=True
            ),
            padding=ft.padding.only(left=16, right=16, top=10),
            expand=True
        )

    def get_top_recommendation(self, processed_passwords: list[dict]) -> str | None:
        """Encuentra el problema más grave y retorna una recomendación."""
        high_severity = []
        for pw in processed_passwords:
            for v in pw["analysis"]["vulnerabilities"]:
                if v["severity"] == "high":
                    high_severity.append((pw, v))
        
        if not high_severity:
            return None
            
        # Priorizar: Stuffing > Leaked > Reused > Weak (Banking)
        # Ordenar por tipo de vulnerabilidad
        priority = {"stuffing": 0, "leaked": 1, "pin_pattern": 2, "reused": 3, "contextual": 4, "weak": 5}
        high_severity.sort(key=lambda x: (priority.get(x[1]["type"], 99), 0 if x[0]["category_id"] == 1 else 1))
        
        top = high_severity[0]
        return f"En {top[0]['title']}: {top[1]['recommendation']}"

    def get_score_msg(self, score: int) -> str:
        if score > 90: return "¡Excelente seguridad! Mantén tus contraseñas únicas."
        if score > 70: return "Buena seguridad, pero hay margen de mejora."
        if score > 50: return "Seguridad aceptable. Considera cambiar las contraseñas débiles."
        return "Atención requerida. Tienes vulnerabilidades críticas."

    def section_title(self, text: str, color) -> ft.Row:
        return ft.Row(
            [
                ft.Container(width=4, height=16, bgcolor=color, border_radius=2),
                ft.Text(text, size=14, weight=ft.FontWeight.BOLD, color=color)
            ],
            margin=ft.margin.only(top=10, bottom=5)
        )

    def create_issue_card(self, pw: dict, v: dict) -> ft.Container:
        severity_color = {
            "high": ft.Colors.RED_400,
            "medium": ft.Colors.ORANGE_400,
            "low": ft.Colors.YELLOW_400
        }.get(v["severity"], ft.Colors.WHITE54)

        return ft.Container(
            content=ft.ListTile(
                leading=ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, color=severity_color),
                title=ft.Text(pw["title"], color=ft.Colors.WHITE, weight=ft.FontWeight.W_600),
                subtitle=ft.Column(
                    [
                        ft.Text(v["message"], color=ft.Colors.WHITE70, size=12),
                        ft.Text(v["recommendation"], color=ft.Colors.WHITE38, italic=True, size=11),
                    ],
                    spacing=2
                ),
                trailing=ft.IconButton(
                    icon=ft.Icons.EDIT_OUTLINED,
                    icon_color=ft.Colors.CYAN,
                    on_click=lambda e: self.open_edit(pw["id"])
                )
            ),
            bgcolor="#1e293b",
            border_radius=12,
            border=ft.border.all(1, ft.Colors.WHITE10)
        )

    def open_edit(self, pw_id):
        """Dispara la navegación hacia el formulario de edición."""
        if self.on_edit:
            self.on_edit(pw_id)
