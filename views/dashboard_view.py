"""
dashboard_view.py - Vista principal con grid de categorías, búsqueda y favoritos.
"""

import flet as ft
from components.category_tile import create_category_tile
from components.search_bar import create_search_bar
from components.password_card import create_password_card
from security.crypto import decrypt, encrypt, hash_answer
from utils.backup import (
    get_backup_path, list_backups, export_passwords,
    get_backup_metadata, import_passwords
)
import os
import random


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
            tile = create_category_tile(cat, count, self.on_category_click)
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
                on_copy_user=self.show_and_copy_user,
                on_copy_pass=self.show_and_copy_pass,
                on_edit=self.edit_password,
                on_delete=self.delete_password,
                on_favorite=self.toggle_favorite,
                on_open_url=self.open_url,
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
                create_search_bar(self.on_search),
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
                self.settings_card(
                    ft.Icons.LOCK_RESET, "Cambiar contraseña maestra",
                    f"Próximo cambio en {self.auth.days_until_rotation()} días",
                    self.change_password,
                ),
                self.settings_card(
                    ft.Icons.HELP_OUTLINE, "Preguntas de seguridad",
                    "Configurar preguntas de recuperación",
                    self.edit_security_questions,
                ),
                self.settings_card(
                    ft.Icons.TIMER, "Rotación de contraseña",
                    f"Cada {self.db.get_config('password_rotation_days') or '90'} días",
                    self.change_rotation,
                ),
                self.settings_card(
                    ft.Icons.SAVE_ALT, "Salvar KeyVault",
                    "Exportar a archivo seguro (.vk)",
                    self.start_export,
                ),
                self.settings_card(
                    ft.Icons.RESTORE, "Restaurar KeyVault",
                    "Importar desde archivo seguro (.vk)",
                    self.start_import,
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
                    icon=ft.Icons.HEALTH_AND_SAFETY_OUTLINED,
                    selected_icon=ft.Icons.HEALTH_AND_SAFETY,
                    label="Salud",
                ),
                ft.NavigationBarDestination(
                    icon=ft.Icons.SETTINGS_OUTLINED,
                    selected_icon=ft.Icons.SETTINGS,
                    label="Ajustes",
                ),
            ],
            selected_index=0,
            label_behavior=ft.NavigationBarLabelBehavior.ALWAYS_SHOW,
            on_change=self.on_tab_change,
        )

        # FAB
        fab = ft.FloatingActionButton(
            icon=ft.Icons.ADD,
            bgcolor=ft.Colors.CYAN_700,
            foreground_color=ft.Colors.WHITE,
            on_click=lambda e: self.add_password(),
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
    def on_tab_change(self, e):
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
            from views.audit_view import AuditView
            audit = AuditView(self.page, self.db, self.auth, on_edit=self.edit_password)
            self.tab_content.content = audit.build()
        elif idx == 4:
            self.tab_content.content = self.settings_content
        self.page.update()

    # ------------------------------------------------------------------ #
    #  Búsqueda
    # ------------------------------------------------------------------ #
    def on_search(self, query: str):
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
                on_copy_user=self.show_and_copy_user,
                on_copy_pass=self.show_and_copy_pass,
                on_edit=self.edit_password,
                on_delete=self.delete_password,
                on_favorite=self.toggle_favorite,
                on_open_url=self.open_url,
            )
            self.search_results.controls.append(card)

        self.search_results.visible = True
        self.categories_grid.visible = False
        self.page.update()

    # ------------------------------------------------------------------ #
    #  Acciones de contraseñas
    # ------------------------------------------------------------------ #
    def show_and_copy_user(self, e, pw_id):
        pw = self.db.get_password_by_id(pw_id)
        if pw and pw.get("username"):
            username = decrypt(pw["username"], self.auth.key)
            
            # Copiar al portapapeles
            self.page.run_task(self.page.clipboard.set, username)
            
            # Mostrar visualmente en el botón
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
            
            # Mostrar visualmente en el botón
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
        pw = self.db.get_password_by_id(pw_id)
        if pw:
            self.db.update_password(pw_id, is_favorite=0 if pw["is_favorite"] else 1)
            self.on_navigate("dashboard")

    def edit_password(self, pw_id):
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

    def delete_password(self, pw_id):
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

    def add_password(self):
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

    def on_category_click(self, category_id: int):
        self.on_navigate("passwords", category_id=category_id)

    # ------------------------------------------------------------------ #
    #  Settings
    # ------------------------------------------------------------------ #
    def settings_card(self, icon, title, subtitle, on_click) -> ft.Container:
        import asyncio

        def handle_click(e):
            if asyncio.iscoroutinefunction(on_click):
                self.page.run_task(on_click, e)
            else:
                on_click(e)

        return ft.Container(
            content=ft.ListTile(
                leading=ft.Icon(icon, color=ft.Colors.CYAN),
                title=ft.Text(title, color=ft.Colors.WHITE, size=14),
                subtitle=ft.Text(subtitle, color=ft.Colors.WHITE54, size=12),
                trailing=ft.Icon(ft.Icons.CHEVRON_RIGHT, color=ft.Colors.WHITE38),
                on_click=handle_click,
            ),
            bgcolor="#1e2a3a",
            border_radius=14,
            border=ft.border.all(1, ft.Colors.WHITE10),
        )

    def change_password(self, e=None):
        from views.change_password import ChangePasswordView
        view = ChangePasswordView(
            self.page, self.auth,
            on_complete=lambda: self.on_navigate("dashboard"),
        )
        self.page.controls.clear()
        self.page.add(view.build())
        self.page.update()

    def edit_security_questions(self, e=None):
        from views.security_questions import SecurityQuestionsView
        view = SecurityQuestionsView(
            self.page, self.auth, mode="setup",
            on_complete=lambda: self.on_navigate("dashboard"),
            master_password="",  # No-op para re-configurar
        )
        self.page.controls.clear()
        self.page.add(view.build())
        self.page.update()

    def change_rotation(self, e=None):
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

    # ------------------------------------------------------------------ #
    #  Backup (Export / Import)
    # ------------------------------------------------------------------ #
    def start_export(self, e):
        """Inicia el proceso de exportación con la Bóveda Binaria (Cero-Interacción)."""
        questions = self.auth.get_user_questions()
        if not questions:
            self.show_snackbar("Debes configurar preguntas de seguridad primero.")
            return

        # Seleccionar pregunta y hash de respuesta al azar automáticamente
        q_obj = random.choice(questions)
        answer_hash = q_obj["answer_hash"]

        name_field = ft.TextField(
            label="Nombre del backup (opcional)",
            hint_text="ej. mi_copia",
            border_color=ft.Colors.CYAN,
            color=ft.Colors.WHITE,
            text_size=14,
            autofocus=True,
        )

        def close_dialog():
            dialog.open = False
            self.page.update()

        def process_export(e):
            custom_name = name_field.value.strip()
            close_dialog()
            
            # Generar ruta y ejecutar
            path = get_backup_path(custom_name)
            passwords = self.db.get_all_passwords()
            
            # Usar el hash de la respuesta para cifrar de forma transparente
            success, exported, skipped = export_passwords(
                path, passwords, self.auth.key, 
                q_obj["question"], answer_hash
            )
            
            if success:
                # Mostrar éxito con ruta completa en un diálogo persistente
                def close_success(_):
                    success_dialog.open = False
                    self.page.update()

                success_dialog = ft.AlertDialog(
                    title=ft.Text("✅ Exportación Exitosa", color=ft.Colors.CYAN),
                    content=ft.Column([
                        ft.Text(f"Se han salvado {exported} contraseñas."),
                        ft.Container(height=10),
                        ft.Text("Ruta del archivo:", size=12, weight=ft.FontWeight.BOLD),
                        ft.Text(path, size=11, color=ft.Colors.WHITE70, selectable=True),
                    ], tight=True),
                    actions=[ft.TextButton("Entendido", on_click=close_success)],
                    bgcolor="#1e2a3a",
                )
                success_dialog.open = True
                self.page.overlay.append(success_dialog)
                self.page.update()
            else:
                self.show_snackbar("❌ Error al exportar.")

        dialog = ft.AlertDialog(
            title=ft.Text("Generar Backup Seguro", color=ft.Colors.WHITE, weight=ft.FontWeight.BOLD),
            content=ft.Column([
                ft.Text("Se creará una copia cifrada con tus parámetros de seguridad.", size=13, color=ft.Colors.WHITE54),
                name_field,
                ft.Text("El sistema usará una de tus respuestas de seguridad automáticamente.", size=11, color=ft.Colors.CYAN_200),
            ], tight=True, spacing=12),
            bgcolor="#1e2a3a",
            actions=[
                ft.TextButton("Cancelar", on_click=lambda _: close_dialog()),
                ft.ElevatedButton("Exportar Ahora", bgcolor=ft.Colors.CYAN_700, on_click=process_export),
            ]
        )
        dialog.open = True
        self.page.overlay.append(dialog)
        self.page.update()

    def start_import(self, e):
        """Inicia el proceso de restauración buscando archivos .vk en Documentos."""
        backups = list_backups()
        if not backups:
            self.show_snackbar("No se encontraron archivos .vk en Documentos.")
            return

        def close_dialog():
            dialog.open = False
            self.page.update()

        def select_file(path):
            close_dialog()
            self.import_unlock_and_ask(path)

        # Crear lista de botones para cada backup
        backup_list = ft.Column(spacing=8, scroll=ft.ScrollMode.AUTO, height=200)
        for path in backups:
            name = os.path.basename(path)
            backup_list.controls.append(
                ft.ListTile(
                    leading=ft.Icon(ft.Icons.FILE_PRESENT, color=ft.Colors.CYAN),
                    title=ft.Text(name, size=14, color=ft.Colors.WHITE),
                    on_click=lambda _, p=path: select_file(p)
                )
            )

        dialog = ft.AlertDialog(
            title=ft.Text("Seleccionar Respaldo", color=ft.Colors.WHITE),
            content=backup_list,
            bgcolor="#1e2a3a",
            actions=[ft.TextButton("Cerrar", on_click=lambda _: close_dialog())]
        )
        dialog.open = True
        self.page.overlay.append(dialog)
        self.page.update()

    def import_unlock_and_ask(self, path):
        """Abre el binario y pide la respuesta para descifrar con UI mejorada."""
        meta = get_backup_metadata(path)
        if not meta:
            self.show_snackbar("❌ El archivo está dañado o no es válido.")
            return

        answer_field = ft.TextField(
            label="Tu Respuesta",
            password=True,
            can_reveal_password=True,
            border_color=ft.Colors.CYAN,
            color=ft.Colors.WHITE,
            text_size=14,
            autofocus=True,
        )

        def close_dialog():
            dialog.open = False
            self.page.update()

        def do_import(e):
            ans = answer_field.value.strip()
            if not ans:
                answer_field.error_text = "Se requiere la respuesta"
                answer_field.update()
                return
            
            close_dialog()
            # El backup se cifró con el hash de la respuesta, así que hasheamos la entrada
            ans_hash = hash_answer(ans)
            imported_data = import_passwords(meta, ans_hash)
            
            if imported_data is None:
                self.show_snackbar("❌ Respuesta incorrecta o archivo incompatible.")
                return
                
            # 1. Mapear datos actuales por (título, usuario, categoría) para actualización inteligente
            current_passwords = self.db.get_all_passwords()
            existing_map = {}
            for lp in current_passwords:
                u = decrypt(lp["username"], self.auth.key) if lp["username"] else ""
                # Importante: usar la misma lógica de clave que en la inserción
                existing_map[(lp["title"], u, lp["category_id"])] = lp["id"]

            # 2. Integrar a la DB con actualización inteligente
            new_count = 0
            updated_count = 0
            
            all_cats = self.db.get_all_categories()
            valid_ids = [c["id"] for c in all_cats]

            for item in imported_data:
                cat_id = item.get("category_id", 8)
                if cat_id not in valid_ids: cat_id = 8

                key = (item["title"], item["username"], cat_id)
                
                enc_user = encrypt(item["username"], self.auth.key)
                enc_pass = encrypt(item["password"], self.auth.key)
                enc_note = encrypt(item["notes"], self.auth.key) if item.get("notes") else b""

                if key in existing_map:
                    pw_id = existing_map[key]
                    self.db.update_password(
                        pw_id,
                        password=enc_pass,
                        notes=enc_note,
                        url=item.get("url", "")
                    )
                    updated_count += 1
                else:
                    self.db.add_password(
                        title=item["title"],
                        username=enc_user,
                        password=enc_pass,
                        url=item.get("url", ""),
                        notes=enc_note,
                        category_id=cat_id
                    )
                    new_count += 1
            
            msg = f"Restauración finalizada."
            stats = []
            if new_count > 0: stats.append(f"{new_count} nuevas")
            if updated_count > 0: stats.append(f"{updated_count} actualizadas")
            
            def close_result(_):
                result_dialog.open = False
                self.page.update()
                self.on_navigate("dashboard")

            result_dialog = ft.AlertDialog(
                title=ft.Text("✅ Importación Completada", color=ft.Colors.CYAN),
                content=ft.Column([
                    ft.Text(msg),
                    ft.Text(", ".join(stats) if stats else "No hubo cambios.", size=14, color=ft.Colors.WHITE70),
                ], tight=True),
                actions=[ft.TextButton("Entendido", on_click=close_result)],
                bgcolor="#1e2a3a",
            )
            result_dialog.open = True
            self.page.overlay.append(result_dialog)
            self.page.update()

        dialog = ft.AlertDialog(
            title=ft.Text("Restaurar Datos", color=ft.Colors.WHITE, weight=ft.FontWeight.BOLD),
            content=ft.Column([
                ft.Text("El archivo está protegido. Responde para desbloquear:", size=13, color=ft.Colors.WHITE54),
                ft.Text(f"Pregunta: {meta['question_text']}", size=15, weight=ft.FontWeight.W_600, color=ft.Colors.WHITE),
                answer_field,
                ft.Text("Los duplicados exactos se actualizarán automáticamente.", size=11, color=ft.Colors.WHITE38),
            ], tight=True, spacing=12),
            bgcolor="#1e2a3a",
            actions=[
                ft.TextButton("Cancelar", on_click=lambda _: close_dialog()),
                ft.ElevatedButton("Restaurar ahora", bgcolor=ft.Colors.CYAN_700, on_click=do_import),
            ]
        )
        dialog.open = True
        self.page.overlay.append(dialog)
        self.page.update()

    def show_snackbar(self, msg: str):
        self.page.snack_bar = ft.SnackBar(ft.Text(msg, color=ft.Colors.WHITE), bgcolor="#333333")
        self.page.snack_bar.open = True
        self.page.update()
