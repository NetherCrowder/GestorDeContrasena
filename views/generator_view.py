"""
generator_view.py - Vista del generador de contraseñas con perfiles por sitio.
"""

import flet as ft
from database.models import PASSWORD_PROFILES
from utils.helpers import generate_password, password_strength, strength_color


class GeneratorView:
    """Generador de contraseñas con restricciones por sitio."""

    def __init__(self, page: ft.Page, initial_rules: dict | None = None,
                 on_use_password: callable = None, db_manager=None, auth_manager=None):
        self.page = page
        self.on_use_password = on_use_password
        self.db = db_manager
        self.auth = auth_manager
        self.rules = initial_rules or PASSWORD_PROFILES["estandar"].copy()
        self.generated_password = ""
        self._mounted = False  # evita page.update() antes de montar
        self.history_list = ft.ListView(spacing=8, expand=True, scale=1.0)
        self.warehouse_counter = ft.Text("0 contraseñas", size=13, color=ft.Colors.WHITE54, text_align=ft.TextAlign.CENTER)
        
        # Modo independiente vs dialog
        self.has_warehouse = not self.on_use_password and self.db and self.auth
        self.current_view = "warehouse" if self.has_warehouse else "generator"
        
        if self.has_warehouse:
            self.db.cleanup_temp_passwords()
            self.load_history()
            if len(self.history_list.controls) == 0:
                self.current_view = "generator"

    def switch_view(self, view_name):
        self.current_view = view_name
        if hasattr(self, 'warehouse_column') and hasattr(self, 'generator_column'):
            self.warehouse_column.visible = (self.current_view == "warehouse")
            self.generator_column.visible = (self.current_view == "generator")
        
        if view_name == "warehouse":
            self.load_history()
            
        if self._mounted:
            self.page.update()

    def build(self) -> ft.Container:
        # Campo de contraseña generada
        suffix_btn = None
        if not self.on_use_password:
            suffix_btn = ft.IconButton(
                icon=ft.Icons.SAVE,
                icon_color=ft.Colors.CYAN,
                icon_size=20,
                tooltip="Guardar en historial y volver",
                on_click=self.save_current_to_history,
            )
        else:
            suffix_btn = None

        self.password_display = ft.TextField(
            value="",
            read_only=True,
            color=ft.Colors.WHITE,
            text_size=18,
            text_align=ft.TextAlign.CENTER,
            border_color=ft.Colors.CYAN_700,
            bgcolor="#1a1a2e",
            content_padding=ft.padding.symmetric(horizontal=16, vertical=14),
            suffix=suffix_btn,
        )

        self.password_name_input = ft.TextField(
            label="Detalle / Nombre (ej. WiFi, Login...)",
            label_style=ft.TextStyle(color=ft.Colors.WHITE54, size=12),
            color=ft.Colors.WHITE,
            text_size=14,
            border_color=ft.Colors.WHITE24,
            focused_border_color=ft.Colors.CYAN,
            content_padding=ft.padding.symmetric(horizontal=12, vertical=8),
            visible=not self.on_use_password
        )

        self.strength_bar = ft.ProgressBar(
            value=0, color="#4CAF50", bgcolor="#2a2a3e",
            bar_height=6, border_radius=3,
        )
        self.strength_label = ft.Text("", size=12, color=ft.Colors.WHITE54)

        self.profile_dropdown = ft.Dropdown(
            label="Perfil de restricciones",
            label_style=ft.TextStyle(color=ft.Colors.CYAN),
            border_color=ft.Colors.WHITE24,
            focused_border_color=ft.Colors.CYAN,
            color=ft.Colors.WHITE,
            text_size=14,
            value="estandar",
            options=[
                ft.dropdown.Option(key, prof["label"])
                for key, prof in PASSWORD_PROFILES.items()
            ],
            on_select=self.on_profile_change,
            content_padding=ft.padding.symmetric(horizontal=16, vertical=8),
        )

        min_l = self.rules.get("min_length", 8)
        max_l = self.rules.get("max_length", 32)
        default_l = max(min_l, min(16, max_l))
        self.length_label = ft.Text(f"Longitud: {default_l}", size=13, color=ft.Colors.WHITE70)
        self.length_slider = ft.Slider(
            min=min_l, max=max_l, value=default_l,
            divisions=max(1, max_l - min_l),
            active_color=ft.Colors.CYAN, inactive_color=ft.Colors.WHITE24,
            on_change=self.on_length_change,
        )

        self.sw_upper = ft.Switch(
            label="Mayúsculas (A-Z)", value=self.rules.get("allow_uppercase", True),
            active_color=ft.Colors.CYAN, label_text_style=ft.TextStyle(color=ft.Colors.WHITE70, size=13),
            on_change=lambda e: self.generate(),
        )
        self.sw_lower = ft.Switch(
            label="Minúsculas (a-z)", value=self.rules.get("allow_lowercase", True),
            active_color=ft.Colors.CYAN, label_text_style=ft.TextStyle(color=ft.Colors.WHITE70, size=13),
            on_change=lambda e: self.generate(),
        )
        self.sw_numbers = ft.Switch(
            label="Números (0-9)", value=self.rules.get("allow_numbers", True),
            active_color=ft.Colors.CYAN, label_text_style=ft.TextStyle(color=ft.Colors.WHITE70, size=13),
            on_change=lambda e: self.generate(),
        )
        self.sw_symbols = ft.Switch(
            label="Símbolos (!@#$...)", value=self.rules.get("allow_symbols", True),
            active_color=ft.Colors.CYAN, label_text_style=ft.TextStyle(color=ft.Colors.WHITE70, size=13),
            on_change=lambda e: self.on_switch_change(),
        )
        self.symbols_input = ft.TextField(
            label="Símbolos específicos",
            value=self.rules.get("allowed_symbols", ""),
            label_style=ft.TextStyle(color=ft.Colors.WHITE54, size=12),
            color=ft.Colors.WHITE,
            text_size=13,
            border_color=ft.Colors.WHITE10,
            focused_border_color=ft.Colors.CYAN,
            content_padding=ft.padding.symmetric(horizontal=12, vertical=8),
            on_change=lambda e: self.generate(),
            visible=self.sw_symbols.value,
        )

        self.options_column = ft.Column(
            [self.sw_upper, self.sw_lower, self.sw_numbers, self.sw_symbols, self.symbols_input],
            spacing=2,
            visible=False, # Perfil por defecto es 'estandar'
        )

        use_btn = []
        if self.on_use_password:
            use_btn = [
                ft.ElevatedButton(
                    "Usar esta contraseña",
                    icon=ft.Icons.CHECK,
                    bgcolor=ft.Colors.CYAN_700,
                    color=ft.Colors.WHITE,
                    width=260,
                    height=44,
                    style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=12)),
                    on_click=self.use_password,
                ),
            ]

        self.generate_silent()

        # Vista 1: Almacén (Warehouse)
        self.warehouse_column = ft.Column(
            [
                ft.Row([
                    ft.Icon(ft.Icons.HISTORY, color=ft.Colors.CYAN, size=24),
                    ft.Text("Almacén Temporal", size=20, weight=ft.FontWeight.W_700, color=ft.Colors.WHITE),
                ], alignment=ft.MainAxisAlignment.CENTER),
                self.warehouse_counter,
                ft.Text("Contraseñas generadas recientemente (Máx 15 - 24h limit)", size=12, color=ft.Colors.WHITE38, text_align=ft.TextAlign.CENTER),
                ft.Container(height=12),
                ft.Container(
                    content=self.history_list,
                    border=ft.border.all(1, ft.Colors.WHITE10),
                    border_radius=8,
                    padding=8,
                    bgcolor="#1e2a3a",
                    expand=True,
                ),
                ft.Container(height=12),
                ft.ElevatedButton(
                    "Nueva Contraseña",
                    icon=ft.Icons.ADD,
                    bgcolor=ft.Colors.CYAN_700,
                    color=ft.Colors.WHITE,
                    width=240,
                    height=44,
                    style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=12)),
                    on_click=lambda e: self.switch_view("generator"),
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            visible=(self.current_view == "warehouse"),
            expand=True,
        )

        # Vista 2: Generador
        generator_header_row = []
        if self.has_warehouse:
            generator_header_row.append(
                ft.IconButton(
                    icon=ft.Icons.ARROW_BACK,
                    icon_color=ft.Colors.WHITE54,
                    on_click=lambda e: self.switch_view("warehouse"),
                    tooltip="Volver al Almacén"
                )
            )
        generator_header_row.append(
            ft.Text("Generador de Contraseñas", size=20, weight=ft.FontWeight.W_700, color=ft.Colors.WHITE)
        )

        self.generator_column = ft.Column(
            [
                ft.Row(generator_header_row, alignment=ft.MainAxisAlignment.START),
                ft.Container(height=8),
                self.password_display,
                ft.Row(
                    [self.strength_label],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                ),
                self.strength_bar,
                ft.Container(height=4),
                self.password_name_input,
                ft.Container(height=8),
                ft.ElevatedButton(
                    "Generar nueva",
                    icon=ft.Icons.REFRESH,
                    bgcolor="#1e2a3a",
                    color=ft.Colors.CYAN,
                    width=200,
                    style=ft.ButtonStyle(
                        shape=ft.RoundedRectangleBorder(radius=12),
                        side=ft.BorderSide(1, ft.Colors.CYAN_700),
                    ),
                    on_click=lambda e: self.generate(),
                ),
                ft.Container(height=12),
                self.profile_dropdown,
                ft.Container(height=8),
                self.length_label,
                self.length_slider,
                self.options_column,
                ft.Container(height=12),
                *use_btn,
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=6,
            visible=(self.current_view == "generator"),
            scroll=ft.ScrollMode.AUTO,
            expand=True,
        )

        self._mounted = True

        return ft.Container(
            content=ft.Column([self.warehouse_column, self.generator_column], expand=True),
            bgcolor="#0f172a",
            expand=True,
            padding=ft.padding.all(24),
        )

    def on_profile_change(self, e):
        profile_key = e.control.value
        profile = PASSWORD_PROFILES.get(profile_key, PASSWORD_PROFILES["estandar"])
        self.rules = profile.copy()

        # Actualizar controles
        min_l = profile["min_length"]
        max_l = profile["max_length"]

        # Clamp value BEFORE changing slider range to avoid out-of-range
        current_val = int(self.length_slider.value)
        new_val = max(min_l, min(current_val, max_l))

        self.length_slider.min = min_l
        self.length_slider.max = max_l
        self.length_slider.divisions = max(1, max_l - min_l)
        self.length_slider.value = new_val
        self.length_label.value = f"Longitud: {new_val}"

        is_pin = profile.get("pin_only", False)
        is_custom = profile_key == "personalizado"

        self.sw_upper.value = profile["allow_uppercase"]
        self.sw_lower.value = profile["allow_lowercase"]
        self.sw_numbers.value = profile["allow_numbers"]
        self.sw_symbols.value = profile["allow_symbols"]

        # Desactivar switches si no es personalizado
        self.sw_upper.disabled = not is_custom
        self.sw_lower.disabled = not is_custom
        self.sw_numbers.disabled = not is_custom
        self.sw_symbols.disabled = not is_custom
        self.symbols_input.disabled = not (is_custom or profile_key == "estandar")

        self.symbols_input.value = profile.get("allowed_symbols", "")
        self.symbols_input.visible = self.sw_symbols.value and (is_custom or profile_key == "estandar")

        self.options_column.visible = is_custom or profile_key == "estandar"

        self.generate()

    def on_switch_change(self):
        self.symbols_input.visible = self.sw_symbols.value and (self.profile_dropdown.value == "estandar" or self.profile_dropdown.value == "personalizado")
        self.generate()

    def on_length_change(self, e):
        self.length_label.value = f"Longitud: {int(e.control.value)}"
        self.generate()

    def generate_silent(self):
        """Genera una contraseña y actualiza los widgets, SIN llamar page.update()."""
        length = int(self.length_slider.value) if hasattr(self, 'length_slider') else 16
        pin_only = self.rules.get("pin_only", False)

        try:
            self.generated_password = generate_password(
                length=length,
                allow_uppercase=self.sw_upper.value if hasattr(self, 'sw_upper') else True,
                allow_lowercase=self.sw_lower.value if hasattr(self, 'sw_lower') else True,
                allow_numbers=self.sw_numbers.value if hasattr(self, 'sw_numbers') else True,
                allow_symbols=self.sw_symbols.value if hasattr(self, 'sw_symbols') else True,
                allowed_symbols=self.symbols_input.value if hasattr(self, 'symbols_input') else self.rules.get("allowed_symbols", ""),
                pin_only=pin_only,
            )
        except Exception:
            self.generated_password = "Error al generar"

        if hasattr(self, 'password_display'):
            self.password_display.value = self.generated_password
            score, label = password_strength(self.generated_password)
            color = strength_color(score)
            self.strength_bar.value = score / 100
            self.strength_bar.color = color
            self.strength_label.value = f"Fortaleza: {label} ({score}%)"
            self.strength_label.color = color

    def generate(self):
        """Genera una contraseña y actualiza la UI."""
        self.generate_silent()
        
        if self._mounted:
            try:
                self.page.update()
            except Exception:
                pass  # Control aún no montado

    def save_current_to_history(self, e):
        """Guarda la contraseña actual en el historial de forma manual."""
        if not self.on_use_password and self.db and self.auth and self.generated_password:
            from security.crypto import encrypt
            try:
                name = self.password_name_input.value.strip() or "Sin nombre"
                enc_pw = encrypt(self.generated_password, self.auth.key)
                self.db.add_temp_password(enc_pw, name)
                self.db.cleanup_temp_passwords()
                
                # Clear name input for next time
                self.password_name_input.value = ""
                
                # Feedback de guardado
                original_icon = e.control.icon
                original_color = e.control.icon_color
                
                e.control.icon = ft.Icons.CHECK
                e.control.icon_color = ft.Colors.GREEN
                e.control.tooltip = "Guardado"
                e.control.update()
                
                async def restore_btn():
                    import asyncio
                    await asyncio.sleep(0.5)
                    self.switch_view("warehouse")
                    e.control.icon = original_icon
                    e.control.icon_color = original_color
                    e.control.tooltip = "Guardar en historial y volver"
                    e.control.update()
                    
                self.page.run_task(restore_btn)
            except Exception as ex:
                print(f"Error saving temp password: {ex}")

    def show_and_copy_password(self, e):
        if not self.generated_password:
            return
            
        self.page.run_task(self.page.clipboard.set, self.generated_password)
        
        original_icon = e.control.icon
        original_color = e.control.icon_color
        
        e.control.icon = ft.Icons.CHECK
        e.control.icon_color = ft.Colors.GREEN
        e.control.update()
        
        async def restore_btn():
            import asyncio
            await asyncio.sleep(2)
            e.control.icon = original_icon
            e.control.icon_color = original_color
            e.control.update()
            
        self.page.run_task(restore_btn)

    def use_password(self, e):
        if self.on_use_password and self.generated_password:
            self.on_use_password(self.generated_password, self.get_current_rules())

    def get_current_rules(self) -> dict:
        return {
            "min_length": int(self.length_slider.min),
            "max_length": int(self.length_slider.max),
            "allow_uppercase": self.sw_upper.value,
            "allow_lowercase": self.sw_lower.value,
            "allow_numbers": self.sw_numbers.value,
            "allow_symbols": self.sw_symbols.value,
            "allowed_symbols": self.symbols_input.value,
            "pin_only": self.rules.get("pin_only", False),
        }

    # ------------------------------------------------------------------ #
    #  Historial Temporal
    # ------------------------------------------------------------------ #
    def load_history(self):
        if not self.db or not self.auth:
            return
            
        from security.crypto import decrypt
        from datetime import datetime
        
        temps = self.db.get_temp_passwords()
        self.history_list.controls.clear()
        
        # Update counter
        count = len(temps)
        if hasattr(self, 'warehouse_counter'):
            self.warehouse_counter.value = f"{count} contraseña{'s' if count != 1 else ''}"
        
        now = datetime.now()
        
        for idx, row in enumerate(temps):
            try:
                raw_pw = decrypt(row["password"], self.auth.key)
                score, label = password_strength(raw_pw)
                color = strength_color(score)
                
                # Calculate time remaining
                created_at = datetime.fromisoformat(row["created_at"])
                elapsed = now - created_at
                remaining = 24 * 3600 - elapsed.total_seconds()
                
                if remaining > 0:
                    hours = int(remaining // 3600)
                    mins = int((remaining % 3600) // 60)
                    time_str = f"Quedan {hours}h {mins}m"
                else:
                    time_str = "Expirado"
                
                # Ocultar parcialmente por seguridad en la UI
                masked = raw_pw[:4] + "*" * (len(raw_pw)-4) if len(raw_pw) > 4 else "***"
                name = row.get("name", "Sin nombre")
                
                item = ft.ListTile(
                    title=ft.Text(name, color=ft.Colors.WHITE, size=15, weight=ft.FontWeight.W_600),
                    subtitle=ft.Column([
                        ft.Text(masked, color=ft.Colors.WHITE, size=13),
                        ft.Text(f"{label} • {score}%", color=color, size=11),
                    ], spacing=2),
                    trailing=ft.Column([
                        ft.Row([
                            ft.IconButton(
                                icon=ft.Icons.COPY,
                                icon_color=ft.Colors.CYAN,
                                 tooltip="Mostrar y copiar",
                                 on_click=lambda e, pw=raw_pw: self._show_and_copy_history(pw, e.control)
                            ),
                            ft.IconButton(
                                icon=ft.Icons.DELETE,
                                icon_color=ft.Colors.RED_400,
                                tooltip="Eliminar contraseña",
                                on_click=lambda e, tid=row["id"]: self._delete_history(tid)
                            )
                        ], tight=True, alignment=ft.MainAxisAlignment.END),
                        ft.Text(time_str, color=ft.Colors.WHITE38, size=11, weight=ft.FontWeight.W_500, text_align=ft.TextAlign.RIGHT)
                    ], tight=True, alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.END),
                    bgcolor="#16213e" if idx % 2 == 0 else "#1a1a2e"
                )
                self.history_list.controls.append(item)
            except Exception:
                continue

    def delete_history(self, temp_id: int):
        if not self.db:
            return
        self.db.delete_temp_password(temp_id)
        self.load_history()
        self.page.update()
                
    def show_and_copy_history(self, text, icon_btn):
        if not text:
            return
        
        self.page.run_task(self.page.clipboard.set, text)
        
        original_icon = icon_btn.icon
        original_color = icon_btn.icon_color
        
        icon_btn.icon = ft.Icons.CHECK
        icon_btn.icon_color = ft.Colors.GREEN
        icon_btn.update()
        
        async def restore():
            import asyncio
            await asyncio.sleep(2)
            icon_btn.icon = original_icon
            icon_btn.icon_color = original_color
            icon_btn.update()
            
        self.page.run_task(restore)

