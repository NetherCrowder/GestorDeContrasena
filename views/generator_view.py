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
        self.history_list = ft.ListView(spacing=8, height=200, scale=1.0)
        
        # Modo independiente: limpiar viejas y cargar historial
        if not self.on_use_password and self.db and self.auth:
            self.db.cleanup_temp_passwords()
            self._load_history()

    def build(self) -> ft.Container:
        # Campo de contraseña generada
        suffix_btn = None
        if not self.on_use_password:
            suffix_btn = ft.IconButton(
                icon=ft.Icons.SAVE,
                icon_color=ft.Colors.CYAN,
                icon_size=20,
                tooltip="Guardar en historial",
                on_click=self._save_current_to_history,
            )
        else:
            suffix_btn = ft.IconButton(
                icon=ft.Icons.COPY,
                icon_color=ft.Colors.CYAN,
                icon_size=20,
                tooltip="Copiar",
                on_click=self._copy_password,
            )

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

        # Barra de fortaleza
        self.strength_bar = ft.ProgressBar(
            value=0, color="#4CAF50", bgcolor="#2a2a3e",
            bar_height=6, border_radius=3,
        )
        self.strength_label = ft.Text("", size=12, color=ft.Colors.WHITE54)

        # Selector de perfil
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
            on_select=self._on_profile_change,
            content_padding=ft.padding.symmetric(horizontal=16, vertical=8),
        )

        # Slider de longitud
        min_l = self.rules.get("min_length", 8)
        max_l = self.rules.get("max_length", 32)
        default_l = max(min_l, min(16, max_l))
        self.length_label = ft.Text(f"Longitud: {default_l}", size=13, color=ft.Colors.WHITE70)
        self.length_slider = ft.Slider(
            min=min_l, max=max_l, value=default_l,
            divisions=max(1, max_l - min_l),
            active_color=ft.Colors.CYAN, inactive_color=ft.Colors.WHITE24,
            on_change=self._on_length_change,
        )

        # Switches de opciones
        self.sw_upper = ft.Switch(
            label="Mayúsculas (A-Z)", value=self.rules.get("allow_uppercase", True),
            active_color=ft.Colors.CYAN, label_text_style=ft.TextStyle(color=ft.Colors.WHITE70, size=13),
            on_change=lambda e: self._generate(),
        )
        self.sw_lower = ft.Switch(
            label="Minúsculas (a-z)", value=self.rules.get("allow_lowercase", True),
            active_color=ft.Colors.CYAN, label_text_style=ft.TextStyle(color=ft.Colors.WHITE70, size=13),
            on_change=lambda e: self._generate(),
        )
        self.sw_numbers = ft.Switch(
            label="Números (0-9)", value=self.rules.get("allow_numbers", True),
            active_color=ft.Colors.CYAN, label_text_style=ft.TextStyle(color=ft.Colors.WHITE70, size=13),
            on_change=lambda e: self._generate(),
        )
        self.sw_symbols = ft.Switch(
            label="Símbolos (!@#$...)", value=self.rules.get("allow_symbols", True),
            active_color=ft.Colors.CYAN, label_text_style=ft.TextStyle(color=ft.Colors.WHITE70, size=13),
            on_change=lambda e: self._generate(),
        )

        # Opciones container (para mostrar/ocultar en modo PIN)
        self.options_column = ft.Column(
            [self.sw_upper, self.sw_lower, self.sw_numbers, self.sw_symbols],
            spacing=2,
        )

        # Botón de usar esta contraseña
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
                    on_click=self._use_password,
                ),
            ]

        # Historial de generador independiente
        history_section = []
        if not self.on_use_password:
            history_section = [
                ft.Container(height=24),
                ft.Row([
                    ft.Icon(ft.Icons.HISTORY, color=ft.Colors.WHITE54, size=20),
                    ft.Text("Historial Temporal (Máx 15 - 24h)", size=16, weight=ft.FontWeight.W_600, color=ft.Colors.WHITE),
                ]),
                ft.Container(height=8),
                ft.Container(
                    content=self.history_list,
                    border=ft.border.all(1, ft.Colors.WHITE10),
                    border_radius=8,
                    padding=8,
                    bgcolor="#1e2a3a",
                )
            ]

        # Generar una contraseña inicial (sin page.update)
        self._generate_silent()

        content = ft.Column(
            [
                ft.Text(
                    "Generador de Contraseñas",
                    size=20,
                    weight=ft.FontWeight.W_700,
                    color=ft.Colors.WHITE,
                ),
                ft.Container(height=8),
                self.password_display,
                ft.Row(
                    [self.strength_label],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                ),
                self.strength_bar,
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
                    on_click=lambda e: self._generate(),
                ),
                ft.Container(height=12),
                self.profile_dropdown,
                ft.Container(height=8),
                self.length_label,
                self.length_slider,
                self.options_column,
                ft.Container(height=12),
                *use_btn,
                *history_section,
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=6,
            scroll=ft.ScrollMode.AUTO,
        )

        self._mounted = True

        return ft.Container(
            content=content,
            bgcolor="#0f172a",
            expand=True,
            padding=ft.padding.all(24),
        )

    def _on_profile_change(self, e):
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

        if is_pin:
            self.options_column.visible = False
        else:
            self.options_column.visible = True

        self._generate()

    def _on_length_change(self, e):
        self.length_label.value = f"Longitud: {int(e.control.value)}"
        self._generate()

    def _generate_silent(self):
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
                allowed_symbols=self.rules.get("allowed_symbols", "!@#$%^&*()_+-="),
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

    def _generate(self):
        """Genera una contraseña y actualiza la UI."""
        self._generate_silent()
        
        if self._mounted:
            try:
                self.page.update()
            except Exception:
                pass  # Control aún no montado

    def _save_current_to_history(self, e):
        """Guarda la contraseña actual en el historial de forma manual."""
        if not self.on_use_password and self.db and self.auth and self.generated_password:
            from security.crypto import encrypt
            try:
                enc_pw = encrypt(self.generated_password, self.auth.key)
                self.db.add_temp_password(enc_pw)
                self.db.cleanup_temp_passwords()
                self._load_history()
                
                # Feedback de guardado
                original_icon = e.control.icon
                original_color = e.control.icon_color
                
                e.control.icon = ft.Icons.CHECK
                e.control.icon_color = ft.Colors.GREEN
                e.control.tooltip = "Guardado"
                e.control.update()
                
                async def restore_btn():
                    import asyncio
                    await asyncio.sleep(2)
                    e.control.icon = original_icon
                    e.control.icon_color = original_color
                    e.control.tooltip = "Guardar en historial"
                    e.control.update()
                    
                self.page.run_task(restore_btn)
            except Exception as ex:
                print(f"Error saving temp password: {ex}")

    def _copy_password(self, e):
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

    def _use_password(self, e):
        if self.on_use_password and self.generated_password:
            self.on_use_password(self.generated_password, self._get_current_rules())

    def _get_current_rules(self) -> dict:
        return {
            "min_length": int(self.length_slider.min),
            "max_length": int(self.length_slider.max),
            "allow_uppercase": self.sw_upper.value,
            "allow_lowercase": self.sw_lower.value,
            "allow_numbers": self.sw_numbers.value,
            "allow_symbols": self.sw_symbols.value,
            "allowed_symbols": self.rules.get("allowed_symbols", ""),
            "pin_only": self.rules.get("pin_only", False),
        }

    # ------------------------------------------------------------------ #
    #  Historial Temporal
    # ------------------------------------------------------------------ #
    def _load_history(self):
        if not self.db or not self.auth:
            return
            
        from security.crypto import decrypt
        
        temps = self.db.get_temp_passwords()
        self.history_list.controls.clear()
        
        for idx, row in enumerate(temps):
            try:
                raw_pw = decrypt(row["password"], self.auth.key)
                score, label = password_strength(raw_pw)
                color = strength_color(score)
                
                # Ocultar parcialmente por seguridad en la UI
                masked = raw_pw[:4] + "*" * (len(raw_pw)-4) if len(raw_pw) > 4 else "***"
                
                item = ft.ListTile(
                    title=ft.Text(masked, color=ft.Colors.WHITE, size=15, selectable=True),
                    subtitle=ft.Text(f"{label} • {score}%", color=color, size=12),
                    trailing=ft.IconButton(
                        icon=ft.Icons.COPY,
                        icon_color=ft.Colors.CYAN,
                        tooltip="Copiar al portapapeles",
                        on_click=lambda e, pw=raw_pw: self._copy_history(pw, e.control)
                    ),
                    bgcolor="#16213e" if idx % 2 == 0 else "#1a1a2e"
                )
                self.history_list.controls.append(item)
            except Exception:
                continue
                
    def _copy_history(self, text, icon_btn):
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

