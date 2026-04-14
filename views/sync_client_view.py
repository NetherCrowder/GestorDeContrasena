"""
sync_client_view.py - Vista de Cliente (Móvil) para sincronización P2P.
Implementa el flujo de vinculación en 2 Pasos (PIN + Alpha) compatible
con el nuevo servidor BridgeServer de Windows (multi-sesión).
"""

import flet as ft
from utils.sync_service import BridgeClient, SessionEncryptor
import hashlib
import json
import base64
import urllib.request
import urllib.error
import urllib.parse
import threading
from icecream import ic

# Intentar importar zeroconf para autodescubrimiento
try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
    ZEROCONF_AVAILABLE = True
except ImportError:
    ZEROCONF_AVAILABLE = False
    ic("Zeroconf no instalado. El auto-descubrimiento de red estará desactivado.")

class KVListener(ServiceListener if ZEROCONF_AVAILABLE else object):
    def __init__(self, on_found):
        self.on_found = on_found
        
    def add_service(self, zc, type_, name):
        try:
            info = zc.get_service_info(type_, name)
            if info and info.addresses:
                # addresses[0] es la IP en formato bytes, hay que parsearla
                import socket
                ip = socket.inet_ntoa(info.addresses[0])
                self.on_found(ip)
        except Exception as e:
            ic(f"Error procesando servicio {name}: {e}")
            
    def update_service(self, zc, type_, name): pass
    def remove_service(self, zc, type_, name): pass

class SyncClientView:
    def __init__(self, page: ft.Page, db_manager, auth_manager,
                 bridge_client: BridgeClient, on_back: callable):
        self.page = page
        self.db = db_manager
        self.auth = auth_manager
        self.client = bridge_client
        self.on_back = on_back

        # Estado del flujo
        self._step = 1          # 1 = esperando PIN, 2 = esperando Alpha
        self._pin_value = ""    # Guardado del Paso 1 para derivar la llave de transporte
        self._zeroconf = None
        self._browser = None
        self._discovered_ips = set()

        # ------------------------------------------------------------------ #
        # Componentes de UI — Paso 0: Dirección del servidor
        # ------------------------------------------------------------------ #
        saved_ip = self.db.get_config("last_sync_ip") or ""
        self.ip_input = ft.TextField(
            label="IP del PC",
            hint_text="192.168.1.XX",
            value=saved_ip,
            width=260,
            prefix_icon=ft.Icons.COMPUTER,
            keyboard_type=ft.KeyboardType.TEXT,
            visible=False, # Oculto por defecto hasta seleccionar servidor o forzar manual
        )
        
        self.server_list_ui = ft.Column([], spacing=5)
        self.discovery_indicator = ft.Row([
            ft.ProgressRing(width=16, height=16, stroke_width=2),
            ft.Text("Buscando servidores en la red...", size=12, color=ft.Colors.WHITE54)
        ], visible=False)

        # ------------------------------------------------------------------ #
        # Paso 1 — PIN Numérico
        # ------------------------------------------------------------------ #
        self.pin_input = ft.TextField(
            label="PIN del PC (6 dígitos)",
            hint_text="000000",
            text_align=ft.TextAlign.CENTER,
            width=260,
            keyboard_type=ft.KeyboardType.NUMBER,
            password=True,
            can_reveal_password=True,
            on_submit=lambda _: self._handle_action(None),
            max_length=6,
            visible=False, # Oculto en la pantalla de escaneo inicial
        )

        # ------------------------------------------------------------------ #
        # Paso 2 — Clave Alfanumérica
        # ------------------------------------------------------------------ #
        self.alpha_input = ft.TextField(
            label="Clave Alfanumérica del PC",
            hint_text="ABC1234",
            text_align=ft.TextAlign.CENTER,
            width=260,
            keyboard_type=ft.KeyboardType.TEXT,
            visible=False,
            on_submit=lambda _: self._handle_action(None),
            max_length=7,
        )

        # ------------------------------------------------------------------ #
        # Indicadores de estado
        # ------------------------------------------------------------------ #
        self.status_icon = ft.Icon(ft.Icons.PHONELINK_SETUP, size=54, color=ft.Colors.CYAN_300)
        self.status_title = ft.Text(
            "Vincular con PC", size=22, weight=ft.FontWeight.BOLD
        )
        self.status_desc = ft.Text(
            "Buscando tu PC local...",
            size=13, color=ft.Colors.WHITE54, text_align=ft.TextAlign.CENTER,
        )

        self.loading_ring = ft.ProgressRing(visible=False, width=24, height=24, stroke_width=2)
        self.error_banner = ft.Text("", size=13, color=ft.Colors.RED_400, visible=False)

        # ------------------------------------------------------------------ #
        # Botones de acción
        # ------------------------------------------------------------------ #
        self.action_btn = ft.ElevatedButton(
            "Validar PIN",
            icon=ft.Icons.ARROW_FORWARD,
            bgcolor=ft.Colors.CYAN_700,
            color=ft.Colors.WHITE,
            width=220,
            on_click=self._handle_action,
            visible=False,
        )

        self.manual_ip_btn = ft.TextButton(
            "Introducir IP manualmente",
            icon=ft.Icons.ADD_LINK,
            on_click=self._show_manual_ip,
        )

        self.upload_btn = ft.ElevatedButton(
            "📤 Enviar al PC",
            icon=ft.Icons.UPLOAD,
            bgcolor=ft.Colors.TEAL_700,
            color=ft.Colors.WHITE,
            width=220,
            visible=False,
            on_click=self._push_to_server,
        )

        self.disconnect_btn = ft.TextButton(
            "Desconectar",
            icon=ft.Icons.LINK_OFF,
            style=ft.ButtonStyle(color=ft.Colors.RED_400),
            visible=False,
            on_click=self._disconnect,
        )

        self.back_btn = ft.TextButton(
            "Volver al menú",
            icon=ft.Icons.HOME,
            visible=False,
            on_click=self._navigate_back,
        )

        # Si ya hay una sesión activa, mostramos el estado conectado
        if self.client.connected:
            self._show_connected_state()
        else:
            self._start_discovery()

    # ------------------------------------------------------------------ #
    # Construcción de la vista
    # ------------------------------------------------------------------ #
    def build(self) -> ft.Container:
        return ft.Container(
            content=ft.Column(
                [
                    # AppBar simple
                    ft.Row([
                        ft.IconButton(ft.Icons.ARROW_BACK, on_click=self._navigate_back),
                        ft.Text("Sincronización P2P", size=20, weight=ft.FontWeight.BOLD),
                    ]),
                    ft.Divider(height=1, color=ft.Colors.WHITE10),

                    ft.Container(height=16),

                    # Icono y título
                    self.status_icon,
                    ft.Container(height=8),
                    self.status_title,
                    ft.Container(height=6),
                    self.status_desc,

                    ft.Container(height=24),

                    # Campos de entrada
                    self.ip_input,
                    self.discovery_indicator,
                    self.server_list_ui,
                    
                    ft.Container(height=8),
                    self.pin_input,
                    self.alpha_input,

                    ft.Container(height=4),
                    self.error_banner,

                    ft.Container(height=16),

                    # Indicador de carga
                    ft.Row([self.loading_ring], alignment=ft.MainAxisAlignment.CENTER),

                    # Botones
                    self.action_btn,
                    self.manual_ip_btn,
                    ft.Container(height=8),
                    self.upload_btn,
                    ft.Container(height=4),
                    self.disconnect_btn,
                    self.back_btn,

                    ft.Container(expand=True),

                    ft.Text(
                        "🔒 Cifrado de extremo a extremo (E2EE) · AES-256-CTR + HMAC-SHA256",
                        size=11, color=ft.Colors.WHITE24, italic=True,
                        text_align=ft.TextAlign.CENTER,
                    ),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                scroll=ft.ScrollMode.AUTO,
            ),
            padding=ft.padding.symmetric(horizontal=24, vertical=16),
            expand=True,
            bgcolor="#0f172a",
        )

    # ------------------------------------------------------------------ #
    # Lógica del flujo de 2 Pasos
    # ------------------------------------------------------------------ #
    def _handle_action(self, e):
        """Despacha al paso correcto según el estado actual."""
        if self._step == 1:
            self._do_step1()
        elif self._step == 2:
            self._do_step2()

    def _do_step1(self):
        """Paso 1: Verificar el PIN numérico ante el servidor."""
        ip = self.ip_input.value.strip()
        pin = self.pin_input.value.strip()

        # Validaciones
        if not ip:
            self._show_error("Introduce la IP del PC.")
            return
        if len(pin) != 6 or not pin.isdigit():
            self._show_error("El PIN debe ser de exactamente 6 dígitos.")
            return

        self._set_loading(True)

        def worker():
            try:
                pin_hash = hashlib.sha256(pin.encode()).hexdigest()
                url = f"http://{ip}:5005/auth/step1?pin_hash={pin_hash}"
                with urllib.request.urlopen(url, timeout=5) as resp:
                    data = json.loads(resp.read().decode())

                if data.get("status") == "need_alpha":
                    self._pin_value = pin
                    self._step = 2
                    self._show_step2_ui()
                else:
                    self._show_error("Respuesta inesperada del servidor.")

            except urllib.error.HTTPError as he:
                if he.code in (401, 403):
                    msg = "❌ PIN incorrecto o expirado. El PC ha rotado las credenciales."
                else:
                    msg = f"Error del servidor: HTTP {he.code}"
                self._show_error(msg)
            except Exception as ex:
                self._show_error(f"No se pudo conectar: {ex}")
            finally:
                self._set_loading(False)

        threading.Thread(target=worker, daemon=True).start()

    def _do_step2(self):
        """Paso 2: Verificar la Clave Alfa y obtener credenciales de sesión."""
        ip = self.ip_input.value.strip()
        alpha = self.alpha_input.value.strip().upper()
        pin = self._pin_value

        if not alpha:
            self._show_error("Introduce la clave alfanumérica que aparece en el PC.")
            return

        # Obtener/generar device_id persistente
        device_id = self.db.get_config("device_id")
        if not device_id:
            import uuid
            device_id = f"mobile-{uuid.uuid4().hex[:8]}"
            self.db.set_config("device_id", device_id)

        # Nombre del dispositivo (puede mejorar leyendo el modelo real en Android)
        device_name = self.db.get_config("device_name") or "Móvil KeyVault"

        self._set_loading(True)

        def worker():
            try:
                url = (
                    f"http://{ip}:5005/auth/step2"
                    f"?alpha={urllib.parse.quote(alpha)}"
                    f"&device_id={urllib.parse.quote(device_id)}"
                    f"&device_name={urllib.parse.quote(device_name)}"
                )
                with urllib.request.urlopen(url, timeout=8) as resp:
                    data = json.loads(resp.read().decode())

                encrypted_creds = data.get("data", "")

                # Derivar llave de transporte temporal: SHA256(pin + alpha)
                transport_key = hashlib.sha256((pin + alpha).encode()).digest()
                transport_enc = SessionEncryptor(transport_key)
                creds_json = transport_enc.decrypt(encrypted_creds)
                if not creds_json:
                    raise ValueError("Fallo al descifrar las credenciales de sesión.")

                creds = json.loads(creds_json)
                token      = creds["t"]
                key_b64    = creds["k"]
                trust_token = creds.get("trust", "")

                # Guardar configuración persistente
                self.db.set_config("last_sync_ip", ip)
                self.db.set_config("trust_token", trust_token)

                def _safe_clipboard(txt):
                    from utils.clipboard_helper import copy_to_clipboard
                    try:
                        copy_to_clipboard(self.page, txt)
                        self.page.snack_bar = ft.SnackBar(ft.Text("📋 ¡Portapapeles del PC recibido!"), bgcolor=ft.Colors.GREEN_400)
                        self.page.snack_bar.open = True
                        self.page.update()
                    except: pass
                        
                # Conectar el BridgeClient
                success = self.client.connect(
                    ip=ip, port=5005,
                    token=token,
                    encryption_key=key_b64,
                    trust_token=trust_token,
                    device_id=device_id,
                    on_vault=self._on_vault_received,
                    on_clipboard=_safe_clipboard,
                )

                if success:
                    self.client.save_pairing()
                    self._show_connected_state()
                else:
                    self._show_error("Handshake OK, pero falló la conexión persistente. Intenta de nuevo.")

            except urllib.error.HTTPError as he:
                if he.code in (401, 403):
                    msg = "❌ Clave incorrecta o sesión expirada. Vuelve a introducir el PIN."
                    self._reset_to_step1(msg)
                else:
                    self._show_error(f"Error del servidor: HTTP {he.code}")
            except Exception as ex:
                ic(f"Error Paso 2: {ex}")
                self._show_error(f"Error de vinculación: {ex}")
            finally:
                self._set_loading(False)

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------ #
    # Callbacks de sincronización
    # ------------------------------------------------------------------ #
    def _on_vault_received(self, vault_str: str):
        """Procesa la bóveda recibida del PC usando import_from_list."""
        try:
            data_list = json.loads(vault_str)
            if not isinstance(data_list, list):
                ic("Bóveda recibida no es una lista válida.")
                return
            inserted, updated, skipped = self.db.import_from_list(data_list, self.auth.key)
            self.db._increment_version()

            if inserted > 0 or updated > 0:
                msg = f"📦 Sincronizado: {inserted} nuevas, {updated} actualizadas."
            else:
                msg = "✅ Bóveda ya estaba al día (sin cambios nuevos)."

            # Notificar UI si el sistema global tiene callback de refresco
            if hasattr(self.client, "on_vault_sync") and self.client.on_vault_sync:
                self.client.on_vault_sync(inserted, updated)

            self._show_snackbar(msg)
        except json.JSONDecodeError:
            ic("Error al parsear JSON de la bóveda recibida.")
        except Exception as ex:
            ic(f"Error importando bóveda: {ex}")
            self._show_snackbar(f"⚠️ Error al importar: {ex}")

    def _on_clipboard_received(self, text: str):
        """Maneja el texto recibido del portapapeles del PC."""
        from utils.clipboard_helper import copy_to_clipboard
        try:
            copy_to_clipboard(self.page, text)
            self._show_snackbar("📋 Portapapeles actualizado desde el PC.")
        except Exception as ex:
            ic(f"Error seteando clipboard: {ex}")

    def _push_to_server(self, e):
        """Descifra la bóveda local y la envía al PC."""
        if not self.client.connected:
            self._show_snackbar("⚠️ No hay conexión activa con el PC.")
            return

        self._set_loading(True, label="Enviando bóveda al PC...")

        def worker():
            try:
                from security.crypto import decrypt as decrypt_field
                passwords = self.db.get_all_passwords()

                data_list = []
                for pw in passwords:
                    try:
                        data_list.append({
                            "sync_id":     pw.get("sync_id", ""),
                            "title":       pw.get("title", ""),
                            "username":    decrypt_field(pw["username"], self.auth.key) if pw.get("username") else "",
                            "password":    decrypt_field(pw["password"], self.auth.key) if pw.get("password") else "",
                            "url":         pw.get("url", ""),
                            "notes":       decrypt_field(pw["notes"], self.auth.key) if pw.get("notes") else "",
                            "category_id": pw.get("category_id", 8),
                            "is_favorite": pw.get("is_favorite", 0),
                            "created_at":  pw.get("created_at", ""),
                            "updated_at":  pw.get("updated_at", ""),
                        })
                    except Exception:
                        continue

                ok = self.client.push_to_server_raw(data_list)
                msg = "✅ Bóveda enviada al PC correctamente." if ok else "❌ Fallo al enviar la bóveda al PC."
                self._show_snackbar(msg)
            except Exception as ex:
                ic(f"Error en push_to_server: {ex}")
                self._show_snackbar(f"❌ Error: {ex}")
            finally:
                self._set_loading(False)

        threading.Thread(target=worker, daemon=True).start()

    def _disconnect(self, e):
        """Cierra la sesión y limpia el pairing guardado."""
        self.client.stop_listener()
        self.client.clear_pairing()
        self.db.set_config("trust_token", "")
        self._reset_to_step1("Desconectado del PC.")

    # ------------------------------------------------------------------ #
    # Utilidades de UI
    # ------------------------------------------------------------------ #
    def _show_manual_ip(self, e):
        """Muestra los inputs directamente sin esperar al escaner."""
        self._stop_discovery()
        self.discovery_indicator.visible = False
        self.server_list_ui.visible = False
        self.manual_ip_btn.visible = False
        self.ip_input.visible = True
        self.pin_input.visible = True
        self.action_btn.visible = True
        
        self.status_icon.name = ft.Icons.KEYBOARD
        self.status_title.value = "Conexión Manual"
        self.status_desc.value = "Introduce la IP de tu PC y el PIN de 6 dígitos."
        self.page.update()

    def _show_step2_ui(self):
        """Transiciona la UI al Paso 2 (Alpha)."""
        self.status_icon.name = ft.Icons.LOCK_OPEN
        self.status_icon.color = ft.Colors.AMBER_400
        self.status_title.value = "Paso 2 — Clave de Seguridad"
        self.status_desc.value = (
            "¡PIN correcto! Ahora introduce la Clave Alfanumérica de 7 caracteres "
            "que acaba de aparecer en la pantalla de tu PC."
        )
        self.ip_input.visible = False
        self.discovery_indicator.visible = False
        self.server_list_ui.visible = False
        self.pin_input.visible = False
        self.alpha_input.visible = True
        self.action_btn.text = "Finalizar Vinculación"
        self.action_btn.icon = ft.Icons.VERIFIED
        self._hide_error()
        self.page.update()
        
        async def do_focus():
            try:
                if hasattr(self.alpha_input, 'focus_async'):
                    await self.alpha_input.focus_async()
                else:
                    await self.alpha_input.focus()
            except Exception: pass
        try:
            self.page.run_task(do_focus)
        except Exception: pass

    def _show_connected_state(self):
        """Actualiza la UI al estado 'Conectado correctamente'."""
        ip = self.db.get_config("last_sync_ip") or self.ip_input.value.strip()

        self.status_icon.name = ft.Icons.PHONELINK_LOCK
        self.status_icon.color = ft.Colors.GREEN_400
        self.status_title.value = "🎯 Vinculado correctamente"
        self.status_desc.value = (
            f"Conectado con {ip}. La sincronización automática está activa "
            f"y el PC recibirá tus cambios en tiempo real."
        )
        self.ip_input.visible = False
        self.pin_input.visible = False
        self.alpha_input.visible = False
        self.action_btn.visible = False
        self.error_banner.visible = False

        self.upload_btn.visible = True
        self.disconnect_btn.visible = True
        self.back_btn.visible = True
        self._step = 1

        self.page.update()

        # Iniciar loop de sincronización (Grupo 2)
        try:
            self.client.start_auto_sync_loop(self.db, self.auth.key)
            ic("Bucle Auto-sync de 30s iniciado.")
        except Exception as e:
            ic(f"Error iniciando auto-sync: {e}")

    def _reset_to_step1(self, msg: str = ""):
        """Vuelve al estado inicial (Escaneo de red)."""
        self._step = 1
        self._pin_value = ""
        self._discovered_ips.clear()
        self.server_list_ui.controls.clear()
        
        self.status_icon.name = ft.Icons.PHONELINK_SETUP
        self.status_icon.color = ft.Colors.CYAN_300
        self.status_title.value = "Vincular con PC"
        self.status_desc.value = "Buscando tu PC local..."

        self.ip_input.visible = False
        self.discovery_indicator.visible = True
        self.server_list_ui.visible = True
        self.manual_ip_btn.visible = True
        
        self.pin_input.visible = False
        self.pin_input.value = ""
        self.alpha_input.visible = False
        self.alpha_input.value = ""

        self.action_btn.text = "Validar PIN"
        self.action_btn.icon = ft.Icons.ARROW_FORWARD
        self.action_btn.visible = False
        
        self.upload_btn.visible = False
        self.disconnect_btn.visible = False
        self.back_btn.visible = False

        if msg:
            self._show_snackbar(msg)
        self._hide_error()
        self._start_discovery()
        self.page.update()

    # ------------------------------------------------------------------ #
    # Auto-descubrimiento (Zeroconf)
    # ------------------------------------------------------------------ #
    def _start_discovery(self):
        """Inicia el escaneo de servicios mDNS en la red."""
        if not ZEROCONF_AVAILABLE or self._zeroconf is not None:
            return
            
        try:
            self._zeroconf = Zeroconf()
            listener = KVListener(self._on_server_found)
            self._browser = ServiceBrowser(self._zeroconf, "_keyvault._tcp.local.", listener)
            self.discovery_indicator.visible = True
            self.page.update()
            ic("Zeroconf: Escaneo de servidores iniciado.")
        except Exception as e:
            ic(f"Error iniciando Zeroconf: {e}")

    def _stop_discovery(self):
        """Detiene el escaneo para no consumir recursos."""
        if self._zeroconf is not None:
            try:
                self._zeroconf.close()
            except Exception as e:
                ic(f"Error cerrando Zeroconf: {e}")
            self._zeroconf = None
            self._browser = None
            self.discovery_indicator.visible = False
            try:
                self.page.update()
            except Exception:
                pass
            ic("Zeroconf: Escaneo detenido.")

    def _on_server_found(self, ip: str):
        """Callback cuando Zeroconf encuentra un servidor BridgeHost."""
        if ip in self._discovered_ips:
            return
            
        self._discovered_ips.add(ip)
        
        def use_ip(e):
            self._stop_discovery()
            self.ip_input.value = ip
            self.ip_input.visible = True
            self.pin_input.visible = True
            self.action_btn.visible = True
            
            self.discovery_indicator.visible = False
            self.server_list_ui.visible = False
            self.manual_ip_btn.visible = False
            
            self.status_desc.value = f"Destino: {ip}\nIntroduce el PIN numérico de seguridad."
            self.page.update()
            
            # Ejecutar focus como corrutina en Flet
            async def do_focus():
                try: 
                    if hasattr(self.pin_input, 'focus_async'):
                        await self.pin_input.focus_async()
                    else:
                        await self.pin_input.focus()
                except Exception: pass
            
            try:
                self.page.run_task(do_focus)
            except Exception: pass

        btn = ft.ElevatedButton(
            f"📡 Usar PC en {ip}",
            icon=ft.Icons.WIFI,
            bgcolor=ft.Colors.BLUE_GREY_800,
            color=ft.Colors.WHITE,
            width=260,
            on_click=use_ip
        )
        self.server_list_ui.controls.append(btn)
        self.discovery_indicator.visible = False
        self.page.update()
            
    def _navigate_back(self, e=None):
        """Intercepta volver atrás para detener servicios en segundo plano."""
        self._stop_discovery()
        self.on_back()

    def _set_loading(self, value: bool, label: str = ""):
        self.loading_ring.visible = value
        self.action_btn.disabled = value
        self.upload_btn.disabled = value
        self.page.update()

    def _show_error(self, msg: str):
        self.error_banner.value = msg
        self.error_banner.visible = True
        self.page.update()

    def _hide_error(self):
        self.error_banner.visible = False
        self.page.update()

    def _show_snackbar(self, msg: str):
        self.page.snack_bar = ft.SnackBar(ft.Text(msg))
        self.page.snack_bar.open = True
        self.page.update()
