"""
sync_client_view.py - Vista de Cliente (Móvil) para sincronización local.
Implementa el flujo de Handshake de 2 Pasos con Auto-Descubrimiento.
"""

import flet as ft
from utils.sync_service import BridgeClient, SessionEncryptor
import hashlib
import json
import base64
import time
import asyncio
import threading
import queue
import urllib.error
from icecream import ic

class SyncClientView:
    def __init__(self, page: ft.Page, db_manager, auth_manager, bridge_client, on_back: callable):
        self.page = page
        self.db = db_manager
        self.auth = auth_manager
        self.bridge = bridge_client
        self.on_back = on_back
        
        # Estado del descubrimiento
        self.discovered_server = None # (ip, port)
        
        # Componentes UI
        self.status_icon = ft.Icon(ft.Icons.SEARCH, color=ft.Colors.CYAN, size=50)
        self.status_title = ft.Text("Buscando PC...", size=22, weight=ft.FontWeight.BOLD)
        self.status_desc = ft.Text(
            "Asegúrate de que el 'Puente KeyVault' esté activo en tu PC y ambos estén en la misma red.",
            size=14, color=ft.Colors.WHITE38, text_align=ft.TextAlign.CENTER
        )
        
        # Paso 1: PIN Numérico
        self.pin_input = ft.TextField(
            label="PIN del PC (6 dígitos)",
            hint_text="000000",
            text_align=ft.TextAlign.CENTER,
            width=250,
            keyboard_type=ft.KeyboardType.NUMBER,
            password=True,
            can_reveal_password=True,
            visible=False,
            on_submit=lambda _: self.proceed_to_step2()
        )
        
        # Paso 2: Clave Alfanumérica
        self.alpha_input = ft.TextField(
            label="Clave de Seguridad (PC)",
            hint_text="ABC1234",
            text_align=ft.TextAlign.CENTER,
            width=250,
            keyboard_type=ft.KeyboardType.TEXT,
            visible=False,
            on_submit=lambda _: self.finalize_sync()
        )
        
        self.action_btn = ft.ElevatedButton(
            "Continuar",
            icon=ft.Icons.ARROW_FORWARD,
            bgcolor=ft.Colors.CYAN_700,
            color=ft.Colors.WHITE,
            visible=False,
            on_click=self.handle_action
        )
        
        self.loading_ring = ft.ProgressRing(visible=True, width=30, height=30)
        self.retry_btn = ft.TextButton("Reintentar búsqueda", icon=ft.Icons.REFRESH, visible=False, on_click=self.start_discovery)
        
        # Listener de Zeroconf
        self.stop_discovery_event = threading.Event()

    def build(self):
        # Iniciar descubrimiento al entrar
        self.page.run_task(self.start_discovery)
        
        return ft.Container(
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.IconButton(ft.Icons.ARROW_BACK, on_click=self.handle_back),
                            ft.Text("Vincular con PC", size=20, weight=ft.FontWeight.BOLD),
                        ],
                    ),
                    ft.Divider(height=20, color=ft.Colors.WHITE10),
                    
                    ft.Container(height=20),
                    self.status_icon,
                    self.status_title,
                    self.status_desc,
                    
                    ft.Container(height=30),
                    self.loading_ring,
                    self.pin_input,
                    self.alpha_input,
                    
                    ft.Container(height=20),
                    self.action_btn,
                    self.retry_btn,
                    
                    ft.Container(expand=True),
                    ft.Text(
                        "Sincronización Local E2EE (Cifrado de extremo a extremo)",
                        size=12, color=ft.Colors.WHITE24, italic=True
                    ),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            padding=20,
            expand=True,
            bgcolor="#0f172a",
        )

    def handle_back(self, e):
        self.stop_discovery_event.set()
        self.on_back()

    async def start_discovery(self, e=None):
        """Inicia la búsqueda mDNS para localizar el PC."""
        self.discovered_server = None
        self.status_title.value = "Buscando PC..."
        self.status_icon.name = ft.Icons.SEARCH
        self.status_icon.color = ft.Colors.CYAN
        self.loading_ring.visible = True
        self.pin_input.visible = False
        self.alpha_input.visible = False
        self.action_btn.visible = False
        self.retry_btn.visible = False
        self.page.update()

        from zeroconf import Zeroconf, ServiceBrowser
        
        class KVListener:
            def __init__(self, outer):
                self.outer = outer
            def add_service(self, zc, type, name):
                info = zc.get_service_info(type, name)
                if info:
                    ip = socket.inet_ntoa(info.addresses[0])
                    port = info.port
                    self.outer.server_found(ip, port)
            def update_service(self, *args): pass
            def remove_service(self, *args): pass

        import socket
        zeroconf = Zeroconf()
        listener = KVListener(self)
        browser = ServiceBrowser(zeroconf, "_keyvault._tcp.local.", listener)
        
        # Esperar hasta 10 segundos o hasta que se encuentre
        for _ in range(20):
            if self.discovered_server or self.stop_discovery_event.is_set():
                break
            await asyncio.sleep(0.5)
        
        zeroconf.close()
        
        if not self.discovered_server and not self.stop_discovery_event.is_set():
            self.status_title.value = "PC no encontrado"
            self.status_desc.value = "Asegúrate de estar en la misma red o usa el IP manual (Próximamente)."
            self.loading_ring.visible = False
            self.retry_btn.visible = True
            self.page.update()

    def reset_view(self):
        """Restaura la UI al estado inicial del Paso 1."""
        self.status_title.value = "PC Encontrado"
        self.status_desc.value = "Ingresa el PIN de 6 dígitos que aparece en la pantalla de tu PC."
        self.pin_input.visible = True
        self.pin_input.value = ""
        self.alpha_input.visible = False
        self.alpha_input.value = ""
        self.action_btn.text = "Validar PIN"
        self.action_btn.icon = ft.Icons.CHECK
        self.action_btn.on_click = self.handle_action
        self.action_btn.visible = True
        self.loading_ring.visible = False
        self.page.update()

    def server_found(self, ip, port):
        """Callback cuando Zeroconf encuentra el servicio."""
        self.discovered_server = (ip, port)
        self.status_title.value = "¡PC Detectado!"
        self.status_desc.value = f"Servidor encontrado en {ip}. Introduce el PIN de 6 dígitos."
        self.status_icon.name = ft.Icons.TV
        self.status_icon.color = ft.Colors.GREEN
        self.loading_ring.visible = False
        self.pin_input.visible = True
        self.action_btn.visible = True
        self.action_btn.text = "Validar PIN"
        self.page.update()

    def handle_action(self, e):
        if self.pin_input.visible and not self.alpha_input.visible:
            self.proceed_to_step2()
        elif self.alpha_input.visible:
            self.finalize_sync()

    def proceed_to_step2(self):
        """Paso 1: Validar PIN Numérico ante el servidor."""
        pin = self.pin_input.value.strip()
        if len(pin) != 6:
            self.pin_input.error_text = "El PIN debe ser de 6 dígitos"
            self.page.update()
            return
            
        self.loading_ring.visible = True
        self.action_btn.disabled = True
        self.page.update()
        
        try:
            import urllib.request
            import hashlib
            
            ip, port = self.discovered_server
            token_h = hashlib.sha256(pin.encode()).hexdigest()
            url = f"http://{ip}:{port}/auth/step1?token={token_h}"
            
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                if data.get("status") == "need_alpha":
                    # ÉXITO Paso 1
                    self.status_title.value = "Paso 2: Seguridad"
                    self.status_desc.value = "¡Perfecto! Ahora ingresa la clave alfanumérica que acaba de aparecer en tu PC."
                    self.pin_input.visible = False
                    self.alpha_input.visible = True
                    self.action_btn.text = "Finalizar Vinculación"
                    self.action_btn.icon = ft.Icons.CHECK
                else:
                    raise Exception("Respuesta inesperada del servidor")
                    
        except urllib.error.HTTPError as he:
            if he.code in [401, 403]:
                self.show_snackbar("❌ Sesión expirada o PIN rotado. Inicia de nuevo.")
                self.reset_view() # Volver al inicio
            else:
                self.show_snackbar(f"Error del servidor: {he.code}")
        except Exception as ex:
            ic(f"Error Paso 1: {ex}")
            self.show_snackbar("PIN Incorrecto o servidor no responde.")
            
        self.loading_ring.visible = False
        self.action_btn.disabled = False
        self.page.update()

    def finalize_sync(self):
        """Paso 2: Validar Alpha Key, obtener llaves y sincronizar."""
        alpha = self.alpha_input.value.strip()
        pin = self.pin_input.value.strip()
        
        if not alpha:
            self.alpha_input.error_text = "Introduce la clave mostrada en el PC"
            self.page.update()
            return

        self.loading_ring.visible = True
        self.action_btn.disabled = True
        self.page.update()
        
        try:
            import urllib.request
            import hashlib
            from utils.sync_service import SessionEncryptor
            
            ip, port = self.discovered_server
            
            # Paso 2: Obtener credenciales cifradas del PC
            url_v = f"http://{ip}:{port}/auth/step2?alpha={alpha}&device_id={self.db.get_config('device_id') or 'mobile'}"
            with urllib.request.urlopen(url_v, timeout=5) as resp:
                data_v = json.loads(resp.read().decode())
                encrypted_creds = data_v["data"]
                
                # Derivar llave de transporte temporal para descifrar el paquete de sesión
                transport_seed = (pin + alpha).encode()
                transport_key = hashlib.sha256(transport_seed).digest()
                transport_enc = SessionEncryptor(transport_key)
                
                creds_json = transport_enc.decrypt(encrypted_creds)
                if not creds_json:
                    raise Exception("Fallo al descifrar llaves de sesión")
                
                creds = json.loads(creds_json)
                
                # PERSISTENCIA: Guardar servidor y token de confianza
                self.db.set_config("last_sync_ip", ip)
                self.db.set_config("trust_token", creds["trust"])
                
                # ID de dispositivo para el Host
                device_id = self.db.get_config("device_id")
                if not device_id:
                    import uuid
                    device_id = str(uuid.uuid4())[:8]
                    self.db.set_config("device_id", device_id)

                # VINCULAR BRIDGE: Activa polling automático y clipboard listener
                success = self.bridge.connect(
                    ip, port, token=creds["t"], encryption_key=creds["k"], 
                    trust_token=creds["trust"],
                    device_id=device_id,
                    on_vault=self.import_vault_data,
                    on_clipboard=lambda msg: self.page.set_clipboard(msg)
                )
                
                if success:
                    self.status_title.value = "🎯 ¡Vinculado correctamente!"
                    self.status_desc.value = f"Tu dispositivo ahora está sincronizado con {ip} en tiempo real."
                    self.pin_input.visible = False
                    self.alpha_input.visible = False
                    self.action_btn.text = "Volver al Inicio"
                    self.action_btn.icon = ft.Icons.HOME
                    self.action_btn.on_click = lambda _: self.on_back()
                    self.show_snackbar("✨ Conexión Establecida")
                else:
                    self.show_snackbar("⚠️ Handshake OK, pero falló la conexión persistente.")

        except urllib.error.HTTPError as he:
            if he.code in [401, 403]:
                self.show_snackbar("❌ Clave de seguridad no autorizada o caducada.")
                self.reset_view() # Resetear flujo
            else:
                self.show_snackbar(f"Error: {he.code}")
        except Exception as ex:
            ic(f"Error Paso 2: {ex}")
            self.show_snackbar(f"Error de vinculación: {ex}")
            
        self.loading_ring.visible = False
        self.action_btn.disabled = False
        self.page.update()

    def import_vault_data(self, vault_data):
        """Procesa e importa la bóveda recibida (JSON o Binario .vk)."""
        if not vault_data:
            self.show_snackbar("❌ Datos de bóveda vacíos o corruptos.")
            return

        try:
            # Intentar decodificar Base64 si viene del simulador (que envía b64 de JSON)
            try:
                # El decrypt entrega un string. Si ese string es Base64, lo decodificamos.
                # Nota: El test_server envía base64(json).
                decoded_content = base64.b64decode(vault_data).decode("utf-8")
                data_list = json.loads(decoded_content)
                if isinstance(data_list, list):
                    import_count = self.db.import_from_list(data_list, self.auth.key)
                    self.show_snackbar(f"✅ Sincronización exitosa: {import_count} ítems.")
                    return
            except:
                pass
            
            # Intentar como JSON directo
            try:
                data_list = json.loads(vault_data)
                if isinstance(data_list, list):
                    import_count = self.db.import_from_list(data_list, self.auth.key)
                    self.show_snackbar(f"✅ Sincronización exitosa: {import_count} ítems.")
                    return
            except:
                pass

            # Si llegamos aquí, probablemente sea un binario .vk (Host de Windows real)
            from utils.backup import get_backup_metadata_from_bytes, import_passwords
            
            # Intentar ver si es un paquete .vk válido
            if isinstance(vault_data, str):
                vault_data = vault_data.encode()

            metadata = get_backup_metadata_from_bytes(vault_data)
            if metadata:
                # Si es un backup real, necesitamos la respuesta de seguridad.
                # Por simplicidad operativa en P2P, podrías considerar que el Host envíe el JSON ya descifrado,
                # pero por ahora informamos que se requiere integración.
                self.show_snackbar("📦 Recibida Bóveda Binaria (.vk). Se requiere respuesta de seguridad.")
                # Aquí podrías abrir un diálogo pidiendo la respuesta de la pregunta: metadata['question_text']
            else:
                self.show_snackbar("❌ Formato de sincronización no reconocido.")
                
        except Exception as e:
            ic(f"Error importing vault: {e}")
            self.show_snackbar("❌ Fallo crítico al procesar la bóveda.")

    def show_snackbar(self, msg: str):
        self.page.snack_bar = ft.SnackBar(ft.Text(msg))
        self.page.snack_bar.open = True
        self.page.update()
