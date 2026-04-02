"""
sync_host_view.py - Vista de Servidor (PC) para sincronización local.
Muestra el QR y el PIN para que el móvil se vincule.
"""

import flet as ft
import base64
import random
from utils.sync_service import BridgeServer
from utils.backup import export_passwords_to_bytes
from icecream import ic

class SyncHostView:
    def __init__(self, page: ft.Page, db_manager, auth_manager, bridge_server, on_back: callable):
        self.page = page
        self.db = db_manager
        self.auth = auth_manager
        self.server = bridge_server
        self.on_back = on_back
        
        self.is_active = self.server.is_running
        
        # Componentes UI
        self.status_text = ft.Text("Puente Desconectado", size=16, color=ft.Colors.WHITE54)
        
        self.pin_text = ft.Text("", size=60, weight=ft.FontWeight.BOLD, color=ft.Colors.CYAN, selectable=True)
        self.pin_area = ft.Column([
            ft.Text("PASO 1: PIN NUMÉRICO", size=14, weight=ft.FontWeight.W_800, color=ft.Colors.WHITE60),
            ft.Text("Ingresa este código en tu dispositivo móvil", size=12, color=ft.Colors.WHITE38),
            self.pin_text,
        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, visible=False)

        self.alpha_text = ft.Text("", size=50, weight=ft.FontWeight.BOLD, color=ft.Colors.AMBER_400, selectable=True)
        self.alpha_area = ft.Column([
            ft.Divider(height=30, color=ft.Colors.WHITE10),
            ft.Text("PASO 2: VERIFICACIÓN DE SEGURIDAD", size=14, weight=ft.FontWeight.W_800, color=ft.Colors.AMBER_700),
            ft.Text("¡Dispositivo detectado! Confirma con esta clave:", size=12, color=ft.Colors.WHITE38),
            self.alpha_text,
        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, visible=False)
        
        self.ip_text = ft.Text("", size=14, color=ft.Colors.WHITE38)
        self.clients_list = ft.Column(spacing=5)
        
        self.start_btn = ft.ElevatedButton(
            "Iniciar Puente Seguro",
            icon=ft.Icons.ROUTER,
            bgcolor=ft.Colors.CYAN_700,
            color=ft.Colors.WHITE,
            on_click=self.toggle_bridge
        )
        self.refresh_loop_running = False

    def build(self):
        # Si el servidor ya está activo, restaurar UI
        if self.is_active:
            self.restore_active_ui()

        return ft.Container(
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.IconButton(ft.Icons.ARROW_BACK, on_click=lambda _: self.on_back()),
                            ft.Text("Puente KeyVault", size=20, weight=ft.FontWeight.BOLD),
                        ],
                        alignment=ft.MainAxisAlignment.START,
                    ),
                    ft.Divider(height=20, color=ft.Colors.WHITE10),
                    
                    ft.Column(
                        [
                            ft.Icon(ft.Icons.CELL_WIFI, size=50, color=ft.Colors.CYAN),
                            ft.Text("Sincronización Local", size=24, weight=ft.FontWeight.W_700),
                            ft.Text(
                                "Activa el Hotspot de Windows si no estás en la misma red WiFi.",
                                size=13, color=ft.Colors.WHITE38, text_align=ft.TextAlign.CENTER
                            ),
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=10,
                        width=float("inf"),
                    ),
                    
                    ft.Container(height=20),
                    
                    # Área de Emparejamiento
                    ft.Container(
                        content=ft.Column(
                            [
                                self.status_text,
                                self.pin_area,
                                self.alpha_area,
                                self.ip_text,
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=15,
                        ),
                        bgcolor="#1e2a3a",
                        padding=30,
                        border_radius=20,
                        border=ft.border.all(1, ft.Colors.WHITE10),
                        width=400,
                    ),
                    
                    ft.Container(height=10),
                    self.start_btn,
                    
                    ft.Container(height=20),
                    ft.Text("Dispositivos en línea:", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE54),
                    self.clients_list,
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                scroll=ft.ScrollMode.AUTO,
            ),
            padding=20,
            expand=True,
            bgcolor="#0f172a",
        )



    def toggle_bridge(self, e):
        if not self.is_active:
            self.start_bridge()
        else:
            self.stop_bridge()

    def start_bridge(self):
        try:
            # 1. Preparar datos de la bóveda (usando una pregunta al azar de las existentes)
            questions = self.auth.get_user_questions()
            if not questions:
                self.page.snack_bar = ft.SnackBar(ft.Text("Configura preguntas de seguridad primero"))
                self.page.snack_bar.open = True
                self.page.update()
                return
            
            q_obj = random.choice(questions)
            passwords = self.db.get_all_passwords()
            
            # Exportar directamente a bytes (binario .vk)
            vault_bytes = export_passwords_to_bytes(
                passwords, self.auth.key, q_obj["question"], q_obj["answer_hash"]
            )
            
            if not vault_bytes:
                raise Exception("Error al preparar paquete binario")

            # 2. Iniciar Servidor
            vault_b64 = base64.b64encode(vault_bytes).decode()
            config = self.server.start(vault_b64)
            
            # Guardamos el formato de pregunta en la instancia por si es requerido después
            self.current_q_obj = q_obj
            
            # 4. Actualizar UI
            self.pin_text.value = config["pin"]
            self.alpha_text.value = config["alpha"]
            self.pin_area.visible = True
            self.alpha_area.visible = False # Invisible hasta que alguien haga handshake
            self.ip_text.value = f"Servidor activo en: {config['ip']}"
            self.status_text.value = "🟢 Esperando PIN Numérico..."
            self.status_text.color = ft.Colors.CYAN
            self.start_btn.text = "Detener Puente"
            self.start_btn.bgcolor = ft.Colors.RED_700
            
            self.is_active = True
            print("Servidor de sincronización iniciado (2-Step Auth)")
            
            # Iniciar refresco de clientes si no está corriendo
            if not self.refresh_loop_running:
                self.page.run_task(self.refresh_clients_loop)
            
        except Exception as ex:
            print(f"Fallo al iniciar servidor: {ex}")
            self.page.snack_bar = ft.SnackBar(ft.Text(f"Error: {ex}"))
            self.page.snack_bar.open = True
            
        self.page.update()

    def stop_bridge(self):
        self.server.stop()
        self.pin_area.visible = False
        self.alpha_area.visible = False
        self.ip_text.value = ""
        self.status_text.value = "Puente Desconectado"
        self.status_text.color = ft.Colors.WHITE54
        self.start_btn.text = "Iniciar Puente Seguro"
        self.start_btn.bgcolor = ft.Colors.CYAN_700
        self.is_active = False
        self.page.update()

    async def refresh_clients_loop(self):
        """Ciclo de actualización de la lista de clientes."""
        import time
        import asyncio
        self.refresh_loop_running = True
        while self.is_active:
            try:
                now = time.time()
                active_clients = []
                # Limpiar clientes que no han hecho poll en 45 segundos
                to_remove = []
                # Acceder a bridge_server.connected_clients
                clients = self.server.connected_clients
                for ip, last_seen in list(clients.items()):
                    if now - last_seen < 45:
                        active_clients.append(ip)
                    else:
                        to_remove.append(ip)
                
                for ip in to_remove:
                    if ip in clients: del clients[ip]
                
                # Actualizar lista de clientes conectados
                self.clients_list.controls = [
                    ft.Row([
                        ft.Icon(ft.Icons.PHONELINK_LOCK, size=16, color=ft.Colors.GREEN),
                        ft.Text(f"Móvil ({ip})", size=13, color=ft.Colors.WHITE70)
                    ]) for ip in active_clients
                ]
                
                if not active_clients:
                    self.clients_list.controls = [ft.Text("Esperando conexiones...", size=12, italic=True, color=ft.Colors.WHITE38)]
                
                # Monitor de 'Toque' inicial (Paso 1)
                if self.server.pending_handshakers:
                    if not self.alpha_area.visible:
                        self.alpha_area.visible = True
                        self.status_text.value = "🟡 Validando Paso 2..."
                        self.status_text.color = ft.Colors.AMBER_400
                
                # Gestión de Eventos de Autenticación (Feedback Paso 2)
                while self.server.auth_events:
                    ev_type, ev_ip, _ = self.server.auth_events.pop(0)
                    if ev_type == "success":
                        self.page.snack_bar = ft.SnackBar(
                            ft.Text(f"Cliente ({ev_ip}) conectado"),
                            bgcolor=ft.Colors.GREEN_700,
                            duration=3000
                        )
                    else:
                        self.page.snack_bar = ft.SnackBar(
                            ft.Text(f"Cliente (IP: {ev_ip}) no ha podido conectarse"),
                            bgcolor=ft.Colors.RED_700,
                            duration=4000
                        )
                    self.page.snack_bar.open = True
                    
                    # Forzar actualización de PINs y limpiar UI
                    self.pin_text.value = self.server.numeric_pin
                    self.alpha_text.value = self.server.alpha_key
                    self.alpha_area.visible = False
                    self.status_text.value = "🟢 Esperando PIN Numérico..."
                    self.status_text.color = ft.Colors.CYAN

                self.page.update()
            except Exception as e:
                print(f"Error en refresh loop: {e}")
            
            await asyncio.sleep(2)
        self.refresh_loop_running = False

    def show_snackbar(self, msg: str):
        self.page.snack_bar = ft.SnackBar(ft.Text(msg))
        self.page.snack_bar.open = True
        self.page.update()

    def stop_and_back(self):
        self.stop_bridge()
        self.on_back()

    def restore_active_ui(self):
        """Si el servidor ya está corriendo, restaura la UI con el último config."""
        try:
            config = self.server.last_config
            if not config: return
            
            self.pin_text.value = config["pin"]
            self.alpha_text.value = config["alpha"]
            self.pin_area.visible = True
            self.alpha_area.visible = bool(self.server.pending_handshakers)
            
            self.ip_text.value = f"Servidor activo en: {config['ip']}"
            self.status_text.value = "🟢 Puente Activo" if not self.server.pending_handshakers else "🟡 Validando Paso 2..."
            self.status_text.color = ft.Colors.CYAN if not self.server.pending_handshakers else ft.Colors.AMBER_400
            self.start_btn.text = "Detener Puente"
            self.start_btn.bgcolor = ft.Colors.RED_700
            
            # Re-iniciar refresh loop si no está corriendo
            if not self.refresh_loop_running:
                self.page.run_task(self.refresh_clients_loop)
        except Exception as e:
            ic(f"Error restaurando UI: {e}")
