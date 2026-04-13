"""
test_server.py - Simulador de Servidor (Host) para desarrollo móvil.
Permite probar la sincronización de 2 pasos sin ejecutar toda la app de Windows.
"""

import sys
import os
import json
import base64
import time
import threading
from icecream import ic

# Asegurar que podemos importar desde el root
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.sync_service import BridgeServer

class MockDB:
    """Simulador de base de datos para el servidor de pruebas."""
    def __init__(self):
        self.config = {"sync_version": "1"}
        self.devices = {}
        self.persistence_file = "test_devices.json"
        
        # Cargar persistencia
        if os.path.exists(self.persistence_file):
            try:
                with open(self.persistence_file, "r") as f:
                    self.devices = json.load(f)
                print(f"[DB] Persistencia cargada: {len(self.devices)} dispositivos conocidos.")
            except:
                pass
                
        self.vault_list = [
            {"title": "Google", "username": "user1", "password": "pass123", "url": "google.com", "notes": "Test account"},
            {"title": "Netflix", "username": "movie_fan", "password": "cool_password", "url": "netflix.com", "notes": "Shared with family"},
        ]
    
    def _save(self):
        try:
            with open(self.persistence_file, "w") as f:
                json.dump(self.devices, f)
        except:
            pass

    def get_config(self, key): return self.config.get(key)
    def set_config(self, key, val): self.config[key] = val
    def register_trusted_device(self, d_id, name, token): 
        self.devices[d_id] = {"trust_token": token, "device_name": name}
        print(f"[DB] Dispositivo '{name}' registrado como confiable.")
        self._save()
    
    def get_trusted_device(self, d_id): return self.devices.get(d_id)
    def update_device_connection(self, d_id): pass
    def import_from_list(self, data_list, key):
        print(f"[DB] Recibidos {len(data_list)} ítems desde móvil.")
        self.vault_list = data_list # Simular actualización completa
        self.config["sync_version"] = str(int(self.config["sync_version"]) + 1)

    def get_vault_b64(self):
        return base64.b64encode(json.dumps(self.vault_list).encode()).decode()

def run_test_server():
    print("="*50)
    print(" KEYVAULT - SIMULADOR DE SERVIDOR (DEBUG MODE) ")
    print("="*50)
    
    mock_db = MockDB()
    server = BridgeServer(port=5005, db_manager=mock_db)
    
    config = server.start(mock_db.get_vault_b64())
    
    # Callback para cuando el servidor recibe datos del cliente (upload)
    def _on_upload(data):
        mock_db.import_from_list(data, None)
        server.vault_data = mock_db.get_vault_b64() # Actualizar b64 circulando
        print(f"[SYNC] Bóveda actualizada localmente. Nueva Versión: {mock_db.get_config('sync_version')}")

    server.on_vault_received = _on_upload

    print(f"\n[ESTADO] Servidor iniciado correctamente.")
    print(f"[RED] IP: {config['ip']} | Puerto: {config['port']}")
    print(f"\n" + "-"*30)
    print(f"  PASO 1 (PIN):   {config['pin']}")
    print(f"  PASO 2 (ALPHA): {config['alpha']}")
    print("-" * 30 + "\n")
    
    print("Consola Interactiva:")
    print(" - Escribe algo para enviar al PORTAPAPELES del móvil.")
    print(" - 'add': Simula añadir una contraseña en el PC (Sincronización LIVE).")
    print(" - 'regen': Rota los PINs (Simular fallo/reintento).")
    print(" - 'exit': Cerrar.\n")

    def monitor_events():
        last_event_count = 0
        while server.is_running:
            if len(server.auth_events) > last_event_count:
                new_events = server.auth_events[last_event_count:]
                for ev in new_events:
                    ev_type, ev_ip, _ = ev
                    status = "✅ ÉXITO" if ev_type == "success" else "❌ FALLO"
                    print(f"\n[EVENTO] {status} - Intento desde {ev_ip}")
                    if ev_type == "failure":
                        print(f"[INFO] PINs rotados automáticamente.")
                        print(f"  NUEVO PIN: {server.numeric_pin}")
                        print(f"  NUEVA CLAVE: {server.alpha_key}")
                last_event_count = len(server.auth_events)
            time.sleep(1)

    threading.Thread(target=monitor_events, daemon=True).start()

    try:
        while True:
            cmd = input("KV-Host > ").strip()
            if not cmd: continue
            
            if cmd.lower() == 'exit': break
            elif cmd.lower() == 'regen':
                server.regenerate_pins()
                print(f"[ROTACIÓN] Nuevos PINs generados: {server.numeric_pin}")
            elif cmd.lower() == 'add':
                # Simular cambio en la base de datos
                new_item = {"title": f"Nuevo_{int(time.time())}", "username": "admin", "password": "123", "url": "local.dev"}
                mock_db.vault_list.append(new_item)
                # Incrementar versión
                v = int(mock_db.get_config("sync_version")) + 1
                mock_db.set_config("sync_version", str(v))
                # Actualizar data en el servidor
                server.vault_data = mock_db.get_vault_b64()
                print(f"[DB] Ítem añadido. Nueva versión: {v}. El móvil debería detectarlo solo.")
            else:
                server.push_clipboard(cmd)
                print(f"[PUSH] '{cmd}' enviado a clientes.")
    except KeyboardInterrupt:
        pass
    finally:
        print("\nCerrando servidor...")
        server.stop()
        print("Hecho.")

if __name__ == "__main__":
    run_test_server()
