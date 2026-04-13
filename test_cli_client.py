import sys
import hashlib
import time
import base64
import json
import socket
import urllib.request
from icecream import ic
from zeroconf import Zeroconf, ServiceBrowser

# Deshabilitar IC para la consola limpia
ic.disable()

from utils.sync_service import BridgeClient, SessionEncryptor

def on_vault_received(vault_data):
    print("\n📦 --- BÓVEDA RECIBIDA DESDE EL PC ---")
    print(f"Bóveda descargada y descifrada con éxito.")
    print("--------------------------------------\n")

def on_clipboard_received(text):
    print(f"\n📋 [PC -> MÓVIL] Portapapeles: {text}\n")

class MyListener:
    def __init__(self):
        self.services = {}

    def remove_service(self, zeroconf, type, name):
        if name in self.services:
            del self.services[name]

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            self.services[name] = info

    def update_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            self.services[name] = info

def test_client():
    print("=== 📱 Prueba de Cliente Auto-Descubrimiento (CLI) ===")
    print("Buscando servidores KeyVault en tu red WiFi local...\n")
    
    zeroconf = Zeroconf()
    listener = MyListener()
    browser = ServiceBrowser(zeroconf, "_keyvault._tcp.local.", listener)
    
    time.sleep(3) # Escanear red por 3 segundos
    
    if not listener.services:
        print("❌ No se encontraron servidores KeyVault en la red.")
        zeroconf.close()
        return

    servers = list(listener.services.values())
    target_info = servers[0] # Tomamos el primero para simplificar
    
    ip = socket.inet_ntoa(target_info.addresses[0])
    port = target_info.port
    print(f"✅ Servidor detectado en: {ip}:{port}")
    
    # Extraer payload cifrado inicial (Invite)
    props = target_info.properties
    encrypted_invite = props.get(b'p', props.get('p'))
    if isinstance(encrypted_invite, bytes):
        encrypted_invite = encrypted_invite.decode("utf-8")

    zeroconf.close()
    
    # ---------------------------------------------------------
    # PASO 1: PIN NUMÉRICO
    # ---------------------------------------------------------
    pin_num = input("\n🔑 [PASO 1] Digita el PIN NUMÉRICO (6 dígitos): ").strip()
    
    # Validar localmente descifrando el 'Invite'
    try:
        pin_hash = hashlib.sha256(pin_num.encode()).digest()
        pin_enc = SessionEncryptor(pin_hash)
        invite_raw = pin_enc.decrypt(encrypted_invite)
        if not invite_raw: raise ValueError()
        print("🟢 PIN Numérico aceptado.")
    except:
        print("❌ PIN Incorrecto. El paquete no se puede descifrar.")
        return

    # Handshake Inicial (Notifica al PC que alguien entró)
    try:
        token_handshake = hashlib.sha256(pin_num.encode()).hexdigest()
        url_h = f"http://{ip}:{port}/auth/step1?token={token_handshake}"
        with urllib.request.urlopen(url_h, timeout=5) as resp:
            data_h = json.loads(resp.read().decode())
            if data_h.get("status") != "need_alpha":
                print("❌ Error en el handshake del servidor.")
                return
    except Exception as e:
        print(f"❌ Fallo al contactar servidor: {e}")
        return

    # ---------------------------------------------------------
    # PASO 2: CLAVE ALFANUMÉRICA (Mostrada en PC)
    # ---------------------------------------------------------
    print("\n⚠️  Revisa la pantalla del PC.")
    alpha_code = input("🔑 [PASO 2] Digita la CLAVE ALFANUMÉRICA mostrada: ").strip().upper()
    
    # Verificar y obtener llaves finales
    try:
        url_v = f"http://{ip}:{port}/auth/step2?alpha={alpha_code}"
        with urllib.request.urlopen(url_v, timeout=5) as resp:
            data_v = json.loads(resp.read().decode())
            encrypted_creds = data_v["data"]
            
            # Descifrar credenciales con la llave combinada
            transport_seed = (pin_num + alpha_code).encode()
            transport_key = hashlib.sha256(transport_seed).digest()
            transport_enc = SessionEncryptor(transport_key)
            
            creds_raw = transport_enc.decrypt(encrypted_creds)
            if not creds_raw: raise ValueError()
            
            creds = json.loads(creds_raw)
            token_final = creds["t"]
            master_key = base64.b64decode(creds["k"])
            
    except Exception as e:
        print(f"❌ Error de autenticación en Paso 2: {e}")
        return

    print("🟢 VINCULACIÓN EXITOSA. Clave AES recibida mediante E2EE secundario.")
    
    client = BridgeClient()
    success = client.connect(
        ip=ip, 
        port=port, 
        token=token_final, 
        encryption_key=master_key, 
        on_vault=on_vault_received,
        on_clipboard=on_clipboard_received
    )
    
    if success:
        print("\n🚀 CONEXIÓN ESTABLECIDA Y ESCUCHANDO...")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nCerrando sesión...")
    else:
        print("❌ Falló la sincronización final.")

if __name__ == "__main__":
    test_client()
