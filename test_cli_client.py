import sys
import hashlib
import time
import base64

from utils.sync_service import BridgeClient

def on_vault_received(vault_data):
    print("\n📦 --- BÓVEDA RECIBIDA DESDE EL PC ---")
    print(f"Tamaño de los datos descifrados: {len(vault_data)} caracteres.")
    print("Contenido (truncado):", vault_data[:100], "...")
    print("--------------------------------------\n")

def on_clipboard_received(text):
    print(f"\n📋 [PORTAPAPELES ACTUALIZADO]: {text}\n")

def test_client():
    print("=== 📱 Prueba de Cliente de Sincronización (CLI) ===")
    print("1. En la aplicación de Windows, enciende el 'Puente KeyVault'.")
    print("2. Haz clic en el botón 'Copiar Enlace Manual' que aparece bajo el QR.")
    print("3. Pega todo el código aquí.")
    
    code = input("\nPega el código (Ej. KV_SYNC|192.168.x.x|...): ").strip()
    
    if not code.startswith("KV_SYNC|"):
        print("❌ Código no válido. Asegúrate de copiar el enlace de vinculación completo.")
        return

    # Parsear el payload (mismo método que la App Android real)
    try:
        parts = code.split("|")
        ip = parts[1]
        port = int(parts[2])
        token = parts[3]
        key_b64 = parts[4]
        key = base64.b64decode(key_b64)
    except Exception as e:
        print("❌ El código copiado está incompleto o corrupto.")
        return
        
    client = BridgeClient()
    
    print(f"\n🔄 Iniciando el 'Handshake' con el PC ({ip}:{port})...")
    success = client.connect(
        ip=ip, 
        port=port, 
        token=token, 
        encryption_key=key, 
        on_vault=on_vault_received,
        on_clipboard=on_clipboard_received
    )
    
    if success:
        print("🟢 VINCULACIÓN EXITOSA CON E2EE.")
        print("Escuchando eventos del portapapeles del PC de forma asíncrona...")
        print("Presiona Ctrl+C en cualquier momento para desconectar.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nDesconectando el cliente...")
            client.stop_listener()
    else:
        print("❌ FALLÓ LA CONEXIÓN.")
        print("Revisa que el Servidor esté activo y que tu equipo permita las conexiones de red.")

if __name__ == "__main__":
    test_client()
