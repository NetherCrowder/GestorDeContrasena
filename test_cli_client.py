"""
test_cli_client.py - Cliente de Pruebas CLI para el nuevo Puente KeyVault.

Flujo de uso:
  1. Ejecuta 'python main_windows.py', inicia sesión.
  2. Ve a "Puente KeyVault" y activa el servidor.
  3. Ejecuta este script en otra terminal.
  4. Introduce el PIN de 6 dígitos que aparece en pantalla.
  5. Introduce la Clave de Seguridad alfanumérica.
  6. La reconexión automática se prueba cerrando y volviendo a ejecutar el script.
"""

import sys
import os
import json
import hashlib
import base64
import time
import uuid
import threading
import urllib.request
import urllib.parse
import urllib.error

# Asegurar importaciones desde el root
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.sync_service import BridgeClient, SessionEncryptor

# ------------------------------------------------------------------ #
#  Archivo de persistencia del cliente de pruebas
# ------------------------------------------------------------------ #
PAIRING_FILE = "test_client_pairing.json"


def save_pairing(ip, port, token, key_b64, trust_token, device_id):
    data = {
        "ip": ip, "port": port, "token": token,
        "key_b64": key_b64, "trust_token": trust_token,
        "device_id": device_id
    }
    with open(PAIRING_FILE, "w") as f:
        json.dump(data, f)
    print(f"  [✓] Pairing guardado en '{PAIRING_FILE}'")


def load_pairing():
    if not os.path.exists(PAIRING_FILE):
        return None
    try:
        with open(PAIRING_FILE) as f:
            return json.load(f)
    except Exception:
        return None


# ------------------------------------------------------------------ #
#  Flujo de autenticación en 2 pasos
# ------------------------------------------------------------------ #
def do_pairing(ip, port, device_id) -> dict | None:
    """Ejecuta el Handshake de 2 pasos y retorna las credenciales."""
    base = f"http://{ip}:{port}"

    # --- PASO 1: Ingresar PIN ---
    print("\n[Paso 1 de 2] Ingresa el PIN de 6 dígitos mostrado en el PC.")
    pin = input("  PIN > ").strip()
    if not pin:
        print("  [✗] PIN vacío. Abortando.")
        return None

    pin_hash = hashlib.sha256(pin.encode()).hexdigest()
    url1 = f"{base}/auth/step1?pin_hash={pin_hash}"
    try:
        with urllib.request.urlopen(url1, timeout=5) as resp:
            body = json.loads(resp.read().decode())
            if body.get("status") != "need_alpha":
                print(f"  [✗] Respuesta inesperada: {body}")
                return None
        print("  [✓] PIN correcto. Continuando al Paso 2...")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("  [✗] PIN incorrecto o expirado. El PC ha generado un nuevo PIN.")
        else:
            print(f"  [✗] Error HTTP {e.code}.")
        return None
    except urllib.error.URLError as e:
        print(f"  [✗] No se pudo conectar al servidor: {e.reason}")
        return None

    # --- PASO 2: Ingresar Clave de Seguridad ---
    print("\n[Paso 2 de 2] Ingresa la Clave de Seguridad alfanumérica mostrada en el PC.")
    alpha = input("  Clave > ").strip().upper()
    if not alpha:
        print("  [✗] Clave vacía. Abortando.")
        return None

    url2 = (
        f"{base}/auth/step2"
        f"?alpha={urllib.parse.quote(alpha)}"
        f"&device_id={device_id}"
        f"&device_name=CLI-Test"
    )
    try:
        with urllib.request.urlopen(url2, timeout=5) as resp:
            body = json.loads(resp.read().decode())
            encrypted_creds = body.get("data")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("  [✗] Clave incorrecta. El PC ha generado nuevas credenciales.")
        elif e.code == 403:
            print("  [✗] Sesión del Paso 1 expirada. Reinicia el proceso.")
        else:
            print(f"  [✗] Error HTTP {e.code}.")
        return None

    # Descifrar credenciales con SHA256(pin + alpha)
    transport_seed = (pin + alpha).encode()
    transport_key = hashlib.sha256(transport_seed).digest()
    transport_enc = SessionEncryptor(transport_key)
    creds_json = transport_enc.decrypt(encrypted_creds)

    if not creds_json:
        print("  [✗] Falló el descifrado. Asegúrate de ingresar el PIN y la clave correctos.")
        return None

    creds = json.loads(creds_json)
    print(f"  [✓] Autenticación completa. Trust Token recibido.")
    return {
        "ip": ip, "port": port,
        "token": creds["t"],
        "key_b64": creds["k"],
        "trust_token": creds["trust"],
        "device_id": device_id,
    }


# ------------------------------------------------------------------ #
#  Reconexión silenciosa
# ------------------------------------------------------------------ #
def try_silent_reconnect(pairing: dict) -> bool:
    """Intenta reconectarse usando el trust_token guardado."""
    ip = pairing["ip"]
    port = pairing["port"]
    device_id = pairing["device_id"]
    trust_token = pairing["trust_token"]

    url = (
        f"http://{ip}:{port}/auth/trust"
        f"?device_id={device_id}"
        f"&trust_token={urllib.parse.quote(trust_token)}"
    )
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            body = json.loads(resp.read().decode())
            encrypted_creds = body.get("data")

        transport_key = hashlib.sha256(trust_token.encode()).digest()
        transport_enc = SessionEncryptor(transport_key)
        creds_json = transport_enc.decrypt(encrypted_creds)
        creds = json.loads(creds_json)

        # Actualizar pairing con las nuevas credenciales de sesión
        pairing["token"] = creds["t"]
        pairing["key_b64"] = creds["k"]
        return True

    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("  [!] Token de confianza rechazado. Necesitas volver a vincular.")
        return False
    except urllib.error.URLError:
        return False


# ------------------------------------------------------------------ #
#  Bucle de sincronización en vivo
# ------------------------------------------------------------------ #
def start_live_session(pairing: dict):
    """Inicia una sesión de sincronización en vivo tras la autenticación."""
    ip = pairing["ip"]
    port = pairing["port"]
    token = pairing["token"]
    key = base64.b64decode(pairing["key_b64"])
    enc = SessionEncryptor(key)
    base_url = f"http://{ip}:{port}"

    print(f"\n{'='*54}")
    print("  SESION ACTIVA — KeyVault Sync Bridge")
    print(f"  Servidor: {ip}:{port}")
    print(f"  Dispositivo: {pairing['device_id']}")
    print(f"{'='*54}")
    print("  Comandos disponibles:")
    print("    vault    → Descargar la bóveda del PC")
    print("    status   → Ver dispositivos conectados")
    print("    exit     → Desconectar")
    print(f"{'='*54}\n")

    # Hilo para mostrar clipboard pushes del PC
    def clipboard_listener():
        url = f"{base_url}/clipboard/poll?token={token}"
        while True:
            try:
                with urllib.request.urlopen(url, timeout=35) as resp:
                    if resp.status == 200:
                        raw = json.loads(resp.read().decode())
                        decrypted = enc.decrypt(raw["data"])
                        if decrypted:
                            print(f"\n  [CLIPBOARD PUSH]: {decrypted}\n  > ", end="", flush=True)
            except Exception:
                time.sleep(3)

    clip_thread = threading.Thread(target=clipboard_listener, daemon=True)
    clip_thread.start()

    # Loop interactivo
    while True:
        try:
            cmd = input("  > ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\n  Desconectando...")
            break

        if cmd == "exit":
            print("  Sesión cerrada.")
            break

        elif cmd == "vault":
            try:
                url = f"{base_url}/sync?token={token}"
                with urllib.request.urlopen(url, timeout=10) as resp:
                    encrypted = resp.read().decode("utf-8")
                    vault_json = enc.decrypt(encrypted)
                    if vault_json:
                        vault = json.loads(vault_json)
                        print(f"\n  Boveda recibida: {len(vault)} contraseñas")
                        for i, item in enumerate(vault[:5], 1):
                            print(f"    {i}. {item.get('title', '?')} — {item.get('username', '?')}")
                        if len(vault) > 5:
                            print(f"    ... y {len(vault)-5} más.")
                    else:
                        print("  [✗] No se pudo descifrar la bóveda.")
            except Exception as e:
                print(f"  [✗] Error: {e}")

        elif cmd == "status":
            try:
                url = f"{base_url}/sync/status?token={token}"
                with urllib.request.urlopen(url, timeout=5) as resp:
                    data = json.loads(resp.read().decode())
                    clients = data.get("clients", [])
                    print(f"\n  Dispositivos conectados: {len(clients)}")
                    for c in clients:
                        print(f"    • {c['device_name']} ({c['ip']}) — hace {c['last_seen_ago']}s")
            except Exception as e:
                print(f"  [✗] Error: {e}")

        else:
            print("  Comando no reconocido. Usa: vault, status, exit")


# ------------------------------------------------------------------ #
#  Punto de entrada
# ------------------------------------------------------------------ #
def main():
    print()
    print("=" * 54)
    print("  KeyVault — Cliente de Pruebas CLI")
    print("=" * 54)

    # Cargar pairing guardado
    pairing = load_pairing()

    if pairing:
        print(f"\n  Pairing guardado encontrado (Dispositivo: {pairing['device_id']})")
        print("  Intentando reconexion silenciosa...")
        if try_silent_reconnect(pairing):
            print("  [✓] Reconexion exitosa.")
            save_pairing(**{k: pairing[k] for k in
                           ["ip", "port", "token", "key_b64", "trust_token", "device_id"]})
            start_live_session(pairing)
            return
        else:
            print("  [!] Reconexion fallida. Iniciando vinculacion manual.")
            os.remove(PAIRING_FILE)

    # Vinculación manual
    print("\n  Asegúrate de que 'main_windows.py' esté corriendo y el Puente activo.")
    ip = input("  IP del PC (Enter para 127.0.0.1): ").strip() or "127.0.0.1"
    port_str = input("  Puerto (Enter para 5005): ").strip()
    port = int(port_str) if port_str.isdigit() else 5005

    # Generar device_id único para este cliente de pruebas
    device_id = f"cli-{str(uuid.uuid4())[:8]}"
    print(f"  ID de dispositivo asignado: {device_id}")

    pairing = do_pairing(ip, port, device_id)
    if not pairing:
        print("\n  [✗] Vinculacion fallida. Verifica el estado del servidor e intenta de nuevo.")
        sys.exit(1)

    save_pairing(**{k: pairing[k] for k in
                   ["ip", "port", "token", "key_b64", "trust_token", "device_id"]})
    start_live_session(pairing)


if __name__ == "__main__":
    main()
