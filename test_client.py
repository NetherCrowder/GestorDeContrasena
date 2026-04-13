"""
test_client.py - Cliente de Pruebas CLI para el Puente KeyVault.

Prueba el flujo completo del nuevo sistema de sincronización:
  • Autenticación en 2 pasos (PIN + Clave Alfanumérica)
  • Reconexión automática por trust_token
  • Recepción de push dirigido (usuario o contraseña por separado)
  • Descarga de bóveda (vault)
  • Estado de dispositivos conectados

Uso:
  1. Ejecuta 'python main_windows.py' e inicia sesión.
  2. El Puente arranca automáticamente. Anota el PIN y la Clave que aparecen en pantalla.
  3. En otra terminal: python test_client.py
  4. Para probar el push: en la app de Windows, abre una contraseña
     y haz clic en el ícono de "Enviar al Móvil".
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
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.sync_service import SessionEncryptor

# ------------------------------------------------------------------ #
#  Constantes y estado global
# ------------------------------------------------------------------ #
PAIRING_FILE = "test_client_pairing.json"
_last_push_label = ["(sin recibir)"]  # tipo del último push recibido
_push_count = [0]                      # contador de pushes recibidos


# ------------------------------------------------------------------ #
#  Persistencia de pairing
# ------------------------------------------------------------------ #
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
#  Autenticación en 2 pasos
# ------------------------------------------------------------------ #
def do_pairing(ip: str, port: int, device_id: str) -> dict | None:
    """Handshake en 2 pasos: PIN → Alpha Key → trust_token."""
    base = f"http://{ip}:{port}"

    # --- PASO 1: PIN ---
    print("\n  [Paso 1/2] Ingresa el PIN de 6 dígitos que aparece en el PC.")
    pin = input("  PIN > ").strip()
    if not pin:
        print("  [✗] PIN vacío.")
        return None

    pin_hash = hashlib.sha256(pin.encode()).hexdigest()
    try:
        with urllib.request.urlopen(f"{base}/auth/step1?pin_hash={pin_hash}", timeout=5) as r:
            body = json.loads(r.read().decode())
            if body.get("status") != "need_alpha":
                print(f"  [✗] Respuesta inesperada: {body}")
                return None
        print("  [✓] PIN correcto → Paso 2")
    except urllib.error.HTTPError as e:
        print(f"  [✗] PIN incorrecto o expirado (HTTP {e.code}). El PC rotó las credenciales.")
        return None
    except urllib.error.URLError as e:
        print(f"  [✗] Sin conexión al servidor: {e.reason}")
        return None

    # --- PASO 2: Clave Alfanumérica ---
    print("\n  [Paso 2/2] Ingresa la Clave Alfanumérica mostrada en el PC.")
    alpha = input("  Clave > ").strip().upper()
    if not alpha:
        print("  [✗] Clave vacía.")
        return None

    url2 = (
        f"{base}/auth/step2"
        f"?alpha={urllib.parse.quote(alpha)}"
        f"&device_id={device_id}"
        f"&device_name=CLI-Test"
    )
    try:
        with urllib.request.urlopen(url2, timeout=5) as r:
            body = json.loads(r.read().decode())
            encrypted_creds = body.get("data")
    except urllib.error.HTTPError as e:
        codes = {401: "Clave incorrecta. PC rotó credenciales.",
                 403: "Sesión del Paso 1 expirada. Reinicia el proceso."}
        print(f"  [✗] {codes.get(e.code, f'Error HTTP {e.code}.')}")
        return None

    # Descifrar con SHA256(pin + alpha)
    transport_key = hashlib.sha256((pin + alpha).encode()).digest()
    creds_json = SessionEncryptor(transport_key).decrypt(encrypted_creds)
    if not creds_json:
        print("  [✗] Falló el descifrado de credenciales.")
        return None

    creds = json.loads(creds_json)
    print("  [✓] Autenticación completa ✅")
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
    ip, port = pairing["ip"], pairing["port"]
    device_id, trust_token = pairing["device_id"], pairing["trust_token"]

    url = (
        f"http://{ip}:{port}/auth/trust"
        f"?device_id={device_id}"
        f"&trust_token={urllib.parse.quote(trust_token)}"
    )
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            body = json.loads(r.read().decode())

        transport_key = hashlib.sha256(trust_token.encode()).digest()
        creds_json = SessionEncryptor(transport_key).decrypt(body.get("data", ""))
        if not creds_json:
            return False
        creds = json.loads(creds_json)
        pairing["token"] = creds["t"]
        pairing["key_b64"] = creds["k"]
        return True

    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("  [!] Trust token rechazado — necesitas volver a vincular.")
        return False
    except urllib.error.URLError:
        print("  [!] Servidor no disponible.")
        return False


# ------------------------------------------------------------------ #
#  Listener de portapapeles (Thread)
# ------------------------------------------------------------------ #
def start_clipboard_thread(base_url: str, token: str, enc: SessionEncryptor):
    """Escucha pushes del PC en segundo plano, diferenciando user/pass."""

    def _loop():
        url = f"{base_url}/clipboard/poll?token={token}"
        consecutive_errors = 0
        while True:
            try:
                with urllib.request.urlopen(url, timeout=35) as r:
                    if r.status == 200:
                        raw = json.loads(r.read().decode())
                        decrypted = enc.decrypt(raw.get("data", ""))
                        if decrypted:
                            consecutive_errors = 0
                            _push_count[0] += 1
                            ts = datetime.now().strftime("%H:%M:%S")
                            # Separador visual prominente para no perderse el push
                            print(f"\n  {'─'*50}")
                            print(f"  📲 PUSH RECIBIDO [{ts}] #{_push_count[0]}")
                            print(f"  Valor: {decrypted}")
                            print(f"  {'─'*50}")
                            print("  > ", end="", flush=True)
            except Exception:
                consecutive_errors += 1
                if consecutive_errors >= 5:
                    print("\n  [!] Perdí conexión con el servidor. Reintentando...\n  > ",
                          end="", flush=True)
                    time.sleep(5)
                else:
                    time.sleep(2)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()


# ------------------------------------------------------------------ #
#  Sesión interactiva en vivo
# ------------------------------------------------------------------ #
def start_live_session(pairing: dict):
    ip    = pairing["ip"]
    port  = pairing["port"]
    token = pairing["token"]
    key   = base64.b64decode(pairing["key_b64"])
    enc   = SessionEncryptor(key)
    base_url = f"http://{ip}:{port}"

    # Banner de bienvenida
    print(f"\n  {'═'*54}")
    print(f"  ✅ SESIÓN ACTIVA — KeyVault Bridge CLI Test")
    print(f"  {'═'*54}")
    print(f"  Servidor  : {ip}:{port}")
    print(f"  Device ID : {pairing['device_id']}")
    print(f"  {'─'*54}")
    print("  COMANDOS:")
    print("    vault      → Descargar y listar contraseñas de la bóveda")
    print("    status     → Ver dispositivos conectados al servidor")
    print("    ping       → Comprobar que el servidor responde")
    print("    count      → Número de pushes recibidos en esta sesión")
    print("    help       → Mostrar esta ayuda")
    print("    exit       → Cerrar sesión")
    print(f"  {'─'*54}")
    print("  💡 Para probar el push: en la app de Windows, abre una")
    print("     contraseña y haz clic en el ícono 📲 'Enviar al Móvil'.")
    print("     Elige 'Enviar Usuario' o 'Enviar Contraseña' (por separado).")
    print(f"  {'═'*54}\n")

    # Arrancar hilo de portapapeles
    start_clipboard_thread(base_url, token, enc)

    # Loop interactivo
    while True:
        try:
            cmd = input("  > ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\n  Desconectando...")
            break

        if not cmd:
            continue

        elif cmd in ("exit", "quit"):
            print("  Sesión cerrada. ¡Hasta pronto!")
            break

        elif cmd == "vault":
            try:
                with urllib.request.urlopen(
                    f"{base_url}/sync?token={token}", timeout=10
                ) as r:
                    decrypted = enc.decrypt(r.read().decode())
                    if decrypted:
                        vault = json.loads(decrypted)
                        print(f"\n  📦 Bóveda recibida: {len(vault)} contraseña(s)")
                        for i, item in enumerate(vault[:10], 1):
                            title = item.get("title", "?")
                            user  = item.get("username", "—")
                            print(f"    {i:2}. {title:<25} Usuario: {user}")
                        if len(vault) > 10:
                            print(f"    ... y {len(vault)-10} más.")
                        print()
                    else:
                        print("  [✗] No se pudo descifrar la bóveda.")
            except urllib.error.HTTPError as e:
                print(f"  [✗] Error HTTP {e.code} — ¿sesión expirada?")
            except Exception as e:
                print(f"  [✗] Error: {e}")

        elif cmd == "status":
            try:
                with urllib.request.urlopen(
                    f"{base_url}/sync/status?token={token}", timeout=5
                ) as r:
                    data = json.loads(r.read().decode())
                    clients = data.get("clients", [])
                    print(f"\n  📡 Dispositivos conectados: {len(clients)}")
                    if clients:
                        print(f"  {'Nombre':<20} {'IP':<18} Última actividad")
                        print(f"  {'─'*52}")
                        for c in clients:
                            print(
                                f"  {c['device_name']:<20} {c['ip']:<18} "
                                f"hace {c['last_seen_ago']}s"
                            )
                    else:
                        print("  (ninguno)")
                    print()
            except Exception as e:
                print(f"  [✗] Error: {e}")

        elif cmd == "ping":
            try:
                t0 = time.time()
                with urllib.request.urlopen(
                    f"{base_url}/handshake?token={token}", timeout=5
                ) as r:
                    ms = int((time.time() - t0) * 1000)
                    print(f"  🟢 Servidor responde — {ms}ms\n")
            except Exception:
                print("  🔴 Sin respuesta del servidor.\n")

        elif cmd == "count":
            print(f"  📬 Pushes recibidos en esta sesión: {_push_count[0]}\n")

        elif cmd == "help":
            print("  Comandos: vault | status | ping | count | help | exit\n")

        else:
            print(f"  Comando '{cmd}' no reconocido. Escribe 'help' para ver los comandos.\n")


# ------------------------------------------------------------------ #
#  Punto de entrada
# ------------------------------------------------------------------ #
def main():
    print()
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║     KeyVault — Cliente de Pruebas CLI (Bridge)      ║")
    print("  ╚══════════════════════════════════════════════════════╝")

    pairing = load_pairing()

    if pairing:
        print(f"\n  Pairing previo encontrado ({pairing['device_id']})")
        print("  Intentando reconexión silenciosa...")
        if try_silent_reconnect(pairing):
            print("  [✓] Reconexión exitosa.")
            save_pairing(**{k: pairing[k] for k in
                            ["ip", "port", "token", "key_b64", "trust_token", "device_id"]})
            start_live_session(pairing)
            return
        else:
            print("  [!] Reconexión fallida. Iniciando vinculación manual.")
            if os.path.exists(PAIRING_FILE):
                os.remove(PAIRING_FILE)

    # Vinculación manual
    print("\n  Asegúrate de que 'main_windows.py' está corriendo y con sesión iniciada.")
    ip = input("  IP del PC (Enter = 127.0.0.1): ").strip() or "127.0.0.1"
    port_raw = input("  Puerto (Enter = 5005): ").strip()
    port = int(port_raw) if port_raw.isdigit() else 5005

    device_id = f"cli-{str(uuid.uuid4())[:8]}"
    print(f"  Device ID asignado: {device_id}")

    pairing = do_pairing(ip, port, device_id)
    if not pairing:
        print("\n  [✗] Vinculación fallida. Verifica el servidor e intenta de nuevo.")
        sys.exit(1)

    save_pairing(**{k: pairing[k] for k in
                   ["ip", "port", "token", "key_b64", "trust_token", "device_id"]})
    start_live_session(pairing)


if __name__ == "__main__":
    main()
