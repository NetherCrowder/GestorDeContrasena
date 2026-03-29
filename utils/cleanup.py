"""
cleanup.py - Utilidad para liberar bloqueos de archivos en Windows.
Especialmente útil cuando OneDrive bloquea la carpeta 'build' durante la compilación.
"""

import os
import subprocess
import signal
import time

def kill_process_by_name(process_name):
    """Mata procesos por nombre usando taskkill."""
    try:
        print(f"Cerrando procesos: {process_name}...")
        subprocess.run(["taskkill", "/F", "/IM", process_name], 
                       stdout=subprocess.DEVNULL, 
                       stderr=subprocess.DEVNULL)
        return True
    except Exception as e:
        print(f"Error al intentar cerrar {process_name}: {e}")
        return False

def cleanup_build():
    """Limpia procesos que suelen bloquear la carpeta build."""
    print("Iniciando limpieza de entorno para compilación...")
    
    # Procesos comunes que bloquean la carpeta
    processes_to_kill = [
        "KeyVault.exe",  # La propia app en ejecución
        "flet.exe",      # Servidor flet
        "python.exe",    # Instancias de python (opcional, usar con cuidado)
        "java.exe"       # Emuladores de Android si están abiertos
    ]
    
    for p in processes_to_kill:
        kill_process_by_name(p)
    
    # Pausa breve para que el SO libere los handles
    print("Esperando liberación de recursos...")
    time.sleep(2)
    
    # Intentar limpiar la carpeta build si existe (opcional)
    build_dir = "build"
    if os.path.exists(build_dir):
        print(f"Carpeta '{build_dir}' detectada. Si OneDrive la bloquea, considera pausar la sincronización.")
    
    print("Limpieza completada. Puedes intentar compilar ahora.")

if __name__ == "__main__":
    cleanup_build()
