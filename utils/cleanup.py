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
    """Limpia procesos y libera bloqueos de OneDrive."""
    print(">>> Iniciando limpieza profunda del entorno...")
    
    # Procesos que suelen bloquear la carpeta build (No incluimos python.exe para no cerrar este script)
    processes_to_kill = ["KeyVault.exe", "flet.exe", "msedge.exe", "chrome.exe"]
    
    for p in processes_to_kill:
        kill_process_by_name(p)
    
    print("Esperando liberación de handles...")
    time.sleep(2)
    
    build_dir = "build"
    if os.path.exists(build_dir):
        print(f"Detectada carpeta '{build_dir}'. Aplicando parche de OneDrive...")
        try:
            # Marcamos la carpeta como 'Online Only' para que OneDrive no la bloquee para sincronización local inmediata
            # +U = Unpinned / Online Only
            subprocess.run(["attrib", "+U", "/s", "/d", build_dir], capture_output=True)
            print("Atributos de OneDrive actualizados (Online-Only).")
            
            # Intento de borrado forzado si el usuario lo requiere o como parte del ciclo
            # print("Intentando borrado forzado de archivos temporales...")
            # os.system(f"rmdir /s /q {build_dir}") # Comentario: A veces falla, robocopy es mejor
        except Exception as e:
            print(f"Aviso: No se pudo modificar atributos de OneDrive: {e}")
    
    print(">>> Limpieza completada satisfactoriamente.")

if __name__ == "__main__":
    cleanup_build()
