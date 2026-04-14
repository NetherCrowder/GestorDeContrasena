import logging
import os
from icecream import ic

# Configuración de IceCream
# Podemos desactivarlo globalmente llamando a ic.disable()
# Por defecto está activo para desarrollo.
ic.configureOutput(prefix='DEBUG | ')

def setup_logging():
    """Configura el sistema de registro de errores persistente."""
    # Usar AppData/Local/KeyVault para los logs
    import os
    from pathlib import Path
    
    app_storage = os.environ.get("FLET_APP_STORAGE_DATA")
    if app_storage:
        base_dir = Path(app_storage)
    else:
        base_dir = Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))) / "KeyVault"
        
    base_dir.mkdir(parents=True, exist_ok=True)
    log_file = base_dir / "errors.log"
    
    import sys
    handlers = [logging.FileHandler(log_file)]
    
    # Solo añadir StreamHandler si hay una consola disponible (stdout/stderr no son None)
    if sys.stderr is not None or sys.stdout is not None:
        handlers.append(logging.StreamHandler())

    # Asegurar que el logger estándar escriba en un archivo
    logging.basicConfig(
        level=logging.ERROR,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=handlers
    )
    
    # Mensaje de inicialización (solo en debug)
    ic("Sistema de logging inicializado")

def register_error(message, exception=None):
    """Registra un error en el archivo y opcionalmente lo muestra con ic()."""
    if exception:
        error_msg = f"{message}: {str(exception)}"
        logging.error(error_msg, exc_info=True)
    else:
        error_msg = message
        logging.error(error_msg)
    
    # También lo mandamos a ic para verlo en consola durante desarrollo
    ic(f"ERROR REGISTRADO: {error_msg}")
