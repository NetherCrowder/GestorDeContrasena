"""
clipboard_helper.py
Abstracción de la API de portapapeles de Flet 0.83.x.

IMPORTANTE: En Flet 0.83, page.clipboard devuelve una instancia del control Clipboard
que debe accederse desde dentro del event loop de Flet (no desde hilos externos).
La solución correcta es envolver la llamada en una coroutine y pasarla a page.run_task().
"""


def copy_to_clipboard(page, text: str) -> bool:
    """
    Copia `text` al portapapeles nativo del dispositivo.
    Funciona desde hilos normales (no-async) con Flet 0.83+ en desktop y móvil.

    La clave: page.clipboard NO debe evaluarse en el hilo de fondo,
    sino dentro de la coroutine que corre en el event loop de Flet.
    """
    if not text:
        return False

    # Capturar la página en el cierre para no acceder a .clipboard ahora
    _page = page

    async def _do_set():
        try:
            # Acceder a page.clipboard DENTRO del event loop de Flet
            await _page.clipboard.set(text)
        except Exception:
            # Fallback: versiones donde set_clipboard era sincrónico
            try:
                if hasattr(_page, "set_clipboard"):
                    _page.set_clipboard(text)
            except Exception:
                pass

    try:
        page.run_task(_do_set)
        return True
    except Exception:
        return False
