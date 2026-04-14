# KeyVault - Edición Windows (Desktop)

KeyVault es un gestor de contraseñas de máxima seguridad, 100% offline, diseñado para proteger tu información mediante criptografía de grado militar (AES-256 EtM). 

Esta rama contiene exclusivamente el cliente nativo para **Windows**. Se ejecuta como una aplicación de escritorio que no solo almacena tus contraseñas, sino que además actúa como un **BridgeServer** (servidor local P2P) para sincronizarse automáticamente de forma bidireccional con tu aplicación móvil complementaria.

## ✨ Características Principales
- **Diseño Autónomo Local:** Nada se sube a la nube corporativa. Tú posees tu base de datos SQLite y los backups cifrados (`.vk`).
- **AutoBridge Inalámbrico:** Levanta en segundo plano un servidor FastAPI para enlazarse por Wi-Fi (mDNS) con tu teléfono de manera encriptada y automática.
- **Portapapeles Cruzado:** Si le das a "Copiar" en la app de Windows, el texto viaja seguro e infecta directamente el portapapeles de tu Android/iOS, y viceversa.
- **Auditoría Local:** Escanea la fortaleza de tus claves sin enviarlas a servidores externos.

## 🚀 Empezando

### Requisitos
- Python 3.10+
- Entorno de Windows (Powershell sugerido)

### Instalación
1. Clona el repositorio y cambia a la rama de Windows.
2. Instala las dependencias:
   ```bash
   pip install -r requirements.txt
   ```
3. Ejecuta la aplicación en su entorno de escritorio:
   ```bash
   python main.py
   ```

### Construcción del Ejecutable (Windows)
```bash
flet pack main.py -n "KeyVault" -i assets/icon.png --add-data "assets;assets"
```
Esto generará un archivo `.exe` independiente en la carpeta `dist/`. *(Nota: Se utiliza `flet pack` para evadir los fallos de CMake cuando la carpeta está sincronizada con OneDrive, ya que utiliza PyInstaller internamente)*.

## 📚 Documentación
- `docs/WINDOWS_DOCS.md`: Detalle interno del protocolo del servidor y portapapeles.
- `docs/USER_GUIDE.md`: Manual del usuario de la interfaz.
- `docs/ARCHITECTURE.md`: Modelo criptográfico (AES/PBKDF2) y esquema de SQLite.
- `docs/use_cases.md`: Casos de uso de los emparejamientos y migraciones de dispositivos.
