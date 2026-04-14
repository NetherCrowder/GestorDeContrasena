# KeyVault - Edición Móvil (Cliente)

KeyVault es un gestor de contraseñas de máxima seguridad, 100% offline, diseñado para proteger tu información mediante criptografía de grado militar (AES-256 EtM). 

Esta rama contiene exclusivamente el cliente de **Móvil (Android/iOS)**. A diferencia de un gestor de contraseñas convencional donde los datos rebotan a través de servidores de terceros (AWS/Azure), este cliente interactúa P2P a través de la Red LAN directamente a tu PC de escritorio gracias al protocolo mDNS/AutoBridge.

## ✨ Características Principales
- **Cifrado Real Offline:** Tu bóveda base nunca sale de tus dispositivos locales hacia Internet.
- **Detección Silenciosa (ZeroConf):** Descubre, valida y autentica tu conexión a tu Desktop PC (BridgeServer) de forma transparente mediante Wi-Fi Local.
- **Native Clipboard Push:** Cualquier contraseña que veas en tu teléfono puede incrustarse de forma transparente en el portapapeles global de la computadora remota (Tu PC) mediante 1 toque, útil para rellenar SmartTVs o Formularios en el Desktop.
- **Portabilidad Limpia:** Esta rama ha sido podada de cualquier librería de Host Web o de Desktop para mantener el bloque generador del APK bajo un peso mínimo y rendimiento máximo de UI en Flutter/Flet.

## 🚀 Empezando

### Requisitos
- Android Device / Emulador o iOS con la app oficial de Flet.
- SDKs Android configurados y dependencias resueltas.

### Construcción
Asegúrate de preparar tú entorno antes de compilar para móviles:
```bash
# Compilar Archivo APK para Android
flet build apk -v
```

*(Importante: Si usas Windows para construir, OneDrive u otros sincronizadores en la nube deben pausarse sobre la carpeta de tu Workspace para evitar que Gradle falle).*

## 📚 Documentación
- `docs/MOBILE_DOCS.md`: Infraestructura de cliente ligero, zero-config y payload push.
- `docs/USER_GUIDE.md`: Manual del usuario (Enfocado en la perspectiva Móvil).
- `docs/ARCHITECTURE.md`: Análisis técnico e integraciones AES-256.
