# Cliente Móvil (KeyVault) - Edición Android/iOS

Esta rama (`Movil`) compila específicamente el cliente de Flet para arquitecturas de bolsillo. El rol de esta rama de código es conectarse a un Anfitrión o Servidor remoto temporalmente para sincronizar y manipular datos bidireccionalmente.

## Arquitectura de Cliente Móvil

### 1. Aplicación Autónoma Ligera
A diferencia de la rama de escritorio completa, el cliente móvil carece de dependencias pesadas de servidor web como `fastapi` o `uvicorn`, manteniendo el tamaño del APK al mínimo. Confía plenamente en `flet` para la ejecución del UI asíncrona dentro del Event Loop primitivo de la aplicación.

### 2. AutoBridge: Localización Multicast (ZeroConf)
En la fase de vinculación inicial:
- El móvil utiliza la librería de `zeroconf` en su faceta *Browser* (Buscador).
- Escanea por el identificador de Multicast DNS `_keyvault._tcp.local.`.
- El celular extrae dinámicamente la IP y puerto y muestra un panel de Pairing mediante **PIN** numérico y **Clave Alpha**.

### 3. Autenticación a Prueba de Ataques MITM
Una vez emparejado, se establece un túnel AES-256 CTR EtM con el puente nativo. El Servidor remite un token de confianza permanente alojado de manera segura. Las reconexiones futuras de este teléfono a ese PC ya no exigen interacción manual y ocurren *"Shadow connection"* (en las sombras).

### 4. Sincronización Push a Nivel Sistema (Native Clipboard)
La característica crítica del móvil radica en el envío instantáneo de strings hacia el OS huésped:
Mediante la vista de bóveda, al presionar "Enviar al Móvil" el *Mobile Client* orquesta un payload cifrado (`/clipboard/push`) directamente a Windows Powershell de la PC vinculada posibilitando Pegados (Ctrl+V) inmediatos en el escritorio remoto y SmartTVs.

### Construcción de APK / AAB
1. Asegúrate de tener Flutter SDK / Flet tools instaladas y `jdk` de java.
2. Ejecuta:
   ```bash
   flet build apk -v
   ```
*(Nota personal: Pausa o desvincula temporalmente cualquier servicio de sincronización en la nube (como OneDrive) sobre la carpeta del proyecto para evitar bloqueos NTFS de concurrencia que corrompan el motor Gradle).*
