# Gestor de Contraseñas (KeyVault) - Edición Servidor/Escritorio

El presente documento detalla la arquitectura, funciones y especificaciones técnicas de la versión pura de escritorio de KeyVault (rama `Windows`). Toda lógica pre-existente relativa al emparejamiento manual o persistente del rol "cliente" ha sido purgada, estableciendo al sistema como emisor de puente bidireccional (`BridgeServer`).

## El `BridgeServer`

KeyVault para Escritorio integra un servidor FastAPI local de forma asíncrona dentro de la interfaz gráfica de usuario. Al iniciar sesión en el escritorio, el servicio enciende automáticamente en el fondo para escuchar las interacciones móviles en la red local.

### Descubrimiento en Red
El servidor no requiere configuración IP por parte del usuario final. En su inicialización, se propaga gracias al protocolo de Zero Configuration (Zeroconf), utilizando **mDNS** (*Multicast DNS*). 
Los clientes suscritos detectan el servicio bajo:
- Identificador de servicio: `_keyvault._tcp.local.` 
- Puerto TCP fijo: `5005`

### Emparejamiento por Claves Efímeras
Una vez el BridgeServer está operando, si las credenciales en Memoria no tienen registro previo emitirán:
*   Un **PIN** numérico dinámico de 6 dígitos para la primera validación.
*   Una llave criptográfica **Alfa** (`Alpha`) de 7 dígitos para el inicio del túnel AES.

Cuando el dispositivo Móvil ingresa dichas claves satisfactoriamente, el PC despacha un `trust_token` persistente. Este token de confianza se guarda en el repositorio de validación de Windows en la ruta `%LOCALAPPDATA%\KeyVault\bridge_devices.json` permitiendo reconexiones *"silenciosas"* sin volver a consultar el PIN/Alfa.

### Sincronización Doble Dirección (Vault)

*   **PC -> Móvil** (`/sync`): Tras autentificarse el Móvil, efectúa una consulta `GET` y recibe todo el estado cifrado actual de la DB SQLite local enviada directamente por el `vault_provider` a RAM.
*   **Móvil -> PC** (`POST /sync/upload`): Cuando el Móvil realiza una modificación, envía una lista delta (o total) al Endpoint el cual gatilla el Event Binding de Flet e introduce los guardados inmediatamente a la base de datos de escritorio vía `db.import_from_list`.

### Integración Nivel SO del Portapapeles
Como valor añadido sin fricción, el BridgeServer funciona de Portapapeles en LAN:
- Si el usuario **copia en PC**, el evento se empuja (`q.put(text)`) al canal *Long-Polling* de HTTP que esperan los móviles conectados. (Despacho a Flet)
- Si el usuario interactúa desde el **Móvil hacia PC**, la invocación `POST /clipboard/push` insertará por medio de inyección directa Powershell o Pyperclip el string exacto al portapapeles global del sistema de Microsoft Windows para Pegado automático.

---
**Nota de limpieza de Repositorio:** El remanente `test_client_pairing.json` y el simulador de terminal de pruebas que lo generaba (`test_client.py`) han sido purgados por diseño. El archivo de caché de emparejamiento propio de Flet Servidor es `bridge_devices.json`.
