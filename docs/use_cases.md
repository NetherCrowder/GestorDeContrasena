# Casos de Uso - KeyVault Desktop

Este documento detalla los escenarios principales de uso para KeyVault, demostrando cómo las características de seguridad y gestión se aplican en el día a día.

## 1. Configuración Inicial y Registro
**Actor**: Usuario Nuevo
**Objetivo**: Establecer una bóveda segura desde cero.
- El usuario inicia la aplicación por primera vez.
- Define una **Contraseña Maestra** fuerte y un **PIN** de acceso rápido.
- Selecciona y responde al menos 3 **Preguntas de Seguridad**.
- KeyVault deriva las claves criptográficas y cifra la respuesta a las preguntas usando el Motor de Bóveda Binaria.

## 2. Gestión Diaria de Credenciales
**Actor**: Usuario Registrado
**Objetivo**: Acceder y organizar contraseñas.
- El usuario ingresa mediante su PIN.
- Agrega una nueva credencial (Título, Usuario, Password, URL).
- El sistema cifra instantáneamente los datos usando **AES-256**.
- Marca la credencial como **Favorita** para acceso rápido desde el dashboard principal.

## 3. Auditoría de Salud Digital
**Actor**: Usuario preocupado por la seguridad
**Objetivo**: Identificar debilidades en su bóveda.
- El usuario navega a la pestaña de **Auditoría**.
- El sistema analiza la fortaleza de cada contraseña basándose en longitud, entropía y patrones comunes (ej. "123456").
- El usuario recibe una lista priorizada:
    - **Crítico**: Contraseñas muy cortas o predecibles.
    - **Moderado**: Contraseñas sin caracteres especiales.
    - **Recomendación**: La acción más urgente para mejorar su puntuación global.

## 4. Generación y Almacenamiento Temporal (Warehouse)
**Actor**: Usuario que crea una cuenta nueva en un sitio web.
**Objetivo**: Generar una clave fuerte sin guardarla permanentemente aún.
- El usuario usa el **Generador** para crear 5 opciones de contraseñas.
- Las opciones se guardan en el **Warehouse** (Limbo seguro).
- El usuario copia una para el sitio web.
- Más tarde, decide guardar formalmente esa contraseña en su base de datos o limpiar el warehouse.

## 5. Importación Inteligente (Upsert)
**Actor**: Usuario que migra desde otro gestor o backup.
**Objetivo**: Actualizar su base de datos sin duplicados.
- El usuario carga un archivo de exportación.
- El sistema detecta que el registro "Gmail" ya existe pero tiene una contraseña diferente.
- El sistema realiza un **Upsert**: actualiza la contraseña anterior por la nueva y registra la fecha de actualización, evitando duplicar la entrada.

## 6. Recuperación por Olvido de Clave
**Actor**: Usuario que olvidó su Contraseña Maestra.
**Objetivo**: Recuperar el acceso a sus datos.
- En la pantalla de login, el usuario selecciona "Recuperar acceso".
- El sistema presenta las preguntas de seguridad configuradas.
- Si el usuario responde correctamente al menos 3, se le permite definir una **nueva Contraseña Maestra**.
- Los datos se re-cifran automáticamente con la nueva clave.

## 7. AutoBridge: Sincronización Wifi Transparente
**Actor**: Usuario de escritorio con un dispositivo Celular nuevo.
**Objetivo**: Ligar la app Móvil para tener portabilidad de credenciales.
- El usuario enciende su PC y accede a KeyVault.
- Arranca la app de KeyVault en el Smartphone.
- A través de *Zeroconf mDNS*, el teléfono detecta instantáneamente la IP de la computadora (`_keyvault._tcp.local.`).
- El PC refleja en su menú un mensaje de Emparejamiento Seguro exhibiendo un **PIN numérico** y una **Clase Alfanumérica (Alpha)**.
- El usuario lo ingresa en su teléfono y la confianza se establece permanentemente gracias a un `trust_token` local. Las veces posteriores, la unión se hará de espaldas e instantánea sin claves.

## 8. Magia de Portapapeles Horizontal (Clipboard Push)
**Actor**: Usuario emparejado con su celular trabajando.
**Objetivo**: Pegar una contraseña de la TV (con el móvil) hacia la sesión de la computadora sin tener que abrir el cliente en PC.
- El PC manda la base de datos a memoria del celular a través del Tunnel cifrado y las credenciales operan offline en el teléfono.
- El usuario busca "Netflix" en el móvil y presiona el ícono de **Copiar (Push to PC)**.
- El teléfono envía por `/clipboard/push` por red un string asimétricamente encriptado.
- El BridgeServer en Windows lo desencripta y mediante el API `Get-Clipboard` / Flet, lo sitúa directo en el portapapeles global del sistema.
- El usuario presiona `CRTL + V` en el televisor o en el ordenador remoto y pega su clave sin verla ni memorizarla.

## 9. Soporte Técnico y Logs
**Actor**: Usuario que experimenta un error.
**Objetivo**: Proveer información para soporte.
- El usuario encuentra un error inesperado.
- El sistema registra el error de forma silenciosa e interna en `%LOCALAPPDATA%/KeyVault/errors.log`.
- El usuario puede proveer este archivo al equipo de soporte para un diagnóstico preciso sin comprometer sus contraseñas reales (las cuales permanecen cifradas).
