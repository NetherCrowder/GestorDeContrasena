# Arquitectura Técnica de KeyVault

Este documento detalla la estructura interna, los componentes y las decisiones de diseño que hacen de KeyVault un gestor de contraseñas robusto y seguro.

## 📂 Estructura del Proyecto

```text
GestorDeContrasena/
├── assets/              # Iconos y recursos visuales
├── components/          # Widgets reutilizables (PasswordCard, SearchBar, etc.)
├── database/            # Capa de persistencia (SQLite Manager, Modelos)
├── security/            # Motor criptográfico y gestión de sesión
├── utils/               # Utilidades, backups y configuración de logs
├── views/               # Vistas principales de la aplicación (Flet)
├── main.py              # Punto de entrada y gestión de navegación
├── vault.db             # Base de datos local
├── pyaes/               # Librería AES 100% Python puro (Vendored)
└── requirements.txt     # Dependencias: flet, icecream
```

---

## 🔐 Capas de Seguridad

### 1. Sistema de Bóveda Binaria
KeyVault no almacena tu "Bóveda" en la nube. Todo el proceso ocurre en el dispositivo:
- **KDF (Key Derivation Function)**: Utilizamos **PBKDF2-HMAC-SHA256** (100.000 iteraciones) para transformar tu contraseña en una clave binaria fuerte de 256 bits.
- **Salt**: Se genera un Salt aleatorio de **32 bytes (256 bits)** que se almacena localmente para evitar ataques de tablas arcoíris.

### 2. Motor Criptográfico (security/crypto.py)
Para garantizar una compatibilidad del **100% en compilaciones Android (APK)** sin sufrir errores silenciosos de dependencias C/Rust, utilizamos la librería vendoreada **`pyaes`** (Python puro) combinada con la librería estándar.
Implementamos **AES-256 en modo CTR** combinado con un **HMAC-SHA256** mediante el paradigma **Encrypt-then-MAC (EtM)**. Este modelo garantiza una seguridad e integridad matemática equivalente a GCM, pero siendo indestructible entre arquitecturas cruzadas.

**Formato de almacenamiento binario:** `[ IV (16 B) ] + [ HMAC (32 B) ] + [ Ciphertext ]`

### 3. Gestión de Identidad (security/auth.py)
- **PIN vs Master Password**: El PIN de 6 dígitos permite un desbloqueo rápido. Internamente, el PIN cifra la contraseña maestra, que a su vez deriva la clave de la bóveda.
- **Rotación**: Implementamos un control de antigüedad basado en Timestamps guardados en la base de datos local.

---

## 🏛️ Componentes y Vistas

### Gestión de Datos (database/db_manager.py)
Utilizamos SQLite para la persistencia. El esquema incluye:
- `passwords`: Almacena usuarios y claves cifradas.
- `categories`: Taxonomía para organizar la información.
- `temp_passwords`: Almacén temporal con limpieza automática (24h).
- `config`: Almacena hashes y parámetros de seguridad.

### Vistas (views/)
La aplicación utiliza un patrón de **Navegación por Estado**:
- `LoginView`: Gestiona el acceso inicial y registro.
- `DashboardView`: El centro de control con grid dinámico de categorías.
- `AuditView`: Analiza la entropía de las claves y detecta vulnerabilidades (como patrones de teclado o palabras comunes).
- `GeneratorView`: Motor de generación aleatoria con parámetros ajustables.

## 📶 4. Capa de Red Local: AutoBridge (BridgeServer)
Para permitir que aplicaciones acompañantes móviles modifiquen y lean los datos de KeyVault sin violar las políticas _Offline_, el escritorio asume el rol de Nodo de Sincronización a través de una red local compartida y directa (WLAN/LAN).

- **Descubrimiento Transparente**: Se utiliza la dependencia `zeroconf` en Python para publicar el servicio por multidifusión mDNS bajo el puntero `_keyvault._tcp.local.`, evitando que el usuario ingrese la IP de su computador de manera estática.
- **Micro-Servidor API (FastAPI)**: Cuando el usuario se Identifica en la interfaz de Host Principal en el escritorio, un hilo alterno *Daemon* invoca un servicio FastApi hosteado por Uvicorn (enlazado al puerto `5005`). 
- **Persistencia de Vínculo Local**: El modelo de autenticación por Token entre pares (Trust Token) se archiva directamente en el directorio interno de datos de la cuenta de usuario de la computadora huesped (`%LOCALAPPDATA%\KeyVault\bridge_devices.json`).
- **Endpoints de Clipboard**: FastApi expone una ruta `POST /clipboard/push` la cual emplea el módulo de portapapeles global del OS (`Get-Clipboard` / Flet Page API) para acoplar el Buffer de Portapapeles de la PC al Buffer de Celular de manera bidireccional casi a un nivel nativo.

---

## 🔄 Flujos de Datos Críticos

### Respaldos (.vk)
El formato `.vk` es un binario propietario de KeyVault que contiene:
1.  **Encabezado**: Metadatos sobre la pregunta de seguridad utilizada.
2.  **Carga Útil**: Datos de contraseñas re-cifrados con el hash de la respuesta de seguridad.
Esto permite que los archivos sean portátiles pero inútiles sin la respuesta correcta.

### Importación Inteligente
KeyVault utiliza un algoritmo de **Diferenciación de Registros**:
- Se comparan (Título, Usuario, Categoría).
- Si hay coincidencia, se realiza un *Upsert* (actualización de la clave si ha cambiado).
- Si no hay coincidencia, se inserta como nuevo.

---

## 📝 Registro y Depuración (Logging)

### 1. IceCream (`ic`)
Utilizamos **IceCream** para reemplazar los `print` tradicionales durante el desarrollo.
- **Ventaja**: Muestra el nombre de la variable, su valor y la línea exacta de ejecución.
- **Producción**: Puede desactivarse globalmente con un solo comando (`ic.disable()`) sin necesidad de borrar las líneas del código.

### 2. Gestión de Errores (Internal Error Log)
Implementamos una capa de **Registro de Errores** persistente:
- **Try/Except**: Todos los flujos críticos están envueltos en bloques de captura de errores.
- **Persistencia**: Los errores capturados se guardan en un archivo `errors.log` para facilitar el soporte técnico.
- **UI Feedback**: Los errores fatales se muestran en una vista de "Crash" para evitar el cierre silencioso de la aplicación.

---

<div align="center">
  <p>Diseñado para ser Privado, Local y Seguro.</p>
</div>
