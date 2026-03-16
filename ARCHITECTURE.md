# Arquitectura Técnica de KeyVault

Este documento detalla la estructura interna, los componentes y las decisiones de diseño que hacen de KeyVault un gestor de contraseñas robusto y seguro.

## 📂 Estructura del Proyecto

```text
GestorDeContrasena/
├── components/          # Widgets reutilizables (PasswordCard, SearchBar, etc.)
├── database/            # Capa de persistencia (SQLite Manager, Modelos)
├── security/            # Motor criptográfico y gestión de sesión (AES, Auth)
├── utils/               # Utilidades de backup, importación y validaciones
├── views/               # Vistas principales de la aplicación (Flet)
├── main.py              # Punto de entrada y gestión de navegación
├── vault.db             # Base de datos local (creada en el primer inicio)
└── requirements.txt     # Dependencias del proyecto
```

---

## 🔐 Capas de Seguridad

### 1. Sistema de Bóveda Binaria
KeyVault no almacena tu "Bóveda" en la nube. Todo el proceso ocurre en el dispositivo:
- **KDF (Key Derivation Function)**: Utilizamos PBKDF2 (Password-Based Key Derivation Function 2) para transformar tu contraseña en una clave binaria fuerte.
- **Salt**: Se genera un Salt aleatorio de 16 bytes que se almacena localmente para evitar ataques de tablas arcoíris.

### 2. Motor Criptográfico (security/crypto.py)
Utilizamos la librería `cryptography` (Python) para implementar **AES-GCM (Galois/Counter Mode)**. Este modo no solo cifra los datos, sino que garantiza su integridad (autenticación).

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

<div align="center">
  <p>Diseñado para ser Privado, Local y Seguro.</p>
</div>
