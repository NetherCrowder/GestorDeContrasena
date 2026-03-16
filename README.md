<div align="center">
  <img src="https://img.icons8.com/isometric/100/shield.png" alt="KeyVault Logo" width="100" />
  <h1>KeyVault</h1>
  <p><strong>Bóveda Binaria: El Guardián Inteligente de tus Identidades Digitales</strong></p>

  [![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://python.org)
  [![Flet](https://img.shields.io/badge/UI-Flet-00BCD4?logo=google-cloud&logoColor=white)](https://flet.dev)
  [![Security](https://img.shields.io/badge/Security-AES--256-green)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
</div>

---

## 🔒 Sobre el Proyecto

**KeyVault** es un gestor de contraseñas de última generación diseñado para ofrecer la máxima seguridad con la mínima fricción. Construido sobre un motor de **Cifrado AES-256** y una interfaz moderna impulsada por **Flet**, KeyVault no solo almacena tus claves, sino que audita tu salud digital.

### ✨ Características Principales

*   **🛡️ Bóveda Inteligente**: Organización por categorías (Trabajo, Social, Finanzas, etc.) con búsqueda instantánea y favoritos.
*   **📂 Respaldos de "Cero Interacción"**: Genera copias de seguridad seguras (`.vk`) con un solo clic. El sistema elige automáticamente tus preguntas de seguridad para el cifrado.
*   **⚡ Almacén Temporal (Warehouse)**: Genera múltiples contraseñas y guárdalas temporalmente en un "limbo" seguro hasta que decidas usarlas o descartarlas.
*   **🩺 Auditoría de Salud**: Análisis en tiempo real de la fortaleza de tus contraseñas con detección de patrones débiles y recomendaciones prioritarias.
*   **🔄 Rotación Gestionada**: Seguimiento automático de la antigüedad de tus claves con recordatorios de rotación personalizables.
*   **🧩 Importación Inteligente**: Sistema de integración de datos que detecta duplicados y realiza actualizaciones inteligentes (upserts) sin perder historial.

---

## 🚀 Instalación y Uso

### Requisitos Previos

- Python 3.9 o superior
- Pip (gestor de paquetes)

### Instalación

1. Clona el repositorio o descarga el código.
2. Crea un entorno virtual (recomendado):
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # En Windows: .venv\Scripts\activate
   ```
3. Instala las dependencias:
   ```bash
   pip install -r requirements.txt
   ```

### Iniciar Aplicación

```bash
python main.py
```

---

## 🏗️ Arquitectura de Seguridad

KeyVault utiliza un modelo de seguridad de capas:

1.  **Derivación de Clave**: Las contraseñas maestras nunca se guardan en texto plano. Se utiliza **PBKDF2** con un *Salt* único por instalación para derivar la clave AES de 256 bits.
2.  **Cifrado Local**: Todos los datos sensibles (usuarios, contraseñas, notas) se cifran localmente antes de tocar la base de datos SQLite.
3.  **PIN de Acceso Rápido**: Un PIN de 6 dígitos cifra la clave maestra en memoria para permitir un desbloqueo rápido sin comprometer la seguridad de la bóveda principal.
4.  **Bóveda Binaria (.vk)**: Los archivos de exportación están doblemente protegidos por el motor criptográfico y las respuestas a preguntas de seguridad seleccionadas al azar.

---

## 🎨 Interfaz de Usuario

La interfaz de KeyVault ha sido diseñada bajo principios de **Diseño Premium**:
- **Modo Oscuro Profundo**: Optimizado para reducir la fatiga visual.
- **Glassmorphism**: Efectos de transparencia y desenfoque para una sensación moderna.
- **Micro-Animaciones**: Transiciones fluidas entre vistas y feedback visual instantáneo.

---

<div align="center">
  <p>Desarrollado con ❤️ por el equipo de KeyVault</p>
</div>
