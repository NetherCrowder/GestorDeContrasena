# Guía de Usuario: KeyVault Desktop

Bienvenido a **KeyVault Desktop**, tu gestor de contraseñas seguro y personal para computadoras. Esta guía te ayudará a configurar y aprovechar al máximo todas las funciones de tu nueva bóveda.

---

## 🏁 Inicio Rápido

### 1. Configuración Inicial
Al abrir la aplicación por primera vez, deberás:
- Crear una **Contraseña Maestra** (mínimo 8 caracteres). ¡No la olvides! Es la única forma de acceder a tus datos.
- Configurar un **PIN de 6 dígitos** para desbloqueos rápidos.
- Elegir y responder **3 Preguntas de Seguridad**. Estas son vitales para recuperar tu cuenta si olvidadas la contraseña maestra.

### 2. Guardar tu primera contraseña
Haz clic en el botón flotante **"+"** en la pantalla de inicio.
- Rellena el título (ej. "Netflix"), usuario y contraseña.
- Selecciona una categoría para mantener todo organizado.
- Puedes marcar una contraseña como **Favorita** para tenerla siempre a mano en la pestaña de Inicio.

---

## 🛠️ Funciones Avanzadas

### ⚡ El Almacén de Generación (Warehouse)
¿Necesitas muchas contraseñas para diferentes registros?
1. Ve a la pestaña **"Generar"**.
2. Ajusta los parámetros (longitud, símbolos, etc.).
3. Haz clic en "Generar".
4. Las contraseñas se guardarán en el **Almacén Temporal** durante 24 horas. ¡Puedes recuperarlas cuando las necesites!

### 🩺 Auditoría de Salud
¿Tienes contraseñas débiles o repetidas?
1. Ve a la pestaña **"Salud"**.
2. KeyVault analizará tu bóveda automáticamente.
3. Revisa la lista de recomendaciones:
   - 🔴 **Crítico**: Cambiar de inmediato.
   - 🟡 **Moderado**: Se recomienda cambiar pronto.
   - 🟢 **Baja**: Fortaleza aceptable.

### 📂 Respaldos Binarios (.vk)
Tus datos son tuyos. Recomendamos hacer un respaldo periódicamente:
1. Ve a **Ajustes** -> **Salvar KeyVault**.
2. Dale un nombre a tu copia.
3. El archivo `.vk` se guardará en tu carpeta de **Documentos/KeyVault_Backups**.
4. ¡Guarda ese archivo en un lugar seguro (USB, nube privada)!

---

## 📱 Sincronización Móvil (AutoBridge)

Tu KeyVault en el Escritorio está diseñado de forma inteligente para comunicarse con la Aplicación KeyVault en tu dispositivo móvil sin tener que usar ninguna Nube pública.

### Cómo Emparejar tu Teléfono
1. Conecta tu teléfono a la **misma red Wi-Fi** en la que está el ordenador.
2. Inicia sesión en tu KeyVault en la computadora; el "BridgeServer" se encenderá en segundo plano.
3. Abre tu aplicación de Android/iOS y busca dispositivos. El teléfono detectará a la PC automáticamente de forma silenciosa e interactiva.
4. Para la **primera conexión**, el servidor en PC emitirá vía consola un PIN numérico de 6 dígitos y una Clave Alfanumérica por seguridad estricta para garantizar que nadie más se adueñe de tus datos.
5. Ingrésalas en el teléfono. Una vez ligado, tu dispositivo está en la lista de confianza y **se reconectará automáticamente de forma transparente** en el futuro.

### Magia del Portapapeles (Clipboard Sharing)
Si un dispositivo (PC o Móvil) está en sincronía gracias al AutoBridge:
*   Si le das al ícono de "**Copiar**" en la app móvil, el texto va a incrustarse de inmediato en el portapapeles global de tu Windows para que lo pegues rápidamente en el navegador del escritorio (Ctrl+V).
*   Si le das a  "**Enviar al Móvil**" en el escritorio, el teléfono recibe e inserta la clave en su portapapeles.

---

## 🛡️ Seguridad y Privacidad

- **Cierre de Sesión**: Usa el botón de candado rojo en la esquina superior derecha o el botón en Ajustes para cerrar tu bóveda.
- **Rotación**: KeyVault te avisará cuando una contraseña sea demasiado antigua. Puedes ajustar los días de rotación en Ajustes.
- **Privacidad Total**: KeyVault funciona 100% fuera de línea. Nada sale de tu dispositivo sin que tú lo exportes manualmente.

---

<div align="center">
  <p><strong>Tu seguridad es nuestra prioridad.</strong></p>
</div>
