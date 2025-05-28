# Xtream UI para Ubuntu 18.04 20.04 22.04 Debian 10 11 CentOS 7 Fedora 34 35 36 instalación

versión dev no usar

`curl -L https://github.com/Servextex/xtream-ui-ubuntu/raw/master/install.sh | bash -s -- arg`

Este es un espejo de instalación para el software xtream ui en Ubuntu 20.04.
Incluye NGINX 1.19.2 y PHP 7.3.25.

### Actualización 08/03/2021: ###
- No hay actualizaciones planificadas


### Actualización 11/01/2021: ###
- Versión corregida
- Actualizado xtream-ui admin a 22F Mods 13


### Actualización 08/12/2020: ###
- Actualizada la versión de PHP de 7.2 a 7.3 debido a la obsolescencia de 7.2
- Corregido user_watcher.php que desconectaba a los usuarios cada minuto debido a una verificación incorrecta de PID.

Nota: La actividad HLS se informa incorrectamente. Debe usar la salida mpegts y no hls hasta que se solucione.

### AGRADECIMIENTOS ###

- Gracias a GTA por la interfaz original de xtream-ui admin
- Gracias a emre1393 por ser la sabiduría de la comunidad xui
- Gracias a amidevous por la interfaz original de xtream-ui admin

## 🚀 Instalación de Xtream UI

Siga estos pasos para instalar Xtream UI en su sistema. Este instalador es compatible con Ubuntu 18.04, 20.04, 22.04, Debian 10/11, CentOS 7 y Fedora 34/35/36.

### Requisitos previos
- Acceso de superusuario (sudo)
- Conexión a Internet estable
- 8GB de RAM mínimo (se recomiendan 16GB o más)
- 120GB de espacio en disco

### Pasos de instalación

1. **Actualizar el sistema**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Instalar dependencias necesarias**
   ```bash
   sudo apt install -y software-properties-common python3 python3-pip wget curl unzip git
   ```

3. **Clonar el repositorio**
   ```bash
   git clone https://github.com/Servextex/xtream-ui-ubuntu.git
   cd xtream-ui-ubuntu
   ```

4. **Iniciar la instalación**
   ```bash
   sudo bash install.sh
   ```

### Post-instalación

Una vez completada la instalación:
- El panel de administración estará disponible en: `http://tu-servidor:25500`
- Las credenciales por defecto son:
  - Usuario: `admin`
  - Contraseña: `admin`

### Documentación de la API

Para obtener información detallada sobre las APIs de Xtream UI, visite:
- [Documentación Completa de la API](https://servextex.github.io/xtream-ui-ubuntu/api_documentacion_completa.html)
- [Documentación de la API del Player](https://servextex.github.io/xtream-ui-ubuntu/player_api_documentacion.html)

La documentación incluye:
- Endpoints disponibles
- Parámetros requeridos
- Ejemplos de uso
- Respuestas esperadas
- Código de estado HTTP

> **Nota:** Se recomienda revisar la documentación de la API antes de integrar Xtream UI con otros sistemas o desarrollar aplicaciones personalizadas.

> **Nota importante:** Se recomienda encarecidamente cambiar la contraseña predeterminada después del primer inicio de sesión.

### Solución de problemas

Si experimenta algún problema durante la instalación:
1. Verifique que su sistema cumpla con los requisitos
2. Asegúrese de tener todos los permisos necesarios
3. Consulte los logs de instalación en `/home/xtreamcodes/logs/`
4. Si el problema persiste, puede buscar ayuda en la comunidad o abrir un issue en el repositorio


