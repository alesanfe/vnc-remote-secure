# VNC Remote secure 

Este script automatiza la configuración de un entorno de escritorio remoto y acceso a terminal web usando **TigerVNC**, **noVNC** y **ttyd**, con soporte para **SSL** y usuarios temporales.

## 🚀 ¿Qué hace este script?

- Instala las dependencias necesarias (VNC, noVNC, ttyd, XFCE, Certbot, etc.).
- Crea un usuario temporal para sesiones remotas.
- Inicia un servidor VNC con entorno gráfico XFCE.
- Lanza una terminal web segura con ttyd.
- Habilita acceso remoto vía navegador usando noVNC.
- Configura certificados SSL automáticamente con Let's Encrypt (DuckDNS).

## ⚙️ Requisitos

- Sistema basado en Debian/Ubuntu.
- Acceso root o sudo.
- Dominio configurado en DuckDNS.
- Puertos abiertos: `5901`, `5000`, `6080`.

## 🔐 Seguridad

- Usa autenticación básica para ttyd.
- Soporte para certificados SSL.
- Elimina el usuario temporal al cerrar el script.

## 🧪 Uso

1. Edita las variables de configuración al inicio del script (usuario, dominio, email, etc.).
2. Ejecuta el script:

```bash
chmod +x start-remote.sh
./start-remote.sh

