#!/bin/bash
# Install (or remove) linuxpass.service. The code is copied to a root-owned directory, because
# a root service must never run files its desktop user can edit. Re-run after updating the checkout.
#
#   sudo ./install.sh install     # write the unit, reload, enable at boot
#   sudo ./install.sh start|stop|restart|status|logs
#   sudo ./install.sh uninstall   # stop, disable, remove the unit
#
# /etc/default/linuxpass holds the tunables and is NOT overwritten once it exists.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
UNIT=/etc/systemd/system/linuxpass.service
DEFAULTS=/etc/default/linuxpass
POLKIT=/etc/polkit-1/rules.d/50-linuxpass.rules
DESKTOP=/usr/share/applications/linuxpass-gui.desktop
KEYDIR=/etc/linuxpass
LIB=/opt/linuxpass
STATE=/var/lib/linuxpass
GUI_USER=${SUDO_USER:-${GUI_USER:-}}
PY=$(command -v python3)

need_root() { [ "$(id -u)" -eq 0 ] || { echo "needs root; re-run with sudo."; exit 1; }; }

# True if only root can change this path or any directory above it.
root_only() {
  local p
  p=$(readlink -m "$1")
  while :; do
    if [ -e "$p" ]; then
      [ "$(stat -c %u "$p")" = 0 ] || return 1
      case "$(stat -c %A "$p")" in ?????w????|????????w?) return 1 ;; esac
    fi
    [ "$p" = / ] && return 0
    p=$(dirname "$p")
  done
}

# Copies regular files only, so a symlink in the checkout cannot lead root back to user files.
install_code() {
  local d f mode
  rm -rf "${LIB:?}/linuxpass" "${LIB:?}/gui" "${LIB:?}/scripts"
  for d in linuxpass gui scripts; do
    while IFS= read -r -d '' f; do
      mode=0644
      [ -x "$ROOT/$f" ] && mode=0755
      install -D -o root -g root -m "$mode" "$ROOT/$f" "$LIB/$f"
    done < <(cd "$ROOT" && find "$d" -type f ! -path '*/__pycache__/*' -print0)
  done
}

case "${1:-}" in
install)
  need_root
  [ -f "$HERE/linuxpass.service.in" ] || { echo "missing linuxpass.service.in"; exit 1; }
  if [ -z "$PY" ] || ! root_only "$PY"; then
    echo "python3 (${PY:-not found}) can be changed by a non-root user, and the service runs as root."
    echo "Install python3 from your distribution and re-run."
    exit 1
  fi
  install_code
  install -d -o root -g root -m 0755 "$STATE"
  sed -e "s|__ROOT__|$LIB|g" -e "s|__PY__|$PY|g" -e "s|__GUI_USER__|$GUI_USER|g" \
      "$HERE/linuxpass.service.in" > "$UNIT"
  chmod 0644 "$UNIT"
  if [ ! -e "$DEFAULTS" ]; then
    cat > "$DEFAULTS" <<EOF
# Tunables for linuxpass.service. Edit here, then: systemctl restart linuxpass
# SP_IFACE=          # empty or unset: an adapter is picked automatically. Pin one here.
SP_IFACE=
SP_MON=mon0
SP_STORE=$STATE
SP_CHANNELS=1,6,11
SP_WINDOW=180
SP_IDLE=2
# Extra arguments passed straight to \`sp_relay.py run\`, e.g.
#   SP_EXTRA=--exchange-gap 300 --keep-runs 100
# --rotate-identity presents a new MAC per exchange, which no real console can do and which
# defeats the peer's own rate limit. Leave it off unless you mean it.
SP_EXTRA=
EOF
    chmod 0644 "$DEFAULTS"
    echo "wrote $DEFAULTS"
  else
    echo "kept the existing $DEFAULTS"
  fi
  STORE_PATH=$(. "$DEFAULTS" 2>/dev/null; echo "${SP_STORE:-$STATE}")
  if ! root_only "$STORE_PATH"; then
    echo "SP_STORE=$STORE_PATH can be changed by a non-root user, and the service writes there as root."
    echo "Set SP_STORE in $DEFAULTS to a root-owned directory such as $STATE, then re-run."
    exit 1
  fi

  # The GUI runs as an ordinary user and needs to start and stop this ONE unit. Without this,
  # `systemctl start linuxpass` from a desktop session fails with "interactive authentication
  # required" unless a polkit agent happens to be running. The alternatives are worse: a stored
  # password in an askpass helper, or a blanket sudoers line. This grants exactly one verb on
  # exactly one unit to exactly one user, and `uninstall` takes it away again.
  if [ -n "$GUI_USER" ] && [ -d /etc/polkit-1/rules.d ] && [ -f "$HERE/50-linuxpass.rules.in" ]; then
    sed -e "s|__GUI_USER__|$GUI_USER|g" "$HERE/50-linuxpass.rules.in" > "$POLKIT"
    chmod 0644 "$POLKIT"
    echo "wrote $POLKIT  (lets $GUI_USER manage ONLY linuxpass.service)"
  else
    echo "NOTE: no polkit rule written; the GUI will need a polkit agent to start/stop the service"
  fi

  # The GUI is a normal desktop app; give it a menu entry pointing at the installed copy.
  if [ -f "$HERE/linuxpass-gui.desktop.in" ] && [ -d /usr/share/applications ]; then
    sed -e "s|__ROOT__|$LIB|g" -e "s|__PY__|$PY|g" -e "s|__STORE__|$STORE_PATH|g" \
        "$HERE/linuxpass-gui.desktop.in" > "$DESKTOP"
    chmod 0644 "$DESKTOP"
    command -v update-desktop-database >/dev/null && update-desktop-database -q 2>/dev/null
    echo "wrote $DESKTOP  (menu entry for the GUI)"
  fi

  # The service runs as root, so it looks for keys in /etc/linuxpass rather than in a
  # user's ~/.config. Move them across if the invoking user has them and root does not.
  mkdir -p "$KEYDIR"
  chmod 0700 "$KEYDIR"
  if [ -n "$GUI_USER" ]; then
    USER_CFG=$(getent passwd "$GUI_USER" | cut -d: -f6)/.config/linuxpass
    for k in aes_keys.txt linuxpass.keys; do
      if [ -f "$USER_CFG/$k" ] && [ ! -f "$KEYDIR/$k" ]; then
        install -m 0600 -o root -g root "$USER_CFG/$k" "$KEYDIR/$k"
        echo "copied $k into $KEYDIR (the service runs as root and cannot read \$HOME)"
      fi
    done
  fi
  if [ ! -f "$KEYDIR/aes_keys.txt" ]; then
    echo "NOTE: no $KEYDIR/aes_keys.txt -- the daemon will not derive a link key."
    echo "      See the wiki page \"Getting your keys\"."
  fi

  systemctl daemon-reload
  systemd-analyze verify "$UNIT" 2>&1 | grep -v '^$' && echo "(verify emitted the above)"
  systemctl enable linuxpass.service
  echo
  echo "installed to $LIB. Re-run this after updating the checkout. Nothing is running yet:"
  echo "  sudo systemctl start linuxpass      # or: sudo $0 start"
  echo "  systemctl status linuxpass"
  echo "  journalctl -u linuxpass -f"
  echo
  echo "This unit can restart itself; it cannot reboot the machine."
  ;;
uninstall)
  need_root
  systemctl disable --now linuxpass.service 2>/dev/null
  rm -f "$UNIT" "$POLKIT" "$DESKTOP"
  rm -rf "${LIB:?}"
  systemctl daemon-reload
  command -v update-desktop-database >/dev/null && update-desktop-database -q 2>/dev/null
  echo "removed $UNIT, $POLKIT, $DESKTOP and $LIB"
  echo "left alone: $DEFAULTS, $KEYDIR (your keys) and the store in $STATE"
  ;;
start|stop|restart|status)
  need_root
  systemctl "$1" linuxpass.service
  ;;
logs)
  journalctl -u linuxpass -n "${2:-60}" --no-pager
  ;;
*)
  echo "usage: install.sh {install|uninstall|start|stop|restart|status|logs [n]}"
  exit 1 ;;
esac
