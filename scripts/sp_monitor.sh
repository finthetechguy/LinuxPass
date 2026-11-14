#!/bin/bash
# Bring the active monitor interface up, or put the machine back.
#   sudo ./scripts/sp_monitor.sh up|down
# Settings come from SP_IFACE, SP_MON, SP_STORE and SP_MAC in the environment.
set -u
ACTION=${1:-}
IFACE=${SP_IFACE:-}
MON=${SP_MON:-mon0}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
STORE=${SP_STORE:-$ROOT/relay_store}
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY=$(command -v python3)
NM_FLAG=/run/tuxchange.nm-stopped
RUN_IFACE=/run/tuxchange.iface     # what `up` really took, so `down` restores THAT adapter
WAS_UP=/run/tuxchange.iface-was-up  # written once, so a repeated `up` cannot lose the original state

if [ "$(id -u)" -ne 0 ]; then echo "sp_monitor.sh needs root"; exit 1; fi
for t in iw ip timeout; do command -v $t >/dev/null || { echo "install $t"; exit 1; }; done

pick_iface() {
  # Only ath9k is picked automatically. Any other driver must be named in SP_IFACE.
  local i drv
  for i in $(iw dev 2>/dev/null | sed -n 's/^\tInterface //p'); do
    [ "$i" = "$MON" ] && continue
    drv=$(basename "$(readlink -f "/sys/class/net/$i/device/driver" 2>/dev/null)" 2>/dev/null)
    if [ "$drv" = "ath9k" ]; then
      echo "$i"
      return
    fi
  done
}

release_radio() {
  # Release only this device, because stopping NetworkManager drops every other connection.
  command -v systemctl >/dev/null || return 0
  systemctl is-active --quiet NetworkManager || return 0
  if command -v nmcli >/dev/null && timeout 10 nmcli device set "$IFACE" managed no >/dev/null 2>&1; then
    echo "NetworkManager told to leave $IFACE alone"
    return 0
  fi
  echo "stopping NetworkManager (nmcli could not release $IFACE)"
  timeout 20 systemctl stop NetworkManager && touch "$NM_FLAG"
}

restore_radio() {
  if [ -e "$NM_FLAG" ]; then
    rm -f "$NM_FLAG"
    timeout 20 systemctl start NetworkManager 2>/dev/null && echo "NetworkManager restarted"
  elif command -v nmcli >/dev/null && systemctl is-active --quiet NetworkManager 2>/dev/null; then
    timeout 10 nmcli device set "$IFACE" managed yes >/dev/null 2>&1 \
      && echo "$IFACE handed back to NetworkManager"
  fi
}

case "$ACTION" in
up)
  if [ -z "$IFACE" ]; then
    IFACE=$(pick_iface)
    [ -n "$IFACE" ] || { echo "no ath9k adapter found, so no adapter was touched; name one with SP_IFACE="; exit 1; }
    echo "using $IFACE (set SP_IFACE to pin a different adapter)"
  fi
  if ! timeout 10 iw dev "$IFACE" info >/dev/null 2>&1; then
    ALT=$(pick_iface)
    if [ -z "$ALT" ]; then
      echo "no such wireless interface: $IFACE, and no ath9k adapter to use instead"
      iw dev | sed -n 's/^\tInterface /  /p'; exit 1
    fi
    echo "WARNING: no such wireless interface: $IFACE, falling back to $ALT"
    echo "         pin it with SP_IFACE=$ALT if this is the adapter you want"
    IFACE=$ALT
  fi
  printf '%s\n' "$IFACE" >"$RUN_IFACE" 2>/dev/null || true
  MAC=${SP_MAC:-$("$PY" "$ROOT/tuxchange/sp_relay.py" identity --store "$STORE" 2>/dev/null)}
  case "$MAC" in
    ??:??:??:??:??:??) ;;
    *) echo "could not derive a MAC for store $STORE"; exit 1 ;;
  esac
  case "$(ip -o link show dev "$IFACE" 2>/dev/null)" in
    *'<UP,'*|*',UP,'*|*',UP>'*) : >"$WAS_UP" 2>/dev/null ;;
  esac
  release_radio
  timeout 10 iw dev "$MON" del 2>/dev/null
  # `flags active` must be on the create command, or ath9k dereferences a NULL txq and oopses.
  if ! timeout 15 iw dev "$IFACE" interface add "$MON" type monitor flags active; then
    echo "could not create an ACTIVE monitor interface on $IFACE"; exit 1
  fi
  timeout 10 ip link set "$MON" down
  timeout 10 ip link set "$MON" address "$MAC" || { echo "could not set $MON MAC"; exit 1; }
  # A full YY segment is 1538 bytes at the socket, over the default 1500 MTU.
  timeout 10 ip link set "$MON" mtu 2000 2>/dev/null \
    || echo "WARNING: could not raise $MON MTU; 1452-byte segments will fail with EMSGSIZE"
  # Down before the monitor comes up: the managed vif holds the channel otherwise, some drivers
  # program the full MAC only for the first vif up (mt76x0/mt76x2), and some allow one vif (mt7601u).
  timeout 15 ip link set "$IFACE" down 2>/dev/null
  timeout 15 ip link set "$MON" up || { echo "could not bring $MON up"; exit 1; }
  echo "active monitor $MON up as $MAC (the hardware will ACK frames addressed to it)"
  ;;
down)
  # Hand back the adapter `up` really took, which may differ from SP_IFACE.
  [ -r "$RUN_IFACE" ] && IFACE=$(cat "$RUN_IFACE")
  timeout 10 iw dev "$MON" del 2>/dev/null
  restore_radio
  if [ -e "$WAS_UP" ] && [ -n "$IFACE" ]; then
    if timeout 15 ip link set "$IFACE" up 2>/dev/null; then
      echo "$IFACE brought back up"
    else
      echo "could not bring $IFACE back up; run: sudo ip link set $IFACE up"
    fi
  fi
  rm -f "$RUN_IFACE" "$WAS_UP"
  echo "monitor $MON removed"
  ;;
*)
  echo "usage: sp_monitor.sh {up|down}"; exit 1 ;;
esac
