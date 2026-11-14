#!/bin/bash
# Bring the active monitor interface up, or put the machine back.
#   sudo ./scripts/sp_monitor.sh up|down
# Settings come from SP_IFACE, SP_MON, SP_STORE, SP_MAC, SP_MODE and SP_CHANNELS in the environment.
#
# Two ways to make the hardware ACK the console:
#   active  an active monitor vif carries our MAC (ath9k, most mt76).
#   mixed   a plain monitor vif sends and sniffs while the adapter's own station vif carries our
#           MAC, unassociated, so the chip ACKs it. For adapters without active monitor support.
# SP_MODE=auto (default) uses active when the adapter supports it and mixed otherwise.
set -u
ACTION=${1:-}
IFACE=${SP_IFACE:-}
MON=${SP_MON:-mon0}
MODE=${SP_MODE:-auto}
CHANNELS=${SP_CHANNELS:-1}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
STORE=${SP_STORE:-$ROOT/relay_store}
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY=$(command -v python3)
NM_FLAG=/run/tuxchange.nm-stopped
RUN_IFACE=/run/tuxchange.iface     # what `up` really took, so `down` restores THAT adapter
WAS_UP=/run/tuxchange.iface-was-up  # written once, so a repeated `up` cannot lose the original state
ORIG_MAC=/run/tuxchange.iface-mac   # mixed mode changes the adapter's own MAC; `down` puts it back

if [ "$(id -u)" -ne 0 ]; then echo "sp_monitor.sh needs root"; exit 1; fi
for t in iw ip timeout; do command -v $t >/dev/null || { echo "install $t"; exit 1; }; done

iface_driver() {
  basename "$(readlink -f "/sys/class/net/$1/device/driver" 2>/dev/null)" 2>/dev/null
}

can_active_monitor() {
  # The hardware must ACK frames addressed to the monitor's MAC, which is what active monitor means.
  local phy
  phy=$(cat "/sys/class/net/$1/phy80211/name" 2>/dev/null) || return 1
  timeout 10 iw phy "$phy" info 2>/dev/null | grep -q 'supports active monitor'
}

can_monitor() {
  local phy
  phy=$(cat "/sys/class/net/$1/phy80211/name" 2>/dev/null) || return 1
  timeout 10 iw phy "$phy" info 2>/dev/null | grep -qE '^[[:space:]]+\* monitor$'
}

is_up() {
  [ $(( $(cat "/sys/class/net/$1/flags" 2>/dev/null || echo 0) & 1 )) -eq 1 ]
}

is_connected() {
  timeout 10 iw dev "$1" link 2>/dev/null | grep -q '^Connected'
}

pick_iface() {
  # Active monitor first, ath9k (the tested driver) winning a tie. Failing that, an adapter that
  # can do mixed mode, but never one that is connected, so the machine's own Wi-Fi is left alone.
  local i first= mixed=
  for i in $(iw dev 2>/dev/null | sed -n 's/^\tInterface //p'); do
    [ "$i" = "$MON" ] && continue
    if [ "$MODE" != mixed ] && can_active_monitor "$i"; then
      if [ "$(iface_driver "$i")" = "ath9k" ]; then
        echo "$i"
        return
      fi
      [ -n "$first" ] || first=$i
    elif [ "$MODE" != active ] && [ -z "$mixed" ] && can_monitor "$i" && ! is_connected "$i"; then
      mixed=$i
    fi
  done
  if [ -n "$first" ]; then echo "$first"; elif [ -n "$mixed" ]; then echo "$mixed"; fi
}

release_radio() {
  # Release only this device, because stopping NetworkManager drops every other connection.
  command -v systemctl >/dev/null || return 0
  systemctl is-active --quiet NetworkManager || return 0
  if command -v nmcli >/dev/null && timeout 10 nmcli device set "$IFACE" managed no >/dev/null 2>&1; then
    echo "NetworkManager told to leave $IFACE alone"
    # nmcli returns before NetworkManager and wpa_supplicant finish letting go, and their teardown
    # resets the MAC and takes the link down, which would undo whatever is set up next.
    local n=0
    while [ $n -lt 20 ] && ! timeout 5 nmcli -g GENERAL.STATE device show "$IFACE" 2>/dev/null \
        | grep -q '^10 '; do
      sleep 0.25; n=$((n + 1))
    done
    sleep 1
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
    [ -n "$IFACE" ] || { echo "no usable adapter found (active monitor or mixed mode); name an adapter with SP_IFACE="; exit 1; }
    echo "using $IFACE (set SP_IFACE to use a different adapter)"
  fi
  if ! timeout 10 iw dev "$IFACE" info >/dev/null 2>&1; then
    ALT=$(pick_iface)
    if [ -z "$ALT" ]; then
      echo "no such wireless interface: $IFACE, no usable adapter to use instead"
      iw dev | sed -n 's/^\tInterface /  /p'; exit 1
    fi
    echo "WARNING: no such wireless interface: $IFACE, falling back to $ALT"
    echo "         set SP_IFACE=$ALT if this is the adapter you want instead"
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
  case "$MODE" in
    auto) if can_active_monitor "$IFACE"; then MODE=active; else MODE=mixed; fi ;;
    active|mixed) ;;
    *) echo "SP_MODE must be auto, active or mixed, not $MODE"; exit 1 ;;
  esac
  release_radio
  timeout 10 iw dev "$MON" del 2>/dev/null
  if [ "$MODE" = mixed ]; then
    can_monitor "$IFACE" || { echo "$IFACE cannot run a monitor interface"; exit 1; }
    if [ ! -e "$ORIG_MAC" ]; then
      PERM=$(ip -o link show dev "$IFACE" 2>/dev/null | sed -n 's/.* permaddr \([0-9a-f:]*\).*/\1/p')
      printf '%s\n' "${PERM:-$(cat "/sys/class/net/$IFACE/address")}" >"$ORIG_MAC" 2>/dev/null
    fi
    timeout 15 ip link set "$IFACE" down 2>/dev/null
    if ! timeout 15 iw dev "$IFACE" interface add "$MON" type monitor; then
      echo "could not create a monitor interface on $IFACE"; exit 1
    fi
    timeout 10 ip link set "$MON" mtu 2000 2>/dev/null \
      || echo "WARNING: could not raise $MON MTU; 1452-byte segments will fail with EMSGSIZE"
    timeout 15 ip link set "$MON" up || { echo "could not bring $MON up"; exit 1; }
    # Tune while the monitor is alone on the radio, so the station vif comes up on this channel.
    timeout 10 iw dev "$MON" set channel "${CHANNELS%%,*}" 2>/dev/null \
      || echo "WARNING: could not tune $MON to channel ${CHANNELS%%,*}"
    timeout 10 ip link set "$IFACE" address "$MAC" || { echo "could not set $IFACE MAC"; exit 1; }
    # Up but never associated: the driver programs our MAC into the chip, which then ACKs it.
    timeout 15 ip link set "$IFACE" up || { echo "could not bring $IFACE up"; exit 1; }
    # Anything still letting go of the adapter can take it down again; check it stayed up.
    sleep 2
    if ! is_up "$IFACE" || [ "$(cat "/sys/class/net/$IFACE/address")" != "$MAC" ]; then
      echo "$IFACE was taken down or changed behind our back; setting it up again"
      timeout 15 ip link set "$IFACE" down 2>/dev/null
      timeout 10 ip link set "$IFACE" address "$MAC" || { echo "could not set $IFACE MAC"; exit 1; }
      timeout 15 ip link set "$IFACE" up || { echo "could not bring $IFACE up"; exit 1; }
    fi
    echo "mixed mode: monitor $MON sends and listens, $IFACE up as $MAC (the hardware will ACK frames addressed to it)"
    exit 0
  fi
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
  if [ -r "$ORIG_MAC" ] && [ -n "$IFACE" ]; then
    timeout 15 ip link set "$IFACE" down 2>/dev/null
    timeout 10 ip link set "$IFACE" address "$(cat "$ORIG_MAC")" 2>/dev/null \
      && echo "$IFACE MAC put back to $(cat "$ORIG_MAC")"
  fi
  restore_radio
  if [ -e "$WAS_UP" ] && [ -n "$IFACE" ]; then
    if timeout 15 ip link set "$IFACE" up 2>/dev/null; then
      echo "$IFACE brought back up"
    else
      echo "could not bring $IFACE back up; run: sudo ip link set $IFACE up"
    fi
  fi
  rm -f "$RUN_IFACE" "$WAS_UP" "$ORIG_MAC"
  echo "monitor $MON removed"
  ;;
*)
  echo "usage: sp_monitor.sh {up|down}"; exit 1 ;;
esac
