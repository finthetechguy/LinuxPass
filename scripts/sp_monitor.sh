#!/bin/bash
# Bring the ACTIVE monitor interface up, or put the machine back.
#
#   sudo ./scripts/sp_monitor.sh up
#   sudo ./scripts/sp_monitor.sh down
#
# Tunables come from the environment so the systemd unit and the manual wrapper share one copy of
# this logic:
#   SP_IFACE  the real wireless interface       (default: pick one automatically)
#   SP_MON    the monitor vif to create         (default mon0)
#   SP_STORE  the relay store, used to derive our fixed MAC
#   SP_MAC    an explicit MAC, overriding the store-derived one
#
# NOTHING IN HERE REBOOTS THE MACHINE. Recovery from a wedged radio is: tear the vif down, build
# it again. That is what `ExecStartPre` does on every restart of linuxpass.service.
set -u
ACTION=${1:-}
IFACE=${SP_IFACE:-}
MON=${SP_MON:-mon0}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
STORE=${SP_STORE:-$ROOT/relay_store}
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY=$(command -v python3)
NM_FLAG=/run/linuxpass.nm-stopped
RUN_IFACE=/run/linuxpass.iface     # what `up` really took, so `down` restores THAT adapter

if [ "$(id -u)" -ne 0 ]; then echo "sp_monitor.sh needs root"; exit 1; fi
for t in iw ip timeout; do command -v $t >/dev/null || { echo "install $t"; exit 1; }; done

pick_iface() {
  # Interface names are NOT stable. This box has enumerated the same adapter as wlp3s0 and as
  # wlp4s0 across reboots, and because `up` treated a missing SP_IFACE as fatal, ExecStartPre
  # failed and linuxpass.service would not start at all -- it took a reboot to get the old name
  # back (6 Sep 2026). A missing adapter is now a substitution and a warning, never fatal.
  #
  # ath9k is preferred because it is the only driver on this bench that can inject; an MT7902
  # will associate and sniff but silently transmits nothing, so picking it would look like a
  # dead console rather than a wrong adapter.
  local i drv first="" best=""
  for i in $(iw dev 2>/dev/null | sed -n 's/^\tInterface //p'); do
    [ "$i" = "$MON" ] && continue
    [ -z "$first" ] && first="$i"
    drv=$(basename "$(readlink -f "/sys/class/net/$i/device/driver" 2>/dev/null)" 2>/dev/null)
    [ "$drv" = "ath9k" ] && [ -z "$best" ] && best="$i"
  done
  echo "${best:-$first}"
}

release_radio() {
  # Prefer handing NetworkManager the single device: stopping NM outright takes every other
  # connection on the box down with it, and this machine is reached over ethernet precisely so
  # that the wifi can be commandeered. Only fall back to stopping NM if nmcli cannot do it.
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
    [ -n "$IFACE" ] || { echo "no wireless interface found; pin one with SP_IFACE="; exit 1; }
    echo "using $IFACE (set SP_IFACE to pin a different adapter)"
  fi
  if ! timeout 10 iw dev "$IFACE" info >/dev/null 2>&1; then
    ALT=$(pick_iface)
    if [ -z "$ALT" ]; then
      echo "no such wireless interface: $IFACE, and no other wireless device to fall back to"
      iw dev | sed -n 's/^\tInterface /  /p'; exit 1
    fi
    echo "WARNING: no such wireless interface: $IFACE -- falling back to $ALT"
    echo "         pin it with SP_IFACE=$ALT if this is the adapter you want"
    IFACE=$ALT
  fi
  printf '%s\n' "$IFACE" >"$RUN_IFACE" 2>/dev/null || true
  MAC=${SP_MAC:-$("$PY" "$ROOT/linuxpass/sp_relay.py" identity --store "$STORE" 2>/dev/null)}
  case "$MAC" in
    ??:??:??:??:??:??) ;;
    *) echo "could not derive a MAC for store $STORE"; exit 1 ;;
  esac
  release_radio
  timeout 10 iw dev "$MON" del 2>/dev/null
  # ACTIVE MONITOR. `flags active` MUST be on the CREATE command: mac80211 allocates the per-vif
  # TXQ in ieee80211_if_add() only when MONITOR_FLAG_ACTIVE is present at that moment. Creating
  # plain and then `iw dev mon0 set monitor active` sets the flag but cannot retroactively
  # allocate the TXQ, and ath9k's ath_tx_node_init() then dereferences it -- an oops that wedges
  # the machine. That is not a guess: this box's own journal has it twice, 31 Aug 2026 21:03 and
  # 23:20, both `BUG: kernel NULL pointer dereference` at `ath_tx_node_init+0x41` reached through
  # ath9k_add_interface <- ieee80211_do_open, i.e. at `ip link set mon0 up`. Do not reintroduce
  # the two-step form.
  if ! timeout 15 iw dev "$IFACE" interface add "$MON" type monitor flags active; then
    echo "could not create an ACTIVE monitor interface on $IFACE"; exit 1
  fi
  timeout 10 ip link set "$MON" down
  timeout 10 ip link set "$MON" address "$MAC" || { echo "could not set $MON MAC"; exit 1; }
  # 1500 is too small for a full StreetPass data frame: radiotap(12) + 802.11(24) + CCMP(8) +
  # LLC/SNAP+pad(10) + YY(24) + payload(1452) + MIC(8) = 1538 handed to the socket, and
  # AF_PACKET rejects anything over the MTU with EMSGSIZE.
  timeout 10 ip link set "$MON" mtu 2000 2>/dev/null \
    || echo "WARNING: could not raise $MON MTU; 1452-byte segments will fail with EMSGSIZE"
  timeout 15 ip link set "$MON" up || { echo "could not bring $MON up"; exit 1; }
  timeout 15 ip link set "$IFACE" down 2>/dev/null    # the managed vif holds the channel otherwise
  echo "active monitor $MON up as $MAC (the hardware will ACK frames addressed to it)"
  ;;
down)
  # `up` may have substituted a different adapter than SP_IFACE names; hand back the one it
  # actually took, otherwise NetworkManager never regains control of the real device.
  [ -r "$RUN_IFACE" ] && IFACE=$(cat "$RUN_IFACE")
  timeout 10 iw dev "$MON" del 2>/dev/null
  restore_radio
  rm -f "$RUN_IFACE"
  echo "monitor $MON removed"
  ;;
*)
  echo "usage: sp_monitor.sh {up|down}"; exit 1 ;;
esac
