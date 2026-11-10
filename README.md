# LinuxPass

StreetPass a real Nintendo 3DS from a Linux device, with your own data.

Walk past a 3DS with LinuxPass running and the console treats it like any other 3DS. It exchanges
a StreetPass message, blinks its notification LED green, and exchanges title-specific data.

## Status

Research-grade, v0.1. LinuxPass has reached a green LED against retail hardware many times, but
it has rough edges. Only one radio driver is supported, the protocol work behind it is recent,
and a first StreetPass usually takes more than one attempt (see below).

Working end to end:

- A real 3DS receives CEC (StreetPass) data from Linux
  - The notification LED blinks green
  - Individual title data appears in the Notifications applet
- Linux receives CEC data from a 3DS
  - Saved on disk
  - Shown in the GUI's Inbox tab

## What it does

- Discovers 3DS consoles on channels 1, 6 and 11 and answers their StreetPass probes.
- Completes the real handshake, derives the CCMP link key, and holds an encrypted link.
- Exchanges CEC objects. It sends a Mii Plaza message it built itself and receives whatever the
  console offers, for every title both sides have enabled.
- Keeps received messages in a local store you can inspect.
- Runs as a systemd service with a watchdog, with a GTK4 GUI on top.

## What it does not do

- It does not relay other people's passes. A message it receives is never handed to another
  console. It exchanges your data, the way one console does with another.
- It does not touch your console's firmware, save data, or online account.
- It does not work over the internet. Everything is local radio.

## Hardware

| | |
|---|---|
| Radio | An ath9k card that supports active monitor mode. Nothing else will do. |
| Known not to work | MT7902, which will not inject at all. |
| Console | Any 3DS-family console: 3DS, 3DS XL, 2DS, New 3DS, New 2DS XL. Exchanging needs no homebrew, but dumping the keys needs GodMode9, which needs boot9strap. |

Active monitor mode matters because the card must send hardware ACKs for the console's frames.
Without them the console gives up partway through the handshake. The wiki page *Hardware* has the
details, including one driver bug to avoid.

## Dependencies

No Python packages are required. The daemon, the handshake, the CCMP crypto and every self-test
run on the standard library. `linuxpass/sp_aes.py` is a pure-Python AES-128/CCM implementation
used whenever a faster backend is missing. You need Python 3.10+, plus `iw` and `ip` from your
distribution.

Optional:

| Package | What it adds |
|---|---|
| `pycryptodome` | Faster AES. Nothing changes functionally. |
| `scapy` | Reading packet captures: `tools/sp_report.py`, `tools/sp_diag.py`, and the `--replay` modes. |
| `PyGObject` + GTK4 + libadwaita | The GUI. |

## You must supply your own keys

LinuxPass ships no console keys and cannot work without them. The protocol is authenticated and
encrypted with keys that live on the console, so you supply them from hardware you own. Sort this
out first.

You will need two files in `~/.config/linuxpass/`:

- `aes_keys.txt`: AES keyslots, dumped with GodMode9 on your own console.
- `linuxpass.keys`: two constants read out of your own dumps, written for you by
  `tools/lp_extract_keys.py`.

The installer copies them to `/etc/linuxpass/`, where the service looks for them. It does not
replace copies already there, so if you dump new ones, copy them across yourself.

Check what LinuxPass can currently see:

```sh
python3 tools/lp_extract_keys.py
```

The wiki page *Getting your keys* walks through both. [NOTICE.md](NOTICE.md) lists exactly what
is and is not in this repository.

## Quick start

```sh
git clone https://github.com/finthetechguy/LinuxPass && cd LinuxPass
mkdir -p ~/.config/linuxpass
install -m 600 /path/to/aes_keys.txt ~/.config/linuxpass/
python3 tools/lp_extract_keys.py --cecd /path/to/cecd/code.bin \
                                 --cec-store /path/to/your/CEC-partition.bin
sudo ./install/install.sh install       # copies the code to /opt/linuxpass, writes the unit, polkit rule and menu entry
sudo systemctl start linuxpass
journalctl -u linuxpass -f              # then walk a 3DS past the machine
```

Re-run the installer after updating your checkout, because the service runs from the copy in
`/opt/linuxpass`.

To watch it in a terminal instead, `sudo ./scripts/linuxpass` runs the same daemon in the
foreground. When you stop it, it hands the adapter back to NetworkManager. Without NetworkManager,
you need to bring the interface back up yourself.

## "It took three tries"

That is expected. Over 365 runs against two consoles, 34 to 44 percent of completed exchanges
needed more than one engagement. The console goes quiet after an aborted attempt and has to be
nudged into rescanning, which LinuxPass does automatically. If the first pass does nothing, leave
it running.

Before you file a bug, know that a console will exchange with a given peer address once. It
records who it has met and declines a second time. LinuxPass can rotate its own address to work
around this, but rotation is off by default. See the wiki page *The MAC filter*.

## Self-tests

The self-tests need no radio and no console:

```sh
python3 linuxpass/sp_relay.py selftest      # the daemon, the store, the control socket
python3 linuxpass/sp_link.py --selftest     # the handshake, the crypto, the frame builders
python3 linuxpass/sp_link.py --simulate     # a whole exchange, driven through the state machine
```

These pass on a fresh clone with no keys and no console data. Checks that need real hardware
captures report `[SKIP]` and say what is missing.

## Documentation

- [Wiki](https://github.com/finthetechguy/LinuxPass/wiki): setup, hardware, first StreetPass, CLI
  and GUI reference, troubleshooting.
- [docs/SCRIPTS.md](docs/SCRIPTS.md): what every file in the tree is for.
- [docs/SETUP.md](docs/SETUP.md): installation on one page.
- [docs/HARDWARE.md](docs/HARDWARE.md): radios, and why active monitor mode is required.

## Legal and ethical notes

LinuxPass is an independent reimplementation built through reverse engineering. It includes no
copied Nintendo code, console keyslots, retail HMAC keys or assets. See [NOTICE.md](NOTICE.md)
for the details, including two fixed values that do appear in the source.

Use it with your own consoles and with people who know what you are doing. A StreetPass exchange
carries real people's Mii names and greetings, so treat what you receive as their data and do not
publish it. Keep captures and key files out of bug reports (see [SECURITY.md](SECURITY.md)).

Nintendo, Nintendo 3DS and StreetPass are trademarks of Nintendo. This project is not affiliated
with or endorsed by Nintendo.

## Licence

[MIT](LICENSE).
