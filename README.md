# LinuxPass

**StreetPass a real Nintendo 3DS from a Linux device, with your own data.**

Walk past a 3DS with LinuxPass running and the console does what it does for any other 3DS:
it exchanges a StreetPass message, blinks its notification LED green, and exchanges title-specific
data.

## Status

**Research-grade, v0.1.** It works, end to end, and it has been driven to a green LED against
retail hardware many times. It also has sharp edges: one radio driver is supported, the
protocol reconstruction behind it is recent, and a first StreetPass usually takes more than
one attempt (see below — that is normal, not a bug).

**Working from end-to-end**
- Real 3DS recieves CEC (StreetPass) data from Linux
  - Notification LED blinks green - successful
  - Invidual title data shown in Notifications applet
- Linux recieves CEC data from 3DS
  - Saved on disk
  - Shown in GUI ('Inbox' tab)

## What it does

- Discovers 3DS consoles on channels 1, 6 and 11 and answers their StreetPass probes.
- Completes the real handshake, derives the CCMP link key, and holds an encrypted link.
- Exchanges CEC objects: it sends a Mii Plaza message it built itself and receives whatever
  the console offers, for every title both sides have enabled.
- Keeps received messages in a local store you can inspect.
- Runs as a systemd service with a watchdog, with a GTK4 GUI on top.

## What it does not do

- **It is not a relay of other people's passes.** A message it receives is never handed to
  another console. It exchanges *your* data, the way one console does with another.
- It does not touch your console's firmware, save data, or online account.
- It does not work over the internet. Everything is local radio.

## Hardware

| | |
|---|---|
| **Radio** | An **ath9k** card that supports *active* monitor mode. This is a requirement, not a preference. |
| **Known not to work** | MT7902 — it will not inject at all. |
| **Console** | Any 3DS-family console: 3DS, 3DS XL, 2DS, New 3DS, New 2DS XL. Retail firmware is fine. |

Active monitor mode matters because the card must send hardware ACKs for the console's frames.
Without them the console gives up mid-handshake. The wiki page *Hardware* has the details,
including the one driver bug to avoid.

## Dependencies

**None are required.** The daemon, the handshake, the CCMP crypto and every self-test run on
the Python standard library alone — `linuxpass/sp_aes.py` is a pure-Python AES-128/CCM
implementation that takes over whenever a faster backend is missing. You need Python 3.10+,
plus `iw` and `ip` from your distribution.

Optional:

| Package | Buys you |
|---|---|
| `pycryptodome` | Faster AES. Nothing changes functionally. |
| `scapy` | Reading packet captures: `tools/sp_report.py`, `tools/sp_diag.py`, and the `--replay` modes. |
| `PyGObject` + GTK4 + libadwaita | The GUI. |

## You must supply your own keys

LinuxPass ships **no key material**, and it cannot work without some. The protocol is
authenticated and encrypted with keys that live on the console, so you supply them from
hardware you own. This is the first thing to sort out, not a surprise for later.

You will need two files in `~/.config/linuxpass/`:

- **`aes_keys.txt`** — AES keyslots, dumped with GodMode9 on your own console.
- **`linuxpass.keys`** — two constants read out of your own dumps, written for you by
  `tools/lp_extract_keys.py`.

Check what LinuxPass can currently see:

```sh
python3 tools/lp_extract_keys.py
```

The wiki page *Getting your keys* walks through both. See [NOTICE.md](NOTICE.md) for exactly
what is and is not in this repository, and why.

## Quick start

```sh
git clone https://github.com/<owner>/LinuxPass && cd LinuxPass
python3 tools/lp_extract_keys.py --cecd /path/to/cecd/code.bin \
                                 --cec-store /path/to/your/CEC-partition.bin
sudo ./install/install.sh install       # writes the unit, the polkit rule and a menu entry
sudo systemctl start linuxpass
journalctl -u linuxpass -f              # then walk a 3DS past the machine
```

Prefer to watch it rather than run it as a service? `sudo ./scripts/linuxpass` runs the same
daemon in the foreground and puts your networking back when you stop it.

## "It took three tries"

That is the expected behaviour, not a fault. Measured over 365 runs against two consoles,
**34–44 % of completed exchanges needed more than one engagement** — the console goes quiet
after an aborted attempt and has to be nudged into rescanning, which LinuxPass does
automatically. If the first pass does nothing, leave it running.

The other rule worth knowing before you file a bug: **a console will exchange with a given
peer address once**. It records who it has met and declines a second time. LinuxPass rotates
its own identity to work around this — see the wiki page *The MAC filter*.

## Self-tests

Everything is testable without a radio and without a console:

```sh
python3 linuxpass/sp_relay.py selftest      # the daemon, the store, the control socket
python3 linuxpass/sp_link.py --selftest     # the handshake, the crypto, the frame builders
python3 linuxpass/sp_link.py --simulate     # a whole exchange, driven through the state machine
```

These pass on a fresh clone with no keys and no console data. Checks that genuinely need real
hardware captures report `[SKIP]` and say what is missing.

## Documentation

- **[Wiki](https://github.com/<owner>/LinuxPass/wiki)** — setup, hardware, first StreetPass,
  CLI and GUI reference, troubleshooting.
- **[docs/SCRIPTS.md](docs/SCRIPTS.md)** — what every file in the tree is for.
- **[docs/SETUP.md](docs/SETUP.md)** — installation in one page.
- **[docs/HARDWARE.md](docs/HARDWARE.md)** — radios, and why active monitor mode.

## Legal and ethical notes

This is clean-room interoperability work: the protocol was reconstructed by observation and
analysis, and reimplemented. No Nintendo code, keys or assets are included — see
[NOTICE.md](NOTICE.md).

Use it with your own consoles and with people who know what you are doing. A StreetPass
exchange carries real people's Mii names and greetings; treat what you receive as their data,
not yours to publish. Do not put captures or key files in bug reports — see
[SECURITY.md](SECURITY.md).

Nintendo, Nintendo 3DS and StreetPass are trademarks of Nintendo. This project is not
affiliated with or endorsed by Nintendo.

## Licence

[MIT](LICENSE).
