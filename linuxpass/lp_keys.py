#!/usr/bin/env python3
"""Console-derived key material, loaded at runtime from files you produce."""
import os
import re
import sys

CONFIG_DIR_NAME = 'linuxpass'
AES_KEYS_FILE = 'aes_keys.txt'
CONSTANTS_FILE = 'linuxpass.keys'
SYSTEM_DIR = '/etc/linuxpass'

# Public constant from 3dbrew, identical on every console.
SCRAMBLER_C = 0x1FF9E9AAC5FE0408024591DC5D52768A

_WIKI = 'https://github.com/finthetechguy/LinuxPass/wiki/Getting-your-keys'


class MissingKey(Exception):
    """A console-derived value was needed and no file supplied it."""


def _config_dir():
    base = os.environ.get('XDG_CONFIG_HOME') or os.path.join(os.path.expanduser('~'), '.config')
    return os.path.join(base, CONFIG_DIR_NAME)


def search_paths(filename, explicit=None):
    """Every path `filename` is looked for, in order. Used by the error messages too."""
    out = []
    if explicit:
        out.append(explicit if os.path.isdir(explicit) is False else os.path.join(explicit, filename))
    env = os.environ.get('LINUXPASS_KEYS' if filename == AES_KEYS_FILE else 'LINUXPASS_KEYFILE')
    if env:
        out.append(env if not os.path.isdir(env) else os.path.join(env, filename))
    envdir = os.environ.get('LINUXPASS_KEYDIR')
    if envdir:
        out.append(os.path.join(envdir, filename))
    out.append(os.path.join(_config_dir(), filename))
    out.append(os.path.join(SYSTEM_DIR, filename))
    out.append(os.path.join(os.getcwd(), filename))
    seen, uniq = set(), []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def locate(filename, explicit=None):
    """First existing path for `filename`, or None."""
    for p in search_paths(filename, explicit):
        if os.path.isfile(p):
            return p
    return None


def _missing(what, filename, how, explicit=None):
    where = '\n'.join('      %s' % p for p in search_paths(filename, explicit))
    return MissingKey(
        "LinuxPass needs %s, which comes from your own console and is not shipped.\n"
        "\n"
        "  Expected it in %s. Looked in:\n%s\n"
        "\n"
        "  To produce that file:\n      %s\n"
        "\n"
        "  See %s\n" % (what, filename, where, how, _WIKI))


_AES_CACHE = {}

_SLOT_RE = re.compile(r'^\s*slot0x([0-9A-Fa-f]{2})Key([XYN])\s*=\s*([0-9A-Fa-f]{32})\s*$')
_NAMED_RE = re.compile(r'^\s*([A-Za-z][A-Za-z0-9_]*)\s*=\s*([0-9A-Fa-f]{32})\s*$')


def aes_keys(explicit=None, required=True):
    """Parse the GodMode9 aes_keys.txt dump into {'slot0x2EKeyX': b'...', ...}."""
    path = locate(AES_KEYS_FILE, explicit)
    if path is None:
        if not required:
            return {}
        raise _missing('an AES keyslot dump', AES_KEYS_FILE,
                       'Boot GodMode9 on your console, press HOME -> Scripts -> GM9Megascript\n'
                       '      -> Dump options -> "Dump aes_keys.txt", then copy the file off the SD card.',
                       explicit)
    key = (path, os.path.getmtime(path))
    if key in _AES_CACHE:
        return _AES_CACHE[key]
    out = {}
    with open(path, 'r', errors='replace') as fh:
        for line in fh:
            line = line.split('#', 1)[0]
            m = _SLOT_RE.match(line)
            if m:
                out['slot0x%sKey%s' % (m.group(1).upper(), m.group(2).upper())] = bytes.fromhex(m.group(3))
                continue
            m = _NAMED_RE.match(line)
            if m:
                out[m.group(1)] = bytes.fromhex(m.group(2))
    _AES_CACHE.clear()
    _AES_CACHE[key] = out
    return out


def have_aes_keys(explicit=None):
    return locate(AES_KEYS_FILE, explicit) is not None


def slot(number, half, explicit=None):
    """One raw keyslot half, e.g. slot(0x2E, 'X'). Raises MissingKey if absent."""
    name = 'slot0x%02XKey%s' % (number, half.upper())
    ks = aes_keys(explicit)
    if name not in ks:
        raise _missing('keyslot %s' % name, AES_KEYS_FILE,
                       'Re-dump aes_keys.txt with GodMode9 -- the dump you have is missing this slot.',
                       explicit)
    return ks[name]


def _rol128(v, n):
    n &= 127
    return ((v << n) | (v >> (128 - n))) & ((1 << 128) - 1)


def keyscrambler(key_x, key_y):
    """The 3DS AES key scrambler: (KeyX, KeyY) -> the normal key the hardware uses."""
    x = int.from_bytes(key_x, 'big')
    y = int.from_bytes(key_y, 'big')
    n = _rol128((_rol128(x, 2) ^ y) + SCRAMBLER_C, 87)
    return n.to_bytes(16, 'big')


def normalkey(number, explicit=None):
    """The normal key for an AES keyslot, derived from your KeyX/KeyY."""
    ks = aes_keys(explicit)
    direct = 'slot0x%02XKeyN' % number
    if direct in ks:
        return ks[direct]
    return keyscrambler(slot(number, 'X', explicit), slot(number, 'Y', explicit))


def normalkey_2e(explicit=None):
    """Keyslot 0x2E: the slot cecd runs the StreetPass CCMP link key through."""
    return normalkey(0x2E, explicit)


def apt_key(explicit=None):
    """Keyslot 0x31: the APT key that wraps the CFPB Mii container."""
    return normalkey(0x31, explicit)


_CONST_CACHE = {}
_CONST_RE = re.compile(r'^\s*([A-Za-z][A-Za-z0-9_.]*)\s*=\s*(.+?)\s*$')


def constants(explicit=None, required=False):
    """Parse linuxpass.keys into {name: bytes}."""
    path = locate(CONSTANTS_FILE, explicit)
    if path is None:
        if not required:
            return {}
        raise _missing('extracted binary constants', CONSTANTS_FILE,
                       'python3 tools/lp_extract_keys.py --cecd <your cecd code.bin> '
                       '--cec-store <your CEC store dir>', explicit)
    ck = (path, os.path.getmtime(path))
    if ck in _CONST_CACHE:
        return _CONST_CACHE[ck]
    out = {}
    with open(path, 'r', errors='replace') as fh:
        for line in fh:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            m = _CONST_RE.match(line)
            if not m:
                continue
            name, raw = m.group(1), m.group(2)
            if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in '"\'':
                body = raw[1:-1].replace('\\0', '\x00').replace('\\x00', '\x00')
                out[name] = body.encode('latin-1')
            elif re.fullmatch(r'[0-9A-Fa-f]+', raw) and len(raw) % 2 == 0:
                out[name] = bytes.fromhex(raw)
    _CONST_CACHE.clear()
    _CONST_CACHE[ck] = out
    return out


def have_constants(explicit=None):
    return locate(CONSTANTS_FILE, explicit) is not None


def constant(name, what, how, explicit=None):
    c = constants(explicit)
    if name not in c:
        raise _missing(what, CONSTANTS_FILE, how, explicit)
    return c[name]


def cecd_hmac_key(dev=False, explicit=None):
    """cecd's 17-byte HMAC key (16 ASCII characters plus the trailing NUL)."""
    name = 'cecd_hmac_dev' if dev else 'cecd_hmac_retail'
    k = constant(name, 'cecd\'s %s HMAC key string' % ('dev' if dev else 'retail'),
                 'python3 tools/lp_extract_keys.py --cecd <your cecd code.bin>', explicit)
    if len(k) == 16:
        k += b'\x00'      # the key length cecd passes is 0x11: the NUL is part of the key
    if len(k) != 17:
        raise MissingKey('%s in %s must be 16 characters (or 17 including the NUL), got %d'
                         % (name, CONSTANTS_FILE, len(k)))
    return k


def title_hmac_key(title_id, explicit=None):
    """A CEC title's 32-byte message HMAC key."""
    name = 'title_hmac_%08X' % title_id
    return constant(name, 'the message HMAC key for CEC title %08X' % title_id,
                    'python3 tools/lp_extract_keys.py --cec-store <your CEC store dir>', explicit)


PLAZA_TITLE_ID = 0x00020800


def plaza_hmac_key(explicit=None):
    """Mii Plaza's message HMAC key, from your console's CEC store."""
    return title_hmac_key(PLAZA_TITLE_ID, explicit)


def install_test_keys(directory, seed=0x1105):
    """Write a throwaway key set into `directory` and point the loader at it."""
    import random
    rnd = random.Random(seed)

    def hx(n):
        return bytes(rnd.getrandbits(8) for _ in range(n)).hex()

    os.makedirs(directory, exist_ok=True)
    lines = ['# THROWAWAY self-test keys -- generated, not real. See lp_keys.install_test_keys.']
    for n in (0x2C, 0x2D, 0x2E, 0x2F, 0x31):
        lines.append('slot0x%02XKeyX=%s' % (n, hx(16)))
        lines.append('slot0x%02XKeyY=%s' % (n, hx(16)))
    with open(os.path.join(directory, AES_KEYS_FILE), 'w') as fh:
        fh.write('\n'.join(lines) + '\n')

    with open(os.path.join(directory, CONSTANTS_FILE), 'w') as fh:
        fh.write('# THROWAWAY self-test constants -- generated, not real.\n'
                 'cecd_hmac_retail = "LinuxPassSelfTes"\n'
                 'cecd_hmac_dev    = "LinuxPassSelfDev"\n'
                 'title_hmac_%08X = %s\n'
                 'title_hmac_%08X = %s\n'
                 % (PLAZA_TITLE_ID, hx(32), 0x00030600, hx(32)))

    os.environ['LINUXPASS_KEYDIR'] = directory
    _AES_CACHE.clear()
    _CONST_CACHE.clear()
    return directory


def selftest_keys():
    """Make sure a self-test has key material, without ever inventing it silently."""
    if have_aes_keys() and have_constants():
        return False
    import tempfile
    install_test_keys(os.path.join(tempfile.mkdtemp(prefix='linuxpass-selftest-'), 'keys'))
    return True


def status(explicit=None):
    """(ok, lines) describing what is present. Used by `linuxpass keys` and the GUI."""
    lines = []
    ok = True
    ap = locate(AES_KEYS_FILE, explicit)
    lines.append('%-16s %s' % (AES_KEYS_FILE, ap or 'NOT FOUND'))
    if ap:
        ks = aes_keys(explicit)
        for n in (0x2E, 0x31):
            present = ('slot0x%02XKeyX' % n) in ks and ('slot0x%02XKeyY' % n) in ks
            present = present or ('slot0x%02XKeyN' % n) in ks
            lines.append('    keyslot 0x%02X    %s' % (n, 'present' if present else 'MISSING'))
            ok = ok and present
    else:
        ok = False
    cp = locate(CONSTANTS_FILE, explicit)
    lines.append('%-16s %s' % (CONSTANTS_FILE, cp or 'NOT FOUND'))
    if cp:
        c = constants(explicit)
        for n in ('cecd_hmac_retail', 'title_hmac_%08X' % PLAZA_TITLE_ID):
            lines.append('    %-22s %s' % (n, 'present' if n in c else 'MISSING'))
            ok = ok and (n in c)
    else:
        ok = False
    return ok, lines


if __name__ == '__main__':
    good, report = status()
    print('\n'.join(report))
    print('\n%s' % ('all key material present' if good
                    else 'incomplete -- see the wiki page "Getting your keys"'))
    sys.exit(0 if good else 1)
