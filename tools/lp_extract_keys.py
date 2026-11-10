#!/usr/bin/env python3
"""Write linuxpass.keys by reading constants out of your own console dumps."""
import argparse
import os
import string
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'linuxpass'))

import lp_keys as keys                                              # noqa: E402

# The development key is a generic string that marks where the retail key sits.
DEV_NEEDLE = (string.digits + 'abcdef').encode('ascii') + b'\x00'
SLOT_STRIDE = 0x14          # the two keys sit in adjacent 4-byte-aligned 20-byte slots
KEY_CHARS = 16
PRINTABLE = set(string.ascii_letters.encode() + string.digits.encode() + b'_-.')


def extract_cecd(path, offset=None):
    """-> {'cecd_hmac_retail': b'...', 'cecd_hmac_dev': b'...'} from a cecd code.bin."""
    with open(path, 'rb') as fh:
        data = fh.read()
    if offset is not None:
        dev_off = offset + SLOT_STRIDE
    else:
        dev_off = data.find(DEV_NEEDLE)
        if dev_off < 0:
            raise SystemExit(
                'error: %s does not look like a decrypted cecd code.bin -- the development\n'
                '       key string is not in it. Is the module still encrypted?' % path)
        if data.find(DEV_NEEDLE, dev_off + 1) >= 0:
            print('warning: more than one candidate found; using the first at %#x' % dev_off,
                  file=sys.stderr)
    retail_off = dev_off - SLOT_STRIDE
    if retail_off < 0:
        raise SystemExit('error: no room for the retail key before offset %#x' % dev_off)
    retail = data[retail_off:retail_off + KEY_CHARS]
    dev = data[dev_off:dev_off + KEY_CHARS]
    if not set(retail) <= PRINTABLE or data[retail_off + KEY_CHARS] != 0:
        raise SystemExit(
            'error: the 16 bytes before the development key are not a NUL-terminated ASCII\n'
            '       string (%r). This cecd build may lay them out differently; find the\n'
            '       retail string yourself and pass --cecd-offset.' % retail)
    print('  cecd retail key found at %#x (module VA %#x)' % (retail_off, retail_off + 0x100000))
    print('  cecd dev    key found at %#x (module VA %#x)' % (dev_off, dev_off + 0x100000))
    return {'cecd_hmac_retail': retail, 'cecd_hmac_dev': dev}


def extract_cec_store(path):
    """-> {'title_hmac_XXXXXXXX': b'...'} for every title in a CEC store."""
    import sp_cecstore
    if os.path.isdir(path):
        boxes = {}
        for root, _dirs, names in os.walk(path):
            if 'MBoxInfo____' not in names:
                continue
            try:
                tid = int(os.path.basename(root), 16)
            except ValueError:
                continue
            with open(os.path.join(root, 'MBoxInfo____'), 'rb') as fh:
                try:
                    info = sp_cecstore.parse_mboxinfo(fh.read())
                except ValueError:
                    continue
            boxes[tid] = {'name': None, 'hmac_key': info['hmac_key']}
        if not boxes:
            raise SystemExit('error: %s holds no MBoxInfo____ files' % path)
    else:
        boxes = sp_cecstore.title_metadata(path)
    out = {}
    for tid, info in sorted(boxes.items()):
        k = info.get('hmac_key')
        if not k or len(k) != 32:
            continue
        if k == b'\x00' * 32:
            print('  title %08X %-32s all-zero key, skipped'
                  % (tid, (info.get('name') or '')[:32]))
            continue
        out['title_hmac_%08X' % tid] = k
        print('  title %08X %-32s key recovered' % (tid, (info.get('name') or '')[:32]))
    if not out:
        raise SystemExit('error: no usable HMAC keys in %s' % path)
    return out


def render(values):
    lines = ['# linuxpass.keys -- constants read out of your own console dumps.',
             '# Written by tools/lp_extract_keys.py. Treat this file as private:',
             '# it is console-derived material and must never be committed or shared.',
             '']
    for name in sorted(values):
        v = values[name]
        if name.startswith('cecd_hmac'):
            lines.append('%-24s = "%s"' % (name, v.decode('ascii').rstrip('\x00')))
        else:
            lines.append('%-24s = %s' % (name, v.hex()))
    return '\n'.join(lines) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='Write linuxpass.keys from your own console dumps.',
        epilog='Run with no source and it just reports what LinuxPass can currently find.')
    ap.add_argument('--cecd', metavar='CODE_BIN',
                    help='decrypted cecd code.bin -- supplies the CCMP HMAC key strings')
    ap.add_argument('--cecd-offset', type=lambda s: int(s, 0), metavar='OFF',
                    help='file offset of the retail key, if the search cannot find it')
    ap.add_argument('--cec-store', metavar='PATH',
                    help='a CEC SAVE image or extracted store -- supplies title HMAC keys')
    ap.add_argument('-o', '--output', metavar='PATH',
                    help='where to write (default: ~/.config/linuxpass/linuxpass.keys)')
    ap.add_argument('--stdout', action='store_true', help='print instead of writing a file')
    ap.add_argument('--force', action='store_true', help='overwrite an existing file')
    a = ap.parse_args(argv)

    if not a.cecd and not a.cec_store:
        ok, report = keys.status()
        print('\n'.join(report))
        print('\n%s' % ('all key material present' if ok else
                        'incomplete -- pass --cecd and/or --cec-store to fill the gaps'))
        return 0 if ok else 1

    values = {}
    if a.cecd:
        print('reading %s' % a.cecd)
        values.update(extract_cecd(a.cecd, a.cecd_offset))
    if a.cec_store:
        print('reading %s' % a.cec_store)
        values.update(extract_cec_store(a.cec_store))

    existing = keys.constants()
    merged = dict(existing)
    merged.update(values)

    text = render(merged)
    if a.stdout:
        sys.stdout.write(text)
        return 0

    out = a.output or os.path.join(
        os.environ.get('XDG_CONFIG_HOME') or os.path.join(os.path.expanduser('~'), '.config'),
        'linuxpass', keys.CONSTANTS_FILE)
    if os.path.exists(out) and not a.force and not existing:
        raise SystemExit('error: %s exists; pass --force to overwrite' % out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as fh:
        fh.write(text)
    print('\nwrote %d value(s) to %s (mode 0600)' % (len(merged), out))
    ok, report = keys.status()
    print('\n'.join(report))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
