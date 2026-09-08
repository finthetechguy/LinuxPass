#!/usr/bin/env python3
"""Recover CEC messages a console sent us, out of an sp_link run log.

Capturing real messages off the air is the other half of a relay: it is how a Linux box acquires
content for titles it has no dump for. `sp_cecstore.py` reads messages out of a console's own save
image; this reads them out of an encounter.

The log records the decrypted plaintext of every frame the console sent, so the messages are all
there -- but a naive "concatenate the payloads in order" reassembly desynchronises the moment a
frame is repeated, which is exactly what happens on a long transfer. Place each payload at its own
YY `seq` instead, the way the receiver does (cecd 0x106E80 indexes by bytes-received), and start a
new object on the peer's SYN.
"""
import re, struct, sys, os, hmac, hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sp_yy, sp_cec

ENVELOPE_MAGIC = 0x6161
CONTAINER_MAGIC = 0x6060


def objects_from_log(path):
    """Every complete object the console sent, reassembled by seq. -> [bytes]"""
    out, buf, high = [], bytearray(), 0
    for line in open(path, errors='replace'):
        m = re.search(r'plaintext: ([0-9a-f]+)', line)
        if not m:
            continue
        y = sp_yy.parse(bytes.fromhex(m.group(1)))
        if not y or not y.get('ok'):
            continue
        f = y['flags']
        if f & sp_yy.SYN and not (f & sp_yy.ACK):     # peer opens a connection
            buf, high = bytearray(), 0
            continue
        pl = y.get('payload') or b''
        if not pl:
            continue
        seq = y['seq']
        if seq + len(pl) > len(buf):
            buf.extend(b'\x00' * (seq + len(pl) - len(buf)))
        buf[seq:seq + len(pl)] = pl                   # a repeat overwrites itself, harmlessly
        high = max(high, seq + len(pl))
        if f & sp_yy.URG:                             # END: a whole object, or a window flush
            cand = bytes(buf[:high])
            if _looks_complete(cand):
                out.append(cand)
                buf, high = bytearray(), 0
    return out


def _looks_complete(b):
    """An object is done when its own declared length is all there."""
    if len(b) >= 0x10 and b[:2] == b'\x63\x63':
        return len(b) >= 0x10 + struct.unpack_from('<I', b, 0x0C)[0]
    if len(b) >= 0x18 and struct.unpack_from('<H', b, 0)[0] == ENVELOPE_MAGIC:
        return len(b) >= struct.unpack_from('<I', b, 4)[0]
    return False


def messages_from_log(path):
    """Just the CEC messages, as bare 0x6060 containers. -> [(title, container)]"""
    out = []
    for o in objects_from_log(path):
        if len(o) < 0x14 + 0x70 or struct.unpack_from('<H', o, 0)[0] != ENVELOPE_MAGIC:
            continue
        if struct.unpack_from('<H', o, 0x14)[0] != CONTAINER_MAGIC:
            continue
        try:
            h = sp_cec.parse_header(o[0x14:])
        except ValueError:
            continue
        if h['total_size'] and len(o) >= 0x14 + h['total_size']:
            out.append((h['cec_title_id'], o[0x14:0x14 + h['total_size']]))
    return out


def verify(container, key):
    """-> True if the 0x20 trailer is HMAC-SHA256 over the body under `key`."""
    h = sp_cec.parse_header(container)
    body = container[h['header_size']:h['header_size'] + h['body_size']]
    tag = container[h['header_size'] + h['body_size']:h['total_size']]
    return len(tag) == 0x20 and hmac.new(key, body, hashlib.sha256).digest() == tag


def _selftest():
    ok = tot = 0

    def chk(n, c, g=''):
        nonlocal ok, tot
        tot += 1; ok += bool(c)
        print('  [%s] %s%s' % ('PASS' if c else 'FAIL', n, ('  %s' % (g,)) if g else ''))

    here = os.path.dirname(os.path.abspath(__file__))
    log = os.path.join(here, 'stage2_FOUR_TITLES.log')
    if not os.path.exists(log):
        print('  (no capture to test against)'); return 0
    msgs = messages_from_log(log)
    by = {t: c for t, c in msgs}
    chk('all three messages the console sent are recovered', len(msgs) == 3, len(msgs))
    chk('Mario Kart 7, Mii Plaza and Super Mario Maker',
        sorted(by) == [0x00020800, 0x00030600, 0x001A0400], ['%08X' % t for t in sorted(by)])
    for t, want in ((0x00030600, 0x377C), (0x00020800, 0x7FC8), (0x001A0400, 0x18D44)):
        if t in by:
            chk('%08X is its declared size' % t, len(by[t]) == want,
                '%#x vs %#x' % (len(by[t]), want))
    # the HMAC is the real integrity check: a mis-assembled body cannot pass it
    try:
        import sp_savefs, sp_cecstore
        pa = os.path.join(here, 'partitionA.bin')
        if os.path.exists(pa):
            fs = sp_savefs.SaveFS(open(pa, 'rb').read())
            keys = {k: v['hmac_key'] for k, v in sp_cecstore.title_metadata(fs).items()}
            for t, c in sorted(by.items()):
                if t in keys:
                    chk('%08X body verifies against its MBoxInfo key' % t, verify(c, keys[t]))
    except ImportError:
        pass
    print('\n%d/%d checks passed' % (ok, tot))
    return 0 if ok == tot else 1


if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] == '--selftest':
        sys.exit(_selftest())
    outdir = sys.argv[2] if len(sys.argv) > 2 else 'captured'
    os.makedirs(outdir, exist_ok=True)
    for t, c in messages_from_log(sys.argv[1]):
        h = sp_cec.parse_header(c)
        p = os.path.join(outdir, '%08X_%s.bin' % (t, c[0x20:0x28].hex()))
        open(p, 'wb').write(c)
        print('%-52s total=%#-8x body=%#-8x mode=%d' %
              (p, h['total_size'], h['body_size'], h['send_mode']))
