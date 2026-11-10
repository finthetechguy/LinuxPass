#!/usr/bin/env python3
"""Decode the 3DS `data:/CEC/MacFilter___` entry format from planted known plaintext."""
import argparse
import struct
import sys

PLANT = [
    ('ba:ae:6e:77:88:99', 1788626863.099),
    ('ba:ae:6e:c0:ff:11', 1788628155.579),
    ('ba:ae:6e:c0:ff:22', 1788628209.799),
    ('ba:ae:6e:c0:ff:33', 1788628264.485),
    ('ba:ae:6e:c0:ff:44', 1788628473.573),
    ('ba:ae:6e:c0:ff:55', 1788628585.995),
    ('ba:ae:6e:c0:ff:66', 1788628875.289),
    ('ba:ae:6e:c0:ff:77', 1788629206.837),
]

TOL = 10.0


def macbytes(s):
    return bytes(int(x, 16) for x in s.split(':'))


def macstr(b):
    return ':'.join('%02x' % c for c in b)


def find_entries(blob, plant=PLANT):
    """Locate each planted MAC in `blob`."""
    hits, reversed_hits = {}, {}
    for mac, _t in plant:
        mb = macbytes(mac)
        fwd, rev = [], []
        start = 0
        while True:
            i = blob.find(mb, start)
            if i < 0:
                break
            fwd.append(i)
            start = i + 1
        start = 0
        while True:
            i = blob.find(mb[::-1], start)
            if i < 0:
                break
            rev.append(i)
            start = i + 1
        hits[mac] = fwd
        reversed_hits[mac] = rev
    return hits, reversed_hits


def infer_stride(offsets):
    """Given sorted entry offsets, return (stride, consistent)."""
    if len(offsets) < 2:
        return None, False
    diffs = [b - a for a, b in zip(offsets, offsets[1:])]
    return diffs[0], all(d == diffs[0] for d in diffs)


def candidate_timefields(blob, entries, stride, tol=TOL):
    """Search every field position/width/endianness for one whose deltas match the recorded ones."""
    out = []
    if len(entries) < 3:
        return out
    base_t = entries[0][2]
    want = [e[2] - base_t for e in entries]
    for width, fmts in ((4, ('<I', '>I')), (8, ('<Q', '>Q'))):
        for rel in range(0, max(1, stride - width + 1)):
            for fmt in fmts:
                vals = []
                ok = True
                for _mac, off, _t in entries:
                    p = off + rel
                    if p + width > len(blob):
                        ok = False
                        break
                    vals.append(struct.unpack_from(fmt, blob, p)[0])
                if not ok:
                    continue
                for scale, unit in ((1.0, 's'), (1000.0, 'ms'), (1 / 60.0, 'min')):
                    got = [(v - vals[0]) / scale for v in vals]
                    resid = [g - w for g, w in zip(got, want)]
                    if all(abs(r) <= tol for r in resid):
                        out.append({'rel': rel, 'fmt': fmt, 'width': width, 'unit': unit,
                                    'scale': scale, 'values': vals,
                                    'resid': resid, 'max_resid': max(abs(r) for r in resid)})
    return out


HEADER_DOC = """The 20-byte header, already decoded from the 1-2 Sep dumps (see the
cec-macfilter-format note): +0x00 MAC, +0x06 two bytes the loader never reads, +0x08 u32 year,
+0x0C month/day/day-of-week/hour, +0x10 minute/second/u16 milliseconds."""


def decode_header(blob):
    """Decode the 20-byte header using the layout recovered from the 1-2 Sep dumps."""
    if len(blob) < 20:
        return None
    mac = macstr(blob[0:6])
    unread = blob[6:8]
    year = struct.unpack_from('<I', blob, 8)[0]
    month, day, dow, hour = blob[12], blob[13], blob[14], blob[15]
    minute, second = blob[16], blob[17]
    ms = struct.unpack_from('<H', blob, 18)[0]
    d = {'mac': mac, 'unread': unread.hex(), 'year': year, 'month': month, 'day': day,
         'dow': dow, 'hour': hour, 'minute': minute, 'second': second, 'ms': ms}
    try:
        import datetime
        dt = datetime.datetime(year, month, day, hour, minute, second)
        d['iso'] = dt.isoformat()
        d['dow_py_mon0'] = dt.weekday()
        d['dow_sun0'] = (dt.weekday() + 1) % 7
        d['dow_consistent'] = dow in (dt.weekday(), (dt.weekday() + 1) % 7)
    except (ValueError, OverflowError) as e:
        d['iso'] = None
        d['error'] = str(e)
        d['dow_consistent'] = False
    return d


def report(blob, plant=PLANT, tol=TOL, out=sys.stdout):
    p = lambda *a: print(*a, file=out)
    p('file size: %d bytes (0x%X)' % (len(blob), len(blob)))
    p('')
    p('first 32 bytes: %s' % blob[:32].hex())
    p('')
    h = decode_header(blob)
    if h:
        p('header (layout from the 1-2 Sep dumps):')
        p('  MAC        %s' % h['mac'])
        p('  +0x06      %s   (never read by the loader)' % h['unread'])
        p('  timestamp  %s  .%03d ms' % (h.get('iso') or 'INVALID', h['ms']))
        p('  day-of-week byte %d -> %s (Mon=0 gives %s, Sun=0 gives %s)'
          % (h['dow'], 'CONSISTENT' if h['dow_consistent'] else 'INCONSISTENT',
             h.get('dow_py_mon0'), h.get('dow_sun0')))
        if plant:
            last_mac, last_t = max(plant, key=lambda e: e[1])
            p('  expected, if the header records the LAST exchange: %s at %s'
              % (last_mac, __import__('datetime').datetime.fromtimestamp(last_t)
                 .strftime('%Y-%m-%dT%H:%M:%S')))
            p('  header MAC matches that: %s' % (h['mac'] == last_mac))
    p('')

    hits, rev = find_entries(blob, plant)
    n_fwd = sum(len(v) for v in hits.values())
    n_rev = sum(len(v) for v in rev.values())
    p('planted MACs found: %d forwards, %d reversed' % (n_fwd, n_rev))
    if n_fwd == 0 and n_rev > 0:
        p('  -> entries store the MAC REVERSED; re-run interpreting it that way')
        hits = rev
        n_fwd = n_rev
    if n_fwd == 0:
        p('  -> NONE of the planted MACs appear in this file.')
        p('     Either this is not the filter that was written, or entries are not stored as')
        p('     plain MACs. Do not guess further from here. Dump the surrounding bytes.')
        return None

    found = []
    for mac, t in plant:
        for off in hits.get(mac, []):
            found.append((mac, off, t))
    found.sort(key=lambda e: e[1])

    p('')
    p('%-20s %-8s %-12s %s' % ('MAC', 'offset', 'recorded', 'entry bytes'))
    for mac, off, t in found:
        p('%-20s 0x%04X   %.3f  (see stride below)' % (mac, off, t))

    missing = [m for m, _t in plant if not hits.get(m)]
    if missing:
        p('')
        p('NOT PRESENT: %s' % ', '.join(missing))

    dupes = {m: v for m, v in hits.items() if len(v) > 1}
    if dupes:
        p('')
        for m, v in dupes.items():
            p('APPEARS %d TIMES: %s at %s  -> a repeat exchange APPENDS rather than updates'
              % (len(v), m, ', '.join('0x%04X' % o for o in v)))
    else:
        p('')
        p('every planted MAC appears exactly once')

    offs = [e[1] for e in found]
    stride, consistent = infer_stride(offs)
    p('')
    if stride is None:
        p('stride: indeterminate (need >= 2 entries)')
        return None
    p('stride: %d bytes%s' % (stride, '' if consistent else '  (not constant; see diffs)'))
    if not consistent:
        p('  offset diffs: %s' % [b - a for a, b in zip(offs, offs[1:])])
    p('first entry begins at 0x%04X, so the header is %d bytes' % (offs[0], offs[0]))

    p('')
    p('entry bytes (stride %d, MAC highlighted by position):' % stride)
    for mac, off, _t in found:
        p('  0x%04X  %s' % (off, blob[off:off + stride].hex(' ')))

    if consistent:
        p('')
        cands = candidate_timefields(blob, found, stride, tol)
        if not cands:
            p('no field in the entry reproduces the recorded time deltas.')
            p('  Deltas sought (s, from the first entry): %s'
              % ['%.0f' % (e[2] - found[0][2]) for e in found])
            p('  A field that merely looks date-shaped is deliberately NOT accepted here.')
        else:
            cands.sort(key=lambda c: c['max_resid'])
            p('TIMESTAMP FIELD(S) that reproduce the recorded deltas:')
            for c in cands:
                p('  entry+0x%02X  %s (%d B)  unit=%s  max residual %.2f s'
                  % (c['rel'], c['fmt'], c['width'], c['unit'], c['max_resid']))
                p('      values: %s' % [hex(v) for v in c['values']])
                base_epoch = found[0][2] - c['values'][0] / c['scale']
                p('      implied epoch: value 0 == %.0f (unix)' % base_epoch)
    return found


def _synth_header(mac, when):
    import datetime
    dt = datetime.datetime.fromtimestamp(when)
    b = bytearray(20)
    b[0:6] = macbytes(mac)
    b[6:8] = b'\x00\x30'
    struct.pack_into('<I', b, 8, dt.year)
    b[12], b[13], b[14], b[15] = dt.month, dt.day, dt.weekday(), dt.hour
    b[16], b[17] = dt.minute, dt.second
    struct.pack_into('<H', b, 18, 0)
    return bytes(b)


def _synth(header=20, stride=20, tfield=12, fmt='<I', epoch=946684800.0, plant=PLANT):
    """Build a synthetic filter with a known layout, to prove the decoder finds it."""
    blob = bytearray(b'\x5a' * header)
    for mac, t in plant:
        e = bytearray(b'\x00' * stride)
        e[0:6] = macbytes(mac)
        struct.pack_into(fmt, e, tfield, int(t - epoch))
        blob += e
    return bytes(blob)


def selftest():
    import io
    checks = []

    def chk(name, cond):
        checks.append((name, bool(cond)))

    lm, lt = max(PLANT, key=lambda e: e[1])
    hb = _synth_header(lm, lt) + b'\x00' * 40
    h = decode_header(hb)
    chk('header MAC decodes', h['mac'] == lm)
    chk('header date decodes', h['iso'].startswith('2026-09-05T18:26:46'))
    chk('header day-of-week is consistent', h['dow_consistent'])
    chk('header rejects an impossible date', decode_header(b'\xff' * 20)['dow_consistent'] is False)

    b = _synth()
    out = io.StringIO()
    found = report(b, out=out)
    s = out.getvalue()
    chk('finds all 8 planted MACs', found is not None and len(found) == 8)
    chk('reports the 20-byte stride', 'stride: 20 bytes' in s)
    chk('reports the 20-byte header', 'header is 20 bytes' in s)
    chk('recovers the timestamp field at +0x0C', 'entry+0x0C' in s)
    chk('recovers the epoch', 'implied epoch: value 0 == 946684800' in s)
    chk('says each MAC appears once', 'exactly once' in s)

    b2 = _synth(header=8, stride=24, tfield=16, fmt='>I')
    out2 = io.StringIO()
    report(b2, out=out2)
    s2 = out2.getvalue()
    chk('handles a 24-byte stride', 'stride: 24 bytes' in s2)
    chk('handles an 8-byte header', 'header is 8 bytes' in s2)
    chk('handles big-endian time', "entry+0x10  >I" in s2)

    b3 = bytearray(_synth())
    for mac, _t in PLANT:
        i = b3.find(macbytes(mac))
        b3[i:i + 6] = macbytes(mac)[::-1]
    out3 = io.StringIO()
    report(bytes(b3), out=out3)
    chk('detects reversed MAC storage', 'store the MAC REVERSED' in out3.getvalue())

    import random
    random.seed(1)
    b4 = bytes(random.getrandbits(8) for _ in range(1551))
    out4 = io.StringIO()
    r4 = report(b4, out=out4)
    chk('finds nothing in random data', r4 is None and 'NONE of the planted MACs' in out4.getvalue())

    b5 = _synth(tfield=12, fmt='<I', epoch=0)
    b5 = bytearray(b5)
    for i in range(20, len(b5)):
        if (i - 20) % 20 >= 12:
            b5[i] = 0x77
    out5 = io.StringIO()
    report(bytes(b5), out=out5)
    chk('refuses to claim a timestamp when deltas do not match',
        'no field in the entry reproduces' in out5.getvalue())

    ok = sum(1 for _n, c in checks if c)
    for n, c in checks:
        print('%s  %s' % ('ok  ' if c else 'FAIL', n))
    print('%d/%d checks passed' % (ok, len(checks)))
    return 0 if ok == len(checks) else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('path', nargs='?', help='the MacFilter___ file')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--tol', type=float, default=TOL, help='delta tolerance in seconds')
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.path:
        ap.error('give a MacFilter___ file, or --selftest')
    with open(a.path, 'rb') as f:
        report(f.read(), tol=a.tol)
    return 0


if __name__ == '__main__':
    sys.exit(main())
