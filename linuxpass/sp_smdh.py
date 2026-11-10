#!/usr/bin/env python3
"""Plaza body regions A and B: the featured title's SMDH (metadata + icons)."""
import struct

REGION_A_OFF, REGION_A_LEN = 0x0000, 0x2038
REGION_B_OFF, REGION_B_LEN = 0x2038, 0x1680
TITLES_OFF, TITLE_STRIDE, N_LANG = 0x30, 0x200, 16
SHORT_LEN, LONG_LEN, PUB_LEN = 0x80, 0x100, 0x80
SMALL_ICON_OFF, SMALL_ICON_DIM = 0x0000, 24
LARGE_ICON_OFF, LARGE_ICON_DIM = 0x0480, 48
NO_TITLE = 0xFFFFFFFFFFFFFFFF


def _utf16z(b): return b.decode('utf-16-le', 'replace').split('\x00', 1)[0]


def _morton8(i):
    """3DS 8x8 tile Z-order: interleaved bits -> (x, y)."""
    x = y = 0
    for b in range(3):
        x |= ((i >> (2 * b)) & 1) << b
        y |= ((i >> (2 * b + 1)) & 1) << b
    return x, y


def parse_region_a(body):
    a = body[REGION_A_OFF:REGION_A_OFF + REGION_A_LEN]
    if len(a) < REGION_A_LEN:
        raise ValueError('region A truncated: %#x' % len(a))
    tid = struct.unpack_from('<Q', a, 0)[0]
    titles = []
    for i in range(N_LANG):
        b = TITLES_OFF + i * TITLE_STRIDE
        titles.append({'short': _utf16z(a[b:b + SHORT_LEN]),
                       'long': _utf16z(a[b + SHORT_LEN:b + SHORT_LEN + LONG_LEN]),
                       'publisher': _utf16z(a[b + SHORT_LEN + LONG_LEN:b + TITLE_STRIDE])})
    return {'title_id': tid,
            'has_title': tid not in (0, NO_TITLE),
            'category_ok': ((tid >> 32) >> 14) == 0x10,
            'region_lockout': struct.unpack_from('<I', a, 0x10)[0],
            'titles': titles,
            'enum_2030': struct.unpack_from('<I', a, 0x2030)[0],
            'icon_ptr': struct.unpack_from('<I', a, 0x2034)[0]}


def decode_icon(body, large=True):
    """-> size x size list of rows of RGB565 u16."""
    b = body[REGION_B_OFF:REGION_B_OFF + REGION_B_LEN]
    off, dim = (LARGE_ICON_OFF, LARGE_ICON_DIM) if large else (SMALL_ICON_OFF, SMALL_ICON_DIM)
    px = [[0] * dim for _ in range(dim)]
    i = 0
    for ty in range(0, dim, 8):
        for tx in range(0, dim, 8):
            for k in range(64):
                x, y = _morton8(k)
                px[ty + y][tx + x] = struct.unpack_from('<H', b, off + i * 2)[0]
                i += 1
    return px


def encode_icon(px):
    """Inverse of decode_icon: size x size rows of RGB565 -> tiled bytes."""
    dim = len(px)
    out = bytearray(dim * dim * 2)
    i = 0
    for ty in range(0, dim, 8):
        for tx in range(0, dim, 8):
            for k in range(64):
                x, y = _morton8(k)
                struct.pack_into('<H', out, i * 2, px[ty + y][tx + x])
                i += 1
    return bytes(out)


def build_region_a(title_id, short='', long='', publisher='',
                   region_lockout=0x7FFFFFFF, enum_2030=0):
    """Synthesise region A."""
    a = bytearray(REGION_A_LEN)
    struct.pack_into('<Q', a, 0, title_id)
    struct.pack_into('<I', a, 0x10, region_lockout)
    for i in range(N_LANG):
        b = TITLES_OFF + i * TITLE_STRIDE
        for off, cap, s in ((0, SHORT_LEN, short), (SHORT_LEN, LONG_LEN, long),
                            (SHORT_LEN + LONG_LEN, PUB_LEN, publisher)):
            e = s.encode('utf-16-le')[:cap - 2]
            a[b + off:b + off + len(e)] = e
    struct.pack_into('<I', a, 0x2030, enum_2030)
    struct.pack_into('<I', a, 0x2034, 0)        # zero on the wire; the receiver re-links it
    return bytes(a)


def build_region_b(small=None, large=None, fill=0x0000):
    """Synthesise region B from two pixel grids (or a flat fill)."""
    if small is None:
        small = [[fill] * SMALL_ICON_DIM for _ in range(SMALL_ICON_DIM)]
    if large is None:
        large = [[fill] * LARGE_ICON_DIM for _ in range(LARGE_ICON_DIM)]
    return encode_icon(small) + encode_icon(large)


def write_regions(body, region_a, region_b):
    if len(region_a) != REGION_A_LEN or len(region_b) != REGION_B_LEN:
        raise ValueError('wrong region sizes')
    b = bytearray(body)
    b[REGION_A_OFF:REGION_A_OFF + REGION_A_LEN] = region_a
    b[REGION_B_OFF:REGION_B_OFF + REGION_B_LEN] = region_b
    return bytes(b)


def validate_region_a(body):
    """Replicate sub_19C338, the receive-side gate. -> (ok, [reasons])."""
    a = body[REGION_A_OFF:REGION_A_OFF + REGION_A_LEN]
    why = []
    tid = struct.unpack_from('<Q', a, 0)[0]
    if tid == 0:
        why.append('title id is zero (sub_19C338 rejects)')
    elif tid == NO_TITLE:
        why.append('title id is the ~0 "no title" sentinel (sub_19C338 rejects)')
    e = struct.unpack_from('<I', a, 0x2030)[0]
    if e not in (0, 1, 2):
        why.append('enum at +0x2030 is %d, must be 0/1/2 (sub_19C338 rejects)' % e)
    return (not why), why


def ascii_icon(px, ramp=' .:-=+*#%@'):
    def lum(v):
        r = ((v >> 11) & 0x1F) * 255 // 31
        g = ((v >> 5) & 0x3F) * 255 // 63
        b = (v & 0x1F) * 255 // 31
        return (r * 299 + g * 587 + b * 114) // 1000
    return '\n'.join(''.join(ramp[min(len(ramp) - 1, lum(v) * len(ramp) // 256)] for v in row)
                     for row in px)


def _selftest():
    import sp_cec
    ok = tot = skipped = 0

    def chk(name, cond, got=''):
        nonlocal ok, tot
        tot += 1; ok += bool(cond)
        print('  [%s] %s%s' % ('PASS' if cond else 'FAIL', name, ('  %s' % (got,)) if got else ''))

    def skip(name, why):
        nonlocal skipped
        skipped += 1
        print('  [SKIP] %s  (%s)' % (name, why))

    import lp_corpus as corpus
    raw = corpus.load('plaza_message')
    if raw is None:
        body = bytes(sp_cec.PLAZA_BODY_SIZE)
    else:
        b = raw[0x14:]
        h = sp_cec.parse_header(b)
        body = b[h['header_size']:h['header_size'] + h['body_size']]

    if raw is None:
        for n in ('captured region A', 'captured region B', 'captured icons'):
            skip(n, corpus.why_skipped())
    else:
        ta = parse_region_a(body)
        chk('title id is the captured Homebrew Launcher id',
            ta['title_id'] == 0x000400000D921E00, '%016X' % ta['title_id'])
        chk("sub_1D1584's category check passes", ta['category_ok'])
        chk('region lockout 0x7FFFFFFF', ta['region_lockout'] == 0x7FFFFFFF)
        chk('all 16 language slots carry the title name',
            all(t['short'] == 'Homebrew Launcher' for t in ta['titles']))
        chk('publisher round-trips', ta['titles'][0]['publisher'] == 'By Many People')
        chk('enum at +0x2030 is in range', ta['enum_2030'] in (0, 1, 2))
        chk('icon pointer is zero on the wire', ta['icon_ptr'] == 0)
        chk('region A passes the receive gate', validate_region_a(body)[0])

        for large, dim in ((False, 24), (True, 48)):
            px = decode_icon(body, large=large)
            off = LARGE_ICON_OFF if large else SMALL_ICON_OFF
            n = dim * dim * 2
            chk('%dx%d icon re-encodes byte-identically' % (dim, dim),
                encode_icon(px) == body[REGION_B_OFF + off: REGION_B_OFF + off + n])
            def lum(v):
                return (((v >> 11) & 0x1F) * 255 // 31 * 299 + ((v >> 5) & 0x3F) * 255 // 63 * 587
                        + (v & 0x1F) * 255 // 31 * 114) // 1000
            d = sum(abs(lum(px[y][x]) - lum(px[y][x + 1])) for y in range(dim) for x in range(dim - 1))
            real = d / (dim * (dim - 1))
            import random
            flat = [px[y][x] for y in range(dim) for x in range(dim)]
            random.seed(1); random.shuffle(flat)
            sp = [[flat[y * dim + x] for x in range(dim)] for y in range(dim)]
            d2 = sum(abs(lum(sp[y][x]) - lum(sp[y][x + 1])) for y in range(dim) for x in range(dim - 1))
            chk('%dx%d icon is a coherent image, not noise' % (dim, dim),
                real < d2 / 2, 'delta %.1f vs shuffled %.1f' % (real, d2 / (dim * (dim - 1))))

    ra = build_region_a(0x0004000012345600, 'LinuxPass', 'StreetPass from Linux', 'LinuxPass')
    rb = build_region_b(fill=0x7BEF)
    nb = write_regions(body, ra, rb)
    got = parse_region_a(nb)
    chk('synthesised region A round-trips', got['title_id'] == 0x0004000012345600
        and got['titles'][0]['short'] == 'LinuxPass'
        and got['titles'][15]['publisher'] == 'LinuxPass' and got['category_ok'])
    chk('synthesised region A passes the receive gate', validate_region_a(nb)[0])
    chk('synthesised region B decodes to the fill colour',
        all(v == 0x7BEF for row in decode_icon(nb) for v in row))
    chk('writing regions changes only regions A and B',
        all(nb[i] == body[i] for i in range(REGION_B_OFF + REGION_B_LEN, len(body))))
    bad = write_regions(body, build_region_a(NO_TITLE), rb)
    okb, why = validate_region_a(bad)
    chk('the ~0 "no title" sentinel is rejected', not okb and 'sentinel' in why[0])
    bad2 = write_regions(body, build_region_a(0x0004000012345600, enum_2030=7), rb)
    chk('out-of-range enum at +0x2030 is rejected', not validate_region_a(bad2)[0])

    print('\n%d/%d checks passed%s' % (ok, tot,
          '' if not skipped else ', %d skipped (no test corpus)' % skipped))
    return 0 if ok == tot else 1


if __name__ == '__main__':
    import sys
    sys.exit(_selftest())
