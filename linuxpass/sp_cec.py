#!/usr/bin/env python3
"""CEC message container parser + StreetPass Mii Plaza body decoder."""
import struct, sys

MAX_BODY  = 0x18000   # body size must be != 0, <= 0x18000, and 4-byte aligned
MAX_TOTAL = 0x19000   # bodySize + 0x70 must be <= 0x19000  (hence the 0x19000 read buffer)
HDR_LEN   = 0x70

PLAZA_CEC_TITLE_ID = 0x00020800
PLAZA_BODY_SIZE    = 0x60F0
PLAZA_MIN_BODY     = 0x45D8

KNOWN_SERVICES = {
    0x00141000: None, 0x0007ad00: None, 0x00051600: None, 0x0008c500: None,
    0x0012ec00: None, 0x00030b00: None, 0x00020500: None, 0x0007c800: None,
    0x00053f00: None, 0x00030600: None, 0x001a0400: None,
    0x00020800: "StreetPass Mii Plaza",
}


def u8(b, o):  return b[o]
def u32(b, o): return struct.unpack_from('<I', b, o)[0]


def parse_header(buf):
    """The fixed 0x70-byte CEC message header."""
    if len(buf) < HDR_LEN:
        raise ValueError(f"short header: {len(buf)} < {HDR_LEN}")
    h = {
        'total_size':   u32(buf, 0x04),
        'header_size':  u32(buf, 0x08),   # body offset
        'body_size':    u32(buf, 0x0C),
        'cec_title_id': u32(buf, 0x10),
        'field_18':     u32(buf, 0x18),
        'field_34':     u8(buf, 0x34),
        # Send mode. A wrong value makes the receiver discard the message after a complete exchange.
        'field_35':     u8(buf, 0x35),    # send mode
        'send_mode':    u8(buf, 0x35),
        'field_6c':     u8(buf, 0x6C),
        'field_6d':     u8(buf, 0x6D),
        'raw':          buf[:HDR_LEN],
        'created':      parse_timestamp(buf, 0x60),
    }
    h['unique_id'] = h['cec_title_id'] >> 8      # inverse of MakeCecTitleId
    return h


def decode_utf16_name(raw):
    """A console's UTF-16LE name field -> str."""
    raw = raw[:len(raw) - (len(raw) % 2)]
    return raw.decode('utf-16-le', 'replace').split('\x00', 1)[0]


WEEKDAYS = ('Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat')


def parse_timestamp(buf, off=0x60):
    """A CecTimestamp."""
    year, = struct.unpack_from('<H', buf, off)
    mon, day, wday, hour, minute, sec = buf[off + 4:off + 10]
    ms, = struct.unpack_from('<H', buf, off + 10)
    return {'year': year, 'month': mon, 'day': day, 'weekday': wday, 'hour': hour,
            'minute': minute, 'second': sec, 'ms': ms,
            'text': '%04d-%02d-%02d(%s) %02d:%02d:%02d.%03d'
                    % (year, mon, day, WEEKDAYS[wday] if wday < 7 else '?',
                       hour, minute, sec, ms)}


def parse_message(buf):
    """Parse a full serialised CEC message. Mirrors Message::MakeMessageBinary exactly."""
    out = {'problems': []}
    h = parse_header(buf)
    out['header'] = h

    p = HDR_LEN
    exhdrs = []
    # N is not stored in the blob, so walk until we reach the body.
    body_start = h['header_size'] if 0 < h['header_size'] <= len(buf) else None
    limit = body_start if body_start else len(buf) - h['body_size']
    while p + 8 <= (limit or 0) and len(exhdrs) < 16:      # table is 16 entries max
        t, sz = struct.unpack_from('<II', buf, p)
        if t == 0 or sz > len(buf):
            break
        data = buf[p + 8: p + 8 + sz]
        exhdrs.append({'type': t, 'size': sz, 'data': data})
        p += 8 + ((sz + 3) & ~3)
    out['exheaders'] = exhdrs
    if body_start is None:
        body_start = p
    out['body_offset'] = body_start

    body = buf[body_start: body_start + h['body_size']]
    out['body'] = body
    if len(body) != h['body_size']:
        out['problems'].append(
            f"truncated body: have {len(body)} of {h['body_size']} "
            f"(reassembly incomplete? a plaza message is ~{HDR_LEN + PLAZA_BODY_SIZE} B "
            f"and cannot fit in one MPDU)")

    tail = buf[body_start + h['body_size']:]
    out['hmac'] = tail[:0x20] if len(tail) >= 0x20 else None

    if h['body_size'] == 0 or h['body_size'] > MAX_BODY:
        out['problems'].append(f"body_size {h['body_size']:#x} outside (0, {MAX_BODY:#x}]")
    if h['body_size'] & 3:
        out['problems'].append(f"body_size {h['body_size']:#x} not 4-byte aligned")
    if h['body_size'] + HDR_LEN > MAX_TOTAL:
        out['problems'].append(f"body_size + 0x70 exceeds {MAX_TOTAL:#x}")
    if h['total_size'] and not (0x84 <= h['total_size'] <= MAX_TOTAL):
        out['problems'].append(
            f"total_size {h['total_size']:#x} outside [0x84, {MAX_TOTAL:#x}] (cecd rejects this)")
    if h['field_35'] >= 4:
        out['problems'].append(f"header+0x35 = {h['field_35']} must be < 4")
    if h['field_6d'] > 1 and h['field_6c'] > 1:
        out['problems'].append("header+0x6D and +0x6C both > 1 (NewMessage would have rejected)")
    return out


# [P] means proven from the title's code. [?] means inferred.
PLAZA_MAP = [
    (0x0000, 0x2038, 'region_a',       '[P] title info: u64 titleId | 0x30 hdr | 16 x 0x200 SMDH '
                                       'title entries | u32 enum(0..2) @0x2030 | u32 icon ptr'),
    (0x2038, 0x1680, 'region_b',       '[P] SMDH icons: 24x24 (0x480) + 48x48 (0x1200) RGB565, tiled'),
    (0x36B8, 0x0004, 'present_flag',   'builder writes 1; both real messages carry 0x100'),
    (0x36BC, 0x00A0, 'mii_data',       '[P] "CFPB" container: magic|ver=1|12 zero|count=1|'
                                       'one 0x70 entry = 10-byte identity + 0x66 opaque bytes'),
    (0x375C, 0x0004, 'address_code',   'SimpleAddress[0]'),
    (0x3760, 0x0400, 'country_names',  '16 x 0x40 UTF-16, one per language'),
    (0x3B60, 0x0400, 'region_names',   '16 x 0x40 UTF-16, one per language'),
    (0x3F60, 0x0010, 'struct_3f60',    'from save+0x43E70; bytes +6..+9 are enums'),
    (0x3F70, 0x0022, 'greeting',       '[P] UTF-16, 16 chars + NUL'),
    (0x3F92, 0x00A0, 'met_ids',        '[P] 16 x 0x0A identities {u32 id; u8 mac[6]}'),
    (0x4032, 0x0220, 'met_names_a',    '[P] 16 x 0x22 UTF-16, 16 chars + NUL'),
    (0x4252, 0x0220, 'met_names_b',    '[P] 16 x 0x22 UTF-16, 16 chars + NUL'),
    (0x4472, 0x0010, 'met_flags',      '[P] 16 x u8, one per met_ids slot'),
    (0x4482, 0x0001, 'plaza_mii_count','[P] meet_CountPlazaMiis @0x1fd9a8 over 100 slots; < 0x65'),
    (0x4484, 0x0140, 'met_consoles',   '[P] 32 x 0x0A identities, copied verbatim from '
                                       'save+0x44392 by the builder; FIFO, oldest evicted'),
    (0x45C4, 0x000E, 'bitmap_45c4',    '7 x u16; bit15 cleared on receive'),
    (0x45D2, 0x0001, 'enum_45d2',      'valid < 4'),
    (0x45D3, 0x1B18, 'block_45d3',     'from save+0x45578'),
    # From 0x60EC on, only the expansion build emits these, and their purpose is unknown.
    (0x60EC, 0x0040, 'x_60EC',  '[P] size only'),
    (0x612C, 0x0010, 'x_612C',  '[P] size only; filled with x_613C as one 0x20 copy'),
    (0x613C, 0x0010, 'x_613C',  '[P] size only'),
    (0x614C, 0x0001, 'x_614C',  '[P] size only; the only tail byte set on BOTH consoles'),
    (0x614D, 0x0007, 'x_614D',  '[P] size only; filled with x_614C as one 8-byte copy'),
    (0x6154, 0x0004, 'x_6154',  '[P] u32'),
    (0x6158, 0x00E8, 'x_6158',  '[P] size only'),
    (0x6240, 0x0500, 'x_6240',  '[P] size only'),
    (0x6740, 0x0100, 'x_6740',  '[P] size only'),
    (0x6840, 0x0100, 'x_6840',  '[P] size only'),
    (0x6940, 0x0010, 'x_6940',  '[P] size only; filled with x_6950 as one 0x20 copy'),
    (0x6950, 0x0010, 'x_6950',  '[P] size only'),
    (0x6960, 0x0008, 'x_6960',  '[P] 8 bytes (builder clears 1, filler writes 2 u32)'),
    (0x696C, 0x0200, 'x_696C',  '[P] size only'),
    (0x6B6C, 0x0200, 'x_6B6C',  '[P] size only'),
    (0x6D6C, 0x0001, 'x_6D6C',  '[P] u8'),
    (0x6D6D, 0x0001, 'x_6D6D',  '[P] u8'),
    (0x6D6E, 0x0002, 'x_6D6E',  '[P] u16'),
    (0x6D70, 0x0004, 'x_6D70',  '[P] u32'),
    (0x6D74, 0x0400, 'x_6D74',  '[P] the tail region carrying the most live data on the 2DS XL'),
    (0x7174, 0x0100, 'x_7174',  '[P] size only'),
    (0x7274, 0x0004, 'x_7274',  '[P] u32'),
    (0x727C, 0x0004, 'x_727C',  '[P] u32; ends the body at 0x7280 exactly'),
]

PLAZA_CLAMPS = {0x3F66: 0x4C, 0x3F67: 0x03, 0x3F68: 0x14, 0x3F69: 0x1C,
                0x4482: 0x65, 0x45D2: 0x04}


def _utf16z(b):
    s = b.decode('utf-16-le', errors='replace')
    return s.split('\x00', 1)[0]


def parse_plaza_body(body):
    out = {'fields': {}, 'problems': []}
    for off, size, name, note in PLAZA_MAP:
        if off + size <= len(body):
            out['fields'][name] = (off, size, body[off:off + size], note)
    if len(body) < PLAZA_MIN_BODY:
        out['problems'].append(f"body {len(body):#x} < receiver minimum {PLAZA_MIN_BODY:#x}")
    for off, bound in PLAZA_CLAMPS.items():
        if off < len(body) and body[off] >= bound:
            out['problems'].append(f"+{off:#06x} = {body[off]} >= {bound} (receiver would zero it)")
    if 0x36BC <= len(body):
        out['greeting'] = _utf16z(body[0x3F70:0x3F92]) if len(body) >= 0x3F92 else None
        out['country'] = [_utf16z(body[0x3760 + i * 0x40: 0x3760 + (i + 1) * 0x40])
                          for i in range(16)] if len(body) >= 0x3B60 else []
        out['region'] = [_utf16z(body[0x3B60 + i * 0x40: 0x3B60 + (i + 1) * 0x40])
                         for i in range(16)] if len(body) >= 0x3F60 else []
        out['met16'] = []
        if len(body) >= 0x4482:
            for i in range(16):
                r = body[0x3F92 + i * 10: 0x3F92 + (i + 1) * 10]
                na = _utf16z(body[0x4032 + i * 0x22: 0x4032 + (i + 1) * 0x22])
                nb = _utf16z(body[0x4252 + i * 0x22: 0x4252 + (i + 1) * 0x22])
                if any(r) or na or nb:
                    out['met16'].append({'idx': i, 'id': struct.unpack_from('<I', r, 0)[0],
                                         'mac': ':'.join('%02x' % c for c in r[4:]),
                                         'name_a': na, 'name_b': nb, 'flag': body[0x4472 + i]})
        met = []
        if len(body) >= 0x45C4:
            for i in range(32):
                r = body[0x4484 + i * 10: 0x4484 + (i + 1) * 10]
                if any(r):
                    met.append({'idx': i, 'id': struct.unpack_from('<I', r, 0)[0],
                                'mac': ':'.join('%02x' % c for c in r[4:])})
        out['met_consoles'] = met
        out['plaza_mii_count'] = body[0x4482] if len(body) > 0x4482 else None
        # The 10 bytes at body+0x36D4 are the CCM nonce, not the identity.
        try:
            import sp_mii
            cfl, mac_ok = sp_mii.read_plaza_mii(body)
            out['mii'] = sp_mii.parse_cfl(cfl)
            out['mii']['ccm_mac_ok'] = mac_ok
            out['own_identity'] = {'id': out['mii']['mii_id'],
                                   'mac': out['mii']['creator_mac']}
        except Exception as e:
            out['mii'] = None
            out['problems'].append('CFPB Mii not decoded: %s' % (e,))
    return out


def score(buf):
    """Semantic plausibility that `buf` is a plaza CEC message."""
    pts, why = 0, []
    try:
        m = parse_message(buf)
    except ValueError as e:
        return 0, [str(e)]
    h = m['header']
    if h['cec_title_id'] == PLAZA_CEC_TITLE_ID:
        pts += 40; why.append("cec_title_id == 0x00020800 (Mii Plaza)")
    elif 0 < h['cec_title_id'] <= 0xFFFFFF and (h['cec_title_id'] & 0xFF) == 0:
        pts += 10; why.append(f"cec_title_id {h['cec_title_id']:#08x} plausible (uid {h['cec_title_id']>>8:#x})")
    if h['body_size'] == PLAZA_BODY_SIZE:
        pts += 30; why.append("body_size == 0x60F0")
    elif 0 < h['body_size'] <= MAX_BODY and not (h['body_size'] & 3):
        pts += 10; why.append(f"body_size {h['body_size']:#x} in range and aligned")
    if h['field_35'] < 4:
        pts += 5; why.append("header+0x35 < 4")
    if h['total_size'] and h['total_size'] <= MAX_TOTAL:
        pts += 5; why.append("total_size within 0x19000")
    body = m['body']          # body starts past the ex-headers, not at HDR_LEN
    if len(body) >= 0x36BC and u32(body, 0x36B8) == 1:
        pts += 10; why.append("body+0x36B8 == 1")
    if any('truncated' in p for p in m['problems']):
        pts -= 25; why.append("TRUNCATED - reassembly incomplete")
    return max(pts, 0), why


def reassemble(items):
    """items: iterable of (ccmp_pn, decrypted_payload) -> (blob, stats)."""
    by_pn, dupes = {}, 0
    for pn, pt in items:
        if pn in by_pn:
            dupes += 1
            continue
        by_pn[pn] = pt
    pns = sorted(by_pn)
    gaps = [(pns[i], pns[i + 1]) for i in range(len(pns) - 1) if pns[i + 1] != pns[i] + 1]
    parts = [by_pn[p] for p in pns]
    enc = 8 if parts and all(p[:3] == b'\xaa\xaa\x03' for p in parts) else 0
    blob = b''.join(p[enc:] for p in parts)
    stats = {'frames': len(pns), 'dupes': dupes, 'gaps': gaps,
             'missing': sum(hi - lo - 1 for lo, hi in gaps), 'enc': enc,
             'pn_lo': pns[0] if pns else None, 'pn_hi': pns[-1] if pns else None}
    return blob, stats


def find_container_offsets(blob, limit=64):
    """Locate plausible CEC message starts anywhere in `blob`."""
    hits = []
    for off in range(0, max(0, len(blob) - HDR_LEN) + 1):
        tid = u32(blob, off + 0x10)
        if tid not in KNOWN_SERVICES:
            continue
        bs, ts = u32(blob, off + 0x0C), u32(blob, off + 0x04)
        if not (0 < bs <= MAX_BODY) or (bs & 3):
            continue
        if not (0 < ts <= MAX_TOTAL) or ts < HDR_LEN + bs:
            continue
        hits.append(off)
        if len(hits) >= limit:
            break
    return hits


def parse_stream(blob, max_msgs=64):
    """Walk a reassembled plaintext stream that may hold SEVERAL messages."""
    msgs = []
    p = 0
    try:
        parse_header(blob)
        first_ok = u32(blob, 0x10) in KNOWN_SERVICES
    except ValueError:
        first_ok = False
    if not first_ok:
        starts = find_container_offsets(blob, limit=1)
        if starts:
            p = starts[0]
    while p + HDR_LEN <= len(blob) and len(msgs) < max_msgs:
        try:
            h = parse_header(blob[p:])
        except ValueError:
            break
        total = h['total_size']
        sane = 0 < total <= MAX_TOTAL and p + HDR_LEN <= p + total
        chunk = blob[p:p + total] if sane and p + total <= len(blob) else blob[p:]
        try:
            m = parse_message(chunk)
        except ValueError:
            break
        m['offset'] = p
        msgs.append(m)
        if not sane:
            m['problems'].append(
                f"total_size {total:#x} unusable - cannot locate the next message in the stream")
            break
        if p + total > len(blob):
            m['problems'].append("stream ends mid-message (capture stopped early?)")
            break
        p += total
    return msgs


def dump_stream(blob):
    msgs = parse_stream(blob)
    print(f"stream: {len(blob)} bytes -> {len(msgs)} CEC message(s)")
    for i, m in enumerate(msgs):
        h = m['header']
        name = KNOWN_SERVICES.get(h['cec_title_id'])
        print(f"\n[{i}] offset {m['offset']:#x}  cec_title_id {h['cec_title_id']:#010x}"
              f"  (uniqueId {h['unique_id']:#x})"
              + (f"  = {name}" if name else
                 "  = not Mii Plaza; container decoded, body left raw"))
        total = h['total_size']
        end = m['offset'] + total if (0 < total <= MAX_TOTAL and m['offset'] + total <= len(blob)) else len(blob)
        dump(blob[m['offset']:end])
    return msgs


def dump(buf):
    m = parse_message(buf)
    h = m['header']
    print(f"CEC message: {len(buf)} bytes")
    print(f"  total_size   {h['total_size']:#x}")
    print(f"  header_size  {h['header_size']:#x}   [?]")
    print(f"  body_size    {h['body_size']:#x}")
    print(f"  cec_title_id {h['cec_title_id']:#010x}  (uniqueId {h['unique_id']:#x})"
          + ("  <-- StreetPass Mii Plaza" if h['cec_title_id'] == PLAZA_CEC_TITLE_ID else ""))
    print(f"  +0x18 {h['field_18']:#x}  +0x34 {h['field_34']}  +0x35 {h['field_35']}"
          f"  +0x6C {h['field_6c']:#x}  +0x6D {h['field_6d']}")
    print(f"  ex-headers: {len(m['exheaders'])}")
    for e in m['exheaders']:
        tag = ' (InfoText)' if e['type'] == 4 else ''
        prev = _utf16z(e['data']) if e['type'] == 4 else e['data'][:24].hex()
        print(f"    type {e['type']}{tag} size {e['size']:#x}: {prev!r}")
    print(f"  hmac: {'present (0x20)' if m['hmac'] else 'absent (EXPECTED for Mii Plaza)'}")
    for p in m['problems']:
        print(f"  !! {p}")
    if h['cec_title_id'] != PLAZA_CEC_TITLE_ID and m['body']:
        name = KNOWN_SERVICES.get(h['cec_title_id'])
        print(f"\n  -- body: {len(m['body'])} bytes, format UNKNOWN "
              f"({name or 'title not identified'}) --")
        print(f"    first 48: {m['body'][:48].hex()}")
        print("    (only the Mii Plaza body layout has been reverse-engineered; the CEC")
        print("     container above is title-agnostic and applies to every StreetPass title)")
    if h['cec_title_id'] == PLAZA_CEC_TITLE_ID and m['body']:
        b = parse_plaza_body(m['body'])
        print("\n  -- Mii Plaza body --")
        if b.get('greeting') is not None:
            print(f"    greeting: {b['greeting']!r}")
        for k in ('country', 'region'):
            vals = [v for v in b.get(k, []) if v]
            if vals: print(f"    {k}: {vals[:4]}{' ...' if len(vals) > 4 else ''}")
        for name, (off, size, data, note) in b['fields'].items():
            print(f"    +{off:#06x} {size:#06x} {name:<14} {data[:12].hex()}{'..' if size > 12 else ''}"
                  + (f"   # {note}" if note else ""))
        for p in b['problems']:
            print(f"    !! {p}")
    s, why = score(buf)
    print(f"\n  plausibility score {s}/90: " + "; ".join(why))
    return m


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    dump(open(sys.argv[1], 'rb').read())
