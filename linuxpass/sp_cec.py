#!/usr/bin/env python3
"""
CEC message container parser + StreetPass Mii Plaza body decoder.

This is the piece sp_decrypt_pcap.py was missing: it decrypts frames and then prints
`plaintext[:64].hex()`. Feed the reassembled plaintext here to get structure.

Offsets marked [P] are PROVEN from MiiPlaza/code.bin (see MiiPlaza/STREETPASS_READ.md):
  Message::MakeMessageBinary @0x2dde6c  -> serialisation order
  Message::NewMessage        @0x161fb0  -> header field offsets
  Message::SetMessageBody    @0x162280  -> size limits
  Message::GetExHeader       @0x20969c  -> ex-header table
  meet_Cec_BuildOutgoingBody @0x1d2950  -> plaza body partition
Offsets marked [?] are inferred and NOT yet confirmed against real data.
"""
import struct, sys

# ---- container limits, all [P] from Message::SetMessageBody ----
MAX_BODY  = 0x18000   # body size must be != 0, <= 0x18000, and 4-byte aligned
MAX_TOTAL = 0x19000   # bodySize + 0x70 must be <= 0x19000  (hence the 0x19000 read buffer)
HDR_LEN   = 0x70      # [P] MakeMessageBinary memcpy(dst, this, 0x70)

PLAZA_CEC_TITLE_ID = 0x00020800   # [P] MakeCecTitleId(0x208, 0)
PLAZA_BODY_SIZE    = 0x60F0       # [P] SetMessageBody(body, 0x60F0)
PLAZA_MIN_BODY     = 0x45D8       # [P] receiver gate in meet_Cec_ValidateAndLoadMessage

# CEC title IDs advertised by the owned console's probe (extracted/CAPTURE_FINDINGS.md).
# Only 0x00020800 is identified from a binary; the rest are uniqueIds awaiting a titledb lookup.
KNOWN_SERVICES = {
    0x00141000: None, 0x0007ad00: None, 0x00051600: None, 0x0008c500: None,
    0x0012ec00: None, 0x00030b00: None, 0x00020500: None, 0x0007c800: None,
    0x00053f00: None, 0x00030600: None, 0x001a0400: None,
    0x00020800: "StreetPass Mii Plaza",
}       # [P] receiver gate in meet_Cec_ValidateAndLoadMessage


def u8(b, o):  return b[o]
def u32(b, o): return struct.unpack_from('<I', b, o)[0]


def parse_header(buf):
    """The fixed 0x70-byte CEC message header."""
    if len(buf) < HDR_LEN:
        raise ValueError(f"short header: {len(buf)} < {HDR_LEN}")
    h = {
        'total_size':   u32(buf, 0x04),   # [P] MakeMessageBinary returns *(u32*)(this+4)
        'header_size':  u32(buf, 0x08),   # [P] = BODY OFFSET. cecd 0x11CC7C hmacs [base+hdr[8], hdr[0xC])
        'body_size':    u32(buf, 0x0C),   # [P] validator compares this against 0x45D8
        'cec_title_id': u32(buf, 0x10),   # [P] NewMessage: str r1,[r0,#0x10]
        'field_18':     u32(buf, 0x18),   # [P] NewMessage arg2 (plaza sends 0)
        'field_34':     u8(buf, 0x34),    # [P] NewMessage arg3 (plaza sends 3) -> ee entry +0x05
        # [P] NewMessage arg4, must be < 4. Plaza sends 0; almost every other title sends 3.
        # cecd copies it into the ee list entry at +0x04 (0x10BCA6) and the RECEIVER'S store gate
        # (0x1031D0) turns on it: non-zero = keep the message outright, zero = keep it only if the
        # receiver's own entry for this title is also zero and it has already sent its own message.
        # Declaring the wrong value silently discards the message after a complete exchange.
        # See EE_SEND_MODE.md.
        'field_35':     u8(buf, 0x35),    # = SEND MODE
        'send_mode':    u8(buf, 0x35),
        'field_6c':     u8(buf, 0x6C),    # [P] NewMessage arg5 (plaza sends 0xFF)
        'field_6d':     u8(buf, 0x6D),    # [P] NewMessage arg6, <= 1 (plaza sends 1)
        'raw':          buf[:HDR_LEN],
        'created':      parse_timestamp(buf, 0x60),   # [P] see parse_timestamp
    }
    h['unique_id'] = h['cec_title_id'] >> 8      # inverse of MakeCecTitleId
    return h


def decode_utf16_name(raw):
    """A console's UTF-16LE name field -> str. Truncate to whole units BEFORE decoding.

    Real files are not always an even length: the 2DS's `MBoxData.010` for Super Mario Maker is
    35 bytes -- "Super Mario Maker" (34) plus one stray 0x00. Decoding that with errors='replace'
    turns the odd byte into U+FFFD. Harmless if you only print it; CORRUPTING if you write the
    decoded string back out, which is what the store did -- the title was then permanently named
    "Super Mario Maker\ufffd", on disk, in the GUI, and in anything reading it afterwards.
    """
    raw = raw[:len(raw) - (len(raw) % 2)]
    return raw.decode('utf-16-le', 'replace').split('\x00', 1)[0]


WEEKDAYS = ('Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat')


def parse_timestamp(buf, off=0x60):
    """A CecTimestamp. [P] pinned by cecd's own format string at 0x107340:

        '%04d/%02d/%02d(%d) %02d:%02d:%02d.%04d'   year/month/day(weekday) h:m:s.ms

    which is eight fields, so the byte after the day is the WEEKDAY, not the hour:

        +0x00 u16 year   +0x02 u16 pad
        +0x04 u8 month   +0x05 u8 day   +0x06 u8 weekday (0=Sunday)
        +0x07 u8 hour    +0x08 u8 minute +0x09 u8 second  +0x0A u16 millisecond

    Getting this off by one shifts the hour into the day and reads a message as created at
    03:19 when it was created at 19:15. The weekday is the check: it must agree with the date.
    """
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
    # MakeMessageBinary writes {u32 type; u32 size} then size bytes, 4-byte aligned, N times.
    # N is not stored in the blob, so walk until we reach the body.
    body_start = h['header_size'] if 0 < h['header_size'] <= len(buf) else None
    limit = body_start if body_start else len(buf) - h['body_size']
    while p + 8 <= (limit or 0) and len(exhdrs) < 16:      # [P] table is 16 entries max
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
    # [P] Optional 0x20 trailer, and StreetPass Mii Plaza NEVER attaches one: Message::Message()
    # nulls the +0x13C hmac pointer, meet_Cec_PublishOutgoingMessage never sets it, and
    # WriteMessageWithHmac is unreachable dead code. So `absent` is EXPECTED for a plaza message and
    # is not evidence of a truncated or mis-parsed capture. (See extracted/MESSAGE_HMAC.md)
    out['hmac'] = tail[:0x20] if len(tail) >= 0x20 else None

    # container-level sanity, all [P]
    if h['body_size'] == 0 or h['body_size'] > MAX_BODY:
        out['problems'].append(f"body_size {h['body_size']:#x} outside (0, {MAX_BODY:#x}]")
    if h['body_size'] & 3:
        out['problems'].append(f"body_size {h['body_size']:#x} not 4-byte aligned")
    if h['body_size'] + HDR_LEN > MAX_TOTAL:
        out['problems'].append(f"body_size + 0x70 exceeds {MAX_TOTAL:#x}")
    if h['total_size'] and not (0x84 <= h['total_size'] <= MAX_TOTAL):
        # [P] cecd 0x1071C2: `total - 0x84 >= 0x18F7D` -> error 0x36, i.e. 0x84 <= total <= 0x19000
        out['problems'].append(
            f"total_size {h['total_size']:#x} outside [0x84, {MAX_TOTAL:#x}] (cecd rejects this)")
    if h['field_35'] >= 4:
        out['problems'].append(f"header+0x35 = {h['field_35']} must be < 4")
    if h['field_6d'] > 1 and h['field_6c'] > 1:
        out['problems'].append("header+0x6D and +0x6C both > 1 (NewMessage would have rejected)")
    return out


# ---------------- Mii Plaza body ----------------
# All [P] from meet_Cec_BuildOutgoingBody @0x1d2950 (region partition) and
# meet_Cec_SanitiseAndImportBody @0x2bac18 (valid ranges).
PLAZA_MAP = [
    # Regions A and B are ONE logical object: the featured title's SMDH, split across the wire
    # and re-linked on receive (bufA+0x2034 = bufB). Producer sub_1D1584; see sp_smdh.py.
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
    # ---- the 0x512 profile block, body+0x3F70 .. body+0x4482 -------------------------------
    # One memcpy from save+0x43E80 in the builder. It is a STRUCTURE OF ARRAYS for 16 met
    # people, proved by meet_MetList16_Insert @0x19d8e4, which on a miss shifts all four
    # arrays down one slot and writes the new record into slot 15:
    #     memmove(save+0x43EA2, save+0x43EAC, 0x96)    16 x 0x0A identities
    #     memmove(save+0x43F42, save+0x43F64, 0x1FE)   16 x 0x22 name A
    #     memmove(save+0x44162, save+0x44184, 0x1FE)   16 x 0x22 name B
    #     memmove(save+0x44382, save+0x44383, 0x0F)    16 x 0x01 flag
    # 0x22 + 0xA0 + 0x220 + 0x220 + 0x10 == 0x512 exactly.
    (0x3F70, 0x0022, 'greeting',       '[P] UTF-16, 16 chars + NUL'),
    (0x3F92, 0x00A0, 'met_ids',        '[P] 16 x 0x0A identities {u32 id; u8 mac[6]}'),
    (0x4032, 0x0220, 'met_names_a',    '[P] 16 x 0x22 UTF-16, 16 chars + NUL'),
    (0x4252, 0x0220, 'met_names_b',    '[P] 16 x 0x22 UTF-16, 16 chars + NUL'),
    (0x4472, 0x0010, 'met_flags',      '[P] 16 x u8, one per met_ids slot'),
    # ---------------------------------------------------------------------------------------
    (0x4482, 0x0001, 'plaza_mii_count','[P] meet_CountPlazaMiis @0x1fd9a8 over 100 slots; < 0x65'),
    (0x4484, 0x0140, 'met_consoles',   '[P] 32 x 0x0A identities, copied verbatim from '
                                       'save+0x44392 by the builder; FIFO, oldest evicted'),
    (0x45C4, 0x000E, 'bitmap_45c4',    '7 x u16; bit15 cleared on receive'),
    (0x45D2, 0x0001, 'enum_45d2',      'valid < 4'),
    (0x45D3, 0x1B18, 'block_45d3',     'from save+0x45578'),
    # ---- from 0x60EC on, only the StreetPass Mii Plaza EXPANSION build emits these ----
    # The base title (0004001000022800 v5122) builds a 0x60F0 body and ends at 0x60EB. The consoles
    # run the expansion update 0004000E00022800, whose builder meet_BuildOutgoingBody_upd @0x2C4794
    # partitions a 0x7280 body. Its clears for body[0 .. 0x60EB] are IDENTICAL to the base build's,
    # which is why every offset above stayed valid; from 0x60EC it replaces the base build's 5 bytes
    # of padding with the regions below. The partition closes on 0x7280 exactly (13 bytes of
    # alignment gaps). Sizes are [P]; the PURPOSE of each region is NOT established -- they are the
    # expansion games' StreetPass state, and are ~99.9% zero in both captured consoles.
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
        # The 16-deep met list: identity + two 16-char names + a flag, four parallel arrays.
        # Insert/eviction proved in meet_MetList16_Insert @0x19d8e4; an entry is "occupied"
        # when its 10 identity bytes are not all zero (meet_IdentityValid @0x20f208).
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
        # The 32-deep console list. Same 10-byte identity type. Written by the builder from
        # save+0x44392; on receive meet_AppendVisitor @0x30b758 copies it into the visitor
        # record at +0x512, and meet_HaveTheyMetMe @0x2be6cc searches those 32 slots for our
        # own identity. It is NOT an admission-control input -- see MET_CONSOLE_LIST.md.
        met = []
        if len(body) >= 0x45C4:
            for i in range(32):
                r = body[0x4484 + i * 10: 0x4484 + (i + 1) * 10]
                if any(r):
                    met.append({'idx': i, 'id': struct.unpack_from('<I', r, 0)[0],
                                'mac': ':'.join('%02x' % c for c in r[4:])})
        out['met_consoles'] = met
        out['plaza_mii_count'] = body[0x4482] if len(body) > 0x4482 else None
        # Owner Mii. The CFPB entry is AES-CCM wrapped (APT keyslot 0x31); sp_mii unwraps it.
        # NOTE the 10 bytes at body+0x36D4 are the CCM NONCE, not the identity -- the identity is
        # inside the decrypted CFLStoreData. They look alike because the nonce IS the first 8
        # bytes of `mii_id || creator_mac`. See CFPB_MII.md.
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
    """Semantic plausibility that `buf` is a plaza CEC message. Not a crypto oracle -
    the CCMP MIC already is one. Use this to confirm the payload MODEL and to detect
    incomplete reassembly. Max 90."""
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
    """items: iterable of (ccmp_pn, decrypted_payload) -> (blob, stats).

    Orders by CCMP PN (a per-key monotonic counter), drops retransmissions (a retry carries the
    SAME PN), reports PN gaps (= frames the sniffer missed), and strips a uniform LLC/SNAP
    prefix if every frame has one."""
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
    """Locate plausible CEC message starts anywhere in `blob`.

    The decrypted 802.11 payload may be wrapped (LLC/SNAP, or an NWM/UDS layer) so the container
    is not guaranteed to start at offset 0. Rather than assume, scan for a header whose
    cec_title_id is one the console actually advertises AND whose size fields are self-consistent.
    False positives are very unlikely: that is 3 correlated 32-bit constraints."""
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
    """Walk a reassembled plaintext stream that may hold SEVERAL messages.

    A StreetPass encounter exchanges a message for every title both consoles have enabled -
    the probe service list advertises 12 - so a decrypted direction is usually a run of
    concatenated CEC messages, not one. Advance by header+0x04 (total message size).

    The stream does NOT necessarily begin with the message header. Measured on sweep_new, a
    real 32,732-byte object starts with a 20-byte envelope:

        +0x00 u32  0x6161            +0x0C u32  0
        +0x04 u32  0x7FDC = 32732    +0x10 u32  1        (message count)
        +0x08 u32  0x00020800        -- CEC title id, repeated in the message header at +0x10

    and 0x7FDC - 0x7FC8 == 20 exactly: the envelope's total minus the message's own total is
    the envelope length. So locate the first real header with find_container_offsets() instead
    of assuming offset 0 - otherwise the envelope is misread as the header (title 0x00000001,
    body_size 0) and the whole message is rejected."""
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
