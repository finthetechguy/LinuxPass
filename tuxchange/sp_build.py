#!/usr/bin/env python3
"""Build a complete StreetPass Mii Plaza CEC message from scratch, with no captured input."""
import struct, os, hmac, hashlib

import sp_cec
import lp_keys as _keys, sp_mii, sp_smdh

ENVELOPE_LEN = 0x14
HDR_LEN      = 0x70
BODY_LEN     = 0x7280          # the expansion build; the base title used 0x60F0
TRAILER_LEN  = 0x20
PLAZA_TITLE  = 0x00020800
INFO_TEXT    = "You've got company!"
CEC_ICON_DIM = 40              # the CEC icon is 40x40 RGB565 = 0xC80 bytes


def plaza_hmac_key(key_file=None):
    """Mii Plaza's message HMAC key, read from your console's CEC store."""
    return _keys.plaza_hmac_key(key_file)
O81_SLOTS    = 24              # the 0x81 payload is 196 B = 4 + 24*8

OFF_PRESENT, OFF_MII, OFF_ADDR = 0x36B8, 0x36BC, 0x375C
OFF_COUNTRY, OFF_REGION, OFF_GREETING = 0x3760, 0x3B60, 0x3F70
PRESENT_FLAG = 0x100


def cec_icon(path=None, **draw_kw):
    """The 0xC80-byte 40x40 CEC icon that rides along with the message."""
    if path is not None:
        with open(path, 'rb') as fh:
            d = fh.read()
        if len(d) != 0xC80:
            raise ValueError('CEC icon must be 0xC80 bytes, got %#x' % len(d))
        return d
    d = sp_smdh.encode_icon(draw_icon(CEC_ICON_DIM, **draw_kw))
    assert len(d) == 0xC80, hex(len(d))
    return d


# Appearance bitfields: name, CFL offset, high bit, low bit, validator bound (None = width only).
APPEARANCE = [
    ('face_shape',      0x30, 4, 1,  None),   ('skin_colour',     0x30, 7, 5,  5),
    ('wrinkles',        0x30, 11, 8, None),   ('makeup',          0x30, 15, 12, 11),
    ('hair_style',      0x32, 7, 0,  None),   ('hair_colour',     0x32, 10, 8, 7),
    ('hair_flip',       0x32, 11, 11, None),
    ('eye_style',       0x34, 5, 0,  59),     ('eye_colour',      0x34, 8, 6,  None),
    ('eye_scale',       0x34, 12, 9, 7),      ('eye_yscale',      0x34, 15, 13, None),
    ('eye_rotation',    0x36, 4, 0,  7),      ('eye_spacing',     0x36, 8, 5,  12),
    ('eye_ypos',        0x36, 13, 9, 18),
    ('eyebrow_style',   0x38, 4, 0,  None),   ('eyebrow_colour',  0x38, 7, 5,  7),
    ('eyebrow_scale',   0x38, 11, 8, None),   ('eyebrow_yscale',  0x38, 14, 12, 6),
    ('eyebrow_rotation',0x3A, 4, 0,  11),     ('eyebrow_spacing', 0x3A, 8, 5,  12),
    ('eyebrow_ypos',    0x3A, 13, 9, 18),     # ALSO has a lower bound of 3 -- see MIN_BOUNDS
    ('nose_style',      0x3C, 4, 0,  17),     ('nose_scale',      0x3C, 8, 5,  None),
    ('nose_ypos',       0x3C, 13, 9, 18),
    ('mouth_style',     0x3E, 5, 0,  None),   ('mouth_colour',    0x3E, 8, 6,  4),
    ('mouth_scale',     0x3E, 12, 9, None),   ('mouth_yscale',    0x3E, 15, 13, 6),
    ('mouth_ypos',      0x40, 4, 0,  None),   ('moustache_style', 0x40, 7, 5,  5),
    ('beard_style',     0x42, 2, 0,  None),   ('beard_colour',    0x42, 5, 3,  7),
    ('beard_scale',     0x42, 9, 6,  None),   ('beard_ypos',      0x42, 14, 10, 16),
    ('glasses_style',   0x44, 3, 0,  None),   ('glasses_colour',  0x44, 6, 4,  5),
    ('glasses_scale',   0x44, 10, 7, None),   ('glasses_ypos',    0x44, 15, 11, 20),
    ('mole_on',         0x46, 0, 0,  None),   ('mole_scale',      0x46, 4, 1,  8),
    ('mole_xpos',       0x46, 9, 5,  None),   ('mole_ypos',       0x46, 14, 10, 30),
    ('height',          0x2E, 7, 0,  None),   ('build',           0x2F, 7, 0,  128),
    ('gender',          0x18, 0, 0,  1),      ('birthday_month',  0x18, 4, 1,  None),
    ('birthday_day',    0x18, 9, 5,  None),   ('favourite_colour',0x18, 13, 10, 11),
]
MIN_BOUNDS = {'eyebrow_ypos': 3}          # the only appearance field with a non-zero minimum

# An all-zero face passes validation but renders broken.
DEFAULT_FACE = dict(
    face_shape=0, skin_colour=1, hair_style=33, hair_colour=1,
    eye_style=4, eye_scale=4, eye_yscale=3, eye_rotation=4, eye_spacing=2, eye_ypos=12,
    eyebrow_style=0, eyebrow_colour=1, eyebrow_scale=4, eyebrow_yscale=3,
    eyebrow_rotation=6, eyebrow_spacing=2, eyebrow_ypos=10,
    nose_style=1, nose_scale=4, nose_ypos=9,
    mouth_style=23, mouth_colour=0, mouth_scale=4, mouth_yscale=3, mouth_ypos=13,
    height=64, build=64, favourite_colour=0,
)


def build_cfl(mii_name='Linux', author_name='', mii_id=None, creator_mac='b8:ae:6e:00:00:01',
              device_origin=3, face=None, **overrides):
    """A CFLStoreData that satisfies every gate in meet_ValidateMii AND renders as a normal Mii."""
    for nm in (mii_name, author_name):
        bad = set(nm) & {'%', '\\'}
        if bad:
            raise ValueError('Mii names may not contain %s (0x189F94 rejects them)' % sorted(bad))
    if not (1 <= device_origin <= 3):
        raise ValueError('device_origin must be 1..3 (struct+0x104)')
    vals = dict(DEFAULT_FACE)
    if face: vals.update(face)
    vals.update(overrides)
    if mii_id is None:
        mii_id = sp_mii.random_mii_id()
    if isinstance(creator_mac, str):
        creator_mac = bytes(int(x, 16) for x in creator_mac.split(':'))

    c = bytearray(sp_mii.CFL_LEN)
    struct.pack_into('<I', c, 0x00, 3 | (device_origin << 28))
    struct.pack_into('<I', c, 0x0C, mii_id)
    c[0x10:0x16] = bytes(creator_mac)
    n = mii_name.encode('utf-16-le')[:20]
    c[0x1A:0x1A + len(n)] = n
    a = author_name.encode('utf-16-le')[:20]
    c[0x48:0x48 + len(a)] = a
    check_birthday(vals.get('birthday_month', 0), vals.get('birthday_day', 0))
    known = {f[0] for f in APPEARANCE}
    for k in vals:
        if k not in known:
            raise ValueError('unknown appearance field %r' % k)
    for name, off, hi, lo, ub in APPEARANCE:
        v = int(vals.get(name, 0))
        width = hi - lo + 1
        lb = MIN_BOUNDS.get(name, 0)
        if v < lb or v > (ub if ub is not None else (1 << width) - 1):
            raise ValueError('%s = %d out of range [%d, %s]'
                             % (name, v, lb, ub if ub is not None else (1 << width) - 1))
        if off in (0x2E, 0x2F):
            c[off] = v & 0xFF
        else:
            cur = struct.unpack_from('<H', c, off)[0]
            struct.pack_into('<H', c, off, cur | ((v & ((1 << width) - 1)) << lo))
    return sp_mii.reseal_cfl(bytes(c))


# Mii-card profile block at body+0x3F60. Bounds are the receive-side clamps.
PROFILE = [('streetpass_hits', 0x00, 4, 999999), ('plaza_population', 0x04, 2, 3000),
           ('hat', 0x06, 1, 75), ('pet', 0x07, 1, 2),
           ('dream', 0x08, 1, 19), ('hobby', 0x09, 1, 27)]

DREAM_OPTIONS = ['big', 'champ', 'fly', 'hero', 'long', 'love', 'magic', 'marry', 'master', 'nice',
                 'president', 'princess', 'rich', 'secret', 'space', 'sports', 'star',
                 'supernatural']
HOBBY_OPTIONS = ['book', 'camera', 'cleaning', 'cook', 'dance', 'dressup', 'drive', 'drow', 'eat',
                 'fish', 'game', 'help', 'in', 'money', 'movie', 'music', 'out', 'party', 'pet',
                 'secret', 'shop', 'sleep', 'sports', 'study', 'talk', 'travel']

# Inferred, not proven: body+0x614C is the speech-bubble style.
OFF_BUBBLE = 0x614C
BUBBLE_MAX = 5

DAYS_IN_MONTH = (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def build_profile(**kw):
    """-> the 0x10-byte block for body+0x3F60."""
    b = bytearray(0x10)
    for name, off, size, ub in PROFILE:
        v = int(kw.pop(name, 0))
        if not (0 <= v <= ub):
            raise ValueError('%s = %d out of range [0, %d]' % (name, v, ub))
        if size == 4:   struct.pack_into('<I', b, off, v)
        elif size == 2: struct.pack_into('<H', b, off, v)
        else:           b[off] = v
    if kw:
        raise ValueError('unknown profile field(s) %s' % sorted(kw))
    return bytes(b)


def check_birthday(month, day):
    """meet_MiiBounds 0x18A008: both zero, or month 1..12 and day 1..daysInMonth."""
    if month == 0 and day == 0:
        return
    if not (1 <= month <= 12):
        raise ValueError('birthday_month must be 1..12 (or 0 with day 0)')
    if not (1 <= day <= DAYS_IN_MONTH[month - 1]):
        raise ValueError('birthday_day must be 1..%d for month %d' % (DAYS_IN_MONTH[month - 1], month))


def build_body(mii_cfl, greeting='Sent from Linux', title_id=0x0004000000000000,
               title_short='Tuxchange', title_long='StreetPass from Linux',
               title_publisher='Tuxchange', icon_small=None, icon_large=None,
               country='United Kingdom', region='England', address_code=0, profile=None,
               bubble=0):
    body = bytearray(BODY_LEN)
    if icon_small is None and icon_large is None:
        icon_small, icon_large = build_icons()
    ra = sp_smdh.build_region_a(title_id, title_short, title_long, title_publisher)
    rb = sp_smdh.build_region_b(small=icon_small, large=icon_large)
    body[sp_smdh.REGION_A_OFF:sp_smdh.REGION_A_OFF + sp_smdh.REGION_A_LEN] = ra
    body[sp_smdh.REGION_B_OFF:sp_smdh.REGION_B_OFF + sp_smdh.REGION_B_LEN] = rb
    struct.pack_into('<I', body, OFF_PRESENT, PRESENT_FLAG)
    struct.pack_into('<I', body, OFF_ADDR, address_code)
    body[0x3F60:0x3F70] = profile if profile is not None else build_profile()
    if not (0 <= bubble <= BUBBLE_MAX):
        raise ValueError('bubble must be 0..%d (sanitiser clamps < 6)' % BUBBLE_MAX)
    body[OFF_BUBBLE] = bubble
    for base, txt in ((OFF_COUNTRY, country), (OFF_REGION, region)):
        names = list(txt) if isinstance(txt, (list, tuple)) else [txt] * 16
        if len(names) != 16:
            raise ValueError('country/region must be one string or exactly 16')
        for i, s16 in enumerate(names):
            e = s16.encode('utf-16-le')[:0x3E]
            body[base + i * 0x40: base + i * 0x40 + len(e)] = e
    g = greeting.encode('utf-16-le')[:0x20]
    body[OFF_GREETING:OFF_GREETING + len(g)] = g
    struct.pack_into('<4sI', body, OFF_MII, sp_mii.MAGIC_CFPB, 1)
    struct.pack_into('<H', body, OFF_MII + 0x14, 1)
    body = sp_mii.write_plaza_mii(bytes(body), mii_cfl)
    return body


def build_message(body, message_id=None, when=None, info_text=INFO_TEXT, icon=None,
                  cec_title_id=PLAZA_TITLE):
    """Envelope + container header + ex-headers + body + HMAC trailer -> the wire object."""
    import time, random
    if len(body) != BODY_LEN:
        raise ValueError('body must be %#x bytes' % BODY_LEN)
    if message_id is None:
        message_id = random.getrandbits(64)
    if when is None:
        when = time.gmtime()
    icon = icon if icon is not None else cec_icon()

    ex = b''
    for t, d in ((2, icon), (4, info_text.encode('utf-16-le') + b'\x00\x00')):
        ex += struct.pack('<II', t, len(d)) + d + b'\x00' * ((-len(d)) % 4)
    header_size = HDR_LEN + len(ex)
    total = header_size + len(body) + TRAILER_LEN

    h = bytearray(HDR_LEN)
    struct.pack_into('<HH', h, 0x00, 0x6060, 0)
    struct.pack_into('<III', h, 0x04, total, header_size, len(body))
    struct.pack_into('<I', h, 0x10, cec_title_id)
    struct.pack_into('<Q', h, 0x20, message_id)
    h[0x34] = 3
    struct.pack_into('<I', h, 0x60, when.tm_year)
    h[0x64] = when.tm_mon; h[0x65] = when.tm_mday
    h[0x66] = (when.tm_wday + 1) % 7              # console stores 0=Sunday
    h[0x67] = when.tm_hour; h[0x68] = when.tm_min; h[0x69] = when.tm_sec
    struct.pack_into('<H', h, 0x6A, 0)
    h[0x6C] = 0xFF; h[0x6D] = 1

    container = bytes(h) + ex + bytes(body)
    container += hmac.new(plaza_hmac_key(), bytes(body), hashlib.sha256).digest()

    env = bytearray(ENVELOPE_LEN)
    struct.pack_into('<HH', env, 0x00, 0x6161, 0)
    struct.pack_into('<I', env, 0x04, ENVELOPE_LEN + total)
    struct.pack_into('<I', env, 0x08, cec_title_id)
    struct.pack_into('<I', env, 0x10, 1)
    return bytes(env) + container


def parse_appearance(cfl):
    """Inverse of the APPEARANCE packing, matching what meet_MiiDecode produces."""
    out = {}
    for name, off, hi, lo, ub in APPEARANCE:
        if off in (0x2E, 0x2F):
            out[name] = cfl[off]
        else:
            out[name] = (struct.unpack_from('<H', cfl, off)[0] >> lo) & ((1 << (hi - lo + 1)) - 1)
    return out


def rgb565(r, g, b):
    return ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)


def draw_icon(dim=48, bg=(96, 168, 232), body=(24, 24, 32), belly=(248, 248, 248),
              beak=(248, 176, 32)):
    """A simple penguin, drawn procedurally."""
    s = dim / 48.0
    px = [[rgb565(*bg)] * dim for _ in range(dim)]

    def ell(cx, cy, rx, ry, colour):
        for y in range(dim):
            for x in range(dim):
                dx = (x + 0.5 - cx * s) / (rx * s)
                dy = (y + 0.5 - cy * s) / (ry * s)
                if dx * dx + dy * dy <= 1.0:
                    px[y][x] = rgb565(*colour)

    ell(24, 40, 13, 7, beak)
    ell(24, 27, 15, 18, body)
    ell(24, 30, 10, 13, belly)
    ell(24, 13, 10, 9, body)
    ell(19, 12, 3, 4, belly); ell(29, 12, 3, 4, belly)
    ell(19, 13, 1.4, 1.8, body); ell(29, 13, 1.4, 1.8, body)
    ell(24, 16, 3, 2.2, beak)
    return px


def build_icons(dim_small=24, dim_large=48, **kw):
    return draw_icon(dim_small, **kw), draw_icon(dim_large, **kw)


def cec_object(otype, payload, flags=0xFFFF):
    return (b'\x63\x63' + struct.pack('<H', flags) + struct.pack('<I', otype)
            + struct.pack('<I', 0) + struct.pack('<I', len(payload)) + bytes(payload))


def build_ee_record(cec_title_id, size, index=1, flags=0x300, count=1):
    """One `ee` message-list record: 0x2C header + `count` 32-byte entries."""
    return build_ee_list([(cec_title_id, flags, size, index)] * count)


def build_ee_list(entries):
    """An `ee` record carrying one 32-byte entry per (title, flags, size, index) tuple."""
    entries = list(entries)
    if len(entries) > 0x18:
        raise ValueError('an ee list holds at most 24 entries, got %d' % len(entries))
    r = bytearray(0x2C + len(entries) * 0x20)
    r[0:2] = b'ee'
    struct.pack_into('<II', r, 4, len(r), len(entries))
    for i, (tid, flags, size, index) in enumerate(entries):
        struct.pack_into('<IIII', r, 0x2C + i * 0x20, tid, flags, size, index)
    return bytes(r)


def header_send_mode(message):
    """The message header's +0x35 ("send mode", 0..3)."""
    off = ENVELOPE_LEN if message[:2] == b'\x61\x61' else 0
    return message[off + 0x35]


def header_flags(message):
    """The message header's +0x34. Goes to ee entry +0x05. cecd never reads it back."""
    off = ENVELOPE_LEN if message[:2] == b'\x61\x61' else 0
    return message[off + 0x34]


def ee_flags(message, phase):
    """The u32 an ee entry needs for `message`: phase 0 for a 0x31/0x32, 1 for a 0x33."""
    return header_send_mode(message) | (header_flags(message) << 8) | (phase << 16)


def message_title(message):
    """The CEC title id a wire message declares, read from its own container header (+0x10)."""
    off = ENVELOPE_LEN if message[:2] == b'\x61\x61' else 0
    if message[off:off + 2] != b'\x60\x60':
        raise ValueError('not a CEC message container (no 6060 magic)')
    return struct.unpack_from('<I', message, off + 0x10)[0]


def unwrap(message):
    """-> the list of bare 0x6060 containers inside `message`."""
    if message[:2] == b'\x60\x60':
        return [message[:struct.unpack_from('<I', message, 4)[0]]]
    if message[:2] != b'\x61\x61':
        raise ValueError('not a CEC message (no 6060 or 6161 magic)')
    n = max(1, struct.unpack_from('<I', message, 0x10)[0])
    out, off = [], ENVELOPE_LEN
    for _ in range(n):
        if off + 0x70 > len(message):
            raise ValueError('envelope declares %d containers, ran out at %d' % (n, len(out)))
        tot = struct.unpack_from('<I', message, off + 4)[0]
        out.append(message[off:off + tot])
        off += tot
    return out


def envelope(containers):
    """-> one wire object: the 0x14 envelope followed by `containers`, all of the same title."""
    if not containers:
        raise ValueError('an envelope needs at least one container')
    titles = {message_title(c) for c in containers}
    if len(titles) != 1:
        raise ValueError('one envelope carries one title, got %s'
                         % sorted('%08X' % t for t in titles))
    total = ENVELOPE_LEN + sum(len(c) for c in containers)
    env = bytearray(ENVELOPE_LEN)
    struct.pack_into('<HH', env, 0x00, 0x6161, 0)
    struct.pack_into('<I', env, 0x04, total)
    struct.pack_into('<I', env, 0x08, titles.pop())
    struct.pack_into('<I', env, 0x10, len(containers))
    return bytes(env) + b''.join(containers)


def as_wire(message):
    """Accept a bare container or an enveloped message; return the enveloped form."""
    if message[:2] == b'\x61\x61':
        return message
    if message[:2] != b'\x60\x60':
        raise ValueError('not a CEC message container (no 6060 magic)')
    total = struct.unpack_from('<I', message, 0x04)[0]
    env = bytearray(ENVELOPE_LEN)
    struct.pack_into('<HH', env, 0x00, 0x6161, 0)
    struct.pack_into('<I', env, 0x04, ENVELOPE_LEN + total)
    struct.pack_into('<I', env, 0x08, struct.unpack_from('<I', message, 0x10)[0])
    struct.pack_into('<I', env, 0x10, 1)
    return bytes(env) + message[:total]


def set_message_id(message, message_id=None):
    """Give a wire message a new id, so the receiver treats it as one it has not seen."""
    import random
    if message_id is None:
        message_id = random.getrandbits(64)
    b = bytearray(as_wire(message))
    struct.pack_into('<Q', b, ENVELOPE_LEN + 0x20, message_id)
    return bytes(b)


def build_outbox(message, console_id=None, cec_title_id=None, send_mode=None):
    """-> the objects a session sends: 0x21, 0x23, 0x31, 0x33, 0x81, then one object per message."""
    import random
    given = [message] if isinstance(message, (bytes, bytearray)) else list(message)
    if not given:
        raise ValueError('build_outbox needs at least one message')
    # One object and one ee entry per title, matching cecd's own list builder.
    groups = []                                   # [(title, [container, ...])]
    index = {}
    for m in given:
        for c in unwrap(m):
            t = message_title(c)
            if t not in index:
                index[t] = len(groups); groups.append((t, []))
            groups[index[t]][1].append(c)
    messages = [envelope(cs) for _t, cs in groups]
    if len(messages) > O81_SLOTS:
        raise ValueError('the 0x81 object holds at most %d titles, got %d'
                         % (O81_SLOTS, len(messages)))

    def _per(v, fn):
        if v is None:
            return [fn(m) for m in messages]
        if isinstance(v, (list, tuple)):
            if len(v) != len(messages):
                raise ValueError('expected %d values, got %d' % (len(messages), len(v)))
            return list(v)
        return [v] * len(messages)

    if console_id is None:
        console_id = random.getrandbits(64)
    titles = _per(cec_title_id, message_title)
    modes = _per(send_mode, header_send_mode)
    # The ee size sums the title's containers. The 0x81 size adds the 0x14 envelope.
    totals = [sum(struct.unpack_from('<I', c, 0x04)[0] for c in cs) for _t, cs in groups]
    counts = [len(cs) for _t, cs in groups]
    envtots = [struct.unpack_from('<I', m, 0x04)[0] for m in messages]
    # Entries are 8 bytes. A wrong stride makes cecd reject the size and end the session.
    o81 = bytearray(4 + O81_SLOTS * 8)
    struct.pack_into('<I', o81, 0, len(messages))
    for i, (t, e) in enumerate(zip(titles, envtots)):
        struct.pack_into('<II', o81, 4 + i * 8, t, e)
    # The send mode must be each message's own, or the peer discards the message.
    f31 = [m | (header_flags(msg) << 8) for m, msg in zip(modes, messages)]
    e31 = [(t, f, tot, n) for t, f, tot, n in zip(titles, f31, totals, counts)]
    e33 = [(t, f | (1 << 16), tot, n) for t, f, tot, n in zip(titles, f31, totals, counts)]
    return [cec_object(0x21, struct.pack('<Q', console_id)),
            cec_object(0x23, struct.pack('<I', 1)),
            cec_object(0x31, build_ee_list(e31)),
            cec_object(0x33, build_ee_list(e33)),
            cec_object(0x81, bytes(o81), flags=0x0000)] + messages


def build(**kw):
    """One call: -> a complete 32,732-byte plaza CEC object."""
    mii = build_cfl(**{k: kw.pop(k) for k in
                       ('mii_name', 'author_name', 'mii_id', 'creator_mac', 'face_shape', 'kind')
                       if k in kw})
    msg_kw = {k: kw.pop(k) for k in
              ('message_id', 'when', 'info_text', 'icon', 'cec_title_id') if k in kw}
    return build_message(build_body(mii, **kw), **msg_kw)


def _raises(fn):
    try:
        fn(); return False
    except ValueError:
        return True


def _selftest():
    ok = tot = skipped = 0

    def chk(name, cond, got=''):
        nonlocal ok, tot
        tot += 1; ok += bool(cond)
        print('  [%s] %s%s' % ('PASS' if cond else 'FAIL', name, ('  %s' % (got,)) if got else ''))

    def skip(name, why):
        nonlocal skipped
        skipped += 1
        print('  [SKIP] %s  (%s)' % (name, why))

    import lp_corpus as corpus, lp_keys as _k
    if _k.selftest_keys():
        print('  (no console keys found, so running on generated throwaway keys)')
    msg = build(mii_name='Linux', author_name='Tuxchange', greeting='Built from zero',
                creator_mac='b8:ae:6e:11:22:33', message_id=0x0123456789ABCDEF)

    chk('message is the same size as a real one', len(msg) == 32732, len(msg))
    real = corpus.load('plaza_message')
    if real is None:
        skip('envelope matches a real one except the size-invariant fields', corpus.why_skipped())
    else:
        chk('envelope matches a real one except the size-invariant fields',
            msg[:4] == real[:4] and msg[4:8] == real[4:8] and msg[8:12] == real[8:12])

    b = msg[ENVELOPE_LEN:]
    h = sp_cec.parse_header(b)
    chk('header parses, plaza title', h['cec_title_id'] == PLAZA_TITLE)
    chk('header_size matches a real message', h['header_size'] == 0xD28, hex(h['header_size']))
    chk('body_size matches a real message', h['body_size'] == 0x7280, hex(h['body_size']))
    chk('total_size matches a real message', h['total_size'] == 0x7FC8, hex(h['total_size']))
    m = sp_cec.parse_message(b)
    chk('no container problems', not m['problems'], str(m['problems']))
    chk('two ex-headers, types 2 and 4',
        [e['type'] for e in m['exheaders']] == [2, 4] and
        [e['size'] for e in m['exheaders']] == [0xC80, 0x28])
    if real is None:
        skip('ex-header type 2 matches a real message', corpus.why_skipped())
        skip('ex-header type 4 is byte-identical to a real message', corpus.why_skipped())
    else:
        rb = sp_cec.parse_message(real[ENVELOPE_LEN:])
        chk('ex-header type 2 matches a real message in size',
            len(m['exheaders'][0]['data']) == len(rb['exheaders'][0]['data']))
        chk('ex-header type 4 is byte-identical to a real message',
            m['exheaders'][1]['data'] == rb['exheaders'][1]['data'])

    body = b[h['header_size']:h['header_size'] + h['body_size']]
    tag = b[h['header_size'] + h['body_size']:h['total_size']]
    chk('HMAC-SHA256 trailer verifies',
        tag == hmac.new(plaza_hmac_key(), body, hashlib.sha256).digest())

    pl = sp_cec.parse_plaza_body(body)
    chk('body parses with no problems', not pl['problems'], str(pl['problems']))
    chk('greeting round-trips', pl['greeting'] == 'Built from zero', repr(pl['greeting']))
    chk('Mii CCM MAC and CRC both valid',
        pl['mii']['ccm_mac_ok'] and pl['mii']['crc_ok'])
    chk('Mii name and author round-trip',
        pl['mii']['mii_name'] == 'Linux' and pl['mii']['author_name'] == 'Tuxchange')
    chk('present_flag is 0x100 as the shipping build writes',
        struct.unpack_from('<I', body, OFF_PRESENT)[0] == 0x100)

    cfl, macok = sp_mii.read_plaza_mii(body)
    okv, why = sp_mii.validate_cfl(cfl)
    chk('Mii passes sp_mii.validate_cfl', okv, str(why))
    chk('Mii id byte has bit 5 clear', not ((cfl[0x0C] >> 5) & 1), '%#04x' % cfl[0x0C])
    chk('struct+0x104 (CFL+0 bits 30:28) is in [1,3]',
        1 <= ((struct.unpack_from('<I', cfl, 0)[0] >> 28) & 7) <= 3)
    chk('struct+0x54 (CFL+0x3A bits 13:9) is in [3,0x12]',
        3 <= ((struct.unpack_from('<H', cfl, 0x3A)[0] >> 9) & 0x1F) <= 0x12)
    okr, whyr = sp_smdh.validate_region_a(body)
    chk('region A passes sp_smdh.validate_region_a', okr, str(whyr))
    ta = sp_smdh.parse_region_a(body)
    chk('region A category check passes', ta['category_ok'])
    chk('region A titles round-trip', ta['titles'][0]['short'] == 'Tuxchange'
        and ta['titles'][15]['publisher'] == 'Tuxchange')

    for bad in ('a%b', 'a\\b'):
        try:
            build_cfl(mii_name=bad); chk('name %r rejected' % bad, False)
        except ValueError:
            chk('name %r rejected' % bad, True)
    for kw, val in (('eyebrow_ypos', 2), ('eyebrow_ypos', 19), ('device_origin', 0),
                    ('device_origin', 4), ('skin_colour', 6), ('eye_style', 60), ('build', 129)):
        try:
            build_cfl(**{kw: val}); chk('%s=%s rejected' % (kw, val), False)
        except ValueError:
            chk('%s=%s rejected' % (kw, val), True)
    chk('unknown appearance field is rejected',
        _raises(lambda: build_cfl(nose_wiggle=1)))

    if real is None:
        for n in ('rebuilding the real body reproduces the Mii',
                  'rebuilding reproduces regions A and B',
                  'rebuilding reproduces the country/region tables',
                  'rebuilding reproduces the greeting'):
            skip(n, corpus.why_skipped())
    else:
        rbody = real[ENVELOPE_LEN:][rb['header']['header_size']:
                                    rb['header']['header_size'] + rb['header']['body_size']]
        rpl = sp_cec.parse_plaza_body(rbody)
        rta = sp_smdh.parse_region_a(rbody)
        clone = build_body(sp_mii.read_plaza_mii(rbody)[0], greeting=rpl['greeting'],
                           title_id=rta['title_id'], title_short=rta['titles'][0]['short'],
                           title_long=rta['titles'][0]['long'],
                           title_publisher=rta['titles'][0]['publisher'],
                           icon_small=sp_smdh.decode_icon(rbody, large=False),
                           icon_large=sp_smdh.decode_icon(rbody, large=True),
                           country=rpl['country'], region=rpl['region'],
                           address_code=struct.unpack_from('<I', rbody, OFF_ADDR)[0])
        diff = [i for i in range(BODY_LEN) if clone[i] != rbody[i]]
        outside = [i for i in diff if not (0x3F60 <= i < 0x3F70 or 0x45C4 <= i < 0x45D3
                                           or 0x45D3 <= i < 0x60EB or 0x60EB <= i < 0x7280
                                           or 0x0 <= i < 0x30)]
        chk('rebuilding the real 2DS body reproduces the Mii exactly',
            clone[OFF_MII:OFF_MII + 0xA0] == rbody[OFF_MII:OFF_MII + 0xA0])
        chk('rebuilding reproduces regions A and B exactly',
            clone[0x30:0x36B8] == rbody[0x30:0x36B8])
        chk('rebuilding reproduces the localised country/region tables exactly',
            clone[0x3760:0x3F60] == rbody[0x3760:0x3F60])
        chk('rebuilding reproduces the greeting exactly',
            clone[0x3F70:0x3F92] == rbody[0x3F70:0x3F92])
        print('       (rebuild differs in %d body bytes; %d of them outside the regions whose'
              ' contents we deliberately do not reproduce)' % (len(diff), len(outside)))

    caps = [corpus.load('plaza_object_%d' % i) for i in range(5)]
    if real is None or any(c is None for c in caps):
        for i in range(5):
            skip('object %d rebuilt byte-exactly' % i, corpus.why_skipped())
    else:
        cid = struct.unpack_from('<Q', caps[0], 0x10)[0]
        ours = build_outbox(real, console_id=cid)
        for i in range(5):
            chk('object %d (type %#x) rebuilt byte-exactly'
                % (i, struct.unpack_from('<I', caps[i], 4)[0]),
                ours[i] == caps[i], '%d vs %d B' % (len(ours[i]), len(caps[i])))
    full = build_outbox(msg)
    chk('a from-scratch outbox is 6 objects with the right sizes',
        [len(o) for o in full] == [24, 20, 92, 92, 212, 32732], [len(o) for o in full])

    cfl2 = build_cfl(mii_name='Tux')
    got = parse_appearance(cfl2)
    chk('every DEFAULT_FACE field round-trips through the bit packing',
        all(got[k] == v for k, v in DEFAULT_FACE.items()),
        str({k: (v, got[k]) for k, v in DEFAULT_FACE.items() if got[k] != v}))
    chk('height and build are the mid-range 64, not 0',
        got['height'] == 64 and got['build'] == 64)
    chk('eyebrow_ypos is above its hard minimum of 3', got['eyebrow_ypos'] > 3, got['eyebrow_ypos'])
    if real is None:
        skip('a captured Mii decodes to plausible appearance values', corpus.why_skipped())
    else:
        chk('a captured Mii decodes to plausible appearance values',
            all(0 <= v for v in parse_appearance(
                sp_mii.read_plaza_mii(rbody)[0]).values()))
    small, large = build_icons()
    chk('drawn icons are the right dimensions', len(small) == 24 and len(large) == 48)
    chk('drawn icon is not a solid colour (the first run shipped all-zero = black)',
        len({v for row in large for v in row}) >= 4,
        '%d distinct colours' % len({v for row in large for v in row}))
    body2 = build_body(cfl2)
    chk('icons survive the region B encode/decode round trip',
        sp_smdh.decode_icon(body2, large=True) == large
        and sp_smdh.decode_icon(body2, large=False) == small)

    prof = build_profile(streetpass_hits=1234, plaza_population=56, hat=7, pet=1, dream=3, hobby=11)
    mb = build_body(build_cfl(mii_name='Tux', birthday_month=8, birthday_day=4,
                              favourite_colour=6), profile=prof)
    got = mb[0x3F60:0x3F70]
    chk('streetpass_hits round-trips', struct.unpack_from('<I', got, 0)[0] == 1234)
    chk('plaza_population round-trips', struct.unpack_from('<H', got, 4)[0] == 56)
    chk('hat/pet/dream/hobby round-trip',
        (got[6], got[7], got[8], got[9]) == (7, 1, 3, 11), str(tuple(got[6:10])))
    ap2 = parse_appearance(sp_mii.read_plaza_mii(mb)[0])
    chk('Mii birthday round-trips',
        (ap2['birthday_month'], ap2['birthday_day']) == (8, 4))
    chk('favourite colour (shirt) round-trips', ap2['favourite_colour'] == 6)
    chk('author name is the card Creator field',
        sp_mii.parse_cfl(sp_mii.read_plaza_mii(build_body(
            build_cfl(mii_name='Tux', author_name='Tuxchange')))[0])['author_name'] == 'Tuxchange')
    for k, v in (('streetpass_hits', 1000000), ('plaza_population', 3001), ('hat', 76),
                 ('pet', 3), ('dream', 20), ('hobby', 28)):
        chk('profile %s=%d rejected' % (k, v), _raises(lambda: build_profile(**{k: v})))
    chk('unknown profile field rejected', _raises(lambda: build_profile(favourite_snack=1)))
    chk('birthday 0/0 accepted', build_cfl(birthday_month=0, birthday_day=0) is not None)
    for m_, d_ in ((13, 1), (0, 5), (2, 30), (1, 0)):
        chk('birthday %d/%d rejected' % (m_, d_),
            _raises(lambda: build_cfl(birthday_month=m_, birthday_day=d_)))
    chk('birthday 2/29 accepted (leap-safe)', build_cfl(birthday_month=2, birthday_day=29) is not None)
    if real is None:
        skip('a captured profile block re-encodes exactly', corpus.why_skipped())
    else:
        rprof = rbody[0x3F60:0x3F70]
        chk('a captured profile block re-encodes exactly',
            build_profile(streetpass_hits=struct.unpack_from('<I', rprof, 0)[0],
                          plaza_population=struct.unpack_from('<H', rprof, 4)[0],
                          hat=rprof[6], pet=rprof[7], dream=rprof[8], hobby=rprof[9]) == rprof)

    bb = build_body(build_cfl(mii_name='Tux'), bubble=4)
    chk('bubble style round-trips at body+0x614C', bb[OFF_BUBBLE] == 4)
    chk('bubble style 6 is rejected', _raises(lambda: build_body(build_cfl(), bubble=6)))
    if real is None:
        skip('both captured consoles carry bubble=1', corpus.why_skipped())
        skip('the per-person arrays match the met16 list', corpus.why_skipped())
    else:
        chk('both captured consoles carry bubble=1', rbody[OFF_BUBBLE] == 1)
        chk('the per-person arrays are non-zero only where met16 is populated',
            [i for i in range(16) if rbody[0x612C + i]] ==
            [e['idx'] for e in sp_cec.parse_plaza_body(rbody)['met16']])

    chk('message_title reads the title from the container', message_title(msg) == PLAZA_TITLE)
    chk('as_wire is idempotent on an enveloped message', as_wire(msg) == msg)
    bare = msg[ENVELOPE_LEN:]
    chk('as_wire wraps a bare container back to the identical wire form', as_wire(bare) == msg)
    other = 0x00141000
    ob2 = build_outbox(msg, console_id=1, cec_title_id=other)
    for i, o in ((2, ob2[2]), (3, ob2[3])):
        chk('object %d ee record carries the requested title' % i,
            struct.unpack_from('<I', o, 0x10 + 0x2C)[0] == other)
    chk('object 0x81 carries the requested title',
        struct.unpack_from('<I', ob2[4], 0x10 + 4)[0] == other)
    ob3 = build_outbox(bare, console_id=1)
    chk('outbox infers the title from a bare container',
        struct.unpack_from('<I', ob3[2], 0x10 + 0x2C)[0] == PLAZA_TITLE and ob3[5] == msg)
    chk('a non-CEC blob is rejected', _raises(lambda: build_outbox(b'\x00' * 64)))

    chk('ee entry +0x04/+0x05 come from the message header +0x35/+0x34',
        header_send_mode(msg) == msg[ENVELOPE_LEN + 0x35] and
        header_flags(msg) == msg[ENVELOPE_LEN + 0x34])
    chk('header accessors work on a bare container too',
        header_send_mode(bare) == header_send_mode(msg) and
        header_flags(bare) == header_flags(msg))
    e31 = ob3[2][0x10 + 0x2C:0x10 + 0x2C + 0x10]
    e33 = ob3[3][0x10 + 0x2C:0x10 + 0x2C + 0x10]
    chk('plaza is send mode 0, so the outbox is byte-identical to the old hardcoded 0x00300',
        struct.unpack_from('<I', e31, 4)[0] == 0x00300, hex(struct.unpack_from('<I', e31, 4)[0]))
    chk('the 0x33 entry is the 0x31 entry with phase 1',
        struct.unpack_from('<I', e33, 4)[0] == 0x10300)
    mk7 = corpus.load('second_title_outbox')
    if mk7 is None:
        skip('send-mode and multi-title checks (need a harvested outbox tree)',
             corpus.why_skipped())
    else:
        chk('a real Mario Kart 7 message declares send mode 3', header_send_mode(mk7) == 3)
        obm = build_outbox(mk7, console_id=1)
        chk('its 0x31 entry now declares mode 3, not Plaza\'s 0',
            struct.unpack_from('<I', obm[2], 0x10 + 0x2C + 4)[0] == 0x00303,
            hex(struct.unpack_from('<I', obm[2], 0x10 + 0x2C + 4)[0]))
        chk('its 0x33 entry declares mode 3 with phase 1',
            struct.unpack_from('<I', obm[3], 0x10 + 0x2C + 4)[0] == 0x10303)
        chk('--send-mode override still reaches the entry',
            struct.unpack_from('<I', build_outbox(mk7, console_id=1, send_mode=0)[2],
                               0x10 + 0x2C + 4)[0] == 0x00300)
        harvested = corpus.glob(os.path.join('harvested', '*.bin'))
        modes = {os.path.basename(f): header_send_mode(open(f, 'rb').read()) for f in harvested}
        zero = [n for n, m in modes.items() if m == 0]
        chk('exactly one harvested message uses send mode 0, and it is Mii Plaza',
            len(zero) == 1 and zero[0].startswith('00020800'), zero)
        chk('every other harvested message would have been lost by the old hardcoded 0',
            all(m != 0 for n, m in modes.items() if not n.startswith('00020800')),
            '%d of %d files' % (len(modes) - len(zero), len(modes)))

        plaza = corpus.load('plaza_outbox')
        multi = build_outbox([plaza, mk7], console_id=1)
        chk('a two-message outbox has 5 control objects then both messages', len(multi) == 7)
        chk('the messages are appended in the order given',
            multi[5] == as_wire(plaza) and multi[6] == as_wire(mk7))
        o81 = multi[4][0x10:]
        chk('the 0x81 declares 2 messages', struct.unpack_from('<I', o81, 0)[0] == 2)
        chk('0x81 entries are 8 bytes apart, as the console emits them',
            struct.unpack_from('<II', o81, 4) == (PLAZA_TITLE, len(as_wire(plaza))) and
            struct.unpack_from('<II', o81, 12) == (0x00030600, len(as_wire(mk7))))
        chk('the 0x81 payload is the console\'s own 196 B', len(o81) == 4 + 24 * 8, len(o81))
        want81 = bytes.fromhex('02000000' '00060300' '90370000' '00080200' 'dc7f0000')
        got81 = build_outbox([mk7, plaza], console_id=1)[4][0x10:0x10 + len(want81)]
        chk('our 0x81 is byte-identical to the console\'s for the same two messages',
            got81 == want81, got81.hex())
        ee = multi[2][0x10:]
        chk('the 0x31 ee record declares 2 entries and is sized for them',
            struct.unpack_from('<II', ee, 4) == (0x2C + 2 * 0x20, 2) and len(ee) == 0x2C + 2 * 0x20)
        chk('each ee entry carries ITS OWN send mode, not one value for the run',
            struct.unpack_from('<I', ee, 0x2C + 4)[0] == 0x00300 and
            struct.unpack_from('<I', ee, 0x2C + 0x20 + 4)[0] == 0x00303)
        chk('the 0x33 is the 0x31 with phase 1 on every entry',
            struct.unpack_from('<I', multi[3][0x10:], 0x2C + 4)[0] == 0x10300 and
            struct.unpack_from('<I', multi[3][0x10:], 0x2C + 0x20 + 4)[0] == 0x10303)
        chk('an ee list longer than 24 entries is rejected',
            _raises(lambda: build_ee_list([(1, 0, 0, 1)] * 25)))
        def _retitled(container, tid):
            b = bytearray(container)
            struct.pack_into('<I', b, 0x10, tid)
            return bytes(b)

        many = [_retitled(plaza, 0x00010000 + (i << 8)) for i in range(25)]
        chk('more than 24 TITLES is rejected', _raises(lambda: build_outbox(many, console_id=1)))
        chk('24 titles is accepted', len(build_outbox(many[:24], console_id=1)) == 29,
            len(build_outbox(many[:24], console_id=1)))

        tomo = corpus.glob(os.path.join('harvested_new', '0008C500_outbox_*.bin'))
        if len(tomo) == 2:
            t1, t2 = (open(x, 'rb').read() for x in tomo)
            ob2t = build_outbox([t1, t2], console_id=1)
            chk('two messages of one title make ONE wire object', len(ob2t) == 6, len(ob2t))
            env = ob2t[5]
            chk('the envelope declares 2 containers',
                struct.unpack_from('<I', env, 0x10)[0] == 2)
            chk('and its total is 0x14 + both container totals',
                struct.unpack_from('<I', env, 0x04)[0] == ENVELOPE_LEN + len(t1) + len(t2) and
                len(env) == ENVELOPE_LEN + len(t1) + len(t2))
            chk('unwrap round-trips both containers back out',
                unwrap(env) == [t1, t2])
            ee2 = ob2t[2][0x10:]
            chk('there is ONE ee entry, not two',
                struct.unpack_from('<I', ee2, 8)[0] == 1)
            chk('its size is the SUM of the two containers',
                struct.unpack_from('<I', ee2, 0x2C + 8)[0] == len(t1) + len(t2),
                hex(struct.unpack_from('<I', ee2, 0x2C + 8)[0]))
            chk('its count field is 2, not 1',
                struct.unpack_from('<I', ee2, 0x2C + 12)[0] == 2)
            o812 = ob2t[4][0x10:]
            chk('the 0x81 declares one entry, sized as the envelope',
                struct.unpack_from('<I', o812, 0)[0] == 1 and
                struct.unpack_from('<II', o812, 4) == (0x0008C500, len(env)))
            mixed = build_outbox([t1, mk7, t2], console_id=1)
            chk('a title is grouped even when its messages are not adjacent',
                len(mixed) == 7 and unwrap(mixed[5]) == [t1, t2] and
                message_title(mixed[6]) == 0x00030600)
            chk('grouping keeps first-appearance order',
                struct.unpack_from('<I', mixed[2][0x10:], 0x2C)[0] == 0x0008C500)
            chk('an envelope will not mix titles', _raises(lambda: envelope([t1, mk7])))
        chk('an empty message list is rejected', _raises(lambda: build_outbox([], console_id=1)))

    import hmac as _h2, hashlib as _hh2
    fresh = set_message_id(msg, 0x0102030405060708)
    chk('set_message_id changes only the 8 id bytes',
        sum(1 for i in range(len(msg)) if msg[i] != fresh[i]) <= 8)
    chk('the new id reads back', struct.unpack_from('<Q', fresh, ENVELOPE_LEN + 0x20)[0]
        == 0x0102030405060708)
    hh3 = sp_cec.parse_header(fresh[ENVELOPE_LEN:])
    bd3 = fresh[ENVELOPE_LEN:][hh3['header_size']:hh3['header_size'] + hh3['body_size']]
    tg3 = fresh[ENVELOPE_LEN:][hh3['header_size'] + hh3['body_size']:hh3['total_size']]
    chk('the HMAC still verifies after the id change',
        tg3 == _h2.new(plaza_hmac_key(), bd3, _hh2.sha256).digest())
    chk('set_message_id works on a bare container too',
        sp_cec.parse_header(set_message_id(bare)[ENVELOPE_LEN:])['cec_title_id'] == PLAZA_TITLE)

    print('\n%d/%d checks passed%s' % (ok, tot,
          '' if not skipped else ', %d skipped (no test corpus)' % skipped))
    return 0 if ok == tot else 1


if __name__ == '__main__':
    import sys
    sys.exit(_selftest())
