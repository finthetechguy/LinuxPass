#!/usr/bin/env python3
"""CFPB Mii container: unwrap, edit, re-wrap."""
import struct

try:
    from Crypto.Cipher import AES as _AES
    def _ecb(key, block): return _AES.new(key, _AES.MODE_ECB).encrypt(block)
    HAVE_PYCRYPTO = True
except ImportError:                                          # pragma: no cover
    import sp_aes
    def _ecb(key, block): return sp_aes.aes_ecb_encrypt(key, block)
    HAVE_PYCRYPTO = False

MAGIC_CFPB   = b'CFPB'
MAGIC_CFPN   = b'CFPN'
HDR_LEN      = 0x18          # entry i is at container + 0x18 + i*0x70
ENTRY_LEN    = 0x70
CFL_LEN      = 0x60
NONCE_OFF    = 0x0C
NONCE_LEN    = 8
MAC_LEN      = 0x10
CCM_L        = 3
PLAZA_MII_OFF = 0x36BC       # container offset inside the plaza body

import lp_keys as _keys


def apt_key(key_file=None):
    """Keyslot 0x31's normal key, from your own dump. Raises lp_keys.MissingKey."""
    return _keys.apt_key(key_file)


def _x(a, b): return bytes(p ^ q for p, q in zip(a, b))


def _ctr(key, nonce12, data):
    out = b''
    for i in range(0, len(data), 16):
        ks = _ecb(key, bytes([CCM_L - 1]) + nonce12 + ((i // 16) + 1).to_bytes(CCM_L, 'big'))
        out += _x(data[i:i + 16], ks)
    return out


def _tag(key, nonce12, pt):
    """CBC-MAC over B0 || zero-padded plaintext. B0 length field is the PADDED length."""
    padded = pt + b'\x00' * (-len(pt) % 16)
    x = _ecb(key, bytes([0x3A]) + nonce12 + len(padded).to_bytes(CCM_L, 'big'))
    for i in range(0, len(padded), 16):
        x = _ecb(key, _x(x, padded[i:i + 16]))
    return x


def unwrap_entry(entry, key=None):
    """0x70 wrapped entry -> (0x60 CFLStoreData, mac_ok). key=None loads yours."""
    if key is None:
        key = apt_key()
    if len(entry) != ENTRY_LEN:
        raise ValueError('entry must be %#x bytes, got %#x' % (ENTRY_LEN, len(entry)))
    nonce = entry[:NONCE_LEN] + b'\x00' * (12 - NONCE_LEN)
    ct, mac = entry[NONCE_LEN:-MAC_LEN], entry[-MAC_LEN:]
    pt = _ctr(key, nonce, ct)
    s0 = _ecb(key, bytes([CCM_L - 1]) + nonce + (0).to_bytes(CCM_L, 'big'))
    ok = _x(_tag(key, nonce, pt), s0[:MAC_LEN]) == mac
    return pt[:NONCE_OFF] + entry[:NONCE_LEN] + pt[NONCE_OFF:], ok


def wrap_entry(cfl, key=None):
    """0x60 CFLStoreData -> 0x70 wrapped entry. The nonce is taken from the data itself."""
    if key is None:
        key = apt_key()
    if len(cfl) != CFL_LEN:
        raise ValueError('cfl must be %#x bytes, got %#x' % (CFL_LEN, len(cfl)))
    nonce8 = cfl[NONCE_OFF:NONCE_OFF + NONCE_LEN]
    pt = cfl[:NONCE_OFF] + cfl[NONCE_OFF + NONCE_LEN:]
    nonce = nonce8 + b'\x00' * (12 - NONCE_LEN)
    ct = _ctr(key, nonce, pt)
    s0 = _ecb(key, bytes([CCM_L - 1]) + nonce + (0).to_bytes(CCM_L, 'big'))
    return nonce8 + ct + _x(_tag(key, nonce, pt), s0[:MAC_LEN])


def mii_crc(cfl):
    """CRC-16/CCITT, poly 0x1021 init 0x0000, over bytes 0..0x5E. Stored big-endian at 0x5E."""
    c = 0
    for b in cfl[:0x5E]:
        c ^= b << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
    return c


def _utf16z(b): return b.decode('utf-16-le', 'replace').split('\x00', 1)[0]


def parse_cfl(cfl):
    return {
        'version':     cfl[0x00],
        'flags':       cfl[0x01],
        'mii_id':      struct.unpack_from('<I', cfl, 0x0C)[0],
        'creator_mac': ':'.join('%02x' % c for c in cfl[0x10:0x16]),
        'mii_name':    _utf16z(cfl[0x1A:0x2E]),
        'author_name': _utf16z(cfl[0x48:0x5C]),
        'crc':         struct.unpack_from('>H', cfl, 0x5E)[0],
        'crc_ok':      struct.unpack_from('>H', cfl, 0x5E)[0] == mii_crc(cfl),
    }


def reseal_cfl(cfl):
    """Recompute the CRC. Call after ANY edit -- 0x159A8C validates it."""
    b = bytearray(cfl)
    struct.pack_into('>H', b, 0x5E, mii_crc(bytes(b)))
    return bytes(b)


def set_mii_name(cfl, name):
    b = bytearray(cfl)
    e = name.encode('utf-16-le')[:20]
    b[0x1A:0x2E] = e + b'\x00' * (0x14 - len(e))
    return reseal_cfl(bytes(b))


def set_author_name(cfl, name):
    b = bytearray(cfl)
    e = name.encode('utf-16-le')[:20]
    b[0x48:0x5C] = e + b'\x00' * (0x14 - len(e))
    return reseal_cfl(bytes(b))


def random_mii_id():
    """A Mii id the plaza will accept."""
    import random as _r
    return (0x90 | _r.getrandbits(4)) | (_r.getrandbits(24) << 8)


def validate_cfl(cfl):
    """Replicate the plaza's own gate."""
    why = []
    if len(cfl) != CFL_LEN:
        return False, ['wrong length %#x' % len(cfl)]
    if mii_crc(cfl) != struct.unpack_from('>H', cfl, 0x5E)[0]:
        why.append('CRC-16/CCITT mismatch at +0x5E (0x2137A0 would be non-zero)')
    ident = cfl[0x0C:0x16]
    if not any(ident):
        why.append('identity is all zero (0x20F04C rejects)')
    if (cfl[0x0C] >> 5) & 1:
        why.append('bit 5 of the Mii id byte at +0x0C is set: 0x%02x (0x20E558 rejects)' % cfl[0x0C])
    return (not why), why


def set_identity(cfl, mii_id=None, creator_mac=None):
    """Change who the Mii claims to be."""
    b = bytearray(cfl)
    if mii_id is not None:
        struct.pack_into('<I', b, 0x0C, mii_id)
    if creator_mac is not None:
        if isinstance(creator_mac, str):
            creator_mac = bytes(int(x, 16) for x in creator_mac.split(':'))
        b[0x10:0x16] = bytes(creator_mac)
    return reseal_cfl(bytes(b))


def container_entries(body, off=PLAZA_MII_OFF):
    """-> (magic, count, [wrapped entry, ...])"""
    magic = body[off:off + 4]
    count = struct.unpack_from('<H', body, off + 0x14)[0]
    return magic, count, [body[off + HDR_LEN + i * ENTRY_LEN:
                               off + HDR_LEN + (i + 1) * ENTRY_LEN] for i in range(count)]


def read_plaza_mii(body, off=PLAZA_MII_OFF, index=0):
    magic, count, ents = container_entries(body, off)
    if magic not in (MAGIC_CFPB, MAGIC_CFPN):
        raise ValueError('not a CFPB/CFPN container: %r' % magic)
    if index >= count:
        raise IndexError('entry %d of %d' % (index, count))
    return unwrap_entry(ents[index])


def write_plaza_mii(body, cfl, off=PLAZA_MII_OFF, index=0):
    """Return `body` with entry `index` replaced by the re-wrapped `cfl`."""
    b = bytearray(body)
    p = off + HDR_LEN + index * ENTRY_LEN
    b[p:p + ENTRY_LEN] = wrap_entry(cfl)
    return bytes(b)


def _selftest():
    import os
    import lp_corpus as corpus
    ok = tot = skipped = 0

    def chk(name, cond, got=''):
        nonlocal ok, tot
        tot += 1; ok += bool(cond)
        print('  [%s] %s%s' % ('PASS' if cond else 'FAIL', name, ('  %s' % (got,)) if got else ''))

    def skip(name, why):
        nonlocal skipped
        skipped += 1
        print('  [SKIP] %s  (%s)' % (name, why))

    tk = os.urandom(16)
    synth = bytearray(CFL_LEN)
    synth[NONCE_OFF:NONCE_OFF + NONCE_LEN] = os.urandom(NONCE_LEN)
    synth = bytes(reseal_cfl(set_mii_name(bytes(synth), 'Tux')))
    wrapped = wrap_entry(synth, key=tk)
    chk('wrap_entry produces a 0x70 entry', len(wrapped) == ENTRY_LEN, hex(len(wrapped)))
    rt, rtok = unwrap_entry(wrapped, key=tk)
    chk('unwrap_entry round-trips and the CCM MAC verifies', rtok and rt == synth)
    chk('a flipped ciphertext byte fails the MAC',
        not unwrap_entry(wrapped[:NONCE_LEN] + bytes([wrapped[NONCE_LEN] ^ 1])
                         + wrapped[NONCE_LEN + 1:], key=tk)[1])
    chk('the nonce is carried in the clear from the data itself',
        wrapped[:NONCE_LEN] == synth[NONCE_OFF:NONCE_OFF + NONCE_LEN])

    if _keys.have_aes_keys():
        try:
            from streetpass_ccmp_key import keyscrambler
            kx = _keys.slot(0x31, 'X'); ky = _keys.slot(0x31, 'Y')
            chk('apt_key() == keyscrambler(slot0x31 KeyX, KeyY)', keyscrambler(kx, ky) == apt_key())
        except Exception as e:
            chk('apt_key() re-derivation', False, repr(e))
    else:
        skip('apt_key() == keyscrambler(slot0x31 KeyX, KeyY)', 'no aes_keys.txt')

    import sp_cec
    cases = [('2DS',    'mii_message_a'),
             ('2DS XL', 'mii_message_b')]
    for label, entry in cases:
        want = (corpus.vector('mii_messages') or {}).get(entry) or {}
        want_name, want_mac = want.get('mii_name'), want.get('creator_mac')
        raw = corpus.load(entry)
        if raw is None or not want_name:
            skip('%s real-message checks' % label, corpus.why_skipped()
                 if raw is None else 'vectors.json has no mii_messages.%s' % entry)
            continue
        if not _keys.have_aes_keys():
            skip('%s real-message checks' % label, 'no aes_keys.txt')
            continue
        b = raw[0x14:] if raw[0x14:0x16] == b'\x60\x60' else raw
        h = sp_cec.parse_header(b)
        body = b[h['header_size']:h['header_size'] + h['body_size']]
        magic, count, ents = container_entries(body)
        chk('%s container magic/count' % label, magic == MAGIC_CFPB and count == 1,
            '%r count=%d' % (magic, count))
        cfl, macok = unwrap_entry(ents[0])
        chk('%s CCM MAC verifies' % label, macok)
        info = parse_cfl(cfl)
        chk('%s Mii name' % label, info['mii_name'] == want_name, repr(info['mii_name']))
        chk('%s creator MAC == console wireless MAC' % label, info['creator_mac'] == want_mac,
            info['creator_mac'])
        chk('%s Mii CRC valid' % label, info['crc_ok'], '%#06x' % info['crc'])
        chk('%s re-wrap is byte-identical' % label, wrap_entry(cfl) == ents[0])
        edited = set_mii_name(cfl, 'Linux')
        back, ok2 = unwrap_entry(wrap_entry(edited))
        chk('%s edited Mii round-trips' % label, ok2 and back == edited
            and parse_cfl(back)['mii_name'] == 'Linux' and parse_cfl(back)['crc_ok'])
        ident = set_identity(cfl, mii_id=0x11223344)
        chk('%s identity edit changes the nonce' % label,
            wrap_entry(ident)[:NONCE_LEN] != ents[0][:NONCE_LEN])
        nb = write_plaza_mii(body, edited)
        chk('%s write/read_plaza_mii agree' % label, read_plaza_mii(nb)[0] == edited)
        chk('%s body edit is local to the entry' % label,
            sum(1 for i in range(len(body)) if body[i] != nb[i]) <= ENTRY_LEN)
        okv, why = validate_cfl(cfl)
        chk('%s real Mii passes validate_cfl' % label, okv, str(why))
        bad = bytearray(cfl); bad[0x0C] |= 0x20
        bad = reseal_cfl(bytes(bad))
        okb, whyb = validate_cfl(bad)
        chk('%s bit5-set Mii id is rejected' % label,
            not okb and any('bit 5' in w for w in whyb), str(whyb))
        nocrc = bytearray(cfl); nocrc[0x1A] ^= 0xFF
        okc, whyc = validate_cfl(bytes(nocrc))
        chk('%s unresealed CRC is rejected' % label, not okc and any('CRC' in w for w in whyc))

    ids = [random_mii_id() for _ in range(2000)]
    chk('random_mii_id always clears bit 5 of byte 0',
        all(((i & 0xFF) >> 5) & 1 == 0 for i in ids))
    chk('random_mii_id always uses high nibble 0x9, as every real Mii does',
        all((i & 0xFF) >> 4 == 9 for i in ids))
    chk('random_mii_id is not constant', len(set(ids)) > 1900)
    chk('the rejected run-2 id (a41067a7) fails the gate the same way',
        ((0xa41067a7 & 0xFF) >> 5) & 1 == 1)

    print('\n%d/%d checks passed%s' % (ok, tot,
          '' if not skipped else ', %d skipped (no test corpus / no keys)' % skipped))
    return 0 if ok == tot else 1


if __name__ == '__main__':
    import sys
    sys.exit(_selftest())
