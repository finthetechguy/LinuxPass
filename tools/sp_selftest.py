#!/usr/bin/env python3
"""End-to-end self-test for the StreetPass passive pipeline, using synthetic data."""
import struct, sys
from itertools import permutations
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), 'linuxpass'))
import lp_keys, sp_ccmp, sp_cec
from streetpass_ccmp_key import derive_ccmp_key

OK = True
def check(cond, label, extra=""):
    global OK
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f"  {extra}" if extra else ""))
    if not cond: OK = False


def build_plaza_message(greeting="hello streetpass", country="United Kingdom",
                        info_text="Mii Plaza", with_hmac=True):
    """Serialise exactly as Message::MakeMessageBinary @0x2dde6c does."""
    body = bytearray(sp_cec.PLAZA_BODY_SIZE)
    struct.pack_into('<I', body, 0x36B8, 1)
    import sp_mii
    cfl = bytearray(0x60)
    cfl[0x00] = 3
    struct.pack_into('<I', cfl, 0x0C, 0xC0FFEE01)
    cfl[0x10:0x16] = bytes.fromhex('ba ae 6e 00 11 22'.replace(' ', ''))
    n = "Linux".encode('utf-16-le'); cfl[0x1A:0x1A + len(n)] = n
    a = "LinuxPass".encode('utf-16-le'); cfl[0x48:0x48 + len(a)] = a
    cfl = sp_mii.reseal_cfl(bytes(cfl))
    cont = bytearray(0xA0)
    cont[0:4] = sp_mii.MAGIC_CFPB
    struct.pack_into('<I', cont, 0x04, 1)
    struct.pack_into('<H', cont, 0x14, 1)
    cont[0x18:0x18 + 0x70] = sp_mii.wrap_entry(cfl)
    body[0x36BC:0x375C] = bytes(cont)
    struct.pack_into('<I', body, 0x375C, 0x00010002)
    g = greeting.encode('utf-16-le')[:0x20]
    body[0x3F70:0x3F70 + len(g)] = g
    for i in range(16):
        c = f"{country}".encode('utf-16-le')[:0x3E]
        body[0x3760 + i * 0x40: 0x3760 + i * 0x40 + len(c)] = c
    body[0x3F66] = 0x4B; body[0x3F67] = 2
    body[0x4482] = 0x64; body[0x45D2] = 3

    ex = [(4, info_text.encode('utf-16-le') + b'\0\0')]
    exblob = b''
    for t, d in ex:
        exblob += struct.pack('<II', t, len(d)) + d
        exblob += b'\0' * ((-len(d)) % 4)
    hdr = bytearray(sp_cec.HDR_LEN)
    header_size = sp_cec.HDR_LEN + len(exblob)
    total = header_size + len(body) + (0x20 if with_hmac else 0)
    struct.pack_into('<I', hdr, 0x04, total)
    struct.pack_into('<I', hdr, 0x08, header_size)
    struct.pack_into('<I', hdr, 0x0C, len(body))
    struct.pack_into('<I', hdr, 0x10, sp_cec.PLAZA_CEC_TITLE_ID)
    struct.pack_into('<I', hdr, 0x18, 0)
    hdr[0x34] = 3; hdr[0x35] = 0; hdr[0x6C] = 0xFF; hdr[0x6D] = 1
    return bytes(hdr) + exblob + bytes(body) + (b'\xA5' * 0x20 if with_hmac else b'')


def mk_frame(key, payload, pn, a1, a2, a3):
    fc = struct.pack('<H', 0x4188)
    ccmphdr = bytes([pn & 0xFF, (pn >> 8) & 0xFF, 0, 0x20, 0, 0, 0, 0])
    hdr = fc + b'\0\0' + a1 + a2 + a3 + struct.pack('<H', pn << 4) + struct.pack('<H', 0) + ccmphdr
    return sp_ccmp.encrypt(key, hdr, payload)


def main():
    if lp_keys.selftest_keys():
        print("  (no console keys found, so running on generated throwaway keys)")
    print("=== 1. container parse (synthetic plaza message) ===")
    msg = build_plaza_message()
    m = sp_cec.parse_message(msg)
    h = m['header']
    check(h['cec_title_id'] == 0x00020800, "cec_title_id == 0x00020800", f"{h['cec_title_id']:#010x}")
    check(h['body_size'] == 0x60F0, "body_size == 0x60F0", f"{h['body_size']:#x}")
    check(not m['problems'], "no container problems", str(m['problems']))
    check(len(m['exheaders']) == 1 and m['exheaders'][0]['type'] == 4, "ex-header type 4 recovered")
    b = sp_cec.parse_plaza_body(m['body'])
    check(b['greeting'] == "hello streetpass", "greeting round-trips", repr(b['greeting']))
    check(b['country'][0] == "United Kingdom", "country name round-trips", repr(b['country'][0]))
    check(not b['problems'], "no body problems", str(b['problems']))
    s, _ = sp_cec.score(msg)
    check(s == 90, "score == 90/90", f"got {s}")
    complete_score = s

    print("\n=== 2. negative: truncated message is detected ===")
    trunc = msg[:0x3000]
    m2 = sp_cec.parse_message(trunc)
    check(any('truncated' in p for p in m2['problems']), "truncation flagged",
          str(m2['problems'])[:100])
    s2, _ = sp_cec.score(trunc)
    check(s2 < complete_score, "truncated scores below a complete message",
          f"{s2} vs {complete_score}")

    print("\n=== 3. CCMP round-trip across fragments ===")
    TK = {'key17': b'LinuxPassSelfTest', 'keyslot_2e_normalkey': bytes(range(16))}
    cid_h = bytes.fromhex("1122334455667788"); cid_c = bytes.fromhex("99aabbccddeeff00")
    mac_h = bytes.fromhex("aabbccddeeff");     mac_c = bytes.fromhex("001122334455")
    key = derive_ccmp_key(cid_h, cid_c, mac_h, mac_c, **TK)
    MTU = 2000
    frags = [msg[i:i + MTU] for i in range(0, len(msg), MTU)]
    frames = [mk_frame(key, f, i + 1, mac_c, mac_h, mac_h) for i, f in enumerate(frags)]
    back = b''.join(sp_ccmp.decrypt(key, fr) for fr in frames)
    check(back == msg, "reassembled plaintext identical", f"{len(frames)} frames, {len(msg)} B")
    check(len(frames) >= 11, "a plaza message needs many MPDUs", f"{len(frames)} at {MTU}B")
    m3 = sp_cec.parse_message(back)
    check(m3['header']['cec_title_id'] == 0x00020800, "parses after decrypt+reassembly")

    print("\n=== 4. permutation search recovers a PLANTED ordering ===")
    planted = {'th': cid_c[::-1], 'tc': cid_h[::-1], 'mh': mac_c, 'mc': mac_h,
               'dev': True}
    pkey = derive_ccmp_key(planted['th'], planted['tc'], planted['mh'], planted['mc'],
                           dev=planted['dev'], **TK)
    frame = mk_frame(pkey, msg[:1200], 7, mac_h, mac_c, mac_c)
    tok_b = [cid_h, cid_c]
    mac_pairs = [(mac_c, mac_h), (mac_h, mac_c)]
    found, tried = None, 0
    for ta0, tc0 in permutations(tok_b, 2):
        for ta, tc in ((ta0, tc0), (ta0[::-1], tc0[::-1])):
            for mh, mc in mac_pairs:
                for dev in (False, True):
                    tried += 1
                    try:
                        k = derive_ccmp_key(ta, tc, mh, mc, dev=dev, **TK)
                        pt = sp_ccmp.decrypt(k, frame)
                    except Exception:
                        continue
                    found = {'th': ta, 'tc': tc, 'mh': mh, 'mc': mc,
                             'dev': dev, 'pt': pt}
    check(found is not None, "MIC oracle found a combination", f"{tried} tried")
    if found:
        check(all(found[k] == planted[k] for k in ('th', 'tc', 'mh', 'mc', 'dev')),
              "recovered combination == planted one")
        check(found['pt'] == msg[:1200], "recovered plaintext matches")
        sc, why = sp_cec.score(found['pt'])
        check(any('0x00020800' in w for w in why), "single fragment still identifies as plaza")
        check(any('TRUNCATED' in w for w in why), "single fragment flagged incomplete", f"{sc}/90")

    print("\n=== 5. a stream of SEVERAL titles' messages ===")
    other = bytearray(sp_cec.HDR_LEN + 0x400)
    struct.pack_into('<I', other, 0x04, len(other))
    struct.pack_into('<I', other, 0x08, sp_cec.HDR_LEN)
    struct.pack_into('<I', other, 0x0C, 0x400)
    struct.pack_into('<I', other, 0x10, 0x00141000)
    other[0x34] = 3; other[0x35] = 0; other[0x6C] = 0xFF; other[0x6D] = 1
    stream = msg + bytes(other)
    ms = sp_cec.parse_stream(stream)
    check(len(ms) == 2, "two messages recovered from one stream", f"got {len(ms)}")
    if len(ms) == 2:
        check(ms[0]['header']['cec_title_id'] == 0x00020800, "first is Mii Plaza")
        check(ms[1]['header']['cec_title_id'] == 0x00141000, "second is the other title",
              f"uid {ms[1]['header']['unique_id']:#x}")
        check(ms[1]['offset'] == len(msg), "second message offset is exact",
              f"{ms[1]['offset']} vs {len(msg)}")
        check(not ms[1]['problems'], "non-plaza message parses cleanly", str(ms[1]['problems']))

    print("\n=== 6. hostile reassembly: LLC wrap, shuffled, retransmitted, lossy ===")
    MTU2 = 1400
    frags = [msg[i:i + MTU2] for i in range(0, len(msg), MTU2)]
    LLC = b'\xaa\xaa\x03\x00\x00\x00\x08\x00'
    items = [(100 + i, LLC + f) for i, f in enumerate(frags)]
    import random
    random.seed(7)
    shuffled = items[:]
    random.shuffle(shuffled)
    shuffled += [items[3], items[3], items[9]]
    blob, st = sp_cec.reassemble(shuffled)
    check(st['enc'] == 8, "LLC/SNAP detected and stripped", f"enc={st['enc']}")
    check(st['dupes'] == 3, "retransmissions dropped", f"{st['dupes']}")
    check(not st['gaps'], "no false gaps reported", str(st['gaps']))
    check(blob == msg, "shuffled + duplicated frames reassemble EXACTLY",
          f"{len(blob)} vs {len(msg)}")

    lossy = [it for it in items if it[0] not in (105, 106)]
    blob2, st2 = sp_cec.reassemble(lossy)
    check(st2['missing'] == 2, "missing frames detected via PN gap", f"missing={st2['missing']}")
    check(blob2 != msg, "lossy reassembly differs from the original (as it must)")

    print("\n=== 7. container found under an unknown wrapper ===")
    wrapped = b'\xde\xad\xbe\xef' * 7 + msg
    offs = sp_cec.find_container_offsets(wrapped)
    check(offs and offs[0] == 28, "container located at the right offset", f"{offs[:4]}")
    check(sp_cec.score(wrapped[offs[0]:])[0] == 90, "re-parses cleanly from that offset")
    noise = bytes((i * 7 + 13) & 0xFF for i in range(40000))
    check(not sp_cec.find_container_offsets(noise), "no false positive on 40 KB of noise")

    print("\n" + ("ALL CHECKS PASSED" if OK else "*** FAILURES ABOVE ***"))
    return 0 if OK else 1


if __name__ == '__main__':
    sys.exit(main())
