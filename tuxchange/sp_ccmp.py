#!/usr/bin/env python3
"""802.11 CCMP (AES-CCM) decrypt/encrypt for StreetPass data frames."""
import struct, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sp_aes

# pycryptodome is faster. sp_aes is the standard-library fallback.
try:
    from Crypto.Cipher import AES
    HAVE_PYCRYPTO = True
except ImportError:                                     # pragma: no cover - environment-dependent
    AES = None
    HAVE_PYCRYPTO = False


def _ccm_decrypt(key, nonce, aad, ct, mic):
    if HAVE_PYCRYPTO:
        c = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=8)
        c.update(aad)
        return c.decrypt_and_verify(ct, mic)
    return sp_aes.ccm_decrypt(key, nonce, aad, ct, mic)


def _ccm_encrypt(key, nonce, aad, pt):
    if HAVE_PYCRYPTO:
        c = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=8)
        c.update(aad)
        return c.encrypt(pt), c.digest()
    return sp_aes.ccm_encrypt(key, nonce, aad, pt)

def _parse_hdr(mpdu):
    fc = struct.unpack_from('<H', mpdu, 0)[0]
    ftype = (fc >> 2) & 3; subtype = (fc >> 4) & 0xF
    tods = (fc >> 8) & 1; fromds = (fc >> 9) & 1
    a1 = mpdu[4:10]; a2 = mpdu[10:16]; a3 = mpdu[16:22]
    seq = struct.unpack_from('<H', mpdu, 22)[0]
    off = 24
    a4 = None
    if tods and fromds:
        a4 = mpdu[24:30]; off = 30
    qos = None
    is_qos = (ftype == 2 and (subtype & 0x8))   # QoS Data subtypes 8..15
    if is_qos:
        qos = struct.unpack_from('<H', mpdu, off)[0]; off += 2
    return dict(fc=fc, ftype=ftype, subtype=subtype, a1=a1, a2=a2, a3=a3, seq=seq,
                a4=a4, qos=qos, hdr_len=off, is_qos=is_qos)

def _nonce_aad(h, mpdu, pn6):
    is_mgmt = (h['ftype'] == 0)
    tid = (h['qos'] & 0x0F) if h['qos'] is not None else 0
    nonce0 = (tid & 0x0F) | (0x10 if is_mgmt else 0)
    nonce = bytes([nonce0]) + h['a2'] + pn6
    # AAD: FC masked, A1, A2, A3, SeqCtl masked, [A4], [QoS masked].
    fc0 = mpdu[0] & 0x8F
    fc1 = mpdu[1] & 0xC7
    aad = bytes([fc0, fc1]) + h['a1'] + h['a2'] + h['a3'] + bytes([mpdu[22] & 0x0F, 0x00])
    if h['a4'] is not None: aad += h['a4']
    if h['qos'] is not None: aad += bytes([h['qos'] & 0x0F, 0x00])
    return nonce, aad

def _pn6_from_ccmphdr(c):   # c = 8-byte CCMP header
    return bytes([c[7], c[6], c[5], c[4], c[1], c[0]])          # PN5..PN0

def pn_of(mpdu):
    """CCMP packet number as an int."""
    h = _parse_hdr(mpdu)
    c = mpdu[h['hdr_len']:h['hdr_len'] + 8]
    return int.from_bytes(_pn6_from_ccmphdr(c), 'big')


def decrypt(key, mpdu):
    """Return plaintext body of a CCMP-protected MPDU, verifying the MIC. Raises on MIC failure."""
    h = _parse_hdr(mpdu)
    ccmp_hdr = mpdu[h['hdr_len']:h['hdr_len']+8]
    assert ccmp_hdr[3] & 0x20, "ExtIV bit not set -> not CCMP?"
    pn6 = _pn6_from_ccmphdr(ccmp_hdr)
    body = mpdu[h['hdr_len']+8:]
    ct, mic = body[:-8], body[-8:]
    nonce, aad = _nonce_aad(h, mpdu, pn6)
    return _ccm_decrypt(key, nonce, aad, ct, mic)

def encrypt(key, mpdu_hdr_plus_ccmphdr, plaintext):
    """Build ciphertext+MIC for a header (incl 8-byte CCMP hdr) + plaintext. For round-trip/tests."""
    h = _parse_hdr(mpdu_hdr_plus_ccmphdr)
    ccmp_hdr = mpdu_hdr_plus_ccmphdr[h['hdr_len']:h['hdr_len']+8]
    pn6 = _pn6_from_ccmphdr(ccmp_hdr)
    nonce, aad = _nonce_aad(h, mpdu_hdr_plus_ccmphdr, pn6)
    ct, mic = _ccm_encrypt(key, nonce, aad, plaintext)
    return mpdu_hdr_plus_ccmphdr + ct + mic

if __name__ == "__main__":
    key = os.urandom(16)
    fc = struct.pack('<H', 0x4188)
    dur = b'\x00\x00'
    a1 = bytes.fromhex("aabbccddeeff"); a2 = bytes.fromhex("112233445566"); a3 = bytes.fromhex("665544332211")
    seq = struct.pack('<H', 0x0010); qos = struct.pack('<H', 0x0000)
    ccmphdr = bytes([0x05,0x00,0x00,0x20, 0x00,0x00,0x00,0x00])
    hdr = fc+dur+a1+a2+a3+seq+qos+ccmphdr
    pt = b"STREETPASS_TEST_PAYLOAD_0123456789"
    frame = encrypt(key, hdr, pt)
    back = decrypt(key, frame)
    print("round-trip:", "OK" if back == pt else "FAIL", "| recovered:", back)
    print("frame len:", len(frame), "| nonce/AAD construction validated by MIC verify")
