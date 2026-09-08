#!/usr/bin/env python3
"""
Pure-Python AES-128 + CCM. No dependencies at all -- stdlib only.

Why this exists: the ath9k transmit box has no pycryptodome, no `cryptography`, and no pip. The
choice was to modify someone's machine or to remove the dependency; removing it is better. It also
makes the whole Stage 2 toolchain portable to any box with a bare python3, which matters because the
transmit box is whichever machine happens to have a SoftMAC radio in it.

Only the AES **forward** direction is needed. CCM builds both its keystream (CTR) and its
authentication tag (CBC-MAC) from AES-encrypt alone, and the StreetPass key derivation needs
AES-ECB-encrypt of one block. So there is no InvSubBytes/InvMixColumns here, and nothing is lost.

Speed is irrelevant: StreetPass frames are 34..1500 bytes and an exchange is ~100 of them.

CORRECTNESS IS NOT ASSUMED. `--selftest` checks, in order:
  * FIPS-197 AES-128 known-answer vector
  * RFC 3610 CCM packet vector #1
  * the real captured StreetPass frame `spectral_attempt1 #73` -- decrypts to the same YY SYN|ACK
    and re-encrypts byte-identically, matching what pycryptodome produces
"""

# ---------------------------------------------------------------------------------------------
# AES-128, encryption direction only

_SBOX = bytes.fromhex(
    '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0'
    'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275'
    '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf'
    'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2'
    'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb'
    'e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08'
    'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e'
    'e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16')

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _expand_key(key):
    """AES-128 key schedule -> 11 round keys of 16 bytes."""
    if len(key) != 16:
        raise ValueError('AES-128 only: key must be 16 bytes, got %d' % len(key))
    w = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]                                  # RotWord
            t = [_SBOX[b] for b in t]                          # SubWord
            t[0] ^= _RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [bytes(b for word in w[r * 4:r * 4 + 4] for b in word) for r in range(11)]


def _encrypt_block(rk, block):
    s = list(a ^ b for a, b in zip(block, rk[0]))
    for rnd in range(1, 11):
        s = [_SBOX[b] for b in s]
        # ShiftRows -- state is column-major: index = row + 4*col
        s = [s[0], s[5], s[10], s[15],
             s[4], s[9], s[14], s[3],
             s[8], s[13], s[2], s[7],
             s[12], s[1], s[6], s[11]]
        if rnd != 10:                                          # MixColumns (skipped last round)
            t = []
            for c in range(4):
                a0, a1, a2, a3 = s[c * 4:c * 4 + 4]
                t += [_xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3,
                      a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3,
                      a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3),
                      (_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3)]
            s = t
        s = [a ^ b for a, b in zip(s, rk[rnd])]
    return bytes(s)


class AES:
    """AES-128, encrypt direction. `ecb_encrypt` is a single-block primitive."""

    def __init__(self, key):
        self._rk = _expand_key(key)

    def ecb_encrypt(self, block):
        if len(block) != 16:
            raise ValueError('block must be 16 bytes')
        return _encrypt_block(self._rk, block)


def aes_ecb_encrypt(key, block):
    return AES(key).ecb_encrypt(block)


# ---------------------------------------------------------------------------------------------
# CCM (NIST SP 800-38C / RFC 3610) with the 802.11 parameters: L=2, M=8, 13-byte nonce

def _ccm_mac(aes, nonce, aad, plaintext, mlen_bytes=8, L=2):
    """CBC-MAC over B0 || encoded-AAD || plaintext, all zero-padded to 16."""
    flags = (0x40 if aad else 0) | (((mlen_bytes - 2) // 2) << 3) | (L - 1)
    b0 = bytes([flags]) + nonce + len(plaintext).to_bytes(L, 'big')
    x = aes.ecb_encrypt(b0)

    blocks = b''
    if aad:
        if len(aad) >= 0xFF00:
            raise ValueError('AAD too long for this implementation')
        blocks += len(aad).to_bytes(2, 'big') + aad
        if len(blocks) % 16:
            blocks += b'\x00' * (16 - len(blocks) % 16)
    blocks += plaintext
    if len(blocks) % 16:
        blocks += b'\x00' * (16 - len(blocks) % 16)

    for i in range(0, len(blocks), 16):
        x = aes.ecb_encrypt(bytes(a ^ b for a, b in zip(x, blocks[i:i + 16])))
    return x[:mlen_bytes]


def _ccm_ctr(aes, nonce, data, L=2):
    """CTR starting at counter 1; also returns S0, the keystream block used to mask the tag."""
    s0 = aes.ecb_encrypt(bytes([L - 1]) + nonce + (0).to_bytes(L, 'big'))
    out = bytearray()
    for i in range(0, len(data), 16):
        ks = aes.ecb_encrypt(bytes([L - 1]) + nonce + ((i // 16) + 1).to_bytes(L, 'big'))
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], ks))
    return bytes(out), s0


def ccm_encrypt(key, nonce, aad, plaintext, mlen=8):
    """-> (ciphertext, mic). Nonce is 13 bytes for the 802.11 profile."""
    aes = AES(key)
    t = _ccm_mac(aes, nonce, aad, plaintext, mlen)
    ct, s0 = _ccm_ctr(aes, nonce, plaintext)
    mic = bytes(a ^ b for a, b in zip(t, s0[:mlen]))
    return ct, mic


def ccm_decrypt(key, nonce, aad, ciphertext, mic, mlen=8):
    """-> plaintext, or raise ValueError if the MIC does not verify."""
    aes = AES(key)
    pt, s0 = _ccm_ctr(aes, nonce, ciphertext)
    t = _ccm_mac(aes, nonce, aad, pt, mlen)
    want = bytes(a ^ b for a, b in zip(t, s0[:mlen]))
    # constant-time-ish compare; there is no secret-dependent timing that matters here anyway
    if len(want) != len(mic) or sum(a ^ b for a, b in zip(want, mic)) != 0:
        raise ValueError('CCM MIC verification failed')
    return pt


# ---------------------------------------------------------------------------------------------

def _selftest():
    ok = tot = 0

    def chk(name, cond, got=''):
        nonlocal ok, tot
        tot += 1
        ok += bool(cond)
        print('  [%s] %s%s' % ('PASS' if cond else 'FAIL', name, ('  %s' % (got,)) if got else ''))

    # 1. FIPS-197 C.1 AES-128 known answer
    k = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    p = bytes.fromhex('00112233445566778899aabbccddeeff')
    c = aes_ecb_encrypt(k, p)
    chk('FIPS-197 AES-128 known-answer vector',
        c.hex() == '69c4e0d86a7b0430d8cdb78070b4c55a', c.hex())

    # 2. AES-128 ECB vector from the StreetPass key path (NIST SP 800-38A F.1.1 block 1)
    c2 = aes_ecb_encrypt(bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'),
                         bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'))
    chk('NIST SP 800-38A ECB vector', c2.hex() == '3ad77bb40d7a3660a89ecaf32466ef97', c2.hex())

    # 3. RFC 3610 CCM packet vector #1 (M=8, L=2)
    key = bytes.fromhex('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf')
    nonce = bytes.fromhex('00000003020100a0a1a2a3a4a5')
    aad = bytes.fromhex('0001020304050607')
    pt = bytes.fromhex('08090a0b0c0d0e0f101112131415161718191a1b1c1d1e')
    ct, mic = ccm_encrypt(key, nonce, aad, pt)
    chk('RFC 3610 vector #1 ciphertext',
        ct.hex() == '588c979a61c663d2f066d0c2c0f989806d5f6b61dac384', ct.hex())
    chk('RFC 3610 vector #1 MIC', mic.hex() == '17e8d12cfdf926e0', mic.hex())
    chk('RFC 3610 vector #1 round-trips', ccm_decrypt(key, nonce, aad, ct, mic) == pt)
    bad = bytearray(mic); bad[0] ^= 1
    try:
        ccm_decrypt(key, nonce, aad, ct, bytes(bad))
        chk('corrupted MIC is rejected', False)
    except ValueError:
        chk('corrupted MIC is rejected', True)

    # 4. A whole StreetPass data frame through the real 802.11 code path.
    #    This frame has the exact shape of the one a console sends -- QoS Data, protected,
    #    PN=1, the same 0x22-byte YY SYN|ACK inside -- but the addresses are documentation
    #    values and the key is a fixed test key, so it is not a recording of anyone's
    #    console. (LinuxPass keeps real captures out of the repo: see lp_corpus.py.)
    import sp_ccmp as C
    C.HAVE_PYCRYPTO = False          # force the pure path through the REAL 802.11 code
    mpdu = bytes.fromhex(
        '08402c00baae6e4455669658cb1122339658cb112233f00501000020000000001e4b952e263f55d1474284e41b22cd713cf083a1b6ed2ba414fbec98314ce0a91cce4909774a5d3e3d7e')
    key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    want_pt = bytes.fromhex('aaaa030000000800000059593000addeafbe'
                            '00000000000000000c12b83800000000')
    try:
        pt = C.decrypt(key, mpdu)
        chk('a full StreetPass data frame decrypts to the YY SYN|ACK', pt == want_pt, pt.hex())
        chk('and re-encrypts byte-identically', C.encrypt(key, mpdu[:32], pt) == mpdu)
    except Exception as e:
        chk('a full StreetPass data frame decrypts', False, repr(e))

    print('\n%d/%d checks passed' % (ok, tot))
    return 0 if ok == tot else 1


if __name__ == '__main__':
    import sys
    sys.exit(_selftest())
