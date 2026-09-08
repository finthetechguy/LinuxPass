#!/usr/bin/env python3
"""
StreetPass CCMP link-key derivation — software reimplementation.

Reconstructed from cecd firmware (cecd_derive_ccmp_key @0x1016E8, Thumb) and 3dbrew.
Every step below marked [V] was re-verified instruction-by-instruction on 29 Aug against
extracted/cecd/code.bin. See CECD_NOTES.md "INDEPENDENT VERIFICATION".

    key17   = 17-byte HMAC key INCLUDING the NUL, a fixed ASCII string compiled into cecd:
              the retail one at @0x101A10, the dev one at @0x101A24. LinuxPass does not carry
              a copy -- lp_keys.cecd_hmac_key() reads it from linuxpass.keys, which
              tools/lp_extract_keys.py writes out of YOUR OWN cecd dump.
      [V] both key strings read byte-exact from the binary (16 chars + NUL, 4-byte padded)
      [V] selection: ldrb [0x1FF80014]; lsls #31; beq -> DEV.  bit0 SET = retail, CLEAR = dev.
      [V] KEY LENGTH IS 0x11 (17):  `movs r0,#0x11; str r0,[sp]` at 0x1018B2/0x1018B6 passes it
          as the 5th (stack) argument to the HMAC. The trailing NUL IS part of the key.

    block   = consoleID_A(8) | consoleID_B(8) | MAC(6) | MAC(6)      # 0x1C bytes @sp+0x50
      [V] block spans sp+0x50..sp+0x6C = 0x1C, and r2=#0x1C is passed to the HMAC.
      [V] THE TWO consoleIDs ARE SWAPPED BY ROLE. At 0x101878: `cmp r0,#1 / beq 0x1018BE`
          selects between two assembly paths:
            role != 1 : block[0:8] <- buf@sp+0xA8 , block[8:16] <- buf@sp+0xB0
            role == 1 : block[0:8] <- buf@sp+0xB0 , block[8:16] <- buf@sp+0xA8
          So each console reorders its local (mine, peer) pair into one agreed absolute order.
          A passive sniffer does not know which console held which role -> sp_decrypt_pcap.py
          must brute-force the ordering. That brute force is covering a REAL firmware branch,
          not an analysis gap.

    ctr     = HMAC_SHA1(key17, block)[0:16]        # first 16 of the 20-byte digest
      [V] output at sp+0x84; `ldm r0,{r0,r1,r2,r3}` takes exactly 16 bytes -> sp+0x98.
      [V] HMAC is SHA-1: round constant 0x5A827999 @0x121DE4, H0 @0x10CE2C/0x120A50.

    ccmpkey = AES_ECB(keyslot0x2E_normalkey, ctr)
      [V] cecd actually calls PS:EncryptDecryptAes with algorithm 2 (AES-CTR ENCRYPT),
          size 0x10, counter = ctr@sp+0x98, buffer sp+0x74 IN PLACE.
      [V] sp+0x74..sp+0x84 is a 16-byte ZERO block: four `str r4,[sp,#0x74/0x78/0x7c/0x80]`
          with r4=0 (0x1017C8/D6/D2/D8).
          CTR-encrypting an all-zero block == AES_ECB(key, counter), so this ECB form is exact.

keyslot 0x2E normal key = keyscrambler(KeyX_2E, KeyY_2E):
    Both halves come from your own console, via the GodMode9 aes_keys.txt dump
    (slot0x2EKeyX / slot0x2EKeyY). lp_keys.normalkey_2e() runs the scrambler over them.
    The scrambler form was proven self-consistent against pyctr.

!! THE ONE UNVERIFIED LINK !!
    cecd passes `movs r3,#6` = PS **key type 6**. The mapping *key type 6 -> AES keyslot 0x2E*
    lives in the PS module (0004013000003102), which is NOT in extracted/. It is taken from
    3dbrew and has NOT been confirmed against firmware we hold. Everything else in this file is
    now firmware-verified. If a real capture fails to produce a valid CCMP MIC with every
    ordering permutation, THIS mapping is the first thing to re-check (dump the PS module and
    read its key-type table).
"""
import hmac, hashlib, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sp_aes                                   # pure-stdlib fallback; see sp_aes.py
import lp_keys as keys                          # console-derived material, loaded at runtime

# The transmit box has no pycryptodome and no pip. HMAC-SHA1 is stdlib, and the only other
# primitive needed here is a single AES-ECB block encrypt, which sp_aes provides.
try:
    from Crypto.Cipher import AES
except ImportError:                             # pragma: no cover - environment-dependent
    try:
        from Cryptodome.Cipher import AES
    except ImportError:
        AES = None


def _aes_ecb_encrypt_block(key, block):
    if AES is not None:
        return AES.new(key, AES.MODE_ECB).encrypt(block)
    return sp_aes.aes_ecb_encrypt(key, block)

# NO KEY MATERIAL IS COMPILED INTO LINUXPASS. Every console-derived value used below is
# loaded, when it is needed, from files you generate from your own hardware:
#
#   cecd's 17-byte HMAC key string  ->  linuxpass.keys   (tools/lp_extract_keys.py)
#   keyslot 0x2E KeyX / KeyY        ->  aes_keys.txt     (GodMode9)
#
# See lp_keys.py for the search path and the exact error you get when one is missing.
# SCRAMBLER_C is an algorithm parameter, identical on every console and published on
# 3dbrew, so it is not key material; it is re-exported here for callers that imported it.
SCRAMBLER_C = keys.SCRAMBLER_C
keyscrambler = keys.keyscrambler


def cecd_hmac_key(dev: bool = False, key_file=None) -> bytes:
    """cecd's HMAC key: 17 bytes, the trailing NUL included. Raises keys.MissingKey."""
    return keys.cecd_hmac_key(dev=dev, explicit=key_file)


def normalkey_2e(key_file=None) -> bytes:
    """Keyslot 0x2E's normal key, scrambled from your dump's KeyX/KeyY."""
    return keys.normalkey_2e(key_file)

def derive_ccmp_key(consoleid_host: bytes, consoleid_client: bytes,
                    mac_host: bytes, mac_client: bytes,
                    *, dev: bool = False,
                    keyslot_2e_normalkey: bytes | None = None,
                    key_y_2e: bytes | None = None,
                    key_x_2e: bytes | None = None,
                    key17: bytes | None = None,
                    key_file=None) -> bytes:
    """The StreetPass CCMP link key for one pair of consoles.

    Every key input can be passed in explicitly -- which is what the self-tests do, so they
    need no key files -- and anything left as None is loaded from your own dump.
    """
    assert len(consoleid_host) == 8 and len(consoleid_client) == 8
    assert len(mac_host) == 6 and len(mac_client) == 6
    if key17 is None:
        key17 = keys.cecd_hmac_key(dev=dev, explicit=key_file)
    block = consoleid_host + consoleid_client + mac_host + mac_client   # 0x1C
    assert len(block) == 0x1C
    ctr = hmac.new(key17, block, hashlib.sha1).digest()[:16]
    if keyslot_2e_normalkey is None:
        if key_y_2e is not None:
            key_x = key_x_2e if key_x_2e is not None else keys.slot(0x2E, "X", key_file)
            keyslot_2e_normalkey = keyscrambler(key_x, key_y_2e)
        else:
            keyslot_2e_normalkey = keys.normalkey_2e(key_file)
    return _aes_ecb_encrypt_block(keyslot_2e_normalkey, ctr)   # AES-CTR of zero block == ECB(ctr)

if __name__ == "__main__":
    # Derivation demo. The consoleIDs and MACs are made up; the key material comes from your
    # own dump, so this prints real output only once your keys are in place.
    cid_h = bytes.fromhex("1122334455667788"); cid_c = bytes.fromhex("99aabbccddeeff00")
    mac_h = bytes.fromhex("aabbccddeeff");     mac_c = bytes.fromhex("001122334455")
    block = cid_h + cid_c + mac_h + mac_c
    print("hash block (0x1C) :", block.hex())
    try:
        k17 = cecd_hmac_key()
        ctr = hmac.new(k17, block, hashlib.sha1).digest()[:16]
        print("CTR = HMAC-SHA1[:16]:", ctr.hex())
        print("CCMP KEY          :", derive_ccmp_key(cid_h, cid_c, mac_h, mac_c).hex())
    except keys.MissingKey as e:
        print()
        print(e)
        sys.exit(1)
