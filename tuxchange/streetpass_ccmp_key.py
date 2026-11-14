#!/usr/bin/env python3
"""StreetPass CCMP link-key derivation, reimplemented in software."""
import hmac, hashlib, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sp_aes
import lp_keys as keys

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

# Every console-derived value is loaded at runtime. See lp_keys.py.
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
    """The StreetPass CCMP link key for one pair of consoles."""
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
