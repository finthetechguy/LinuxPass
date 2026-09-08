#!/usr/bin/env python3
"""
Parse a monitor-mode pcap for StreetPass 802.11 frames.
Classifies: probe-req/resp (SSID Nintendo_3DS_continuous_scan_000 + Nintendo vendor IE 0xDD/00:1F:32),
action frames (cat 0x7f), CCMP data frames. Extracts vendor-IE fields (consoleID/services) + MACs.
Usage: sp_parse.py capture.pcap
"""
import sys, struct, binascii
# scapy is needed only by the pcap-READING half of this module (strip_fcs / classify / main).
# The frame BUILDERS are pure struct code, and the transmit box -- the ath9k machine running
# sp_probe_tx.py -- has no scapy installed and does not need it. So importing this module must not
# require scapy; the readers below raise a clear error if it is genuinely missing.
try:
    from scapy.all import PcapReader, RadioTap, Dot11, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp
    HAVE_SCAPY = True
except ImportError:                                     # pragma: no cover - environment-dependent
    HAVE_SCAPY = False
    PcapReader = RadioTap = Dot11 = Dot11Elt = Dot11ProbeReq = Dot11ProbeResp = None


def _need_scapy(what):
    if not HAVE_SCAPY:
        raise RuntimeError('%s needs scapy, which is not installed here. The frame builders '
                           '(build_probe / build_directed_probe / build_action) do not.' % what)


NIN_OUI = b'\x00\x1f\x32'
SP_SSID = b"Nintendo_3DS_continuous_scan_000"

# Known Nintendo IEEE OUIs (a real 3DS burns a Nintendo OUI, but StreetPass PROBES use a
# randomized locally-administered MAC — so peer/exchange detection must key off the console
# MACs actually seen carrying the Nintendo vendor IE, not off the OUI.)
NIN_OUIS = {"00:1f:32","00:1a:e9","00:09:bf","00:16:56","00:17:ab","00:19:1d","00:1b:ea",
            "00:1c:be","00:1d:bc","00:1e:35","00:21:bd","00:22:4c","00:23:cc","00:24:1e",
            "00:24:44","00:25:a0","00:26:59","00:27:09","0c:fe:45","2c:10:c1","34:af:2c",
            "40:d2:8a","58:bd:a3","5c:52:1e","78:a2:a0","8c:cd:e8","98:b6:e9","a4:5c:27",
            "a4:c0:e1","b8:ae:6e","cc:9e:00","d8:6b:f7","dc:68:eb","e0:0c:7f","e8:4e:ce","ec:c4:0d"}

def _nin_oui(mac):
    return bool(mac) and mac[:8].lower() in NIN_OUIS

def is_laa(mac):
    """Locally-administered (randomized) UNICAST MAC — what 3DS StreetPass probes use.

    Both bits of the first octet matter and both are checked:
      bit 1 (0x02) = locally administered  -> must be SET   (a randomized address)
      bit 0 (0x01) = group/multicast       -> must be CLEAR (a real peer, not a group)
    Skipping the group check makes every IPv6-multicast frame (dst 33:33:xx:xx:xx:xx, and
    0x33 & 0x02 is set) look like a console-to-console frame, which falsely satisfies the
    "protected data frames captured" test on ambient neighbour traffic."""
    if not mac or mac.lower() == "ff:ff:ff:ff:ff:ff":
        return False
    try:
        first = int(mac.split(':')[0], 16)
    except ValueError:
        return False
    return bool(first & 0x02) and not (first & 0x01)

def parse_vendor_tlv(body):
    """Walk the vendor-IE TLV stream exactly as cecd sub_104494 does.

    Record = {u16 hdr; u8 data[len]} with hdr bits [3:0]=typeA, [7:4]=typeB, [15:8]=len.
    Proven from firmware (cecd 0x104494: `lsls #0x1c/lsrs #0x1c` -> A, `lsls #0x18/lsrs #0x1c` -> B,
    `lsls #0x10/lsrs #0x18` -> len, cursor advanced by len+2) and confirmed against real captures:
    the 82-byte probe IE payload parses cleanly and exhaustively from offset 4 (after OUI+subtype)
    into exactly two records -- (A=1,B=1,len=66) service list and (A=0,B=0xF,len=8) session token --
    and offset 4 is the ONLY start offset that yields a clean walk.

    Returns (records, trailing) where records is a list of dicts and trailing is any undecodable tail.
    """
    recs = []
    i = 0
    while i + 2 <= len(body):
        hdr = body[i] | (body[i + 1] << 8)
        a, b, ln = hdr & 0xF, (hdr >> 4) & 0xF, (hdr >> 8) & 0xFF
        if i + 2 + ln > len(body):
            return recs, body[i:]
        recs.append({'a': a, 'b': b, 'len': ln, 'data': body[i + 2:i + 2 + ln], 'off': i})
        i += ln + 2
    return recs, body[i:]


def parse_services(data):
    """Service list record payload: titleID_low(4) + flags(1), plus 6 trailing bytes if flags&0x02.
    Each titleID is a CEC title ID; uniqueId = cecTitleId >> 8."""
    services = []
    i = 0
    while i + 5 <= len(data):
        tid = data[i:i + 4]; flags = data[i + 4]; i += 5
        s = {'titleID': tid.hex(), 'flags': hex(flags)}
        if flags & 0x02:
            s['trailing'] = data[i:i + 6].hex(); i += 6
        services.append(s)
    return services


def build_probe(src_mac, token8, services, seq=0):
    """Build a StreetPass probe request. The inverse of parse_vendor_ie + the IE layout.

    services: iterable of (title_id:int, flags:int, trailing:bytes). ALL services live in ONE
    TLV record (A=1,B=1,len=N) as concatenated 5-byte entries -- a 12-title console emits a
    single len-66 record, not 12 records. The title id is stored BIG-endian. A service whose
    flags have 0x02 set carries 6 extra bytes (a MAC) after the flags byte.

    Verified: rebuilds 1647/1647 captured probes byte-identically across 6 captures, two
    consoles, and both 1-service and 12-service probes.
    """
    fc, dur, bcast = b'\x40\x00', b'\x00\x00', b'\xff' * 6
    hdr = fc + dur + bcast + bytes(src_mac) + bcast + struct.pack('<H', (seq & 0xFFF) << 4)
    ies  = b'\x00\x20' + b'Nintendo_3DS_continuous_scan_000'
    ies += b'\x01\x08' + bytes.fromhex('82848b0c12961824')   # rates  1,2,5.5,6,9,11,12,18
    ies += b'\x32\x04' + bytes.fromhex('3048606c')           # ext    24,36,48,54
    svc = b''.join(struct.pack('>I', t) + bytes([f]) + bytes(tr) for t, f, tr in services)
    tlv  = struct.pack('<H', (len(svc) << 8) | (1 << 4) | 1) + svc
    tlv += struct.pack('<H', (8 << 8) | (0xF << 4) | 0) + bytes(token8)
    vend = NIN_OUI + b'\x01' + tlv
    return hdr + ies + b'\xdd' + bytes([len(vend)]) + vend


def parse_vendor_ie(data):
    """Parse the Nintendo StreetPass vendor IE.

    Layout: OUI(3) | subtype(1) | TLV stream.  The TLV walk and the (A=0,B=0xF,len=8) token record
    are both taken from cecd firmware, not from the shape of one console's capture -- so a peer with
    a different enabled-title set, or with extra TLV records, still decodes correctly.
    """
    out = {}
    if data[:3] != NIN_OUI:
        return out
    out['oui'] = '00:1f:32'
    out['subtype'] = data[3]
    body = data[4:]
    recs, trailing = parse_vendor_tlv(body)
    out['tlv'] = [{'a': r['a'], 'b': r['b'], 'len': r['len'], 'data': r['data'].hex()} for r in recs]
    if trailing:
        out['tlv_trailing'] = trailing.hex()          # non-empty => walk did not fit; treat as suspect
    for r in recs:
        if (r['a'], r['b']) == (1, 1):                # service list
            out['protocol_id'] = 0x11                 # == (b<<4)|a, kept for continuity with old notes
            out['svc_len'] = r['len']
            out['services'] = parse_services(r['data'])
        elif (r['a'], r['b'], r['len']) == (0, 0xF, 8):   # the record cecd_derive_ccmp_key asks for
            out['const_f008'] = 'f008'
            out['consoleID'] = r['data'].hex()
            out['consoleID_tail8'] = out['consoleID']
    if 'services' not in out and 'consoleID' not in out:
        out['body_hex'] = body.hex()
    return out


def strip_fcs(pkt, mpdu):
    """Return the MPDU with the trailing 4-byte 802.11 FCS removed, if the radio appended one.

    THIS IS LOAD-BEARING FOR DECRYPTION. CCMP takes the last 8 bytes of the MPDU as the MIC, so a
    frame that still carries its FCS makes `decrypt_and_verify` fail on EVERY key -- which looks
    exactly like "the key derivation model is wrong" rather than "four extra bytes".

    Whether the FCS is present is a per-RADIO property, not a per-capture one, and the two-sniffer
    setup mixes both in one run: observed 30 Aug 2026, the ath9k box sets radiotap Flags bit 0x10
    (FCS-at-end) and appends it, the MT7902 laptop does not. So this must be decided per frame.

    Decision order:
      1. radiotap Flags bit 0x10 set  -> strip (authoritative; the radio says so)
      2. otherwise, if CRC-32 of mpdu[:-4] equals the last 4 bytes -> strip (flag missing but the
         FCS is demonstrably there; a false positive needs a 1-in-2^32 coincidence)
    """
    if len(mpdu) < 8:
        return mpdu
    rt = pkt.getlayer(RadioTap)
    flags = getattr(rt, 'Flags', None) if rt is not None else None
    has_fcs = False
    try:
        has_fcs = bool(flags) and ('FCS' in str(flags) or (int(flags) & 0x10))
    except Exception:
        has_fcs = 'FCS' in str(flags)
    if not has_fcs:
        has_fcs = (binascii.crc32(mpdu[:-4]) & 0xffffffff).to_bytes(4, 'little') == mpdu[-4:]
    return mpdu[:-4] if has_fcs else mpdu


def classify(pkt):
    _need_scapy('classify()')
    if not pkt.haslayer(Dot11): return None
    d = pkt[Dot11]
    t, st = d.type, d.subtype
    info = {'a1': d.addr1, 'a2': d.addr2, 'a3': d.addr3, 'type': t, 'subtype': st}
    if t == 0 and st in (4, 5):            # probe req/resp
        info['kind'] = 'probe_req' if st == 4 else 'probe_resp'
        el = pkt.getlayer(Dot11Elt)
        while el:
            if el.ID == 0:  info['ssid'] = bytes(el.info)
            if el.ID == 221:
                v = parse_vendor_ie(bytes(el.info))
                if v: info['nintendo_ie'] = v
            el = el.payload.getlayer(Dot11Elt)
        return info
    if t == 0 and st == 13:                # action frame
        info['kind'] = 'action'
        raw = bytes(pkt[Dot11].payload)
        info['action_cat'] = raw[0] if raw else None
        info['action_hex'] = raw[:16].hex()
        return info
    if t == 2:                             # data
        info['kind'] = 'data_qos' if (st & 8) else 'data'
        info['protected'] = bool(d.FCfield & 0x40)
        info['mpdu_hex'] = strip_fcs(pkt, bytes(pkt[Dot11])).hex()   # full MPDU for CCMP decrypt, FCS removed
        return info
    return None

def main(path, verbose=True):
    """Two-pass: (1) classify every frame + learn the console MACs from the Nintendo-IE probes;
    (2) keep StreetPass-relevant frames, including the CCMP data / cat-0x7f action exchange BETWEEN
    those console MACs. Returns (sp_frames, meta). meta has: console_macs {mac->token},
    exchange_data (protected data MPDUs between consoles), and the raw counts.

    `path` may be a single pcap or a LIST of pcaps. Multiple files are for the two-sniffer setup
    (one radio per channel): the frames are simply pooled. Ordering across files does not matter --
    classification is per-frame, and payload reassembly is keyed on the CCMP PN (a per-key monotonic
    counter), not on capture time. So the two radios need no clock sync, and if they happen to sit
    on the same channel the duplicate MPDUs are dropped by sp_cec.reassemble()'s PN dedup."""
    paths = [path] if isinstance(path, (str, bytes)) else list(path)

    def _packets():
        for _p in paths:
            for _pk in PcapReader(_p):
                yield _pk

    counts = {}; classified = []
    console_macs = {}     # mac -> vendor-IE 8-byte token (per-session), from probe senders
    console_tokens = {}   # mac -> [every distinct token seen, in order of first sight]
    for pkt in _packets():
        c = classify(pkt)
        if not c: continue
        k = c['kind']; counts[k] = counts.get(k, 0) + 1
        classified.append(c)
        if 'nintendo_ie' in c and c.get('a2'):
            tok = c['nintendo_ie'].get('consoleID')
            console_macs.setdefault(c['a2'], tok)
            # The on-air 8-byte token ROTATES PER SCAN SESSION, and a single capture is long
            # enough to span a rotation (observed: streetpass_1787921701.pcap has two tokens for
            # 96:58:cb:44:55:66). So one MAC -> many tokens is NORMAL, not an error. What matters
            # is that the KDF is fed the token in force during the exchange, which is not
            # necessarily the first one seen -- hence keep every token, in order of first sight,
            # and let the decrypt stage try them all against the CCMP MIC.
            if tok and tok not in console_tokens.setdefault(c['a2'], []):
                console_tokens[c['a2']].append(tok)
    cmset = set(console_macs)

    def is_exchange(c):
        # a protected data frame or cat-0x7f action frame between two consoles = the exchange.
        # match by learned console MAC, or fall back to "both endpoints are randomized (LAA) MACs"
        # (covers the case where the linked-session MAC differs from the probe MAC).
        a1, a2 = c.get('a1'), c.get('a2')
        peer = (a1 in cmset or a2 in cmset) or (is_laa(a1) and is_laa(a2))
        if c['kind'].startswith('data') and c.get('protected'):
            return peer
        if c['kind'] == 'action' and c.get('action_cat') == 0x7f:
            return peer
        return False

    sp_frames = []
    for c in classified:
        if ('nintendo_ie' in c) or (c.get('ssid') == SP_SSID) or is_exchange(c):
            sp_frames.append(c)

    exchange_data = [c for c in sp_frames if c['kind'].startswith('data') and c.get('protected')]
    exchange_action = [c for c in sp_frames if c['kind'] == 'action' and c.get('action_cat') == 0x7f]
    meta = {'console_macs': console_macs, 'counts': counts,
            'exchange_data': exchange_data, 'exchange_action': exchange_action,
            'console_tokens': console_tokens}

    if verbose:
        print("frame counts:", counts)
        print("console MACs (Nintendo-IE probe senders) -> token:", console_macs or "(none seen)")
        print(f"StreetPass-relevant frames: {len(sp_frames)}   "
              f"(protected data between consoles: {len(exchange_data)}, "
              f"cat-0x7f action: {len(exchange_action)})\n")
        for i, c in enumerate(sp_frames[:60]):
            print(f"[{i}] {c['kind']}  A2(src)={c['a2']} A1(dst)={c['a1']} A3={c['a3']}")
            if 'ssid' in c: print("     SSID:", c['ssid'])
            if 'nintendo_ie' in c: print("     Nintendo IE:", c['nintendo_ie'])
            if c['kind'] == 'action':
                print("     action cat/hex:", hex(c.get('action_cat') or 0), c.get('action_hex'))
            if c['kind'].startswith('data'):
                print("     protected data MPDU (first 32B):", c['mpdu_hex'][:64])
    return sp_frames, meta

if __name__ == "__main__":
    if len(sys.argv) < 2: print("usage: sp_parse.py capture.pcap [capture2.pcap ...]"); sys.exit(1)
    main(sys.argv[1:])


def build_directed_probe(src_mac, dst_mac, seq=0, duration=0x013a):
    """The DIRECTED probe request a console sends once it has chosen a peer.

    Not the same frame as the broadcast StreetPass probe: the SSID is a zero-length wildcard,
    there is NO Nintendo vendor IE, and addr3 (BSSID) is the PEER's MAC rather than broadcast.
    Taken byte-for-byte from frames_1788125397.pcap #2760 (documentation addresses substituted),
    which the console retried 5 times -- so it is also the frame most likely to draw a hardware ACK.
    """
    hdr = (b'\x40\x00' + struct.pack('<H', duration) + bytes(dst_mac) + bytes(src_mac)
           + bytes(dst_mac) + struct.pack('<H', (seq & 0xFFF) << 4))
    ies  = b'\x00\x00'                                       # wildcard SSID, length 0
    ies += b'\x01\x08' + bytes.fromhex('82848b0c12961824')   # rates 1,2,5.5,6,9,11,12,18
    ies += b'\x32\x04' + bytes.fromhex('3048606c')           # ext   24,36,48,54
    return hdr + ies


def build_action(src_mac, dst_mac, seq=0, duration=0x00d5, tail=b'\x00\x00'):
    """The Nintendo vendor-specific action frame (category 0x7f + OUI 00:1f:32 + 2 bytes).

    Byte-for-byte from frames_1788125397.pcap #2756. Body is only 6 bytes -- a signal, not a
    carrier. addr3 (BSSID) is the peer's MAC.
    """
    hdr = (b'\xd0\x00' + struct.pack('<H', duration) + bytes(dst_mac) + bytes(src_mac)
           + bytes(dst_mac) + struct.pack('<H', (seq & 0xFFF) << 4))
    return hdr + b'\x7f' + NIN_OUI + bytes(tail)
