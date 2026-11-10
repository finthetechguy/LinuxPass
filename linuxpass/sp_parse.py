#!/usr/bin/env python3
"""Parse a monitor-mode pcap for StreetPass 802.11 frames."""
import sys, struct, binascii
# scapy is only needed for reading pcaps. The frame builders work without it.
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

# StreetPass probes use randomized MACs, so detect peers by the vendor IE.
NIN_OUIS = {"00:1f:32","00:1a:e9","00:09:bf","00:16:56","00:17:ab","00:19:1d","00:1b:ea",
            "00:1c:be","00:1d:bc","00:1e:35","00:21:bd","00:22:4c","00:23:cc","00:24:1e",
            "00:24:44","00:25:a0","00:26:59","00:27:09","0c:fe:45","2c:10:c1","34:af:2c",
            "40:d2:8a","58:bd:a3","5c:52:1e","78:a2:a0","8c:cd:e8","98:b6:e9","a4:5c:27",
            "a4:c0:e1","b8:ae:6e","cc:9e:00","d8:6b:f7","dc:68:eb","e0:0c:7f","e8:4e:ce","ec:c4:0d"}

def _nin_oui(mac):
    return bool(mac) and mac[:8].lower() in NIN_OUIS

def is_laa(mac):
    """Locally-administered (randomized) unicast MAC, as 3DS StreetPass probes use."""
    if not mac or mac.lower() == "ff:ff:ff:ff:ff:ff":
        return False
    try:
        first = int(mac.split(':')[0], 16)
    except ValueError:
        return False
    return bool(first & 0x02) and not (first & 0x01)

def parse_vendor_tlv(body):
    """Walk the vendor-IE TLV stream exactly as cecd sub_104494 does."""
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
    """Service list record: titleID_low(4) + flags(1), plus 6 trailing bytes if flags&0x02."""
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
    """Build a StreetPass probe request."""
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
    """Parse the Nintendo StreetPass vendor IE."""
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
        if (r['a'], r['b']) == (1, 1):
            out['protocol_id'] = 0x11
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
    """Return the MPDU with the trailing 4-byte 802.11 FCS removed, if the radio appended one."""
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
    if t == 0 and st in (4, 5):
        info['kind'] = 'probe_req' if st == 4 else 'probe_resp'
        el = pkt.getlayer(Dot11Elt)
        while el:
            if el.ID == 0:  info['ssid'] = bytes(el.info)
            if el.ID == 221:
                v = parse_vendor_ie(bytes(el.info))
                if v: info['nintendo_ie'] = v
            el = el.payload.getlayer(Dot11Elt)
        return info
    if t == 0 and st == 13:
        info['kind'] = 'action'
        raw = bytes(pkt[Dot11].payload)
        info['action_cat'] = raw[0] if raw else None
        info['action_hex'] = raw[:16].hex()
        return info
    if t == 2:
        info['kind'] = 'data_qos' if (st & 8) else 'data'
        info['protected'] = bool(d.FCfield & 0x40)
        info['mpdu_hex'] = strip_fcs(pkt, bytes(pkt[Dot11])).hex()   # full MPDU for CCMP decrypt, FCS removed
        return info
    return None

def main(path, verbose=True):
    """Classify every frame, learn the console MACs, and keep StreetPass-relevant frames."""
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
            # The token rotates per scan session, so one MAC can have many tokens.
            if tok and tok not in console_tokens.setdefault(c['a2'], []):
                console_tokens[c['a2']].append(tok)
    cmset = set(console_macs)

    def is_exchange(c):
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
    """The DIRECTED probe request a console sends once it has chosen a peer."""
    hdr = (b'\x40\x00' + struct.pack('<H', duration) + bytes(dst_mac) + bytes(src_mac)
           + bytes(dst_mac) + struct.pack('<H', (seq & 0xFFF) << 4))
    ies  = b'\x00\x00'
    ies += b'\x01\x08' + bytes.fromhex('82848b0c12961824')   # rates 1,2,5.5,6,9,11,12,18
    ies += b'\x32\x04' + bytes.fromhex('3048606c')           # ext   24,36,48,54
    return hdr + ies


def build_action(src_mac, dst_mac, seq=0, duration=0x00d5, tail=b'\x00\x00'):
    """The Nintendo vendor-specific action frame (category 0x7f + OUI 00:1f:32 + 2 bytes)."""
    hdr = (b'\xd0\x00' + struct.pack('<H', duration) + bytes(dst_mac) + bytes(src_mac)
           + bytes(dst_mac) + struct.pack('<H', (seq & 0xFFF) << 4))
    return hdr + b'\x7f' + NIN_OUI + bytes(tail)
