#!/usr/bin/env python3
"""Full-capture report for StreetPass discovery pcaps."""
import sys, os, glob
from collections import Counter
from scapy.all import PcapReader, Dot11, Dot11Elt, RadioTap
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), 'tuxchange'))
from sp_parse import parse_vendor_ie, NIN_OUI, is_laa

TITLE_DB = {}

def rt_field(pkt, name):
    try:
        return pkt[RadioTap].getfieldval(name)
    except Exception:
        return None

def freq_to_ch(f):
    if f is None: return None
    if 2412 <= f <= 2484:
        return 14 if f == 2484 else (f - 2407) // 5
    return f

def report(path):
    print("=" * 78)
    print(f"FILE: {path}   ({os.path.getsize(path)} bytes)")
    print("=" * 78)

    total = 0
    types = Counter()
    rt_channels = Counter()
    sp_probe_ch = Counter()
    sp_macs = Counter()
    sp_dst = Counter()
    sp_ssids = Counter()
    consoleids = Counter()
    ie_lens = Counter()
    seqs = []
    times = []
    rates = Counter()
    rssi = []
    other_vendor_oui = Counter()
    services_last = None
    prot_data = []      # every protected data frame: (a1, a2, len, hex48)
    action = []
    t0 = None

    for pkt in PcapReader(path):
        total += 1
        if not pkt.haslayer(Dot11):
            continue
        d = pkt[Dot11]
        types[(d.type, d.subtype)] += 1
        ch = freq_to_ch(rt_field(pkt, "ChannelFrequency"))
        if ch: rt_channels[ch] += 1

        if d.type == 0 and d.subtype in (4, 5):
            el = pkt.getlayer(Dot11Elt)
            ssid = None; nie = None
            while el:
                if el.ID == 0: ssid = bytes(el.info)
                if el.ID == 221:
                    raw = bytes(el.info)
                    if raw[:3] == NIN_OUI:
                        nie = parse_vendor_ie(raw); ie_lens[len(raw)] += 1
                    else:
                        other_vendor_oui[raw[:3].hex(':')] += 1
                el = el.payload.getlayer(Dot11Elt)
            if nie:
                kind = "probe_req" if d.subtype == 4 else "probe_resp"
                sp_probe_ch[(kind, ch)] += 1
                sp_macs[d.addr2] += 1
                sp_dst[d.addr1] += 1
                sp_ssids[ssid] += 1
                if 'consoleID' in nie: consoleids[nie['consoleID']] += 1
                if 'services' in nie: services_last = nie
                seqs.append(d.SC >> 4)
                ts = float(pkt.time)
                if t0 is None: t0 = ts
                times.append(ts)
                r = rt_field(pkt, "Rate")
                if r is not None: rates[r] += 1
                s = rt_field(pkt, "dBm_AntSignal")
                if s is not None: rssi.append(s)

        elif d.type == 0 and d.subtype == 13:
            raw = bytes(d.payload)
            action.append((d.addr2, d.addr1, raw[:1].hex(), raw[:24].hex()))
        elif d.type == 2:
            if d.FCfield & 0x40:
                prot_data.append((d.addr1, d.addr2, len(bytes(d)), bytes(d)[:48].hex()))

    print(f"\n[1] FRAME CENSUS  (total pcap records: {total})")
    NAMES = {(0,4):"probe-req",(0,5):"probe-resp",(0,8):"beacon",(0,13):"action",
             (0,0):"assoc-req",(0,1):"assoc-resp",(0,10):"disassoc",(0,11):"auth",
             (0,12):"deauth",(1,11):"RTS",(1,12):"CTS",(1,13):"ACK",(1,9):"block-ack",
             (1,8):"block-ack-req",(2,0):"data",(2,4):"null",(2,8):"qos-data",
             (2,12):"qos-null",(2,5):"data-cfpoll"}
    for (t, st), n in types.most_common():
        print(f"    {NAMES.get((t,st), f'type{t}/sub{st}'):<16} {n:>6}")

    print(f"\n[2] RADIOTAP CHANNELS SEEN: {dict(rt_channels)}")

    print("\n[3] STREETPASS PROBES (Nintendo vendor IE present)")
    for (kind, ch), n in sorted(sp_probe_ch.items(), key=lambda x: -x[1]):
        print(f"    {kind} on ch {ch}: {n}")
    print(f"    source MACs (A2): {dict(sp_macs)}")
    print(f"    dest   MACs (A1): {dict(sp_dst)}")
    print(f"    SSIDs: { {(s or b'').decode('latin1'): n for s, n in sp_ssids.items()} }")
    print(f"    consoleIDs: {dict(consoleids)}")
    print(f"    vendor-IE lengths: {dict(ie_lens)}")
    print(f"    PHY rates (0.5Mbps units): {dict(rates)}")
    if rssi:
        print(f"    RSSI dBm: min={min(rssi)} max={max(rssi)} mean={sum(rssi)/len(rssi):.1f}")
    if other_vendor_oui:
        print(f"    non-Nintendo vendor OUIs in probes: {dict(other_vendor_oui)}")

    if seqs:
        print(f"\n[4] SEQUENCE NUMBERS  n={len(seqs)}")
        print(f"    first 16: {seqs[:16]}")
        deltas = Counter(b - a for a, b in zip(seqs, seqs[1:]) if b >= a)
        print(f"    deltas (positive): {dict(deltas)}")

    if len(times) > 1:
        span = times[-1] - times[0]
        gaps = [b - a for a, b in zip(times, times[1:])]
        gaps_s = sorted(gaps)
        print("\n[5] TIMING")
        print(f"    capture span (probes only): {span:.2f}s   n={len(times)}")
        print(f"    inter-probe gap: min={min(gaps)*1000:.1f}ms "
              f"median={gaps_s[len(gaps_s)//2]*1000:.1f}ms max={max(gaps)*1000:.1f}ms")
        burst = [g for g in gaps if g < 0.05]
        idle = [g for g in gaps if g >= 0.05]
        if burst: print(f"    intra-burst (<50ms): n={len(burst)} mean={sum(burst)/len(burst)*1000:.1f}ms")
        if idle:  print(f"    inter-burst (>=50ms): n={len(idle)} mean={sum(idle)/len(idle):.2f}s")

    if services_last:
        print("\n[6] VENDOR IE DECODE (last StreetPass probe)")
        print(f"    OUI={services_last.get('oui')} subtype=0x{services_last.get('subtype',0):02x} "
              f"protocol=0x{services_last.get('protocol_id',0):02x} svc_len={services_last.get('svc_len')}")
        print(f"    const={services_last.get('const_f008')} consoleID={services_last.get('consoleID')}")
        print(f"    services ({len(services_last['services'])}):")
        for i, s in enumerate(services_last['services']):
            tid = s['titleID']
            extra = f"  trailing={s['trailing']}" if 'trailing' in s else ""
            print(f"      [{i:2}] titleID_low=0x{tid}  flags={s['flags']}{extra}")

    if action:
        print(f"\n[7] ACTION FRAMES: {len(action)}")
        for a in action[:10]: print("   ", a)
    else:
        print("\n[7] ACTION FRAMES: 0")

    console_set = set(sp_macs)
    def is_peer(a1, a2):
        return (a1 in console_set or a2 in console_set) or (is_laa(a1) and is_laa(a2))
    exch = [(a1, a2, ln, hx) for (a1, a2, ln, hx) in prot_data if is_peer(a1, a2)]
    convo = Counter()
    for a1, a2, ln, hx in exch:
        convo[frozenset((a1, a2))] += 1
    print(f"\n[8] PROTECTED DATA, EXCHANGE CANDIDATES: {len(exch)} of {len(prot_data)} protected frames")
    if console_set:
        print(f"    console MACs (from Nintendo IE): {sorted(console_set)}")
    if convo:
        print("    conversations (MAC pair -> #protected frames):")
        for pair, n in convo.most_common():
            print(f"      {' <-> '.join(sorted(pair))}: {n}")
        print("    sample MPDUs (first 48B):")
        for a1, a2, ln, hx in exch[:6]:
            print(f"      {a2}->{a1} len={ln}: {hx}")
    else:
        print("    (none: no protected data between consoles. Capture DURING the exchange on a")
        print("     fixed channel; retry ch 1 -> 6 -> 11.)")
    print()

if __name__ == "__main__":
    files = sys.argv[1:] or sorted(glob.glob("pcaps/*.pcap"))
    for f in files:
        report(f)
