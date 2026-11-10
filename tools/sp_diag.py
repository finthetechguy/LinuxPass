#!/usr/bin/env python3
"""Diagnostic: find the 3DS in a pcap."""
import sys, collections
from scapy.all import PcapReader, Dot11, Dot11Elt
NINTENDO_OUI = {b'\x00\x09\xbf',b'\x00\x16\x56',b'\x00\x17\xab',b'\x00\x19\x1d',b'\x00\x19\xfd',
 b'\x00\x1a\xe9',b'\x00\x1b\x7a',b'\x00\x1b\xea',b'\x00\x1c\xbe',b'\x00\x1d\xbc',b'\x00\x1e\x35',
 b'\x00\x1e\xa9',b'\x00\x1f\x32',b'\x00\x1f\xc5',b'\x00\x21\x47',b'\x00\x21\xbd',b'\x00\x22\x4c',
 b'\x00\x22\xaa',b'\x00\x22\xd7',b'\x00\x23\x31',b'\x00\x23\xcc',b'\x00\x24\x1e',b'\x00\x24\x44',
 b'\x00\x24\xf3',b'\x00\x25\xa0',b'\x00\x26\x59',b'\x00\x27\x09',b'\x04\x03\xd6',b'\x18\x2a\x7b',
 b'\x2c\x10\xc1',b'\x34\xaf\x2c',b'\x40\xd2\x8a',b'\x40\xf4\x07',b'\x58\xbd\xa3',b'\x5c\x52\x1e',
 b'\x60\x6b\xff',b'\x64\xb5\xc6',b'\x78\xa2\xa0',b'\x7c\xbb\x8a',b'\x8c\x56\xc5',b'\x8c\xcd\xe8',
 b'\x98\xb6\xe9',b'\x9c\xe6\x35',b'\xa4\x5c\x27',b'\xa4\xc0\xe1',b'\xb8\x8a\xec',b'\xcc\x9e\x00',
 b'\xcc\xfb\x65',b'\xd8\x6b\xf7',b'\xdc\x68\xeb',b'\xe0\x0c\x7f',b'\xe0\xe7\x51',b'\xe8\x4e\xce'}
def oui(mac): 
    try: return bytes(int(x,16) for x in mac.split(':')[:3])
    except: return b''
ssids=collections.Counter(); ie_ouis=collections.Counter(); macs=collections.Counter()
nin_hits=[]; sp_probe=0
for pkt in PcapReader(sys.argv[1]):
    if not pkt.haslayer(Dot11): continue
    d=pkt[Dot11]
    for m in (d.addr1,d.addr2,d.addr3):
        if m: 
            macs[m]+=1
            if oui(m) in NINTENDO_OUI: nin_hits.append(m)
    if d.type==0 and d.subtype in (4,5):
        el=pkt.getlayer(Dot11Elt)
        while el:
            if el.ID==0: 
                s=bytes(el.info); ssids[s]+=1
                if s==b"Nintendo_3DS_continuous_scan_000": sp_probe+=1
            if el.ID==221:
                v=bytes(el.info)[:3]; ie_ouis[v.hex()]+=1
            el=el.payload.getlayer(Dot11Elt)
print("=== probe SSIDs (top 15) ===")
for s,c in ssids.most_common(15): print(f"  {c:5}  {s!r}")
print(f"\n>>> Nintendo_3DS_continuous_scan_000 probes: {sp_probe}")
print("\n=== vendor-IE OUIs seen (top 10) ===")
for o,c in ie_ouis.most_common(10): print(f"  {c:5}  {o}  {'<<< NINTENDO 00:1f:32' if o=='001f32' else ''}")
print("\n=== MACs with a Nintendo OUI ===")
print(" ", sorted(set(nin_hits)) or "NONE FOUND")
print(f"\ntotal unique MACs: {len(macs)}")
