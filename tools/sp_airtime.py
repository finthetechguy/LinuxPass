#!/usr/bin/env python3
"""Radio-time analysis of a relay pcap: when was the console actually listening?

Written to answer one question that the run log cannot: a StreetPass exchange with a console that
is AWAKE behaves differently from one with a console in sleep mode, and the run log only records
what our own state machine noticed. The pcap records the air.

What it measures, per console MAC:

  * PRESENCE WINDOWS -- runs of frames from that console separated by more than `--gap` seconds.
    A console in sleep mode polls on a steady cadence; a console that is awake gets the radio in
    slices, and a slice that ends in the middle of our transfer is exactly the failure we are
    chasing. The window list is the direct measurement of how long we have to work with.
  * RETRIES -- the 802.11 retry bit on frames from the console. A frame it had to repeat is a
    frame we did not acknowledge in time, which is the loss rate that drives everything else.
  * RATES -- radiotap rate / MCS. Ours are all 1 Mbps DSSS; the console's bulk is OFDM. The
    ratio is how much of the exchange is our airtime rather than its.
  * CHANNEL -- read off radiotap, never assumed. An active monitor vif reports no channel through
    `iw`, so a measured value is the only honest one (see sp_link.detect_channel).

Usage:  sp_airtime.py FILE.pcap [FILE.pcap ...] [--gap 0.5] [--mac AA:BB:..] [--json]
"""
import sys, struct, json, argparse

# radiotap "present" bit -> (size, align) for the fields we care about, in order.
_RT_FIELDS = [(8, 8), (1, 1), (1, 1), (4, 2), (2, 2), (1, 1), (1, 1), (2, 2), (2, 2), (2, 2),
              (1, 1), (1, 1), (1, 1), (1, 1), (2, 2), (2, 2), (2, 2), (1, 1), (3, 1), (8, 4)]
TSFT, FLAGS, RATE, CHANNEL, FHSS, DBM_ANT, DBM_NOISE, LOCK, TX_ATT, DB_TX_ATT, DBM_TX, \
    ANTENNA, DB_SIG, DB_NOISE, RX_FLAGS, TX_FLAGS, RTS_RETRIES, DATA_RETRIES, MCS, AMPDU = range(20)

MAC_FMT = '%02x:%02x:%02x:%02x:%02x:%02x'


def macstr(b):
    return MAC_FMT % tuple(b)


def read_pcap(path):
    """-> [(timestamp, raw_frame)]. Handles both microsecond and nanosecond pcap."""
    with open(path, 'rb') as fh:
        gh = fh.read(24)
        if len(gh) < 24:
            return []
        magic = struct.unpack('<I', gh[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            end, div = '<', (1e6 if magic == 0xA1B2C3D4 else 1e9)
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            end, div = '>', (1e6 if magic == 0xD4C3B2A1 else 1e9)
        else:
            raise ValueError('%s: not a pcap (magic %08X)' % (path, magic))
        out = []
        while True:
            rh = fh.read(16)
            if len(rh) < 16:
                break
            ts, tus, caplen, _orig = struct.unpack(end + 'IIII', rh)
            data = fh.read(caplen)
            if len(data) < caplen:
                break
            out.append((ts + tus / div, data))
        return out


def radiotap(buf):
    """-> dict of the radiotap fields we use, or None. Walks the present-bitmap properly:
    guessing a fixed header layout silently mis-reads rate and retry on any capture whose
    driver presents a different field set."""
    if len(buf) < 8:
        return None
    _ver, _pad, length, present = struct.unpack_from('<BBHI', buf, 0)
    if length < 8 or length > len(buf):
        return None
    off, presents = 4, [present]
    while presents[-1] & (1 << 31):                 # extended bitmaps
        off += 4
        if off + 4 > length:
            return None
        presents.append(struct.unpack_from('<I', buf, off)[0])
    off += 4
    out = {'len': length}
    for bit, (size, align) in enumerate(_RT_FIELDS):
        if not (presents[0] & (1 << bit)):
            continue
        off = (off + align - 1) // align * align
        if off + size > length:
            break
        if bit == RATE:
            out['rate'] = buf[off] / 2.0
        elif bit == CHANNEL:
            out['freq'] = struct.unpack_from('<H', buf, off)[0]
        elif bit == DBM_ANT:
            out['rssi'] = struct.unpack_from('<b', buf, off)[0]
        elif bit == MCS:
            out['mcs'] = buf[off + 2]
        off += size
    return out


def frame_info(raw):
    """-> (radiotap dict, addr2 or None, retry flag, type, subtype)."""
    rt = radiotap(raw)
    if not rt:
        return None, None, False, None, None
    mpdu = raw[rt['len']:]
    if len(mpdu) < 10:
        return rt, None, False, None, None
    fc0, fc1 = mpdu[0], mpdu[1]
    ftype, sub = (fc0 >> 2) & 3, (fc0 >> 4) & 0xF
    retry = bool(fc1 & 0x08)
    a2 = macstr(mpdu[10:16]) if (ftype != 1 and len(mpdu) >= 16) else None
    return rt, a2, retry, ftype, sub


def freq_to_chan(f):
    if f is None:
        return None
    if f == 2484:
        return 14
    if 2412 <= f <= 2472:
        return (f - 2407) // 5
    return None


def analyse(paths, gap=0.5, only=None):
    frames = []
    for p in paths:
        frames += read_pcap(p)
    frames.sort(key=lambda x: x[0])
    per = {}
    chans = {}
    for ts, raw in frames:
        rt, a2, retry, ftype, sub = frame_info(raw)
        if rt is None:
            continue
        ch = freq_to_chan(rt.get('freq'))
        if ch:
            chans[ch] = chans.get(ch, 0) + 1
        if a2 is None:
            continue
        if only and a2 != only:
            continue
        d = per.setdefault(a2, {'n': 0, 'retries': 0, 'rates': {}, 'first': ts, 'last': ts,
                                'windows': [], 'kinds': {}, 'rssi': []})
        d['n'] += 1
        d['retries'] += bool(retry)
        r = rt.get('rate')
        key = ('%gM' % r) if r else ('MCS%d' % rt['mcs'] if 'mcs' in rt else '?')
        d['rates'][key] = d['rates'].get(key, 0) + 1
        d['kinds'][(ftype, sub)] = d['kinds'].get((ftype, sub), 0) + 1
        if rt.get('rssi') is not None:
            d['rssi'].append(rt['rssi'])
        if not d['windows'] or ts - d['windows'][-1][1] > gap:
            d['windows'].append([ts, ts, 0])
        d['windows'][-1][1] = ts
        d['windows'][-1][2] += 1
        d['last'] = ts
    return frames, per, chans


NAMES = {(0, 4): 'ProbeReq', (0, 5): 'ProbeResp', (0, 13): 'Action', (0, 8): 'Beacon',
         (1, 13): 'ACK', (2, 0): 'Data', (2, 8): 'QoSData'}


def report(paths, gap, only, as_json=False):
    frames, per, chans = analyse(paths, gap, only)
    if as_json:
        print(json.dumps({'frames': len(frames), 'channels': chans,
                          'stations': {m: {'frames': d['n'], 'retries': d['retries'],
                                           'rates': d['rates'],
                                           'windows': [{'start': w[0], 'secs': w[1] - w[0],
                                                        'frames': w[2]} for w in d['windows']]}
                                       for m, d in per.items()}}, indent=2, default=float))
        return 0
    if not frames:
        print('no frames')
        return 1
    t0 = frames[0][0]
    print('%d frame(s) over %.1f s from %d file(s)' % (len(frames), frames[-1][0] - t0,
                                                       len(paths)))
    print('channels seen (by radiotap, measured not assumed): %s'
          % ', '.join('ch%d:%d' % (c, n) for c, n in sorted(chans.items())))
    for mac, d in sorted(per.items(), key=lambda kv: -kv[1]['n']):
        rates = ', '.join('%s x%d' % (k, v) for k, v in
                          sorted(d['rates'].items(), key=lambda kv: -kv[1]))
        kinds = ', '.join('%s x%d' % (NAMES.get(k, 't%ds%d' % k), v) for k, v in
                          sorted(d['kinds'].items(), key=lambda kv: -kv[1]))
        rssi = ('  rssi %d..%d dBm' % (min(d['rssi']), max(d['rssi']))) if d['rssi'] else ''
        print('\n%s  %d frames  %d retries (%.1f%%)%s'
              % (mac, d['n'], d['retries'], 100.0 * d['retries'] / max(1, d['n']), rssi))
        print('   rates : %s' % rates)
        print('   kinds : %s' % kinds)
        print('   %d presence window(s) (gap > %.2f s):' % (len(d['windows']), gap))
        for st, en, n in d['windows']:
            print('      t=%8.3f  %7.3f s  %4d frames' % (st - t0, en - st, n))
        durs = sorted(w[1] - w[0] for w in d['windows'])
        if durs:
            print('   window length: min %.3f  median %.3f  max %.3f s'
                  % (durs[0], durs[len(durs) // 2], durs[-1]))
    return 0


def _selftest():
    import os, tempfile
    ok = tot = 0

    def chk(n, c, g=''):
        nonlocal ok, tot
        tot += 1
        ok += bool(c)
        print('  [%s] %s%s' % ('PASS' if c else 'FAIL', n, ('  %s' % (g,)) if g else ''))

    # radiotap with TSFT+FLAGS+RATE+CHANNEL+DBM: the alignment rules are what this must get right
    present = (1 << TSFT) | (1 << FLAGS) | (1 << RATE) | (1 << CHANNEL) | (1 << DBM_ANT)
    body = struct.pack('<Q', 12345) + bytes([0x10]) + bytes([2 * 54]) \
        + struct.pack('<HH', 2412, 0x00C0) + struct.pack('<b', -42)
    rt = struct.pack('<BBHI', 0, 0, 8 + len(body), present) + body
    got = radiotap(rt)
    chk('radiotap rate is decoded', got and got['rate'] == 54.0, got)
    chk('radiotap frequency is decoded', got and got['freq'] == 2412, got)
    chk('radiotap rssi is decoded', got and got['rssi'] == -42, got)
    chk('2412 MHz is channel 1', freq_to_chan(2412) == 1)
    chk('2484 MHz is channel 14', freq_to_chan(2484) == 14)
    chk('2437 MHz is channel 6', freq_to_chan(2437) == 6)

    # an unknown/extended present bitmap must not throw
    ext = struct.pack('<BBHII', 0, 0, 12, 0x80000000 | present, 0) + body
    chk('an extended present bitmap is walked, not guessed', radiotap(ext) is not None)
    chk('a truncated header is rejected', radiotap(b'\x00\x00') is None)

    # retry bit and addr2
    mpdu = bytes([0x40, 0x08]) + b'\x00' * 2 + b'\xff' * 6 + bytes(range(0xA0, 0xA6)) \
        + b'\xff' * 6 + b'\x00\x00'
    _r, a2, retry, ft, sb = frame_info(rt + mpdu)
    chk('addr2 is read from the mpdu', a2 == 'a0:a1:a2:a3:a4:a5', a2)
    chk('the retry bit is read', retry is True)
    chk('type/subtype are read', (ft, sb) == (0, 4), (ft, sb))
    mpdu2 = bytes([0x40, 0x00]) + b'\x00' * 2 + b'\xff' * 6 + bytes(range(0xA0, 0xA6)) \
        + b'\xff' * 6 + b'\x00\x00'
    chk('a non-retry frame reads as such', frame_info(rt + mpdu2)[2] is False)

    # a real round trip through the pcap reader, including window splitting
    fd, path = tempfile.mkstemp(suffix='.pcap')
    with os.fdopen(fd, 'wb') as fh:
        fh.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127))
        for t in (0.0, 0.1, 0.2, 5.0, 5.1):          # two clusters, a 4.8 s gap between
            pkt = rt + mpdu
            fh.write(struct.pack('<IIII', 1788400000 + int(t), int(t % 1 * 1e6),
                                 len(pkt), len(pkt)) + pkt)
    frames, per, chans = analyse([path], gap=0.5)
    chk('all five frames are read back', len(frames) == 5, len(frames))
    chk('the channel is counted from radiotap', chans == {1: 5}, chans)
    d = per['a0:a1:a2:a3:a4:a5']
    chk('frames are grouped into two presence windows', len(d['windows']) == 2,
        len(d['windows']))
    chk('the first window holds three frames', d['windows'][0][2] == 3, d['windows'][0][2])
    chk('retries are counted', d['retries'] == 5, d['retries'])
    chk('the rate is tallied', d['rates'] == {'54M': 5}, d['rates'])
    os.unlink(path)

    print('\n%d/%d checks passed' % (ok, tot))
    return 0 if ok == tot else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('pcap', nargs='*')
    ap.add_argument('--gap', type=float, default=0.5,
                    help='seconds of silence that separates two presence windows')
    ap.add_argument('--mac', default=None, help='restrict to one station')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args()
    if a.selftest:
        return _selftest()
    if not a.pcap:
        ap.error('give at least one pcap')
    return report(a.pcap, a.gap, a.mac, a.json)


if __name__ == '__main__':
    sys.exit(main())
