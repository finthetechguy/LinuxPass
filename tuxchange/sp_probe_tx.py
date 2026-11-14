#!/usr/bin/env python3
"""Stage 1: the first transmission. Make a real 3DS react to us."""
import sys, os, time, socket, struct, select, random, re, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sp_parse

# Consoles set the locally-administered bit on a Nintendo OUI, and both forms are on air.
CONSOLE_PREFIXES = ('ba:ae:6e', '96:58:cb', 'b8:ae:6e', '94:58:cb')
SP_SSID = b'Nintendo_3DS_continuous_scan_000'
MIIPLAZA = 0x00020800

SERVICES_MIIPLAZA = [(MIIPLAZA, 0x00, b'')]
SERVICES_FULL = [
    (0x00141000, 0x30, b''), (0x0007ad00, 0x30, b''), (0x00051600, 0x10, b''),
    (0x0008c500, 0x30, b''), (0x0012ec00, 0x30, b''), (0x00030b00, 0x30, b''),
    (0x00020500, 0x32, b'\x00' * 6), (0x0007c800, 0x30, b''), (0x00053f00, 0x30, b''),
    (0x00030600, 0x30, b''), (0x001a0400, 0x10, b''), (0x00020800, 0x00, b''),
]

CH_FREQ = {c: 2412 + (c - 1) * 5 for c in range(1, 14)}
CH_FREQ[14] = 2484
DISCOVERY_CHANNELS = (1, 6, 11)


def is_console(mac):
    return bool(mac) and mac.lower()[:8] in CONSOLE_PREFIXES


def macstr(b):
    return ':'.join('%02x' % c for c in b)


def macbytes(s):
    return bytes.fromhex(s.replace(':', ''))


def radiotap_tx(rate_mbps=1.0, noack=True, noseq=True):
    """Minimal injection radiotap: RATE (bit 2) + TX_FLAGS (bit 15)."""
    flags = (0x0008 if noack else 0) | (0x0010 if noseq else 0)
    present = (1 << 2) | (1 << 15)
    return struct.pack('<BBHIBBH', 0, 0, 12, present, int(round(rate_mbps * 2)), 0, flags)


def rt_len(buf):
    return struct.unpack_from('<H', buf, 2)[0] if len(buf) >= 4 else 0


SUBTYPE = {(0, 4): 'ProbeReq', (0, 5): 'ProbeResp', (0, 13): 'Action', (0, 8): 'Beacon',
           (1, 13): 'ACK', (1, 12): 'CTS', (1, 11): 'RTS', (2, 0): 'Data'}


def parse_mpdu(mpdu):
    """-> dict describing an 802.11 frame, or None if it is too short to classify."""
    if len(mpdu) < 10:
        return None
    fc0, fc1 = mpdu[0], mpdu[1]
    ftype, sub = (fc0 >> 2) & 3, (fc0 >> 4) & 0xF
    out = {'type': ftype, 'subtype': sub, 'retry': bool(fc1 & 0x08),
           'name': SUBTYPE.get((ftype, sub), 't%ds%d' % (ftype, sub)),
           'addr1': macstr(mpdu[4:10]), 'addr2': None, 'addr3': None, 'seq': None}
    if ftype == 1:
        return out
    if len(mpdu) >= 24:
        out['addr2'] = macstr(mpdu[10:16])
        out['addr3'] = macstr(mpdu[16:22])
        out['seq'] = struct.unpack_from('<H', mpdu, 22)[0] >> 4
    return out


def probe_info(mpdu):
    """Pull SSID / vendor IE out of a probe request or response. -> dict or None."""
    if len(mpdu) < 24:
        return None
    ftype, sub = (mpdu[0] >> 2) & 3, (mpdu[0] >> 4) & 0xF
    if ftype != 0 or sub not in (4, 5):
        return None
    body = mpdu[24 + (12 if sub == 5 else 0):]
    info, i = {'ssid': None, 'ds': None, 'services': None, 'token': None, 'vendor': []}, 0
    while i + 2 <= len(body):
        t, ln = body[i], body[i + 1]
        if i + 2 + ln > len(body):
            break
        v = body[i + 2:i + 2 + ln]
        if t == 0:
            info['ssid'] = v
        elif t == 3 and ln == 1:
            info['ds'] = v[0]
        elif t == 221:
            info['vendor'].append(v)
            if v[:3] == sp_parse.NIN_OUI:
                recs, _ = sp_parse.parse_vendor_tlv(v[4:])
                for r in recs:
                    if (r['a'], r['b']) == (1, 1):
                        info['services'] = sp_parse.parse_services(r['data'])
                    elif (r['a'], r['b'], r['len']) == (0, 0xF, 8):
                        info['token'] = r['data'].hex()
        i += 2 + ln
    return info


def is_streetpass_probe(mpdu):
    inf = probe_info(mpdu)
    return bool(inf and inf['ssid'] == SP_SSID)


# If the radio is not transmitting, a silent console proves nothing.

def iface_phy(iface):
    """-> 'phyN' the interface lives on, or None."""
    try:
        with open('/sys/class/net/%s/phy80211/name' % iface) as f:
            return f.read().strip() or None
    except OSError:
        return None


def read_tx_counters(mon):
    """-> (dict, source) of the hardware TX counters for the radio `mon` is on, if it has any.

    Only ath9k exposes them (debugfs). mac80211 does not count injected frames in the monitor's
    netdev statistics, so other radios fall back to counting our own frames echoed back, which
    the callers do."""
    out, src = {}, None
    phy = iface_phy(mon)
    x = phy and '/sys/kernel/debug/ieee80211/%s/ath9k/xmit' % phy
    if x and os.path.exists(x):
        try:
            with open(x) as f:
                for line in f:
                    m = re.match(r'\s*(.+?):\s+((?:\d+\s*)+)$', line)
                    if m:
                        out[m.group(1).strip()] = sum(int(v) for v in m.group(2).split())
            src = x
        except (OSError, PermissionError):
            out = {}
    return out, src


def diff_counters(a, b):
    return {k: b[k] - a[k] for k in b if k in a and b[k] - a[k] != 0}


def sh(cmd):
    import subprocess
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def iface_freq(mon):
    _, out, _ = sh('iw dev %s info' % mon)
    m = re.search(r'channel\s+\d+\s+\((\d+)\s*MHz\)', out)
    return int(m.group(1)) if m else None


def iface_type(mon):
    _, out, _ = sh('iw dev %s info' % mon)
    m = re.search(r'type\s+(\S+)', out)
    return m.group(1) if m else None


def tune(mon, ch, log):
    """Tune and VERIFY by reading the frequency back."""
    want = CH_FREQ[ch]
    for arg in ('set channel %d' % ch, 'set channel %d NOHT' % ch,
                'set freq %d' % want, 'set freq %d NOHT' % want):
        rc, _, err = sh('iw dev %s %s' % (mon, arg))
        got = iface_freq(mon)
        if got == want:
            return True
        if rc != 0:
            log('    tune: `%s` -> %s' % (arg, err or 'failed'), 2)
        else:
            log('    tune: `%s` returned 0 but radio reports %s MHz' % (arg, got), 2)
    return False


class Runner:
    def __init__(self, args):
        self.a = args
        self.t0 = time.time()
        self.sock = None
        self.src = macbytes(args.mac) if args.mac else self._random_console_mac()
        self.token = (bytes.fromhex(args.token) if args.token
                      else bytes(random.getrandbits(8) for _ in range(8)))
        self.services = SERVICES_FULL if args.full_services else SERVICES_MIIPLAZA
        self.seq = random.randrange(0, 4096)
        self.consoles = {}          # mac -> {'last':t,'token':..,'services':..,'n':..,'freq':..}
        self.events = []            # the things that count as a reply
        self.sent = {'broadcast': 0, 'directed': 0, 'action': 0}
        self.echoes = 0
        self.rx_total = 0

    def _random_console_mac(self):
        """Look like a console: real Nintendo OUI with the LAA bit set, random low 3 bytes."""
        base = bytes.fromhex('b8ae6e')
        return bytes([base[0] | 0x02]) + base[1:] + bytes(random.getrandbits(8) for _ in range(3))

    def log(self, msg, level=1):
        if level <= self.a.verbose:
            print('[%8.3f] %s' % (time.time() - self.t0, msg), flush=True)

    def banner(self, msg):
        self.log('')
        self.log('=' * 78)
        self.log('  ' + msg)
        self.log('=' * 78)

    def open_socket(self):
        t = iface_type(self.a.iface)
        if t != 'monitor':
            self.log('FATAL: %s is type %r, not monitor.' % (self.a.iface, t))
            self.log('       Create one with:  sudo iw dev <adapter> interface add %s type monitor' % self.a.iface)
            return False
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            s.bind((self.a.iface, 0))
            s.setblocking(False)
        except PermissionError:
            self.log('FATAL: need root (AF_PACKET raw socket). Use ./tuxchange-probe')
            return False
        except OSError as e:
            self.log('FATAL: cannot open %s: %s' % (self.a.iface, e))
            return False
        self.sock = s
        return True

    def send(self, mpdu, rate=1.0, noack=True, what=''):
        rt = radiotap_tx(rate, noack=noack)
        try:
            self.sock.send(rt + mpdu)
            return True
        except BlockingIOError:
            self.log('    TX queue full, dropping %s' % what, 2)
        except OSError as e:
            self.log('    TX failed (%s): %s' % (what, e))
        return False

    def next_seq(self):
        self.seq = (self.seq + 1) & 0xFFF
        return self.seq

    def pump(self, until, on_probe=None):
        """Read frames until `until` (absolute time)."""
        while time.time() < until:
            r, _, _ = select.select([self.sock], [], [], max(0.0, until - time.time()))
            if not r:
                continue
            try:
                buf = self.sock.recv(4096)
            except (BlockingIOError, OSError):
                continue
            n = rt_len(buf)
            if n == 0 or n >= len(buf):
                continue
            mpdu = buf[n:]
            self.rx_total += 1
            f = parse_mpdu(mpdu)
            if not f:
                continue
            me = macstr(self.src)
            if f['addr2'] == me:
                self.echoes += 1
                continue
            if f['addr1'] == me:
                self.record(f, mpdu)
                continue
            if f['type'] == 0 and f['subtype'] == 4:
                if is_streetpass_probe(mpdu):
                    inf = probe_info(mpdu)
                    c = self.consoles.setdefault(f['addr2'], {'n': 0})
                    c['n'] += 1
                    c['last'] = time.time()
                    c['token'] = inf.get('token')
                    c['services'] = inf.get('services')
                    if c['n'] == 1:
                        self.log('  console discovered: %s  token=%s  %d service(s)'
                                 % (f['addr2'], inf.get('token'),
                                    len(inf.get('services') or [])))
                    if on_probe:
                        on_probe(f['addr2'], mpdu, inf)

    def record(self, f, mpdu):
        """Something on air was addressed to a MAC that exists only because we invented it."""
        ev = {'t': time.time() - self.t0, 'name': f['name'], 'from': f['addr2'],
              'seq': f['seq'], 'retry': f['retry'], 'len': len(mpdu)}
        inf = probe_info(mpdu)
        if inf:
            ev['ssid'] = inf['ssid']
            ev['ds'] = inf['ds']
            ev['services'] = inf['services']
            ev['token'] = inf['token']
        self.events.append(ev)
        tag = {'ACK': 'ACK', 'ProbeResp': 'PROBE RESPONSE', 'Action': 'ACTION FRAME',
               'ProbeReq': 'DIRECTED PROBE'}.get(f['name'], f['name'])
        self.log('  *** %s addressed to us%s'
                 % (tag, ('  from %s' % f['addr2']) if f['addr2'] else ''))
        if inf and inf['ds'] is not None:
            self.log('      DS Parameter Set = channel %d   <-- link channel announcement'
                     % inf['ds'])
        if inf and inf['services']:
            self.log('      services: %s' % [s['titleID'] for s in inf['services']])
        if inf and inf['token']:
            self.log('      token: %s' % inf['token'])

    def phase_listen(self, ch, secs):
        self.banner("LISTEN  ch %d  %.0f s: learn the consoles' live session MACs" % (ch, secs))
        self.pump(time.time() + secs)
        if not self.consoles:
            self.log('  no console probes heard on ch %d' % ch)
        for m, c in sorted(self.consoles.items(), key=lambda kv: -kv[1]['n']):
            self.log('  %s  %d probes  token=%s' % (m, c['n'], c.get('token')))
        return bool(self.consoles)

    def phase_ack(self, ch, secs):
        """Rung 1a: react to console probes with a directed probe and watch for the ACK."""
        self.banner('RUNG 1a  ch %d  %.0f s: directed probe -> expect a hardware ACK' % (ch, secs))
        self.log('  our MAC %s   (an ACK to this MAC can only come from a device that heard us)'
                 % macstr(self.src))
        before, csrc = read_tx_counters(self.a.iface)
        e0 = self.echoes
        fired = [0]
        last = {}

        def on_probe(mac, mpdu, inf):
            now = time.time()
            if now - last.get(mac, 0) < self.a.min_gap:
                return
            last[mac] = now
            dst = macbytes(mac)
            for _ in range(self.a.burst):
                fr = sp_parse.build_directed_probe(self.src, dst, seq=self.next_seq())
                if self.send(fr, rate=1.0, noack=False, what='directed probe'):
                    self.sent['directed'] += 1
            fired[0] += 1
            self.log('  -> %d directed probe(s) to %s' % (self.a.burst, mac), 2)

        self.pump(time.time() + secs, on_probe=on_probe)
        after, _ = read_tx_counters(self.a.iface)
        self.log('  reacted to %d console probe(s); sent %d directed frames'
                 % (fired[0], self.sent['directed']))
        self.report_tx(before, after, csrc, self.echoes - e0)
        return [e for e in self.events if e['name'] == 'ACK']

    def phase_engage(self, ch, secs):
        """Rung 1b. Advertise ourselves as a StreetPass peer and wait to be engaged."""
        self.banner('RUNG 1b  ch %d  %.0f s: broadcast StreetPass probe -> expect a response'
                    % (ch, secs))
        self.log('  token %s   services %s'
                 % (self.token.hex(), ['%08x' % s[0] for s in self.services]))
        before, csrc = read_tx_counters(self.a.iface)
        e0 = self.echoes
        deadline = time.time() + secs
        nxt = 0.0
        while time.time() < deadline:
            if time.time() >= nxt:
                fr = sp_parse.build_probe(self.src, self.token, self.services, seq=self.next_seq())
                if self.send(fr, rate=1.0, noack=True, what='broadcast probe'):
                    self.sent['broadcast'] += 1
                nxt = time.time() + self.a.probe_interval
            self.pump(min(deadline, nxt))
        after, _ = read_tx_counters(self.a.iface)
        self.log('  sent %d broadcast StreetPass probes' % self.sent['broadcast'])
        self.report_tx(before, after, csrc, self.echoes - e0)
        return [e for e in self.events if e['name'] in ('ProbeResp', 'Action', 'ProbeReq')]

    def report_tx(self, before, after, csrc, echoes=0):
        d = diff_counters(before, after)
        if not d and echoes:
            self.log('  TX proof: %d of frames echoed back by the driver after sending'
                     % echoes)
            return True
        if not d:
            self.log('  TX counters did not move and no frames came back! The radio')
            self.log('    may not be transmitting at all.')
            self.log('    Treat any negative result below as unproven until this is fixed.')
            return False
        self.log('  TX proof (%s):' % (csrc or 'unknown'))
        for k, v in sorted(d.items(), key=lambda kv: -abs(kv[1]))[:8]:
            self.log('      %-28s +%d' % (k, v))
        comp = [v for k, v in d.items() if 'Completed' in k]
        retr = [v for k, v in d.items() if 'XRetried' in k or 'Retried' in k]
        if comp:
            self.log('      -> hardware completed %d MPDU(s)%s'
                     % (sum(comp), (', %d retried' % sum(retr)) if retr else ''))
        return True

    def verdict(self, acks, engages):
        self.banner('VERDICT')
        self.log('  frames received  : %d   (our own echoes: %d)' % (self.rx_total, self.echoes))
        self.log('  consoles seen    : %d  %s'
                 % (len(self.consoles), ', '.join(sorted(self.consoles)) or '-'))
        self.log('  frames sent      : %d broadcast, %d directed'
                 % (self.sent['broadcast'], self.sent['directed']))
        self.log('')
        if acks:
            self.log('  RUNG 1a PASS: %d ACK(s) addressed to us.' % len(acks))
            self.log('     A console received a frame we transmitted and its MAC layer answered.')
            self.log('     Injection, addressing, channel and rate are all proven good.')
        else:
            self.log('  RUNG 1a no ACK.')
            self.log('     If TX was proven, frames are on the air but no console')
            self.log('     acknowledged.')
        self.log('')
        if engages:
            kinds = sorted({e['name'] for e in engages})
            self.log('  RUNG 1b PASS: a console engaged us (%s)' % ', '.join(kinds))
            for e in engages:
                self.log('      %+8.3fs  %-12s from %s%s'
                         % (e['t'], e['name'], e['from'],
                            ('  DS=ch%d' % e['ds']) if e.get('ds') is not None else ''))
            ds = [e['ds'] for e in engages if e.get('ds') is not None]
            if ds:
                self.log('')
                self.log('     The response names channel %s. That is the link channel, announced'
                         % ds[0])
                self.log('     by the console.')
            self.log('')
            self.log('     A real console treated a frame built')
            self.log('     from our reconstruction as a genuine StreetPass peer advertisement.')
        else:
            self.log('  RUNG 1b no engagement.')
            if acks:
                self.log('     But 1a passed, so the radio path works. The problem is in what')
                self.log('     we send. Try changing the probe fields next')
                self.log('     (--full-services, --mac, token, rate).')
        return 0 if (acks or engages) else 1

    def run(self):
        self.banner('STAGE 1: make a 3DS react to us')
        self.log('  interface %s   channels %s   our MAC %s'
                 % (self.a.iface, self.a.channels, macstr(self.src)))
        self.log('  token %s' % self.token.hex())
        if not self.open_socket():
            return 2
        acks, engages = [], []
        for ch in self.a.channels:
            if not tune(self.a.iface, ch, self.log):
                self.log('  cannot tune ch %d, skipping' % ch)
                continue
            self.log('')
            self.log('### channel %d (%d MHz) confirmed by readback' % (ch, iface_freq(self.a.iface)))
            self.phase_listen(ch, self.a.listen)
            if self.consoles or self.a.force:
                acks += self.phase_ack(ch, self.a.ack_secs)
                engages += self.phase_engage(ch, self.a.engage_secs)
            else:
                self.log('  no console here; not transmitting on this channel')
        return self.verdict(acks, engages)


def selftest():
    ok = tot = 0

    def chk(name, cond, got=''):
        nonlocal ok, tot
        tot += 1
        ok += bool(cond)
        print('  [%s] %s%s' % ('PASS' if cond else 'FAIL', name, ('  %s' % (got,)) if got else ''))

    A = bytes.fromhex('baae6e445566')
    B = bytes.fromhex('9658cb112233')

    want = bytes.fromhex('40003a01baae6e4455669658cb112233baae6e44556660010000010882848b'
                         '0c1296182432043048606c')
    chk('directed probe has the captured byte layout exactly',
        sp_parse.build_directed_probe(B, A, seq=22) == want)
    want_a = bytes.fromhex('d000d500baae6e4455669658cb112233baae6e44556650017f001f320000')
    chk('action frame has the captured byte layout exactly',
        sp_parse.build_action(B, A, seq=21) == want_a)

    tok = bytes.fromhex('0011223344556677')
    p = sp_parse.build_probe(A, tok, SERVICES_MIIPLAZA, seq=7)
    chk('broadcast probe: mgmt/probe-req to broadcast',
        p[0] == 0x40 and p[4:10] == b'\xff' * 6 and p[10:16] == A)
    inf = probe_info(p)
    chk('broadcast probe: SSID round-trips', inf['ssid'] == SP_SSID)
    chk('broadcast probe: token round-trips', inf['token'] == tok.hex(), inf['token'])
    chk('broadcast probe: service round-trips',
        inf['services'] and inf['services'][0]['titleID'] == '00020800', inf['services'])
    chk('broadcast probe is recognised as StreetPass', is_streetpass_probe(p))
    pf = sp_parse.build_probe(A, tok, SERVICES_FULL, seq=7)
    inf2 = probe_info(pf)
    chk('12-service probe round-trips', len(inf2['services'] or []) == 12, len(inf2['services'] or []))

    ack = b'\xd4\x00\x00\x00' + A
    f = parse_mpdu(ack)
    chk('ACK classified as ACK', f and f['name'] == 'ACK', f and f['name'])
    chk('ACK addr1 is the recipient', f and f['addr1'] == macstr(A), f and f['addr1'])
    chk('ACK carries no addr2 (so it cannot be confused with an echo)', f and f['addr2'] is None)
    f2 = parse_mpdu(want)
    chk('directed probe classified', f2 and f2['name'] == 'ProbeReq' and f2['seq'] == 22)
    chk('action frame classified', parse_mpdu(want_a)['name'] == 'Action')

    resp = bytes.fromhex(
        '5000000096 58cb112233 baae6e445566 baae6e445566 0030'.replace(' ', '') +
        'f644000000000000' + '6400' + '0200' +
        '0020' + SP_SSID.hex() +
        '0108' + '82848b0c12961824' +
        '03010b' + '06020000' + '3204' + '3048606c' +
        'dd15' + '001f3201' + '110500020800' + '00f008' + '95a1dce3c74664fc')
    inf3 = probe_info(resp)
    chk('probe response: SSID', inf3 and inf3['ssid'] == SP_SSID)
    chk('probe response: DS param = link channel 11', inf3 and inf3['ds'] == 11, inf3 and inf3['ds'])
    chk('probe response: token', inf3 and inf3['token'] == '95a1dce3c74664fc', inf3 and inf3['token'])

    rt = radiotap_tx(1.0, noack=True)
    chk('radiotap 12 B, rate=2 (1 Mbps), NOACK|NOSEQ set',
        len(rt) == 12 and rt[8] == 2 and struct.unpack_from('<H', rt, 10)[0] == 0x0018, rt.hex())
    rt2 = radiotap_tx(11.0, noack=False)
    chk('radiotap 11 Mbps, ACK expected (NOACK clear)',
        rt2[8] == 22 and (struct.unpack_from('<H', rt2, 10)[0] & 0x0008) == 0, rt2.hex())

    chk('console prefixes cover both LAA and burned-in forms',
        is_console('ba:ae:6e:1:2:3') and is_console('b8:ae:6e:1:2:3')
        and is_console('96:58:cb:1:2:3') and not is_console('00:11:22:33:44:55'))

    class _A:
        mac = token = None
        full_services = False
    r = Runner.__new__(Runner)
    m = r._random_console_mac()
    chk('generated MAC looks like a console', is_console(macstr(m)) and (m[0] & 0x02), macstr(m))
    chk('generated MACs differ between runs',
        len({macstr(Runner._random_console_mac(r)) for _ in range(20)}) > 15)

    chk('counter diff ignores unchanged and missing keys',
        diff_counters({'a': 1, 'b': 5}, {'a': 4, 'b': 5, 'c': 9}) == {'a': 3})

    print('\n%d/%d checks passed' % (ok, tot))
    return 0 if ok == tot else 1


def replay(path, me):
    """Run the detector over a capture, pretending `me` is our MAC."""
    from scapy.all import PcapReader, Dot11
    r = Runner.__new__(Runner)
    r.t0 = time.time()
    r.a = argparse.Namespace(verbose=1)
    r.src = macbytes(me)
    r.events, r.consoles, r.echoes, r.rx_total = [], {}, 0, 0
    print('replaying %s as if our MAC were %s' % (path, me))
    with PcapReader(path) as pr:
        for p in pr:
            if p.getlayer(Dot11) is None:
                continue
            raw = bytes(p)
            n = rt_len(raw)
            if n == 0 or n >= len(raw):
                continue
            mpdu = raw[n:]
            f = parse_mpdu(mpdu)
            if not f:
                continue
            r.rx_total += 1
            if f['addr2'] == me:
                r.echoes += 1
                continue
            if f['addr1'] == me:
                r.record(f, mpdu)
            elif f['type'] == 0 and f['subtype'] == 4 and is_console(f['addr2']) \
                    and is_streetpass_probe(mpdu):
                r.consoles.setdefault(f['addr2'], {'n': 0})['n'] += 1
    print('\n  %d frame(s) addressed to us, %d own echo(es) ignored, %d console(s) seen'
          % (len(r.events), r.echoes, len(r.consoles)))
    print('  kinds: %s' % (sorted({e['name'] for e in r.events}) or '-'))
    return 0 if r.events else 1


def main():
    ap = argparse.ArgumentParser(description='Stage 1: make a 3DS react to us.')
    ap.add_argument('--iface', default='mon0', help='monitor interface (default mon0)')
    ap.add_argument('--channels', default='1,6,11',
                    help='channels to work, in order (default 1,6,11)')
    ap.add_argument('--listen', type=float, default=20.0, help='listen seconds per channel')
    ap.add_argument('--ack-secs', type=float, default=30.0, help='rung 1a seconds per channel')
    ap.add_argument('--engage-secs', type=float, default=45.0, help='rung 1b seconds per channel')
    ap.add_argument('--burst', type=int, default=3, help='directed probes per console probe heard')
    ap.add_argument('--min-gap', type=float, default=0.3,
                    help='seconds between reactions to the same console')
    ap.add_argument('--probe-interval', type=float, default=0.25,
                    help='broadcast probe period in rung 1b')
    ap.add_argument('--mac', help='our source MAC (default: random console-like)')
    ap.add_argument('--token', help='our 8-byte token as hex (default: random)')
    ap.add_argument('--full-services', action='store_true',
                    help='advertise the full 12-title service list instead of Mii Plaza alone')
    ap.add_argument('--force', action='store_true',
                    help='transmit even on channels where no console was heard')
    ap.add_argument('--dry-run', action='store_true', help='build and print frames, transmit nothing')
    ap.add_argument('--verbose', '-v', type=int, default=1, help='0 quiet, 1 normal, 2 loud')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--replay', metavar='PCAP',
                    help='run the detector over a capture instead of a radio (validates RX)')
    ap.add_argument('--replay-mac',
                    help='MAC to impersonate during --replay (the one your radio used '
                         'when the capture was taken)')
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if a.replay:
        return replay(a.replay, a.replay_mac.lower())

    a.channels = [int(c) for c in a.channels.split(',') if c.strip()]
    for c in a.channels:
        if c not in CH_FREQ:
            print('bad channel %s' % c)
            return 2

    if a.dry_run:
        r = Runner.__new__(Runner)
        r.a = a
        r.src = macbytes(a.mac) if a.mac else Runner._random_console_mac(r)
        r.token = bytes.fromhex(a.token) if a.token else bytes(range(8))
        r.services = SERVICES_FULL if a.full_services else SERVICES_MIIPLAZA
        peer = bytes.fromhex('baae6e445566')
        for name, fr in (('broadcast StreetPass probe',
                          sp_parse.build_probe(r.src, r.token, r.services, seq=1)),
                         ('directed probe request',
                          sp_parse.build_directed_probe(r.src, peer, seq=2)),
                         ('action frame',
                          sp_parse.build_action(r.src, peer, seq=3))):
            print('\n%s  (%d bytes, no FCS; the radio appends it)' % (name, len(fr)))
            for o in range(0, len(fr), 16):
                print('   %04x  %-47s |%s|'
                      % (o, ' '.join('%02x' % c for c in fr[o:o + 16]),
                         ''.join(chr(c) if 32 <= c < 127 else '.' for c in fr[o:o + 16])))
        return 0

    return Runner(a).run()


if __name__ == '__main__':
    sys.exit(main())
