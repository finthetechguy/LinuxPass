#!/usr/bin/env python3
"""Stage 2: drive the handshake to an encrypted link and decrypt what the console sends."""
import sys, os, time, socket, struct, select, random, argparse, inspect

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sp_parse, sp_ccmp, sp_yy, sp_yysession
import sp_mii, sp_smdh, sp_cec
import sp_probe_tx as T
from streetpass_ccmp_key import derive_ccmp_key

YY_SNAP = b'\xaa\xaa\x03\x00\x00\x00' + b'\x08\x00' + b'\x00\x00'
WINDOW = 0x38B8                      # 14520, what both consoles advertise
DATA_DURATION = 0x002C               # 44 us -- the value on all 108 captured bulk frames


def build_yy(flags, seq=0, ack=0, window=WINDOW, payload=b''):
    """One YY segment as it appears INSIDE the CCMP payload (LLC/SNAP + 2 pad + 24-byte header)."""
    yy = (struct.pack('<HHHH', 0x5959, 0x30 + len(payload), 0xDEAD, 0xBEAF)
          + struct.pack('<II', seq, ack)
          + bytes([12, flags]) + struct.pack('<H', window) + b'\x00\x00\x00\x00')
    return YY_SNAP + yy + bytes(payload)


def ccmp_header(pn):
    """8-byte CCMP header for packet number `pn`."""
    p = pn.to_bytes(6, 'big')                    # PN5..PN0
    return bytes([p[5], p[4], 0x00, 0x20, p[3], p[2], p[1], p[0]])


def build_encrypted_data(key, src, dst, bssid, pn, plaintext, seq=0, duration=DATA_DURATION):
    """A CCMP-protected 802.11 data frame, ready to inject."""
    hdr = (b'\x08\x40' + struct.pack('<H', duration)
           + bytes(dst) + bytes(src) + bytes(bssid)
           + struct.pack('<H', (seq & 0xFFF) << 4))
    return sp_ccmp.encrypt(key, hdr + ccmp_header(pn), plaintext)


class Pcap:
    def __init__(self, path):
        self.f = open(path, 'wb')
        self.f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 127))
        self.n = 0

    def write(self, raw, t=None):
        t = time.time() if t is None else t
        self.f.write(struct.pack('<IIII', int(t), int((t % 1) * 1e6), len(raw), len(raw)) + raw)
        self.n += 1

    def close(self):
        try:
            self.f.close()
        except OSError:
            pass


class Link:
    IDLE, ENGAGED, REPLIED, LINKBSS, SYNSENT, DONE = range(6)
    STATE_NAME = {0: 'IDLE', 1: 'ENGAGED', 2: 'REPLIED', 3: 'LINKBSS', 4: 'SYNSENT', 5: 'DONE'}

    def __init__(self, a):
        self.a = a
        self.t0 = time.time()
        self.sock = None
        self.pcap = Pcap(a.pcap) if a.pcap else None
        self.src = T.macbytes(a.mac) if a.mac else T.Runner._random_console_mac(self)
        self.token = (bytes.fromhex(a.token) if a.token
                      else bytes(random.getrandbits(8) for _ in range(8)))
        self.services = T.SERVICES_FULL if a.full_services else T.SERVICES_MIIPLAZA
        self.seq = random.randrange(0, 4096)
        self.pn = 1
        self.state = self.IDLE
        self.max_state = self.IDLE
        self.attempts = 0
        self.peer = None
        self.peer_token = None
        self.keys = []              # [(label, key)]
        self.events = []
        self.rx_total = self.echoes = 0
        self.sent = {}
        self.sent_frames = []
        self.decrypted = []
        self.protected_seen = 0
        self.t_engaged = None
        self.pending_poll = None
        self.linkbss_deadline = None
        self.log_lines = []
        self.session = None
        if getattr(a, 'forward', None):
            import sp_build
            paths = a.forward if isinstance(a.forward, list) else [a.forward]
            wires, tids = [], []
            for path in paths:
                w = sp_build.as_wire(open(path, 'rb').read())
                if not getattr(a, 'keep_msgid', False):
                    # cecd discards a message it already has, so a dumped one needs a new id.
                    old_id = w[0x14 + 0x20:0x14 + 0x28].hex()
                    w = sp_build.set_message_id(w)
                    self.log('    fresh message id: %s -> %s (%s)'
                             % (old_id, w[0x14 + 0x20:0x14 + 0x28].hex(), os.path.basename(path)))
                wires.append(w)
                tids.append(sp_build.message_title(w))
            sm = getattr(a, 'send_mode', None)
            self.outbox = sp_build.build_outbox(wires, send_mode=sm)
            # The service flag is per-title. Plaza's 0x00 on another title stalls the exchange.
            known = {t: (f, tr) for t, f, tr in T.SERVICES_FULL}
            uniq = list(dict.fromkeys(tids))
            self.services = [(t,) + known.get(t, (0x30, b'')) for t in uniq]
            self.log('  FORWARD %d message(s) across %d title(s) in one encounter'
                     % (len(wires), len(uniq)))
            if len(uniq) != len(tids):
                self.log('    %s carries more than one message; they travel as ONE object with '
                         'one ee entry whose count field says how many (cecd 0x10BC5C)'
                         % ', '.join('%08X' % t for t in uniq if tids.count(t) > 1))
            for path, w, t in zip(paths, wires, tids):
                flags = known.get(t, (0x30, b''))[0]
                self.log('    %-42s %7d B  title %08X  flags=%#04x  send mode %d%s'
                         % (os.path.basename(path), len(w), t, flags,
                            sp_build.header_send_mode(w) if sm is None else sm,
                            '' if sm is None else ' (--send-mode override)'))
                try:
                    h = sp_cec.parse_header(w[0x14:])
                    self.log('        container total=%#x header=%#x body=%#x' %
                             (h['total_size'], h['header_size'], h['body_size']))
                except Exception as e:
                    self.log('        (container header did not parse: %s)' % e)
            # With several entries the 0x33 must follow the console's order, so mirror its 0x32.
            if len(uniq) > 1 and not a.mirror_offer:
                a.mirror_offer = True
                self.log('    multi-title: --mirror-offer enabled automatically, so our 0x33 is in '
                         "the console's own entry order (cecd 0x1148C0 compares them pairwise)")
        elif getattr(a, 'from_scratch', False):
            import sp_build
            bm, bd_ = 0, 0
            if getattr(a, 'birthday', None):
                bm, bd_ = (int(x) for x in a.birthday.split('/'))
            mii = sp_build.build_cfl(mii_name=a.mii_name or 'Linux',
                                     author_name=a.author_name or 'LinuxPass',
                                     creator_mac=bytes([0xb8, 0xae, 0x6e]) +
                                     bytes(random.getrandbits(8) for _ in range(3)),
                                     birthday_month=bm, birthday_day=bd_,
                                     favourite_colour=int(getattr(a, 'colour', 0) or 0),
                                     gender=int(getattr(a, 'gender', 0) or 0))
            profile = sp_build.build_profile(
                streetpass_hits=int(getattr(a, 'hits', 0) or 0),
                plaza_population=int(getattr(a, 'population', 0) or 0),
                hat=int(getattr(a, 'hat', 0) or 0), pet=int(getattr(a, 'pet', 0) or 0),
                dream=int(getattr(a, 'dream', 0) or 0), hobby=int(getattr(a, 'hobby', 0) or 0))
            tid = int(a.title_id, 0) if getattr(a, 'title_id', None) else 0x0004000012345600
            body = sp_build.build_body(mii, greeting=a.greeting or 'Built from zero',
                                       title_id=tid,
                                       title_short=getattr(a, 'title_name', None) or 'LinuxPass',
                                       title_long='StreetPass from Linux',
                                       title_publisher='LinuxPass', profile=profile,
                                       bubble=int(getattr(a, 'bubble', 0) or 0))
            self.outbox = sp_build.build_outbox(sp_build.build_message(body))
            info = sp_mii.parse_cfl(mii)
            self.log('  FROM SCRATCH: no captured input. 6 objects %s'
                     % ([len(o) for o in self.outbox],))
            self.log('    mii %r author %r id=%08x mac=%s  greeting %r'
                     % (info['mii_name'], info['author_name'], info['mii_id'],
                        info['creator_mac'], a.greeting or 'Built from zero'))
            okv, why = sp_mii.validate_cfl(mii)
            self.log('    title id %016X  %r' % (tid, getattr(a, 'title_name', None) or 'LinuxPass'))
            self.log('    card: hits=%d pop=%d hat=%d pet=%d dream=%d hobby=%d '
                     'birthday=%d/%d colour=%d creator=%r'
                     % (struct.unpack_from('<I', profile, 0)[0],
                        struct.unpack_from('<H', profile, 4)[0], profile[6], profile[7],
                        profile[8], profile[9], bm, bd_,
                        int(getattr(a, 'colour', 0) or 0), a.author_name or 'LinuxPass'))
            self.log('    gates: validate_cfl=%s  region_a=%s'
                     % (okv, sp_smdh.validate_region_a(body)[0]))
            if not okv:
                raise ValueError('built Mii fails the plaza gate: %s' % why)
        else:
            self.outbox = load_objects(a.objects, self.log) if a.objects else []
        if (not getattr(a, 'from_scratch', False)) and self.outbox and len(self.outbox) >= 6 and (
                a.fresh_mii or a.mii_name or a.author_name):
            self.outbox[5] = edit_mii(self.outbox[5], mii_name=a.mii_name,
                                      author_name=a.author_name,
                                      fresh_identity=a.fresh_mii, log=self.log)
        if (not getattr(a, 'from_scratch', False)) and self.outbox and a.greeting and len(self.outbox) >= 6:
            self.outbox[5] = set_greeting(self.outbox[5], a.greeting, self.log)
        if self.outbox and a.full_sequence:
            pre = [build_obj_41(self.src),
                   cec_object(0x43, OBJ_43_PAYLOAD, flags=0x0000),
                   build_obj_11(self.token, self.services)]
            self.log('  FULL SEQUENCE: prepending 0x41 (%d B), 0x43 (%d B), 0x11 (%d B, %d services)'
                     % (len(pre[0]), len(pre[1]), len(pre[2]), len(self.services)))
            self.outbox = pre + self.outbox
        if self.outbox and a.empty_offer:
            i33 = object_index(self.outbox, 0x33)
            if i33 is None:
                self.log('  --empty-offer: no 0x33 object in the outbox, nothing to replace')
            else:
                self.outbox[i33] = empty_offer_object(self.log)
        if self.outbox and (a.fresh_msgid or a.fresh_consoleid):
            self.outbox = freshen_identity(self.outbox, self.log,
                                           msgid=a.fresh_msgid, consoleid=a.fresh_consoleid)
        # hook(link, peer_mac, peer_services) -> (services, outbox) or None.
        self.peer_hook = None
        self.declined = None
        # Liveness signal: if the radio wedges this stops, and the watchdog restarts the service.
        self.tick_hook = None
        self.sightings = {}          # mac -> {'n','first','last','token','rssi'}
        # A console refusing our MAC sends no probe, so this separates refused from absent.
        self.on_air = {}
        self.last_heartbeat = 0.0
        # Hunt while idle, then lock to the console's channel for the handshake.
        self.channels = [int(c) for c in str(a.channel).split(',') if c.strip()]
        self.chan_idx = 0
        self.chan_locked = False
        self.next_hop = 0.0

    def log(self, msg, level=1):
        line = '[%8.3f] %s' % (time.time() - self.t0, msg)
        self.log_lines.append(line)
        if level <= self.a.verbose:
            print(line, flush=True)

    def banner(self, m):
        self.log('')
        self.log('=' * 78)
        self.log('  ' + m)
        self.log('=' * 78)

    def setstate(self, s):
        if s != self.state:
            self.log('  state %s -> %s' % (self.STATE_NAME[self.state], self.STATE_NAME[s]))
            self.state = s
            # Track the furthest state, because the machine returns to IDLE after a failed attempt.
            self.max_state = max(self.max_state, s)
            if s == self.ENGAGED:
                self.attempts += 1

    def open_socket(self):
        t = T.iface_type(self.a.iface)
        if t != 'monitor':
            self.log('FATAL: %s is type %r, not monitor.' % (self.a.iface, t))
            return False
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            s.bind((self.a.iface, 0))
            s.setblocking(False)
        except PermissionError:
            self.log('FATAL: need root. Use ./linuxpass-link')
            return False
        except OSError as e:
            self.log('FATAL: cannot open %s: %s' % (self.a.iface, e))
            return False
        self.sock = s
        return True

    def send(self, mpdu, rate=1.0, noack=True, what=''):
        rt = T.radiotap_tx(rate, noack=noack)
        try:
            self.sock.send(rt + mpdu)
        except (BlockingIOError, OSError) as e:
            self.log('  TX FAILED (%s): %s' % (what, e))
            return False
        self.sent[what] = self.sent.get(what, 0) + 1
        self.sent_frames.append((what, mpdu))
        if mpdu[4:10] != b'\xff' * 6:
            self._last_directed_tx = time.time()
        if self.pcap:
            self.pcap.write(rt + mpdu)
        self.log('  -> %-24s %d B  seq=%d' % (what, len(mpdu), (self.seq & 0xFFF)), 2)
        return True

    def next_seq(self):
        self.seq = (self.seq + 1) & 0xFFF
        return self.seq

    # None means load from the operator's own dump. The self-tests set throwaway values.
    key17 = None                 # cecd's 17-byte HMAC key
    normalkey_2e = None          # keyslot 0x2E's normal key

    def derive_keys(self):
        """Both role orderings. The host-first one is listed first and used for transmission."""
        self.keys = []
        if not (self.peer and self.peer_token):
            return
        me, them = bytes(self.src), bytes(self.peer)
        mine, theirs = self.token, self.peer_token
        kw = {'key17': self.key17, 'keyslot_2e_normalkey': self.normalkey_2e}
        self.keys.append(('host=console (expected)',
                          derive_ccmp_key(theirs, mine, them, me, **kw)))
        self.keys.append(('host=us',
                          derive_ccmp_key(mine, theirs, me, them, **kw)))
        self.log('  derived %d candidate keys:' % len(self.keys))
        for lbl, k in self.keys:
            self.log('      %-24s %s' % (lbl, k.hex()))

    def try_decrypt(self, mpdu):
        for lbl, k in self.keys:
            try:
                return sp_ccmp.decrypt(k, mpdu), lbl, k
            except Exception:
                continue
        return None, None, None

    def on_probe_response(self, f, mpdu, inf):
        """The console engaged us. Reply with the action frame, then the directed probe."""
        if self.state >= self.LINKBSS:
            return
        self.peer = T.macbytes(f['addr2'])
        self.peer_token = bytes.fromhex(inf['token']) if inf.get('token') else None
        self.t_engaged = time.time()
        self.log('  *** CONSOLE ENGAGED US: %s' % f['addr2'])
        self.log('      token %s   DS=ch%s   %d services'
                 % (inf.get('token'), inf.get('ds'), len(inf.get('services') or [])))
        # The broadcast probe declares everything held. From here, narrow to what this console has.
        if self.peer_hook is not None:
            try:
                picked = self.peer_hook(self, f['addr2'], inf.get('services') or [])
                if picked:
                    self.services, self.outbox = picked
                    self.log('      serving %d title(s), %d object(s) to this peer'
                             % (len(self.services), len(self.outbox)))
                    self.log_our_lists()
            except Exception as e:
                self.log('      peer hook failed (%s: %s) -- serving the default outbox'
                         % (type(e).__name__, e))
        self.setstate(self.ENGAGED)
        self.derive_keys()
        for _ in range(2):
            self.send(sp_parse.build_action(self.src, self.peer, seq=self.next_seq()),
                      rate=11.0, noack=False, what='action cat-0x7f')
        self.pending_poll = time.time() + self.a.poll_delay
        self.setstate(self.REPLIED)

    def on_link_bss(self, f, mpdu, inf):
        """Handle the second probe response, which has PRIVACY set."""
        if self.state < self.ENGAGED or not self.peer:
            return
        if f['addr2'] != T.macstr(self.peer):
            self.log('  ignoring PRIVACY probe response from %s (not our console)'
                     % f['addr2'], 2)
            return
        if self.state >= self.SYNSENT:
            return
        self.log('  *** LINK BSS ANNOUNCED by %s  (capability PRIVACY set)' % f['addr2'])
        self.setstate(self.LINKBSS)
        self.send_syn()

    EE_CODE = {0: 'no decision', 1: 'ACCEPTED', 2: 'REFUSED', 3: 'sent',
               4: 'received', 6: 'refused at store'}

    def log_our_lists(self):
        """Decode OUR OWN outgoing 0x31/0x33/0x81 the same way we decode the peer's 0x32/0x34."""
        for o in self.outbox:
            if len(o) < 0x10 or o[0:2] != b'cc':
                continue
            otype = struct.unpack_from('<I', o, 4)[0]
            if otype == 0x81:
                body = o[0x10:]
                n = struct.unpack_from('<I', body, 0)[0] if len(body) >= 4 else 0
                ents = [struct.unpack_from('<II', body, 4 + i * 8)
                        for i in range(min(n, max(0, (len(body) - 4) // 8)))]
                self.log('  OUR object 0x81 (what we will actually send): %d entry(s) %s'
                         % (n, ['%08X:%d' % (t, sz) for t, sz in ents]))
                continue
            if otype not in (0x31, 0x33):
                continue
            ee = o[0x10:]
            if len(ee) < 0x2C or ee[0:2] != b'ee':
                continue
            count = struct.unpack_from('<I', ee, 8)[0]
            for i in range(min(count, (len(ee) - 0x2C) // 0x20)):
                e = ee[0x2C + i * 0x20:]
                tid, mode, hflags, code, size = (struct.unpack_from('<I', e, 0)[0], e[4], e[5],
                                                 struct.unpack_from('<H', e, 6)[0],
                                                 struct.unpack_from('<I', e, 8)[0])
                self.log('  OUR object 0x%02X entry %d: title %08X send_mode=%d flags=%d '
                         'size=%#x  code=%d (%s)'
                         % (otype, i, tid, mode, hflags, size, code,
                            self.EE_CODE.get(code, '?')))

    def on_object_received(self, idx, obj, sess):
        """Decode the console's list objects, mirroring its 0x32 if asked."""
        if len(obj) < 0x10 or obj[0:2] != b'cc':
            return
        otype = struct.unpack_from('<I', obj, 4)[0]
        ee = obj[0x10:]
        if otype in (0x32, 0x34) and len(ee) >= 0x2C and ee[0:2] == b'ee':
            count = struct.unpack_from('<I', ee, 8)[0]
            whose = 'its own offer' if otype == 0x32 else 'ITS VERDICT on our list'
            for i in range(min(count, (len(ee) - 0x2C) // 0x20)):
                e = ee[0x2C + i * 0x20:]
                tid, mode, hflags, code, size = (struct.unpack_from('<I', e, 0)[0], e[4], e[5],
                                                 struct.unpack_from('<H', e, 6)[0],
                                                 struct.unpack_from('<I', e, 8)[0])
                self.log('  object 0x%02X (%s) entry %d: title %08X send_mode=%d flags=%d '
                         'size=%#x  code=%d (%s)'
                         % (otype, whose, i, tid, mode, hflags, size, code,
                            self.EE_CODE.get(code, '?')))
                if otype == 0x34 and code == 2:
                    self.log('  *** the console REFUSED title %08X. The usual cause is a send-mode '
                             'mismatch: our ee entry +0x04 must equal the message header +0x35 '
                             '(cecd 0x1094F8 / 0x1031D0).' % tid)
        if otype == 0x32 and len(ee) >= 0x2C and ee[0:2] == b'ee':
            offered = [struct.unpack_from('<I', ee, 0x2C + i * 0x20)[0]
                       for i in range(min(struct.unpack_from('<I', ee, 8)[0],
                                          (len(ee) - 0x2C) // 0x20))]
            ours = [t for t, _f, _tr in self.services]
            if sorted(offered) != sorted(ours):
                self.log('  *** OFFER MISMATCH: the console offers %s, we declared %s. cecd '
                         '0x1148C0 requires equal counts and pairwise-equal titles, so this '
                         'exchange will fail. A title it has not enabled, or has no message '
                         'queued for, never appears in its offer.'
                         % (['%08X' % t for t in offered], ['%08X' % t for t in ours]))
        if not self.a.mirror_offer or otype != 0x32:
            return
        i33 = object_index(sess.outbox, 0x33)
        if i33 is None:
            self.log('  cannot align our 0x33: no 0x33 object in the outbox')
            return
        new = reorder_offer_object(sess.outbox[i33], obj[0x10:], self.log)
        if new:
            sess.outbox[i33] = new
            ee = new[0x10:]
            if len(ee) >= 0x2C and ee[0:2] == b'ee':
                cnt = struct.unpack_from('<I', ee, 8)[0]
                for i in range(min(cnt, (len(ee) - 0x2C) // 0x20)):
                    e = ee[0x2C + i * 0x20:]
                    tid, mode, hf, code, size = (struct.unpack_from('<I', e, 0)[0], e[4], e[5],
                                                 struct.unpack_from('<H', e, 6)[0],
                                                 struct.unpack_from('<I', e, 8)[0])
                    self.log('  OUR object 0x33 AS SENT entry %d: title %08X send_mode=%d '
                             'flags=%d size=%#x  code=%d (%s)'
                             % (i, tid, mode, hf, size, code, self.EE_CODE.get(code, '?')))

    def send_yy(self, flags, seq, ack, payload=b''):
        """Encrypt one YY segment and put it on the air. The Stage 3 session's only outlet."""
        if not self.keys:
            return False
        _lbl, key = self.keys[0]
        pt = sp_yysession.build_yy_frame(flags, seq, ack, payload)
        mpdu = build_encrypted_data(key, self.src, self.peer, self.peer, self.pn, pt,
                                    seq=self.next_seq())
        # 11 Mbps saves most of the airtime and keeps CCK link margin.
        ok = self.send(mpdu, rate=self.a.yy_rate, noack=False,
                       what='YY %s' % sp_yy.flagstr(flags).replace('|', '+'))
        self.pn += 1
        return ok

    def send_syn(self):
        if not self.keys:
            self.log('  cannot send SYN: no key (never saw the console token)')
            return
        lbl, _key = self.keys[0]
        self.log('  opening the YY exchange  PN=%d  key[%s]  bssid=%s'
                 % (self.pn, lbl, T.macstr(self.peer)))
        if self.outbox:
            self.session = sp_yysession.YYSession(self.send_yy, self.log, self.outbox,
                                                  on_received=self.on_object_received)
            n = int(getattr(self.a, 'manifest_repeat', 0) or 0)
            if n > 0:
                # By type, never by index, because other modes move it.
                rt = int(getattr(self.a, 'repeat_type', '0x81'), 0)
                i81 = object_index(self.outbox, 0x81)
                islot = object_index(self.outbox, rt)
                obj = None
                if islot is not None:
                    obj = self.outbox[islot]
                elif rt == 0xF2:
                    # cecd answers 0xF2 before reading its state, so it can nudge a silent console.
                    obj = cec_object(0xF2, b'\x00' * 4)
                    islot = -1
                if i81 is None or obj is None:
                    self.log('  --manifest-repeat: no 0x%02X/0x81 in the outbox, nothing to repeat'
                             % rt)
                else:
                    self.session.repeat_slot = i81
                    self.session.repeat_obj = obj
                    self.session.repeat_max = n
                    self.log('  --manifest-repeat %d: sending %s after our 0x81 (object %d)'
                             % (n, ('a synthesised 0xF2 SCAN probe, %d B' % len(obj))
                                if islot < 0 else 'our 0x%02X (object %d)' % (rt, islot), i81))
            self.session.start_send()
        else:
            self.send_yy(sp_yy.SYN, 0, 0)
        self.setstate(self.SYNSENT)

    def on_protected(self, f, mpdu):
        self.protected_seen += 1
        pt, lbl, key = self.try_decrypt(mpdu)
        if pt is None:
            self.log('  protected data from %s -- MIC FAILED under both keys (%d B)'
                     % (f['addr2'], len(mpdu)))
            self.events.append({'t': time.time() - self.t0, 'kind': 'protected-undecryptable',
                                'from': f['addr2'], 'len': len(mpdu)})
            return
        self.log('')
        self.log('  ############################################################')
        self.log('  ###  DECRYPTED A FRAME FROM THE CONSOLE                  ###')
        self.log('  ############################################################')
        self.log('      key      : %s  [%s]' % (key.hex(), lbl))
        self.log('      PN       : %d' % sp_ccmp.pn_of(mpdu))
        self.log('      plaintext: %s' % pt.hex())
        y = sp_yy.parse(pt)
        if y:
            self.log('      YY       : %s' % sp_yy.describe(y))
        self.decrypted.append((pt, lbl))
        self.events.append({'t': time.time() - self.t0, 'kind': 'decrypted',
                            'from': f['addr2'], 'yy': sp_yy.describe(y) if y else None})
        if self.session and y:
            self.session.on_frame(y)
            if self.session.done:
                self.setstate(self.DONE)
        else:
            self.setstate(self.DONE)

    def detect_channel(self, secs=2.0):
        """The channel the radio is really on, from the radiotap of received frames."""
        from collections import Counter
        c, end = Counter(), time.time() + secs
        while time.time() < end:
            if not select.select([self.sock], [], [], 0.2)[0]:
                continue
            try:
                b = self.sock.recv(4096)
            except (BlockingIOError, OSError):
                continue
            f = rt_channel_freq(b)
            if f:
                c[f] += 1
        if not c:
            return None
        freq = c.most_common(1)[0][0]
        for ch, fq in T.CH_FREQ.items():
            if fq == freq:
                return ch
        return None

    def note_on_air(self, mac):
        """A console-OUI frame that is not a StreetPass probe request."""
        now = time.time()
        c = self.on_air.setdefault(mac, {'n': 0, 'first': now})
        c['n'] += 1
        c['last'] = now

    def note_sighting(self, f, mpdu, raw):
        mac = f['addr2']
        c = self.sightings.setdefault(mac, {'n': 0, 'first': time.time(), 'token': None,
                                            'rssi': None})
        c['n'] += 1
        c['last'] = time.time()
        inf = T.probe_info(mpdu)
        if inf and inf.get('token'):
            if c['token'] and c['token'] != inf['token']:
                self.log('  console %s rotated token %s -> %s'
                         % (mac, c['token'], inf['token']))
            c['token'] = inf['token']
        if c['n'] == 1:
            self.log('  console PRESENT: %s  token=%s  %d service(s)'
                     % (mac, inf.get('token') if inf else None,
                        len(inf.get('services') or []) if inf else 0))
            if not self.chan_locked:
                self.chan_locked = True
                self.log('  LOCKED to channel %d (the console is here now)'
                         % self.channels[self.chan_idx])
        if self.a.reactive and self.state == self.IDLE:
            if time.time() - getattr(self, '_last_react', 0) >= self.a.min_gap:
                self._last_react = time.time()
                self.send(sp_parse.build_directed_probe(self.src, T.macbytes(mac),
                                                        seq=self.next_seq()),
                          rate=1.0, noack=False, what='directed probe (reactive)')
                self.send(sp_parse.build_probe(self.src, self.token, self.services,
                                               seq=self.next_seq()),
                          rate=1.0, noack=True, what='broadcast probe (reactive)')

    def heartbeat(self):
        """Periodic 'still nothing' line, so a long silent run is legible while it happens."""
        now = time.time()
        if now - self.last_heartbeat < self.a.heartbeat:
            return
        self.last_heartbeat = now
        if self.sightings:
            tot = sum(c['n'] for c in self.sightings.values())
            age = min(now - c['last'] for c in self.sightings.values())
            self.log('  ... state=%s  consoles=%d  probes heard=%d  last %.1fs ago'
                     % (self.STATE_NAME[self.state], len(self.sightings), tot, age))
        elif self.on_air:
            macs = sorted(self.on_air, key=lambda m: -self.on_air[m]['n'])[:2]
            self.log('  ... state=%s  no console probes (%.0fs), but %d frame(s) from %s -- '
                     'something IS on air and not engaging us'
                     % (self.STATE_NAME[self.state], now - self.t0,
                        sum(c['n'] for c in self.on_air.values()), ', '.join(macs)))
        else:
            self.log('  ... state=%s  NO console probes heard yet (%.0fs)'
                     % (self.STATE_NAME[self.state], now - self.t0))

    def pump(self, until):
        while time.time() < until:
            if self.state == self.REPLIED and self.pending_poll \
                    and time.time() >= self.pending_poll:
                self.pending_poll = None
                for _ in range(self.a.poll_burst):
                    self.send(sp_parse.build_directed_probe(self.src, self.peer,
                                                            seq=self.next_seq()),
                              rate=1.0, noack=False, what='directed probe')
                self.linkbss_deadline = time.time() + self.a.linkbss_wait
            if self.state == self.REPLIED and self.linkbss_deadline \
                    and time.time() >= self.linkbss_deadline:
                self.linkbss_deadline = None
                self.log('  no link-BSS probe response within %.0f ms -- sending SYN anyway'
                         % (self.a.linkbss_wait * 1000))
                self.send_syn()

            self.heartbeat()
            if self.session:
                self.session.poll(self.a.yy_idle)
                # The session can finish inside poll(), with no incoming frame to set DONE.
                if self.session.done and self.state != self.DONE:
                    self.setstate(self.DONE)
            if (not self.chan_locked and self.state == self.IDLE and len(self.channels) > 1
                    and time.time() >= self.next_hop):
                self.chan_idx = (self.chan_idx + 1) % len(self.channels)
                ch = self.channels[self.chan_idx]
                if T.tune(self.a.iface, ch, lambda m, l=2: self.log(m, l)):
                    self.log('  hunting on channel %d' % ch, 2)
                else:
                    # An active monitor interface ignores later channel changes.
                    self.chan_locked = True
                    self.channels = [self.channels[0]]
                    self.chan_idx = 0
                    self.log('  CHANNEL LOCKED to %d: this vif cannot be retuned, so the rest of '
                             'the channel list is ignored. Not a fault -- every engagement this '
                             'project has recorded came in on the channel we were already '
                             'sitting on, because the console is the one that sweeps.'
                             % self.channels[0])
                self.next_hop = time.time() + self.a.dwell
            r, _, _ = select.select([self.sock], [], [], 0.02)
            if not r:
                continue
            try:
                buf = self.sock.recv(4096)
            except (BlockingIOError, OSError):
                continue
            n = T.rt_len(buf)
            if n == 0 or n >= len(buf):
                continue
            mpdu = strip_fcs_radiotap(buf, buf[n:])
            self.rx_total += 1
            f = T.parse_mpdu(mpdu)
            if not f:
                continue
            me = T.macstr(self.src)
            if f['addr2'] == me:
                self.echoes += 1
                continue
            # Identify consoles by SSID, because a MAC prefix list is only a guess.
            is_sp_probe = (f['type'] == 0 and f['subtype'] == 4 and T.is_streetpass_probe(mpdu))
            is_console_frame = is_sp_probe or T.is_console(f['addr2'])
            if is_sp_probe:
                self.note_sighting(f, mpdu, buf)
            elif is_console_frame:
                self.note_on_air(f['addr2'])
            interesting = ((f['addr1'] == me) or is_console_frame
                           or (self.peer and f['addr2'] == T.macstr(self.peer)))
            if self.pcap and (interesting or self.a.pcap_all):
                self.pcap.write(buf)
            if not interesting:
                continue
            if f['type'] == 2 and len(mpdu) > 1 and (mpdu[1] & 0x40):
                self.on_protected(f, mpdu)
                continue
            if f['type'] == 0 and f['subtype'] == 5:
                inf = T.probe_info(mpdu)
                cap = struct.unpack_from('<H', mpdu, 34)[0] if len(mpdu) >= 36 else 0
                if inf and inf.get('token'):
                    self.on_probe_response(f, mpdu, inf)
                elif (cap & 0x10) and self.peer and f['addr2'] == T.macstr(self.peer):
                    self.on_link_bss(f, mpdu, inf)    # PRIVACY -> the encrypted link BSS
                else:
                    self.log('  probe response from %s (cap=0x%04x, no token) -- ignoring'
                             % (f['addr2'], cap), 2)
                continue
            if f['type'] == 1 and f['subtype'] == 13:
                # A repeater can ACK our frames, so only ACKs above the broadcast baseline count.
                dt = time.time() - getattr(self, '_last_directed_tx', 0)
                if dt < 0.001:
                    self.acks_directed = getattr(self, 'acks_directed', 0) + 1
                else:
                    self.acks_baseline = getattr(self, 'acks_baseline', 0) + 1
                self.log('  ACK addressed to us (%s)'
                         % ('after a directed frame' if dt < 0.001 else 'baseline/ambient'), 2)
                continue
            self.log('  %s from %s -> %s' % (f['name'], f['addr2'], f['addr1']), 2)

    def run(self):
        self.banner('STAGE 2  --  complete the handshake and decrypt the console')
        self.log('  interface %s  channels %s  our MAC %s'
                 % (self.a.iface, self.channels, T.macstr(self.src)))
        self.log('  our token %s   services %s'
                 % (self.token.hex(), ['%08x' % s[0] for s in self.services]))
        if self.a.pcap:
            self.log('  writing %s' % self.a.pcap)
        if not self.open_socket():
            return 2
        T.tune(self.a.iface, self.channels[0], self.log)
        # Read the channel from radiotap, because iw cannot report it for an active monitor.
        actual = self.detect_channel(2.0)
        if actual is None:
            self.log('WARNING: no frames received, cannot confirm the channel. Continuing blind.')
        else:
            if actual != self.channels[0]:
                self.log('NOTE: asked for channel %d but the radio is on channel %d.'
                         % (self.channels[0], actual))
                self.log('      An active monitor vif cannot be retuned; working on %d instead.'
                         % actual)
                self.channels = [actual]
                self.chan_locked = True
            self.log('  channel %d (%d MHz) CONFIRMED by measuring received frames'
                     % (actual, T.CH_FREQ[actual]))
        self.next_hop = time.time() + self.a.dwell
        before, csrc = T.read_tx_counters(self.a.iface)

        deadline = time.time() + self.a.secs
        nxt = 0.0
        while time.time() < deadline and self.state != self.DONE:
            if self.tick_hook is not None:
                self.tick_hook(self)
            if self.state in (self.IDLE,) and time.time() >= nxt:
                self.send(sp_parse.build_probe(self.src, self.token, self.services,
                                               seq=self.next_seq()),
                          rate=1.0, noack=True, what='broadcast probe')
                nxt = time.time() + self.a.probe_interval
            self.pump(min(deadline, nxt if self.state == self.IDLE else time.time() + 0.2))
            if self.state != self.IDLE and not self.t_engaged:
                self.log('  in state %s with no engagement in flight -- resetting to IDLE'
                         % self.STATE_NAME[self.state])
                self.setstate(self.IDLE)
            if self.session and (time.time() - self.session.last_activity) < 3.0:
                self.t_engaged = time.time()      # transfer in progress: do not time it out
            if self.state in (self.REPLIED, self.LINKBSS, self.SYNSENT) and self.t_engaged \
                    and time.time() - self.t_engaged > self.a.attempt_timeout:
                self.log('  attempt timed out after %.1f s in state %s -- re-advertising'
                         % (self.a.attempt_timeout, self.STATE_NAME[self.state]))
                self.setstate(self.IDLE)
                self.t_engaged = None
                self.pending_poll = None
                self.linkbss_deadline = None
                self.pn = 1
                nxt = 0.0
        after, _ = T.read_tx_counters(self.a.iface)
        return self.verdict(before, after, csrc)

    def verdict(self, before, after, csrc):
        self.banner('VERDICT')
        self.log('  furthest state reached : %s   (%d engagement attempt(s))'
                 % (self.STATE_NAME[self.max_state], self.attempts))
        if self.declined:
            self.log('  we offered nothing     : %s  -- this pass ended by OUR choice, not the '
                     "console's" % self.declined)
        # `sightings` counts probe requests, which consoles may never send, so NONE proves nothing.
        if self.sightings:
            for m, c in sorted(self.sightings.items(), key=lambda kv: -kv[1]['n']):
                self.log('  console probes heard   : %s  %d probes  token=%s  over %.0fs'
                         % (m, c['n'], c['token'], c['last'] - c['first']))
        else:
            self.log('  console probes heard   : NONE  (normal: these consoles answer our probe '
                     'rather than sending their own -- this is not evidence of absence)')
        if self.on_air:
            for m, c in sorted(self.on_air.items(), key=lambda kv: -kv[1]['n']):
                self.log('  console OUI on air     : %s  %d frame(s) over %.0fs'
                         % (m, c['n'], c['last'] - c['first']))
        else:
            self.log('  console OUI on air     : NONE')
        self.log('  frames received        : %d  (our echoes %d)' % (self.rx_total, self.echoes))
        self.log('  frames sent            : %s' % (self.sent or '-'))
        self.log('  protected frames seen  : %d' % self.protected_seen)
        if self.session:
            st = self.session.stats
            self.log('  YY exchange            : %d/%d objects sent, %d received'
                     % (st['sent_objects'], len(self.outbox), st['recv_objects']))
            self.log('     frames  tx=%d rx=%d' % (st['tx_frames'], st['rx_frames']))
            if st.get('manifest_repeats'):
                self.log('     MANIFEST REPEATS: %d; the peer %s'
                         % (st['manifest_repeats'],
                            'ANSWERED after them -- its send thread was asleep'
                            if self.session.repeat_worked else 'still never answered'))
            if st.get('gaps') or st.get('short_holds'):
                self.log('     LOSS: %d gap(s) in peer data, %d object(s) held back rather than '
                         'completed short'
                         % (st.get('gaps', 0), st.get('short_holds', 0)))
            for n, o in enumerate(self.session.received):
                tag = ''
                if len(o) > 0x14 and o[0x14:0x16] == b'\x60\x60':
                    try:
                        h = sp_cec_header(o[0x14:])
                        tag = '  title=0x%08X body=0x%X' % (h[0], h[1])
                    except Exception:
                        pass
                self.log('     <== object %d: %d B%s' % (n, len(o), tag))
        self.log('  ACKs to our MAC        : %d after a directed frame, %d ambient baseline'
                 % (getattr(self, 'acks_directed', 0), getattr(self, 'acks_baseline', 0)))
        if getattr(self, 'acks_baseline', 0):
            self.log('     (a non-zero baseline means this channel has a repeater echoing us --')
            self.log('      ACK alone is not proof of console contact here)')
        if self.peer:
            self.log('  console                : %s  token=%s'
                     % (T.macstr(self.peer), self.peer_token.hex() if self.peer_token else '-'))
        d = T.diff_counters(before, after)
        if d:
            self.log('  TX proof (%s): %s' % (csrc, {k: v for k, v in list(d.items())[:6]}))
        else:
            self.log('  TX COUNTERS DID NOT MOVE -- treat negatives as unproven.')
        self.log('')
        if self.decrypted:
            self.log('  *** STAGE 2 PASS ***')
            self.log('  We decrypted %d frame(s) the console encrypted to us, with a key derived'
                     % len(self.decrypted))
            self.log('  independently from the two session tokens and the two MACs.')
            for pt, lbl in self.decrypted:
                y = sp_yy.parse(pt)
                self.log('      [%s] %s' % (lbl, sp_yy.describe(y) if y else pt.hex()))
            rc = 0
        else:
            self.log('  Stage 2 did not complete. Where it stopped tells you what to fix:')
            st = self.max_state
            if st >= self.SYNSENT:
                self.log('    -> We completed the whole sequence %d time(s): the console engaged,'
                         % self.attempts)
                self.log('       we replied, and we transmitted an encrypted YY SYN. Nothing came')
                self.log('       back. Our directed frames were mostly NOT acknowledged, so the')
                self.log('       console had stopped listening by then -- consistent with it')
                self.log('       abandoning the attempt because WE never ACKed its probe response.')
                self.log('       An ACK must come from silicon. Next step: IBSS mode.')
            elif not self.sightings and not self.on_air:
                self.log('    -> NOTHING FROM A CONSOLE ON THIS CHANNEL, by either test. Two')
                self.log('       readings and this pass cannot separate them: (a) no console was')
                self.log('       transmitting -- check it is awake with StreetPass active and')
                self.log('       charged; or (b) a console IS there and its MacFilter is refusing')
                self.log('       this source MAC, in which case it answers nothing and looks')
                self.log('       identical. If this MAC has already completed an exchange with')
                self.log('       that console, (b) is the one to bet on: rotate the identity or')
                self.log('       clear the filter. See the wiki page The MAC filter.')
            elif not self.sightings and self.on_air:
                self.log('    -> A CONSOLE OUI WAS ON AIR but never engaged us (see above). It was')
                self.log('       transmitting, so this is not an absence: either it is not in')
                self.log('       StreetPass at all, or its MacFilter is refusing this source MAC.')
                self.log('       Rotate the identity to tell those apart.')
            elif st == self.IDLE:
                self.log('    -> The console WAS present and heard (see above) but never engaged us.')
                self.log('       That is a probe-content question, not a radio one: try')
                self.log('       --full-services, or a different --mac / --token.')
            self.log('    IDLE    - console never engaged.')
            self.log('    ENGAGED - it engaged but our action frame did not advance it.')
            self.log('    REPLIED - action+directed probe sent, no link-BSS response. The console')
            self.log('              may be waiting for a hardware ACK we cannot give in monitor')
            self.log('              mode -- that is the point where IBSS mode becomes necessary.')
            self.log('    SYNSENT - our SYN went out and nothing came back, OR something came back')
            self.log('              that failed the MIC. If protected frames were seen but not')
            self.log('              decrypted, the KEY or its ordering is wrong, not the sequence.')
            rc = 1
        if self.protected_seen and not self.decrypted:
            self.log('')
            self.log('  NOTE: %d protected frame(s) arrived and NONE decrypted. That isolates the'
                     % self.protected_seen)
            self.log('  failure to the key derivation -- the handshake itself clearly worked.')
        if self.pcap:
            self.pcap.close()
            self.log('')
            self.log('  wrote %s (%d frames) for offline analysis' % (self.a.pcap, self.pcap.n))
        if self.a.log:
            with open(self.a.log, 'w') as fh:
                fh.write('\n'.join(self.log_lines) + '\n')
            print('wrote %s' % self.a.log)
        return rc


def sp_cec_header(buf):
    """(cec_title_id, body_size) from a CEC container, for one-line reporting."""
    return struct.unpack_from('<I', buf, 0x10)[0], struct.unpack_from('<I', buf, 0x0C)[0]


def freshen_identity(objs, log, msgid=True, consoleid=True):
    """Make a replayed exchange look like a NEW console sending a NEW message."""
    out = list(objs)
    if consoleid and out and len(out[0]) >= 24:
        o = bytearray(out[0])
        old = bytes(o[16:24])
        o[16:24] = bytes(random.getrandbits(8) for _ in range(8))
        out[0] = bytes(o)
        log('  fresh console id : %s -> %s' % (old.hex(), out[0][16:24].hex()))
    if msgid and len(out) >= 6 and len(out[5]) > 0x3C:
        o = bytearray(out[5])
        old = bytes(o[0x34:0x3C])
        o[0x34:0x3C] = bytes(random.getrandbits(8) for _ in range(8))
        out[5] = bytes(o)
        log('  fresh message id : %s -> %s' % (old.hex(), out[5][0x34:0x3C].hex()))
    return out


# A constant capability blob, identical from both sides in captures.
OBJ_43_PAYLOAD = bytes.fromhex('1b0010001a800f00ffffffff84541200')


def cec_object(otype, payload, flags=0xFFFF):
    """Wrap a payload in the 0x6363 object header (builder at cecd 0x1076BA)."""
    return (b'\x63\x63' + struct.pack('<H', flags) + struct.pack('<I', otype)
            + struct.pack('<I', 0) + struct.pack('<I', len(payload)) + bytes(payload))


def cec_timestamp(t=None):
    """The 12-byte CEC timestamp: u32 year, u8 month/day/weekday/hour/min/sec, u16 millisecond."""
    import time as _t
    lt = _t.localtime(t if t is not None else _t.time())
    ms = int((_t.time() % 1) * 1000)
    return (struct.pack('<I', lt.tm_year) +
            bytes([lt.tm_mon, lt.tm_mday, (lt.tm_wday + 1) % 7, lt.tm_hour, lt.tm_min, lt.tm_sec])
            + struct.pack('<H', ms))


def build_obj_41(mac, log=None):
    """Session-open object. Carries a nonce, the sender's MAC and a timestamp (payload 0x28)."""
    payload = (bytes(random.getrandbits(8) for _ in range(8))
               + b'\x00' * 8
               + bytes(random.getrandbits(8) for _ in range(4))
               + bytes(mac) + b'\x00\x00'
               + cec_timestamp())
    assert len(payload) == 0x28, len(payload)
    return cec_object(0x41, payload, flags=0x0000)


def build_obj_11(token8, services):
    """Declare our enabled titles INSIDE the link."""
    svc = b''.join(struct.pack('>I', t) + bytes([f]) + bytes(tr) for t, f, tr in services)
    tlv = struct.pack('<H', (len(svc) << 8) | (1 << 4) | 1) + svc
    tlv += struct.pack('<H', (8 << 8) | (0xF << 4) | 0) + bytes(token8)
    return cec_object(0x11, tlv, flags=0xFFFF)


def plaza_hmac_key():
    """Mii Plaza's message HMAC key, from your console's CEC store via linuxpass.keys."""
    import lp_keys
    return lp_keys.plaza_hmac_key()

GREETING_OFF = 0x3F70
GREETING_LEN = 0x22            # UTF-16LE, 16 chars + NUL


MII_OFF = 0x36BC


def edit_mii(obj5, mii_name=None, author_name=None, fresh_identity=False, log=None):
    """Edit the sender's Mii, correctly."""
    import sp_mii
    b = bytearray(obj5)
    hs = struct.unpack_from('<I', b, 0x14 + 0x08)[0]
    bs = struct.unpack_from('<I', b, 0x14 + 0x0C)[0]
    body = bytes(b[0x14 + hs: 0x14 + hs + bs])
    if body[MII_OFF:MII_OFF + 4] not in (b'CFPB', b'CFPN'):
        raise ValueError('no CFPB container at body+0x%X' % MII_OFF)
    cfl, mac_ok = sp_mii.read_plaza_mii(body)
    before = sp_mii.parse_cfl(cfl)
    if log:
        log('  MII unwrapped: name=%r author=%r id=%08x mac=%s  (ccm_mac_ok=%s crc_ok=%s)'
            % (before['mii_name'], before['author_name'], before['mii_id'],
               before['creator_mac'], mac_ok, before['crc_ok']))
    if not mac_ok:
        raise ValueError('CFPB CCM MAC failed on the source message -- refusing to edit')
    if fresh_identity:
        # Keep a real Nintendo OUI, because a Mii's creator MAC is never locally administered.
        cfl = sp_mii.set_identity(cfl, mii_id=sp_mii.random_mii_id(),
                                  creator_mac=bytes([0xb8, 0xae, 0x6e]) +
                                  bytes(random.getrandbits(8) for _ in range(3)))
    if mii_name is not None:
        cfl = sp_mii.set_mii_name(cfl, mii_name)
    if author_name is not None:
        cfl = sp_mii.set_author_name(cfl, author_name)
    after = sp_mii.parse_cfl(cfl)
    if log:
        log('  MII edited   : name=%r author=%r id=%08x mac=%s  (crc %#06x, recomputed)'
            % (after['mii_name'], after['author_name'], after['mii_id'],
               after['creator_mac'], after['crc']))
    ok, why = sp_mii.validate_cfl(cfl)
    if not ok:
        raise ValueError('edited Mii would be rejected by the plaza: ' + '; '.join(why))
    if log:
        log('  MII passes the plaza gate (CRC, identity non-zero, id byte bit5 clear)')
    newbody = sp_mii.write_plaza_mii(body, cfl)
    chk, chk_ok = sp_mii.read_plaza_mii(newbody)
    if not chk_ok or chk != cfl:
        raise ValueError('re-wrapped Mii does not verify -- refusing to transmit')
    if log:
        log('  MII re-wrapped and verified (CCM MAC + CRC both valid)')
    b[0x14 + hs: 0x14 + hs + bs] = newbody
    return reseal(bytes(b), log)


def fresh_mii(obj5, log=None):
    """Back-compat shim: a new Mii identity, done correctly."""
    return edit_mii(obj5, fresh_identity=True, log=log)


def reseal(obj5, log=None):
    """Recompute the container's 32-byte trailer = HMAC-SHA256(plaza key, body)."""
    import hmac as _hmac, hashlib as _hashlib
    b = bytearray(obj5)
    hs = struct.unpack_from('<I', b, 0x14 + 0x08)[0]
    bs = struct.unpack_from('<I', b, 0x14 + 0x0C)[0]
    tot = struct.unpack_from('<I', b, 0x14 + 0x04)[0]
    body = bytes(b[0x14 + hs: 0x14 + hs + bs])
    tag_off = 0x14 + hs + bs
    if tot - (hs + bs) != 0x20:
        raise ValueError('unexpected trailer size %d' % (tot - (hs + bs)))
    old = bytes(b[tag_off:tag_off + 0x20])
    new = _hmac.new(plaza_hmac_key(), body, _hashlib.sha256).digest()
    b[tag_off:tag_off + 0x20] = new
    if log:
        log('  RESEALED trailer: %s -> %s' % (old.hex()[:24] + '..', new.hex()[:24] + '..'))
    return bytes(b)


def set_greeting(obj5, text, log):
    """Rewrite the Mii Plaza greeting inside the container, in place."""
    enc = text.encode('utf-16-le')
    if len(enc) > GREETING_LEN - 2:
        raise ValueError('greeting too long: %d UTF-16 bytes, max %d'
                         % (len(enc), GREETING_LEN - 2))
    enc = enc + b'\x00' * (GREETING_LEN - len(enc))
    b = bytearray(obj5)
    hs = struct.unpack_from('<I', b, 0x14 + 0x08)[0]
    off = 0x14 + hs + GREETING_OFF
    old = bytes(b[off:off + GREETING_LEN])
    b[off:off + GREETING_LEN] = enc
    b = bytearray(reseal(bytes(b), log))
    def _dec(x):
        t = x.decode('utf-16-le', 'replace')
        return t.split('\x00')[0]
    log('  GREETING patched at file offset 0x%X: %r -> %r' % (off, _dec(old), _dec(enc)))
    log('    (length unchanged: %d B field, and the trailer was resealed over the new body)'
        % GREETING_LEN)
    return bytes(b)


def object_index(outbox, otype):
    """Index of the first object of type `otype` in `outbox`, or None."""
    for i, o in enumerate(outbox):
        if len(o) >= 8 and o[0:2] == b'cc' and struct.unpack_from('<I', o, 4)[0] == otype:
            return i
    return None


def reorder_offer_object(our_33, console_ee, log):
    """Our own 0x33, with its entries put into the console's order."""
    if len(our_33) < 0x10 + 0x2C or len(console_ee) < 0x2C or console_ee[0:2] != b'ee':
        return None
    ours = bytearray(our_33[0x10:])
    if ours[0:2] != b'ee':
        return None
    n_theirs = struct.unpack_from('<I', console_ee, 8)[0]
    n_ours = struct.unpack_from('<I', ours, 8)[0]
    theirs = [struct.unpack_from('<I', console_ee, 0x2C + i * 0x20)[0]
              for i in range(min(n_theirs, (len(console_ee) - 0x2C) // 0x20))]
    mine = {struct.unpack_from('<I', ours, 0x2C + i * 0x20)[0]:
            bytes(ours[0x2C + i * 0x20:0x2C + (i + 1) * 0x20])
            for i in range(min(n_ours, (len(ours) - 0x2C) // 0x20))}
    if sorted(mine) != sorted(theirs):
        log('  offer sets differ (ours %s, theirs %s) -- mirroring its list verbatim, which is the '
            'only form that can satisfy the count check at cecd 0x1148C0'
            % (['%08X' % t for t in sorted(mine)], ['%08X' % t for t in sorted(theirs)]))
        return mirror_offer_object(console_ee, log)
    rec = bytearray(ours[:0x2C]) + b''.join(mine[t] for t in theirs)
    struct.pack_into('<II', rec, 4, len(rec), len(theirs))
    obj = (b'\x63\x63\xff\xff' + struct.pack('<I', 0x33) + struct.pack('<I', 0)
           + struct.pack('<I', len(rec)) + bytes(rec))
    log('  0x33 REORDERED into the console\'s entry order: %s (%d B)'
        % (['%08X' % t for t in theirs], len(obj)))
    return obj


def mirror_offer_object(ee_src, log):
    """Build our type-0x33 by mirroring the list the console just offered in its 0x32."""
    ee = bytearray(ee_src)
    if len(ee) < 0x2C or ee[0:2] != b'\x65\x65':
        log('  cannot mirror: source is not an ee record')
        return None
    count = struct.unpack_from('<I', ee, 8)[0]
    for i in range(count):
        off = 0x2C + i * 32 + 6
        if off < len(ee):
            ee[off] = 0x01                      # the 0x31 -> 0x33 phase flag
    obj = (b'\x63\x63\xff\xff' + struct.pack('<I', 0x33) + struct.pack('<I', 0)
           + struct.pack('<I', len(ee)) + bytes(ee))
    titles = [struct.unpack_from('<I', ee, 0x2C + i * 32)[0] for i in range(count)]
    log('  MIRRORED 0x33 from the console offer: count=%d titles=%s (%d B)'
        % (count, ['%08X' % t for t in titles], len(obj)))
    return obj


def empty_offer_object(log):
    """A type-0x33 object whose `ee` list is empty (count 0)."""
    ee = b'\x65\x65\x00\x00' + struct.pack('<I', 0x2C) + b'\x00' * 0x24
    obj = (b'\x63\x63\xff\xff' + struct.pack('<I', 0x33) + struct.pack('<I', 0)
           + struct.pack('<I', len(ee)) + ee)
    log('  EMPTY-OFFER 0x33 (%d B, ee len 0x2C, count 0): %s' % (len(obj), obj[:20].hex()))
    return obj


def load_objects(prefix, log):
    """Load the CEC objects to send, in order, from <prefix>0.bin onward."""
    import glob as _glob
    objs = []
    i = 0
    while True:
        cands = _glob.glob('%s%d.bin' % (prefix, i))
        if not cands:
            break
        objs.append(open(cands[0], 'rb').read())
        i += 1
    if not objs:
        log('  WARNING: no objects found matching %s*.bin -- nothing to send' % prefix)
        return []
    log('  outbox: %d object(s) from %s*  sizes %s'
        % (len(objs), prefix, [len(o) for o in objs]))
    return objs


def rt_channel_freq(raw):
    """Radiotap Channel frequency in MHz, or None."""
    if len(raw) < 12:
        return None
    fields = struct.unpack_from('<I', raw, 4)[0]
    off, chain = 8, fields
    while chain & (1 << 31):
        if off + 4 > len(raw):
            return None
        chain = struct.unpack_from('<I', raw, off)[0]
        off += 4
    if fields & (1 << 0):
        off = (off + 7) & ~7
        off += 8
    if fields & (1 << 1):
        off += 1
    if fields & (1 << 2):
        off += 1
    if fields & (1 << 3):
        off = (off + 1) & ~1
        if off + 2 <= len(raw):
            return struct.unpack_from('<H', raw, off)[0]
    return None


def strip_fcs_radiotap(raw, mpdu):
    """Drop the trailing FCS if radiotap's Flags field says the radio appended one."""
    if len(raw) < 8:
        return mpdu
    fields = struct.unpack_from('<I', raw, 4)[0]
    if not (fields & (1 << 1)):                         # no Flags field -> cannot tell
        return mpdu
    off, chain = 8, fields
    while chain & (1 << 31):                            # skip extended present words
        if off + 4 > len(raw):
            return mpdu
        chain = struct.unpack_from('<I', raw, off)[0]
        off += 4
    if fields & (1 << 0):
        off = (off + 7) & ~7
        off += 8
    if off < len(raw) and (raw[off] & 0x10) and len(mpdu) > 4:
        return mpdu[:-4]
    return mpdu



class _FakeSock:
    """Feeds queued RX frames to select()/recv() and records everything sent."""

    def __init__(self, script):
        self.script = list(script)          # [(delay_s, radiotap+mpdu bytes)]
        self.sent = []
        self.t0 = time.time()

    def fileno(self):
        return 0

    def send(self, b):
        self.sent.append(b)
        return len(b)

    def recv(self, n):
        if not self.script:
            raise BlockingIOError()
        delay, frame = self.script[0]
        if time.time() - self.t0 < delay:
            raise BlockingIOError()
        self.script.pop(0)
        return frame

    def ready(self):
        return bool(self.script) and (time.time() - self.t0) >= self.script[0][0]

    def close(self):
        pass


def _rt(mpdu):
    """Radiotap with Flags present and the FCS bit CLEAR, plus a 4-byte fake FCS omitted."""
    return struct.pack('<BBHIBB', 0, 0, 10, (1 << 1) | (1 << 2), 0x00, 2) + mpdu


def simulate(verbose=1, peer_hook=None, out=None):
    """-> 0 if the state machine completes the handshake and decrypts the console's SYN|ACK."""
    import lp_corpus as corpus
    V = corpus.vector('handshake') or {}
    CON = V.get('console_mac') or '96:58:cb:11:22:33'
    CON_TOK = V.get('console_token') or '0011223344556677'
    US = V.get('our_mac') or 'ba:ae:6e:44:55:66'
    US_TOK = V.get('our_token') or '8899aabbccddeeff'
    # Seventeen bytes: cecd's key length is 0x11 and the trailing NUL counts.
    SIM_KEY17 = b'LinuxPassSelfTest'
    SIM_NORMALKEY = bytes(range(16))
    use_real_keys = bool(V.get('synack'))

    a = argparse.Namespace(
        iface='sim', channel=11, secs=8.0, probe_interval=0.25, poll_delay=0.05, poll_burst=2,
        linkbss_wait=0.15, attempt_timeout=6.0, mac=US, token=US_TOK, full_services=False,
        pcap=None, pcap_all=False, log=None, verbose=verbose, reactive=False, min_gap=0.5,
        heartbeat=1e9, objects=None, dwell=6.0, yy_idle=0.4, yy_rate=11.0,
        fresh_msgid=False, fresh_consoleid=False, empty_offer=False, mirror_offer=False, full_sequence=False, greeting=None, fresh_mii=False, mii_name=None, author_name=None, from_scratch=False, forward=None, keep_msgid=False, title_id=None, title_name=None, hits=0, population=0, hat=0, pet=0, dream=0, hobby=0, birthday=None, colour=0, gender=0, bubble=0)
    L = Link(a)
    if not use_real_keys:
        L.key17, L.normalkey_2e = SIM_KEY17, SIM_NORMALKEY
    L.peer_hook = peer_hook
    if out is not None:
        out['link'] = L

    resp = bytes.fromhex(
        '5000' '0000' + US.replace(':', '') + CON.replace(':', '') + CON.replace(':', '') + '0030'
        + 'f644000000000000' + '6400' + '0200'
        + '0020' + T.SP_SSID.hex()
        + '0108' + '82848b0c12961824'
        + '03010b' + '06020000' + '3204' + '3048606c'
        + 'dd15' + '001f3201' + '110500020800' + '00f008' + CON_TOK)
    link = bytes.fromhex(
        '5000' '0000' + US.replace(':', '') + CON.replace(':', '') + CON.replace(':', '') + '0040'
        + '186f000000000000' + '6400' + '1200'
        + '0000' + '0108' + '82848b0c12961824' + '03010b' + '06020000' + '3204' + '3048606c')
    expect_key = derive_ccmp_key(
        bytes.fromhex(CON_TOK), bytes.fromhex(US_TOK), T.macbytes(CON), T.macbytes(US),
        key17=None if use_real_keys else SIM_KEY17,
        keyslot_2e_normalkey=None if use_real_keys else SIM_NORMALKEY)
    if use_real_keys:
        synack = bytes.fromhex(V['synack'])
    else:
        synack = build_encrypted_data(expect_key, T.macbytes(CON), T.macbytes(US),
                                      T.macbytes(CON), 1, build_yy(0x12), seq=95)

    FOREIGN = '00:00:5e:00:53:01'
    foreign = bytes.fromhex(
        '5000' '0000' + US.replace(':', '') + FOREIGN.replace(':', '')
        + FOREIGN.replace(':', '') + '0020'
        + '1111111111111111' + '6400' + '1100'
        + '0004' + '54657374' + '0108' + '82848b0c12961824' + '030106')
    L.sock = _FakeSock([(0.05, _rt(foreign)), (0.20, _rt(resp)),
                        (0.60, _rt(link)), (0.90, _rt(synack))])
    real_select = select.select
    select.select = lambda r, w, x, t=0: ((r if r and r[0].ready() else []), [], [])
    try:
        L.pump(time.time() + 3.0)
    finally:
        select.select = real_select

    ok = tot = 0

    def chk(n, c, g=''):
        nonlocal ok, tot
        tot += 1
        ok += bool(c)
        print('  [%s] %s%s' % ('PASS' if c else 'FAIL', n, ('  %s' % (g,)) if g else ''))

    if peer_hook is None:
        chk('reached DONE', L.state == Link.DONE, Link.STATE_NAME[L.state])
    else:
        chk('handshake completed with a payload queued (the script cannot ACK it)',
            L.max_state >= Link.SYNSENT and L.decrypted, Link.STATE_NAME[L.max_state])
    chk('a foreign AP PRIVACY probe response did NOT hijack the state machine',
        L.peer == T.macbytes(CON))
    chk('identified the console', L.peer == T.macbytes(CON))
    chk('captured the console token', L.peer_token and L.peer_token.hex() == CON_TOK)
    chk('derived the MIC-verified key first',
        L.keys and L.keys[0][1] == expect_key, L.keys[0][1].hex() if L.keys else '-')
    chk('decrypted the console frame', len(L.decrypted) == 1)
    if L.decrypted:
        y = sp_yy.parse(L.decrypted[0][0])
        chk('plaintext is a YY SYN|ACK', y and y['flags'] == (sp_yy.SYN | sp_yy.ACK),
            sp_yy.flagstr(y['flags']) if y else '-')
    chk('sent 2 action frames', L.sent.get('action cat-0x7f') == 2, L.sent.get('action cat-0x7f'))
    chk('sent the directed probe', L.sent.get('directed probe', 0) >= 1, L.sent.get('directed probe'))
    chk('sent exactly one encrypted SYN', L.sent.get('YY SYN') == 1, L.sent.get('YY SYN'))

    syn = [m for w, m in L.sent_frames if w == 'YY SYN']
    chk('our transmitted SYN is exactly one frame', len(syn) == 1)
    if syn and L.keys:
        try:
            pt = sp_ccmp.decrypt(L.keys[0][1], syn[0])
            y = sp_yy.parse(pt)
            chk('our SYN decrypts under the shared key', pt == build_yy(sp_yy.SYN), pt.hex())
            chk('our SYN parses as a YY SYN', y and y['ok'] and y['flags'] == sp_yy.SYN,
                sp_yy.flagstr(y['flags']) if y else '-')
        except Exception as e:
            chk('our SYN decrypts under the shared key', False, repr(e))
        chk('our SYN uses PN=1', sp_ccmp.pn_of(syn[0]) == 1, sp_ccmp.pn_of(syn[0]))
        chk('our SYN addresses the console and uses its BSSID',
            syn[0][4:10] == T.macbytes(CON) and syn[0][16:22] == T.macbytes(CON))
    print('\n  %d/%d simulation checks passed' % (ok, tot))
    return 0 if ok == tot else 1


def replay(paths, mac=None):
    """Decode captures with the Stage 2 decoder: find the handshake, derive keys, decrypt."""
    from scapy.all import PcapReader, Dot11
    frames = []
    for path in paths:
        with PcapReader(path) as pr:
            for i, p in enumerate(pr):
                d = p.getlayer(Dot11)
                if d is None:
                    continue
                raw = bytes(p)
                n = T.rt_len(raw)
                if n == 0 or n >= len(raw):
                    continue
                frames.append((os.path.basename(path) + '#%d' % i, float(p.time),
                               strip_fcs_radiotap(raw, raw[n:])))
    toks = {}
    for i, t, m in frames:
        f = T.parse_mpdu(m)
        if not f or f['type'] != 0 or f['subtype'] not in (4, 5):
            continue
        inf = T.probe_info(m)
        if inf and inf.get('token') and f['addr2']:
            toks.setdefault(f['addr2'], inf['token'])
    print('tokens found:')
    for k, v in toks.items():
        print('   %s  %s' % (k, v))
    prot = [(i, t, m) for i, t, m in frames
            if T.parse_mpdu(m) and T.parse_mpdu(m)['type'] == 2 and len(m) > 1 and (m[1] & 0x40)]
    print('%d protected data frames' % len(prot))
    macs = list(toks)
    ok = 0
    for i, t, m in prot:
        f = T.parse_mpdu(m)
        got = None
        for h in macs:
            for c in macs:
                if h == c:
                    continue
                try:
                    key = derive_ccmp_key(bytes.fromhex(toks[h]), bytes.fromhex(toks[c]),
                                          T.macbytes(h), T.macbytes(c))
                    pt = sp_ccmp.decrypt(key, m)
                except Exception:
                    continue
                got = (pt, h, c, key)
                break
            if got:
                break
        if got:
            ok += 1
            pt, h, c, key = got
            y = sp_yy.parse(pt)
            print('  %s %s -> %s  host=%s  %s'
                  % (i, f['addr2'], f['addr1'], h, sp_yy.describe(y) if y else pt.hex()))
    print('decrypted %d/%d' % (ok, len(prot)))
    return 0 if ok else 1


def selftest():
    import lp_corpus as corpus
    ok = tot = skipped = 0

    def chk(n, c, g=''):
        nonlocal ok, tot
        tot += 1
        ok += bool(c)
        print('  [%s] %s%s' % ('PASS' if c else 'FAIL', n, ('  %s' % (g,)) if g else ''))

    def skip(n, why):
        nonlocal skipped
        skipped += 1
        print('  [SKIP] %s  (%s)' % (n, why))

    want = bytes.fromhex('aaaa030000000800000059593000addeafbe00000000000000000c12b83800000000')
    chk('build_yy(SYN|ACK) == decrypted spectral_attempt1 #73', build_yy(0x12) == want)
    syn = build_yy(sp_yy.SYN)
    chk('build_yy(SYN) differs only in the flags byte',
        sum(a != b for a, b in zip(syn, want)) == 1 and syn[27] == 0x02)
    y = sp_yy.parse(build_yy(sp_yy.SYN))
    chk('our SYN parses back', y and y['ok'] and y['flags'] == sp_yy.SYN and y['length'] == 0x30)
    chk('our SYN advertises the observed window', y['window'] == WINDOW, y['window'])

    chk('ccmp_header(1) matches capture', ccmp_header(1).hex() == '0100002000000000')
    chk('ccmp_header(2) matches capture', ccmp_header(2).hex() == '0200002000000000')

    V = corpus.vector('handshake') or {}
    if V.get('synack'):
        key = derive_ccmp_key(bytes.fromhex(V['console_token']), bytes.fromhex(V['our_token']),
                              T.macbytes(V['console_mac']), T.macbytes(V['our_mac']))
        mpdu = bytes.fromhex(V['synack'])
        _bargs = (key, T.macbytes(V['console_mac']), T.macbytes(V['our_mac']),
                  T.macbytes(V['console_mac']), 1)
        _bseq = V.get('synack_seq', 95)
        built = build_encrypted_data(*_bargs, build_yy(0x12), seq=_bseq)
        chk('build_encrypted_data reproduces the captured console frame byte-for-byte',
            built == mpdu)
    else:
        skip('build_encrypted_data reproduces the captured console frame byte-for-byte',
             corpus.why_skipped())
        key = bytes(range(16))
        _bargs = (key, T.macbytes('96:58:cb:11:22:33'), T.macbytes('ba:ae:6e:44:55:66'),
                  T.macbytes('96:58:cb:11:22:33'), 1)
        _bseq = 95
        built = build_encrypted_data(*_bargs, build_yy(0x12), seq=_bseq)
    chk('pn_of reads our own frame back', sp_ccmp.pn_of(built) == 1, sp_ccmp.pn_of(built))
    chk('our frame decrypts to the YY SYN|ACK', sp_ccmp.decrypt(key, built) == want)

    th = bytes.fromhex('0011223344556677'); tc = bytes.fromhex('8899aabbccddeeff')
    mh = T.macbytes('96:58:cb:11:22:33'); mc = T.macbytes('ba:ae:6e:44:55:66')
    kw = {'key17': b'LinuxPassSelfTest', 'keyslot_2e_normalkey': bytes(range(16))}
    chk('client-first ordering gives a DIFFERENT key (so the order matters)',
        derive_ccmp_key(tc, th, mc, mh, **kw) != derive_ccmp_key(th, tc, mh, mc, **kw))
    if V.get('synack'):
        chk('host-first ordering reproduces the MIC-verified key',
            derive_ccmp_key(bytes.fromhex(V['console_token']), bytes.fromhex(V['our_token']),
                            T.macbytes(V['console_mac']), T.macbytes(V['our_mac'])) == key)
    else:
        skip('host-first ordering reproduces the MIC-verified key', corpus.why_skipped())

    rt_fcs = struct.pack('<BBHIBB', 0, 0, 10, (1 << 1) | (1 << 2), 0x10, 2)
    chk('FCS stripped when radiotap Flags says so',
        strip_fcs_radiotap(rt_fcs + b'A' * 20, b'A' * 20) == b'A' * 16)
    rt_nofcs = struct.pack('<BBHIBB', 0, 0, 10, (1 << 1) | (1 << 2), 0x00, 2)
    chk('FCS kept when the flag is clear',
        strip_fcs_radiotap(rt_nofcs + b'A' * 20, b'A' * 20) == b'A' * 20)
    rt_ath = (struct.pack('<BBHII', 0, 0, 36, 0xa000402f, 0x00000000)
              + struct.pack('<I', 0) + b'\x00' * 8 + bytes([0x10]))
    chk('ath9k-shaped radiotap (chained present words) still finds the FCS flag',
        strip_fcs_radiotap(rt_ath + b'A' * 20, b'A' * 20) == b'A' * 16)

    sp_ccmp.HAVE_PYCRYPTO = False
    chk('pure-stdlib backend builds the identical frame',
        build_encrypted_data(*_bargs, build_yy(0x12), seq=_bseq) == built)
    sp_ccmp.HAVE_PYCRYPTO = hasattr(sp_ccmp, 'AES') and sp_ccmp.AES is not None

    class _L(Link):
        def __init__(self, yy_rate=11.0):
            self.a = argparse.Namespace(verbose=0, iface='sim', yy_rate=yy_rate)
            self.t0 = time.time(); self.log_lines = []; self.pcap = None
            self.src = T.macbytes('ba:ae:6e:01:02:03')
            self.peer = T.macbytes('96:58:cb:0a:0b:0c')
            self.keys = [('t', bytes(range(16)))]
            self.seq = 0; self.pn = 1; self.sent = {}; self.sent_frames = []
            self.sock = None
        def send(self, mpdu, rate=1.0, noack=True, what=''):
            self.sent_frames.append((what, mpdu, rate)); return True
    L2 = _L()
    payload = bytes(range(256)) * 4
    L2.send_yy(sp_yy.ACK, 1452, 0, payload)
    what, mpdu, _r = L2.sent_frames[-1]
    chk('Stage 3 frame is CCMP-protected data to the console',
        mpdu[0] == 0x08 and (mpdu[1] & 0x40) and mpdu[4:10] == L2.peer)
    pt = sp_ccmp.decrypt(L2.keys[0][1], mpdu)
    y = sp_yy.parse(pt)
    chk('it decrypts back to the exact YY segment we asked for',
        y and y['ok'] and y['seq'] == 1452 and y['payload'] == payload, y and y['payload_len'])
    chk('PN advanced after sending', L2.pn == 2, L2.pn)
    L2.send_yy(sp_yy.ACK, 2476, 0, b'z')
    chk('consecutive frames use consecutive PNs',
        sp_ccmp.pn_of(L2.sent_frames[-1][1]) == 2, sp_ccmp.pn_of(L2.sent_frames[-1][1]))

    chk('YY payload frames go out at the configured rate',
        all(r == 11.0 for _w, _m, r in L2.sent_frames), {r for _w, _m, r in L2.sent_frames})
    L3 = _L(yy_rate=1.0)
    L3.send_yy(sp_yy.ACK, 0, 0, b'x' * 1452)
    chk('and 1 Mbps is still selectable for the A/B', L3.sent_frames[-1][2] == 1.0,
        L3.sent_frames[-1][2])
    seg = 24 + 8 + 10 + 24 + 1452 + 8
    us = lambda mbps: seg * 8 / mbps + 192
    chk('the airtime claim behind the change is arithmetic, not hope',
        round(us(1.0) / 1000, 1) == 12.4 and round(us(11.0) / 1000, 1) == 1.3,
        (round(us(1.0) / 1000, 1), round(us(11.0) / 1000, 1)))

    obj = corpus.load('plaza_message')
    if obj is None:
        skip('the real 32,732 B message segments and rejoins intact', corpus.why_skipped())
        skip('every segment survives a build/parse round trip', corpus.why_skipped())
    else:
        segs = sp_yysession.segment(obj)
        chk('the real 32,732 B message segments and rejoins intact',
            b''.join(p for _f, _s, p in segs) == obj and len(segs) == 23, len(segs))
        rebuilt = bytearray()
        for fl, sq, pl in segs:
            yy = sp_yy.parse(sp_yysession.build_yy_frame(fl, sq, 0, pl))
            assert yy and yy['ok']
            rebuilt += yy['payload']
        chk('every segment survives a build/parse round trip', bytes(rebuilt) == obj)

    import sp_build
    pmsg = corpus.load('plaza_outbox')
    mmsg = corpus.load('second_title_outbox')
    if pmsg is None or mmsg is None:
        skip('two-title offer alignment (needs two real outbox messages)', corpus.why_skipped())
    else:
        ob = [build_obj_41(b'\xba\xae\x6e\x01\x02\x03'),
              cec_object(0x43, OBJ_43_PAYLOAD, flags=0x0000),
              build_obj_11(b'\x01' * 8, [(0x00020800, 0x00, b''), (0x00030600, 0x30, b'')])] \
             + sp_build.build_outbox([pmsg, mmsg], console_id=1)
        chk('object_index finds the 0x33 past the --full-sequence prefix',
            object_index(ob, 0x33) == 6, object_index(ob, 0x33))
        chk('index 3 is the 0x21, which is what the old hardcode clobbered',
            struct.unpack_from('<I', ob[3], 4)[0] == 0x21)
        chk('object_index returns None for a type that is not there',
            object_index(ob, 0x77) is None)
        theirs_ee = (b'ee\x00\x00' + struct.pack('<II', 0x6C, 2) + b'\x00' * 0x20
                     + struct.pack('<IIII', 0x00030600, 0x00303, 0x377C, 1) + b'\x00' * 0x10
                     + struct.pack('<IIII', 0x00020800, 0x00300, 0x7FC8, 1) + b'\x00' * 0x10)
        i33 = object_index(ob, 0x33)
        before = [struct.unpack_from('<I', ob[i33][0x10:], 0x2C + i * 0x20)[0] for i in range(2)]
        chk('our 0x33 starts in OUR order', before == [0x00020800, 0x00030600])
        fixed = reorder_offer_object(ob[i33], theirs_ee, lambda m, l=1: None)
        fee = fixed[0x10:]
        after = [struct.unpack_from('<I', fee, 0x2C + i * 0x20)[0] for i in range(2)]
        chk("reorder puts it in the CONSOLE's order, which cecd 0x1148C0 compares pairwise",
            after == [0x00030600, 0x00020800], ['%08X' % t for t in after])
        chk('reorder keeps OUR send modes with their titles',
            fee[0x2C + 4] == 3 and fee[0x2C + 0x20 + 4] == 0)
        chk('reorder sets phase 1 on every entry',
            struct.unpack_from('<H', fee, 0x2C + 6)[0] == 1 and
            struct.unpack_from('<H', fee, 0x2C + 0x20 + 6)[0] == 1)
        chk('the reordered record declares its own size and count',
            struct.unpack_from('<II', fee, 4) == (0x6C, 2) and len(fee) == 0x6C)
        chk('a differing title set falls back to a straight mirror',
            reorder_offer_object(ob[i33],
                                 b'ee\x00\x00' + struct.pack('<II', 0x4C, 1) + b'\x00' * 0x20
                                 + struct.pack('<IIII', 0x00141000, 0x00303, 0x100, 1)
                                 + b'\x00' * 0x10, lambda m, l=1: None) is not None)
    f2 = cec_object(0xF2, b'\x00' * 4)
    chk('the 0xF2 probe is a well-formed 0x6363 wrapper',
        f2[0:2] == b'cc' and struct.unpack_from('<I', f2, 4)[0] == 0xF2, f2.hex())
    chk('its body length passes cecd 0x107404 (0 < len <= 0x5DC)',
        0 < struct.unpack_from('<I', f2, 0x0C)[0] <= 0x5DC,
        struct.unpack_from('<I', f2, 0x0C)[0])
    chk('and the whole object is small enough to be one segment', len(f2) <= 1452, len(f2))

    class _L:
        def __init__(self):
            self.lines = []
            self.sightings = {}
            self.on_air = {}
        log = lambda self, m: self.lines.append(m)
        note_on_air = Link.note_on_air

    L = _L()
    L.note_on_air('96:58:cb:aa:bb:cc')
    L.note_on_air('96:58:cb:aa:bb:cc')
    chk('note_on_air counts repeat frames from one console',
        L.on_air['96:58:cb:aa:bb:cc']['n'] == 2)
    chk('note_on_air records a window', 'first' in L.on_air['96:58:cb:aa:bb:cc']
        and 'last' in L.on_air['96:58:cb:aa:bb:cc'])
    chk('note_on_air does not touch sightings', L.sightings == {})
    chk('is_console accepts both console OUIs and rejects an AP',
        T.is_console('96:58:cb:aa:bb:cc') and T.is_console('ba:ae:6e:dd:ee:ff')
        and not T.is_console('00:00:5e:00:53:02'))
    src = inspect.getsource(Link.verdict)
    chk('the verdict no longer claims absence from probe requests alone',
        'NO CONSOLE WAS TRANSMITTING AT ALL' not in src)
    chk('the absent branch requires BOTH counters to be empty',
        'not self.sightings and not self.on_air' in src)
    chk('there is a branch for on-air-but-never-engaged',
        'not self.sightings and self.on_air' in src)
    chk('the NONE probes line says it is not evidence of absence',
        'not evidence of absence' in src)
    hb = inspect.getsource(Link.heartbeat)
    chk('the live heartbeat reports on-air frames when there are no probes',
        'self.on_air' in hb and 'not engaging us' in hb)
    rx = inspect.getsource(Link.pump)
    chk('the receive loop feeds note_on_air only for non-probe console frames',
        'elif is_console_frame:' in rx and 'self.note_on_air(' in rx)

    print('\n%d/%d checks passed%s' % (ok, tot,
          '' if not skipped else ', %d skipped (no test corpus)' % skipped))
    return 0 if ok == tot else 1


def build_parser():
    """The full option set, shared so other tools can build a Link's arguments."""
    ap = argparse.ArgumentParser(description='Stage 2: complete the link, decrypt the console.')
    ap.add_argument('--iface', default='mon0')
    ap.add_argument('--channel', default='1,6,11',
                    help='channel, or a list to hunt across while idle (default 1,6,11)')
    ap.add_argument('--dwell', type=float, default=6.0,
                    help='seconds per channel while hunting')
    ap.add_argument('--secs', type=float, default=180.0)
    ap.add_argument('--probe-interval', type=float, default=0.25)
    ap.add_argument('--poll-delay', type=float, default=0.144,
                    help='seconds from the action frame to the directed probe (observed 0.144)')
    ap.add_argument('--poll-burst', type=int, default=6,
                    help='directed probes to send (the console sent 6)')
    ap.add_argument('--linkbss-wait', type=float, default=0.30,
                    help='seconds to wait for the link-BSS probe response before sending SYN anyway')
    ap.add_argument('--attempt-timeout', type=float, default=6.0)
    ap.add_argument('--reactive', action='store_true', default=True,
                    help='answer a console probe immediately (default on)')
    ap.add_argument('--no-reactive', dest='reactive', action='store_false')
    ap.add_argument('--min-gap', type=float, default=0.5,
                    help='minimum seconds between reactive bursts to one console')
    ap.add_argument('--manifest-repeat', type=int, default=1, metavar='N',
                    help='when the console answers our 0x81 with nothing, send --repeat-type at '
                         'it, up to N times. ON BY DEFAULT with --repeat-type 0xf2: that is the '
                         'silent-send recovery. About a third of exchanges negotiate fully and '
                         'then never open a connection, delivering nothing in either direction, '
                         'and a synthesised 0xF2 makes cecd rescan and re-engage -- measured '
                         '20/20 recoveries against 0/15 unprobed. Pass 0 to '
                         'disable.')
    ap.add_argument('--repeat-type', default='0xf2', metavar='HEX',
                    help='what --manifest-repeat sends (default 0xf2, a synthesised SCAN probe: '
                         'cecd tests for type 0xF2 at 0x107424 BEFORE it reads the exchange '
                         'state at 0x10742A, so it is the one stimulus a parked console cannot '
                         'route away, and it answers by rescanning). Set it '
                         'to a negotiation type such as 0x33 to PROBE the console state: cecd '
                         'routes an incoming object by its exchange state, so a 0x33 is answered '
                         'with a 0x34 only while the console is still in 0x20 NEGOTIATION, and a '
                         '0x81 is looked at only in 0x31 SEND_RECV_INIT')
    ap.add_argument('--yy-idle', type=float, default=0.4,
                    help='seconds to wait for the peer to open a connection before we continue')
    ap.add_argument('--yy-rate', type=float, default=11.0, metavar='MBPS',
                    help='802.11b rate for the encrypted YY payload frames (default 11, which is '
                         'what two real consoles use to each other). 1 has more link margin but '
                         'costs 12.4 ms per segment instead of 1.3 ms; pass 1 to A/B it.')
    ap.add_argument('--heartbeat', type=float, default=15.0,
                    help='seconds between progress lines')
    ap.add_argument('--mac')
    ap.add_argument('--token')
    ap.add_argument('--full-services', action='store_true')
    ap.add_argument('--send-mode', type=int, default=None,
                    help='override the ee list send mode (entry +0x04) instead of taking it from '
                         "the forwarded message's header +0x35. For the A/B test only: 0 is what "
                         'the pipeline used to hardcode and is correct ONLY for Mii Plaza.')
    ap.add_argument('--fresh-mii', action='store_true',
                    help='give the message a new Mii id + creator MAC (body +0x36D4) and reseal')
    ap.add_argument('--forward', metavar='FILE', nargs='+',
                    help='send CEC messages dumped from any title OutBox, verbatim. The CEC title '
                         'is taken from each message itself, so this works for titles we have never '
                         'reverse-engineered -- a dumped message already has a valid HMAC. Give '
                         'more than one file to hand them all over in ONE encounter, which is what '
                         'a real console does; the console must have every one of those titles '
                         'enabled with a message queued, or its offer will not match ours.')
    ap.add_argument('--keep-msgid', action='store_true',
                    help='do NOT rewrite the forwarded message id. Default is to rewrite it, '
                         'because a harvested message is one the target console already has and '
                         'cecd silently discards duplicates.')
    ap.add_argument('--from-scratch', action='store_true',
                    help='build the entire outbox with sp_build -- no captured objects at all')
    ap.add_argument('--hits', type=int, metavar='N', help='card: StreetPass hits (0..999999)')
    ap.add_argument('--population', type=int, metavar='N', help='card: plaza population (0..3000)')
    ap.add_argument('--hat', type=int, metavar='N', help='card: hat / outfit worn (0..75, 0=none)')
    ap.add_argument('--pet', type=int, metavar='N', help='card: preferred pet (0..2)')
    ap.add_argument('--dream', type=int, metavar='N', help='card: dream (0..19)')
    ap.add_argument('--hobby', type=int, metavar='N', help='card: likes / hobby (0..27)')
    ap.add_argument('--bubble', type=int, metavar='N',
                    help='speech-bubble style 0..5 (body+0x614C), inferred')
    ap.add_argument('--gender', type=int, metavar='N',
                    help='Mii gender 0/1 -- also selects the blue vs pink speech bubble')
    ap.add_argument('--birthday', metavar='M/D', help='Mii birthday, e.g. 8/4 (or omit for none)')
    ap.add_argument('--colour', type=int, metavar='N',
                    help="Mii favourite colour 0..11 -- this is the shirt colour on the Mii")
    ap.add_argument('--title-id', metavar='HEX',
                    help='featured title id for region A (default 0x0004000012345600, an id no '
                         'console has). Every captured message carries 0x000400000D921E00 (HBL), '
                         'which both consoles have installed -- see the icon experiment.')
    ap.add_argument('--title-name', metavar='NAME', help='short title name shown on the Mii card')
    ap.add_argument('--mii-name', metavar='NAME',
                    help='rewrite the sender Mii name (<=10 chars). Unwraps the CFPB CCM, edits, '
                         'reseals the Mii CRC and re-wraps')
    ap.add_argument('--author-name', metavar='NAME',
                    help='rewrite the sender Mii author name (<=10 chars)')
    ap.add_argument('--greeting', default=None,
                    help='rewrite the Mii Plaza greeting (max 16 chars) inside the container')
    ap.add_argument('--full-sequence', action='store_true',
                    help='prepend the 0x41 / 0x43 / 0x11 objects that open a real exchange')
    ap.add_argument('--mirror-offer', action='store_true',
                    help="build object 3 (0x33) by mirroring the console's 0x32 list, which is "
                         'the only list cecd 0x1148C0 will accept')
    ap.add_argument('--empty-offer', action='store_true',
                    help='replace object 3 with a type-0x33 carrying an EMPTY ee list (count 0), '
                         'to test cecd 0x1148C0 count-equality')
    ap.add_argument('--fresh-msgid', action='store_true',
                    help='randomise the CEC message id (container +0x20, outside the HMAC)')
    ap.add_argument('--fresh-consoleid', action='store_true',
                    help='randomise the sending console id (object 0 payload)')
    ap.add_argument('--fresh-identity', action='store_true',
                    help='shorthand for --fresh-msgid --fresh-consoleid')
    ap.add_argument('--objects', default=None,
                    help='prefix of the CEC objects to send, e.g. '
                         'a captured plaza message (replayed verbatim)')
    ap.add_argument('--pcap', default=None, help='write every relevant frame here')
    ap.add_argument('--pcap-all', action='store_true', help='record ambient traffic too')
    ap.add_argument('--log', default=None)
    ap.add_argument('--verbose', '-v', type=int, default=1)
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--replay', nargs='+', metavar='PCAP')
    ap.add_argument('--simulate', action='store_true',
                    help='drive the state machine with a scripted console (no hardware)')
    return ap


def main():
    a = build_parser().parse_args()
    if a.fresh_identity:
        a.fresh_msgid = a.fresh_consoleid = True
    if a.selftest:
        return selftest()
    if a.simulate:
        return simulate(a.verbose)
    if a.replay:
        return replay(a.replay)
    return Link(a).run()


if __name__ == '__main__':
    sys.exit(main())
