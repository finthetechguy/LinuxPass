#!/usr/bin/env python3
"""Stage 3: the YY object exchange that carries the StreetPass payload."""
import struct, time
import sp_yy

MAX_SEG = sp_yy.MAX_SEG          # 1452
WINDOW = 0x38B8                  # 14520 == 10 * MAX_SEG


def build_yy_frame(flags, seq, ack, payload=b'', window=WINDOW):
    """One YY segment as it appears inside the CCMP payload."""
    hdr = (struct.pack('<HHHH', 0x5959, 0x30 + len(payload), 0xDEAD, 0xBEAF)
           + struct.pack('<II', seq, ack)
           + bytes([12, flags]) + struct.pack('<H', window) + b'\x00\x00\x00\x00')
    return b'\xaa\xaa\x03\x00\x00\x00' + b'\x08\x00' + b'\x00\x00' + hdr + bytes(payload)


def segment(obj, window=WINDOW, max_seg=MAX_SEG):
    """Split an object into (flags, seq, payload) exactly as a console does."""
    out, seq = [], 0
    while seq < len(obj):
        chunk = obj[seq:seq + max_seg]
        end_of_obj = (seq + len(chunk)) >= len(obj)
        end_of_win = ((seq + len(chunk)) % window) == 0
        flags = sp_yy.ACK
        if end_of_obj or end_of_win:
            flags |= sp_yy.PSH | sp_yy.URG          # URG is the END bit
        out.append((flags, seq, chunk))
        seq += len(chunk)
    if not out:
        out.append((sp_yy.ACK | sp_yy.PSH | sp_yy.URG, 0, b''))
    return out


# YY has no SACK, so a repeated cumulative ACK is the only loss signal.
DUP_ACK_RETRANSMIT = 2
RETRANSMIT_AFTER = 0.75
# cecd's main thread leaves NEGOTIATION (0x20) only on a 20 ms poll of its object mask
# (0x101CE0). An 0x81 that lands before that poll goes to the negotiation handler 0x108B5C,
# which answers the 0x80 bucket with set_state(0x17): the mask is zeroed (0x1027ee) and a
# role-1 console waits in 0x20 forever. That is the silent send. Over 418 logged engagements a
# gap of 12 ms or more between its 0x34 and our 0x81 never went silent (0 of 24), against
# 158 of 394 below it. Wait out more than one whole poll.
VERDICT_HOLD = 0.06
MAX_RESENDS = 8
MAX_OBJECT = 1 << 20


def object_length(buf):
    """The total length an object declares in its own first 16 bytes, or None if not decodable."""
    if len(buf) < 0x10:
        return None
    magic = struct.unpack_from('<H', buf, 0)[0]
    if magic == 0x6363:
        n = struct.unpack_from('<I', buf, 0x0C)[0] + 0x10
    elif magic == 0x6161:
        n = struct.unpack_from('<I', buf, 0x04)[0]
    else:
        return None
    return n if 0x10 <= n <= MAX_OBJECT else None


def is_verdict(obj):
    """Is this the peer's 0x34 verdict, the last object it sends before its 0x81?"""
    return (len(obj) >= 8 and obj[:2] == b'cc'
            and struct.unpack_from('<I', obj, 4)[0] == 0x34)


class YYSession:
    """The alternating object exchange."""

    def __init__(self, send_yy, log, outbox, on_received=None):
        self.send_yy = send_yy          # send_yy(flags, seq, ack, payload) -> bool
        self.log = log
        self.outbox = list(outbox)
        self.on_received = on_received  # hook(idx, obj) -> may rewrite self.outbox
        self.idx_tx = 0
        self.received = []
        self.role = None
        self.tx_seq = 0
        self.tx_acked = 0
        self.rx_buf = bytearray()
        self.segs = []
        self.tx_obj = b''
        self.dup_acks = 0
        self.resends = 0
        self.last_progress = time.time()
        self.done = False
        self.last_activity = time.time()
        self.idle_since = None
        self.rx_done_len = 0
        self.syn_at = None
        self.syn_resends = 0
        self.rx_expect = None
        # Cleared only by a completed object, because a hole stays until the peer retransmits.
        self.rx_gap = False
        self.repeat_slot = None
        self.repeat_obj = None
        self.repeat_max = 0
        self.repeats_done = 0
        self.repeat_worked = False
        self.peer_fin = False
        self.verdict_hold = VERDICT_HOLD
        self.send_at = None             # deferred start_send(), driven by poll()
        self.stats = {'sent_objects': 0, 'recv_objects': 0, 'tx_frames': 0, 'rx_frames': 0,
                      'resends': 0, 'dup_tails': 0, 'syn_resends': 0, 'gaps': 0,
                      'short_holds': 0, 'manifest_repeats': 0}

    def _emit(self, flags, seq, ack, payload=b''):
        self.stats['tx_frames'] += 1
        self.last_activity = time.time()
        return self.send_yy(flags, seq, ack, payload)

    def start_send(self):
        """Open a connection to send our next object (we are the initiator)."""
        if self.idx_tx >= len(self.outbox):
            self.log('  all %d objects sent' % len(self.outbox))
            self.done = True
            return False
        # Restarting an in-flight object rewinds tx_seq to 0, so it would never finish.
        if self.role == 'send' and self.tx_obj is self.outbox[self.idx_tx]:
            return False
        obj = self.outbox[self.idx_tx]
        self.role = 'send'
        self.tx_seq = self.tx_acked = 0
        self.tx_obj = obj
        self.dup_acks = self.resends = 0
        self.syn_resends = 0
        self.last_progress = time.time()
        self.segs = segment(obj)
        self.log('  --> opening connection for object %d (%d B, %d segment(s))'
                 % (self.idx_tx, len(obj), len(self.segs)))
        self.syn_at = time.time()
        return self._emit(sp_yy.SYN, 0, 0)

    def _pump_send(self, peer_ack, peer_window):
        """Send as much of the current object as the peer's window allows."""
        sent_any = False
        while self.segs:
            flags, seq, chunk = self.segs[0]
            if seq + len(chunk) > peer_ack + max(peer_window, MAX_SEG):
                break
            self.segs.pop(0)
            self._emit(flags, seq, 0, chunk)
            self.tx_seq = max(self.tx_seq, seq + len(chunk))
            sent_any = True
            if flags & sp_yy.URG:
                break
        return sent_any

    def _retransmit(self, why):
        """Re-queue the current object from the last acknowledged offset."""
        if self.resends >= MAX_RESENDS:
            if self.resends == MAX_RESENDS:              # log once, not on every later ACK
                self.resends += 1
                self.log('  giving up on object %d after %d retransmission(s): '
                         '%d of %d B acknowledged'
                         % (self.idx_tx, MAX_RESENDS, self.tx_acked, len(self.tx_obj)))
            return False
        self.resends += 1
        self.stats['resends'] += 1
        self.dup_acks = 0
        self.segs = [seg for seg in segment(self.tx_obj) if seg[1] + len(seg[2]) > self.tx_acked]
        self.tx_seq = self.tx_acked
        self.last_progress = time.time()
        self.log('  RETRANSMIT object %d from %#x (%d of %d B acknowledged, %d segment(s)): %s'
                 % (self.idx_tx, self.tx_acked, self.tx_acked, len(self.tx_obj),
                    len(self.segs), why))
        return True

    def on_frame(self, y):
        """Feed every decrypted YY frame here. Returns True if we transmitted something."""
        if not y or not y.get('ok'):
            return False
        self.stats['rx_frames'] += 1
        self.last_activity = time.time()
        f = y['flags']
        if f & sp_yy.FIN:
            self.peer_fin = True

        if (f & sp_yy.SYN) and not (f & sp_yy.ACK):
            self.send_at = None
            self.role = 'recv'
            self.rx_buf = bytearray()
            self.rx_expect = None
            self.rx_gap = False
            self.log('  <-- peer opened a connection (object %d incoming)'
                     % len(self.received))
            return self._emit(sp_yy.SYN | sp_yy.ACK, 0, 0)

        if (f & sp_yy.SYN) and (f & sp_yy.ACK):
            if self.role != 'send':
                return False
            self.syn_at = None
            self._emit(sp_yy.ACK, 0, 0)
            if self.tx_seq == 0:
                self._pump_send(0, y['window'])
            return True

        # A non-zero seq on an empty buffer is the peer resending its last END, so repeat the ACK.
        if y['payload_len'] > 0 and not self.rx_buf and y['seq'] > 0 and self.role != 'recv':
            self.stats['dup_tails'] += 1
            self.log('  peer repeated the tail of object %d (seq %#x); re-ACKing %d B'
                     % (len(self.received) - 1, y['seq'], self.rx_done_len))
            if f & sp_yy.URG:
                self._emit(sp_yy.ACK, 0, self.rx_done_len)
            return True

        if y['payload_len'] > 0:
            if y['seq'] == len(self.rx_buf):
                self.rx_buf += y['payload']
                if self.rx_expect is None:
                    self.rx_expect = object_length(self.rx_buf)
            elif y['seq'] < len(self.rx_buf):
                pass
            else:
                # As cecd does: drop the segment, repeat the unchanged ACK, and remember the hole.
                self.rx_gap = True
                self.stats['gaps'] += 1
                self.log('  gap in peer data: expected %d, got %d; duplicate-ACKing %d'
                         % (len(self.rx_buf), y['seq'], len(self.rx_buf)))
                self._emit(sp_yy.ACK, 0, len(self.rx_buf))
            if f & sp_yy.URG:
                self._emit(sp_yy.ACK, 0, len(self.rx_buf))
                if not self._object_complete() and self.rx_expect is not None \
                        and len(self.rx_buf) < self.rx_expect and self.rx_gap:
                    self.stats['short_holds'] += 1
                    self.log('  object %d is %d B of a declared %d B and something was lost; '
                             'holding it until the retransmission arrives'
                             % (len(self.received), len(self.rx_buf), self.rx_expect))
                if self._object_complete():
                    # Take exactly the declared length, so a peer cannot append junk.
                    obj = (bytes(self.rx_buf[:self.rx_expect]) if self.rx_expect is not None
                           else bytes(self.rx_buf))
                    if self.rx_expect is not None and len(self.rx_buf) > self.rx_expect:
                        self.log('  object %d overshot its declared length by %d B; trimmed'
                                 % (len(self.received), len(self.rx_buf) - self.rx_expect))
                    self.received.append(obj)
                    self.stats['recv_objects'] += 1
                    self.rx_done_len = len(obj)
                    self.log('  <== received object %d complete: %d B'
                             % (len(self.received) - 1, len(obj)))
                    if self.repeats_done and not self.repeat_worked:
                        self.repeat_worked = True
                        self.log('  *** the peer answered only after %d repeat(s) of our 0x81; '
                                 'its send thread had been asleep ***'
                                 % self.repeats_done)
                    if self.on_received:
                        try:
                            self.on_received(len(self.received) - 1, obj, self)
                        except Exception as e:      # never let a hook break the transfer
                            self.log('  on_received hook failed: %r' % (e,))
                    self.rx_buf = bytearray()
                    self.rx_expect = None
                    self.rx_gap = False
                    self.role = None
                    self.idle_since = None
                    if self.verdict_hold > 0 and is_verdict(obj):
                        # Our next object is the 0x81; let cecd leave NEGOTIATION first.
                        self.send_at = time.time() + self.verdict_hold
                        self.log('  holding our next object %.0f ms so the peer can leave '
                                 'NEGOTIATION' % (self.verdict_hold * 1000))
                        return True
                    return self.start_send()
            return True

        if f & sp_yy.ACK:
            if self.role != 'send':
                return False
            before = self.tx_acked
            self.tx_acked = max(self.tx_acked, y['ack'])
            if self.tx_acked > before:
                self.dup_acks = 0
                self.last_progress = time.time()
            elif self.tx_seq > self.tx_acked and self.tx_acked > 0:
                # `tx_acked > 0` separates a duplicate ACK from handshake ACKs, which carry ack=0.
                self.dup_acks += 1
                if self.dup_acks >= DUP_ACK_RETRANSMIT and not self.segs:
                    self._retransmit('%d duplicate ACK(s) at %#x'
                                     % (self.dup_acks, self.tx_acked))
            if not self.segs and self.tx_acked >= self.tx_seq and self.tx_seq > 0:
                self.log('  ==> object %d delivered (%d B acknowledged)'
                         % (self.idx_tx, self.tx_acked))
                self.idx_tx += 1
                self.stats['sent_objects'] += 1
                self.role = None
                self.idle_since = time.time()
                return False
            return self._pump_send(self.tx_acked, y['window'])
        return False

    def poll(self, idle_timeout=0.4):
        """Break the alternation deadlock when the peer has nothing to send."""
        if self.done:
            return False
        if self.send_at is not None:
            if time.time() < self.send_at:
                return False
            self.send_at = None
            return self.start_send()
        # A SYN carries no data, so the acknowledgement backstop below cannot see it.
        if (self.role == 'send' and self.syn_at is not None
                and time.time() - self.syn_at > RETRANSMIT_AFTER):
            if self.syn_resends >= MAX_RESENDS:
                if self.syn_resends == MAX_RESENDS:
                    self.syn_resends += 1
                    self.log('  no SYN|ACK for object %d after %d attempt(s); giving up on it'
                             % (self.idx_tx, MAX_RESENDS))
                return False
            self.syn_resends += 1
            self.stats['syn_resends'] += 1
            self.syn_at = time.time()
            self.log('  no SYN|ACK for object %d in %.0f ms; repeating the SYN (%d)'
                     % (self.idx_tx, RETRANSMIT_AFTER * 1000, self.syn_resends))
            return self._emit(sp_yy.SYN, 0, 0)
        if (self.role == 'send' and self.tx_obj and self.tx_seq > self.tx_acked
                and time.time() - self.last_progress > RETRANSMIT_AFTER):
            if self._retransmit('no acknowledgement for %.0f ms' % (RETRANSMIT_AFTER * 1000)):
                return self._pump_send(self.tx_acked, WINDOW)
            return False
        if self.role is not None or self.idle_since is None:
            return False
        if time.time() - self.idle_since < idle_timeout:
            return False
        self.idle_since = None
        self.log('  peer did not open a connection in %.0f ms; continuing on our own'
                 % (idle_timeout * 1000))
        self._maybe_repeat_manifest()
        return self.start_send()

    def _maybe_repeat_manifest(self):
        """Send our 0x81 again when the console answers it with nothing."""
        if self.repeat_slot is None or self.repeats_done >= self.repeat_max:
            return
        if self.repeat_worked:
            # A 0x81 after state 0x35 would be read as message bytes and corrupt the transfer.
            return
        if self.idx_tx != self.repeat_slot + 1:
            return
        obj = self.repeat_obj if self.repeat_obj is not None else self.outbox[self.repeat_slot]
        self.repeats_done += 1
        self.stats['manifest_repeats'] += 1
        self.outbox.insert(self.idx_tx, obj)
        self.repeat_slot = self.idx_tx
        self.log('  the peer answered our 0x81 with nothing; repeating a %d B object (attempt '
                 '%d of %d)' % (len(obj), self.repeats_done, self.repeat_max))

    def peer_sent_manifest(self):
        """Did the peer get far enough to store anything we sent?

        cecd only accepts our messages after it has sent its own 0x81 list, and it FINs once it
        has them all. A silent peer does neither, and drops whatever it acknowledged.
        """
        if self.peer_fin:
            return True
        for o in self.received:
            if o[:2] == b'aa':
                return True
            if o[:2] == b'cc' and len(o) >= 8 and struct.unpack_from('<I', o, 4)[0] == 0x81:
                return True
        return False

    def _object_complete(self):
        """Is the object in `rx_buf` finished?"""
        n = len(self.rx_buf)
        if n == 0:
            return False
        if self.rx_expect is not None:
            return n >= self.rx_expect
        if self.rx_gap:
            return False
        return (n % WINDOW) != 0


def _selftest():
    ok = tot = 0

    def chk(n, c, g=''):
        nonlocal ok, tot
        tot += 1
        ok += bool(c)
        print('  [%s] %s%s' % ('PASS' if c else 'FAIL', n, ('  %s' % (g,)) if g else ''))

    obj = bytes(32732)
    segs = segment(obj)
    chk('32732 B splits into 23 segments', len(segs) == 23, len(segs))
    ends = [s + len(p) for fl, s, p in segs if fl & sp_yy.URG]
    chk('END offsets match the capture (0x38B8, 0x7170, 0x7FDC)',
        ends == [0x38B8, 0x7170, 0x7FDC], [hex(e) for e in ends])
    chk('every segment is <= 1452 B', all(len(p) <= 1452 for _f, _s, p in segs))
    chk('segments are contiguous and cover the object',
        b''.join(p for _f, _s, p in segs) == obj)
    chk('data segments carry ACK', all(fl & sp_yy.ACK for fl, _s, _p in segs))

    small = segment(bytes(24))
    chk('a 24 B object is one PSH|ACK|END segment',
        len(small) == 1 and small[0][0] == (sp_yy.ACK | sp_yy.PSH | sp_yy.URG),
        sp_yy.flagstr(small[0][0]))

    fr = build_yy_frame(sp_yy.SYN, 0, 0)
    y = sp_yy.parse(fr)
    chk('SYN frame parses', y and y['ok'] and y['flags'] == sp_yy.SYN and y['length'] == 0x30)
    fr2 = build_yy_frame(sp_yy.ACK, 1452, 0, b'x' * 1452)
    y2 = sp_yy.parse(fr2)
    chk('data frame parses with the right seq/len',
        y2 and y2['ok'] and y2['seq'] == 1452 and y2['payload_len'] == 1452)
    chk('data frame never exceeds MAX_FRAME', y2['length'] <= sp_yy.MAX_FRAME, y2['length'])

    sent = []

    def send_yy(flags, seq, ack, payload=b''):
        sent.append((flags, seq, ack, bytes(payload)))
        return True

    outbox = [bytes(24), bytes(20), bytes(3000)]
    s = YYSession(send_yy, lambda m, l=1: None, outbox)
    s.start_send()
    chk('opens with SYN', sent and sent[0][0] == sp_yy.SYN)

    def feed(flags, seq=0, ack=0, payload=b''):
        s.on_frame(sp_yy.parse(build_yy_frame(flags, seq, ack, payload)))

    feed(sp_yy.SYN | sp_yy.ACK)
    chk('after SYN|ACK we ACK then send the object',
        any(f == sp_yy.ACK and not p for f, _s, _a, p in sent)
        and any(p == bytes(24) for _f, _s, _a, p in sent))
    feed(sp_yy.ACK, ack=24)
    chk('object 0 counted as delivered', s.stats['sent_objects'] == 1, s.stats['sent_objects'])

    feed(sp_yy.SYN)
    chk('we answer the peer SYN with SYN|ACK',
        sent[-1][0] == (sp_yy.SYN | sp_yy.ACK))
    feed(sp_yy.ACK)
    feed(sp_yy.ACK | sp_yy.PSH | sp_yy.URG, seq=0, payload=b'\xaa' * 40)
    chk('peer object received and stored',
        s.received and s.received[0] == b'\xaa' * 40, len(s.received))
    chk('we ACKed the peer object with its length',
        any(f == sp_yy.ACK and a == 40 for f, _s, a, _p in sent))
    chk('and immediately opened our next connection',
        sent[-1][0] == sp_yy.SYN and s.idx_tx == 1)

    s2 = YYSession(send_yy, lambda m, l=1: None, [bytes(3000)])
    sent.clear()
    s2.start_send()
    feed2 = lambda fl, sq=0, ak=0, pl=b'': s2.on_frame(
        sp_yy.parse(build_yy_frame(fl, sq, ak, pl)))
    feed2(sp_yy.SYN | sp_yy.ACK)
    datas = [x for x in sent if x[3]]
    chk('3000 B object sent as 3 segments (1452+1452+96)',
        [len(p) for _f, _s, _a, p in datas] == [1452, 1452, 96],
        [len(p) for _f, _s, _a, p in datas])
    chk('only the final segment carries END',
        [bool(f & sp_yy.URG) for f, _s, _a, p in datas] == [False, False, True])

    import lp_corpus as corpus
    files = sorted(corpus.glob('cecmsg_*.bin'),
                   key=lambda f: int(f.rsplit('_', 1)[1].split('.')[0]))
    if files:
        objs = [open(f, 'rb').read() for f in files]
        peer_objs = [bytes([i]) * (24 + i) for i in range(len(objs))]
        out = []

        def snd(flags, seq, ack, payload=b''):
            out.append((flags, seq, ack, bytes(payload)))
            return True

        sess = YYSession(snd, lambda m, l=1: None, objs)
        sess.start_send()

        def rx(fl, sq=0, ak=0, pl=b''):
            sess.on_frame(sp_yy.parse(build_yy_frame(fl, sq, ak, pl)))

        for i in range(len(objs)):
            rx(sp_yy.SYN | sp_yy.ACK)
            guard = 0
            while sess.role == 'send' and guard < 200:
                guard += 1
                acked = sess.tx_seq
                rx(sp_yy.ACK, ak=acked)
                if sess.role is None:
                    break
            if i < len(peer_objs):
                rx(sp_yy.SYN)
                rx(sp_yy.ACK)
                rx(sp_yy.ACK | sp_yy.PSH | sp_yy.URG, sq=0, pl=peer_objs[i])
        chk('all %d captured objects delivered' % len(objs),
            sess.stats['sent_objects'] == len(objs),
            '%d/%d' % (sess.stats['sent_objects'], len(objs)))
        chk('all peer objects received intact',
            sess.received == peer_objs[:len(sess.received)] and len(sess.received) >= 1,
            len(sess.received))
        big = [p for f, s, a, p in out if len(p) == 1452]
        chk('the 32,732 B object went out as 1452 B segments', len(big) >= 22, len(big))
        total_sent = sum(len(p) for f, s, a, p in out)
        chk('bytes transmitted == sum of object sizes',
            total_sent == sum(len(o) for o in objs),
            '%d vs %d' % (total_sent, sum(len(o) for o in objs)))

    out3 = []

    def snd3(flags, seq, ack, payload=b''):
        out3.append((flags, seq, ack, bytes(payload)))
        return True

    s3 = YYSession(snd3, lambda m, l=1: None, [bytes(24), bytes(20), bytes(92)])
    s3.start_send()
    r3 = lambda fl, sq=0, ak=0, pl=b'': s3.on_frame(build_yy_frame(fl, sq, ak, pl) and
                                                    sp_yy.parse(build_yy_frame(fl, sq, ak, pl)))
    r3(sp_yy.SYN | sp_yy.ACK)
    r3(sp_yy.ACK, ak=24)
    chk('object 0 delivered, now idle waiting for a silent peer',
        s3.stats['sent_objects'] == 1 and s3.role is None and s3.idle_since is not None)
    chk('poll() does nothing before the timeout', s3.poll(idle_timeout=60) is False)
    s3.idle_since = time.time() - 5
    chk('poll() takes the initiative after the timeout', s3.poll(idle_timeout=0.4) is not False)
    chk('and it opened the connection for object 1',
        out3[-1][0] == sp_yy.SYN and s3.idx_tx == 1, s3.idx_tx)
    for _ in range(6):
        r3(sp_yy.SYN | sp_yy.ACK)
        r3(sp_yy.ACK, ak=s3.tx_seq)
        s3.idle_since = time.time() - 5
        s3.poll(idle_timeout=0.4)
    chk('all 3 objects delivered against a silent peer',
        s3.stats['sent_objects'] == 3, s3.stats['sent_objects'])
    big = bytes(range(256)) * 128
    stalled = 0x606C

    def stalling_peer(obj, acks_at, feeder_limit=40):
        sent_f = []
        sess = YYSession(lambda f, sq, a, p=b'': (sent_f.append((f, sq, a, bytes(p))), True)[1],
                         lambda m, l=1: None, [obj])
        sess.start_send()
        sess.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN | sp_yy.ACK, 0, 0)))
        mark = None
        for _ in range(feeder_limit):
            if sess.stats['resends'] and mark is None:
                mark = len(sent_f) - 1
                break
            before = len(sent_f)
            sess.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK, 0, acks_at)))
            if sess.stats['resends'] and mark is None:
                mark = before
                break
        return sess, sent_f, mark

    s4, sent4, mark = stalling_peer(big, stalled)
    chk('a peer that stops advancing triggers a retransmission', s4.stats['resends'] == 1,
        s4.stats['resends'])
    resent = [(sq, p) for f, sq, a, p in sent4[mark:] if p]
    chk('it resends from the acknowledged offset, not from zero',
        resent and resent[0][0] == stalled, resent[0][0] if resent else None)
    chk('resent segments carry their original absolute seq and bytes',
        all(big[sq:sq + len(p)] == p for sq, p in resent))
    chk('nothing already acknowledged is resent', all(sq >= stalled for sq, _p in resent))
    for _ in range(8):
        if s4.stats['sent_objects']:
            break
        s4.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK, 0, len(big))))
    chk('the object completes once the tail is acknowledged',
        s4.stats['sent_objects'] == 1, s4.stats['sent_objects'])
    covered = bytearray(len(big))
    for _f, sq, _a, pl in sent4:
        if pl:
            covered[sq:sq + len(pl)] = pl
    chk('every byte of the object reached the wire at least once', bytes(covered) == big)

    sent5 = []
    s5 = YYSession(lambda f, sq, a, p=b'': (sent5.append((f, sq, a, bytes(p))), True)[1],
                   lambda m, l=1: None, [big])
    s5.start_send()
    s5.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN | sp_yy.ACK, 0, 0)))
    s5.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK, 0, stalled)))
    chk('poll() does not resend before the timeout',
        s5.poll() is False and s5.stats['resends'] == 0)
    s5.last_progress -= RETRANSMIT_AFTER + 0.1
    s5.poll()
    chk('poll() resends once the peer has been silent for RETRANSMIT_AFTER',
        s5.stats['resends'] == 1, s5.stats['resends'])

    giveup_log = []
    s6, _sent6, _m6 = stalling_peer(big, stalled, feeder_limit=200)
    s6.log = lambda m, l=1: giveup_log.append(m)
    for _ in range(MAX_RESENDS * (DUP_ACK_RETRANSMIT + 4)):
        s6.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK, 0, stalled)))
    chk('retransmission is capped at MAX_RESENDS', s6.stats['resends'] == MAX_RESENDS,
        s6.stats['resends'])
    chk('and the give-up notice is logged only once',
        sum(1 for m in giveup_log if 'giving up' in m) == 1,
        sum(1 for m in giveup_log if 'giving up' in m))
    chk('a healthy transfer never retransmits', s.stats['resends'] == 0, s.stats['resends'])

    chk('session reports done', s3.done)

    OBJ = 1400
    tail_log, tail_sent = [], []
    s7 = YYSession(lambda f, sq, a, p=b'': (tail_sent.append((f, sq, a, bytes(p))), True)[1],
                   lambda m, l=1: tail_log.append(m), [b'\xAA' * 40, b'\xBB' * 40])
    s7.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN, 0, 0)))
    s7.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK | sp_yy.PSH | sp_yy.URG, 0,
                                           0, b'z' * OBJ)))
    chk('the peer object is received', s7.received == [b'z' * OBJ], len(s7.received))
    chk('and its length is remembered for a repeat', s7.rx_done_len == OBJ, s7.rx_done_len)
    chk('we then open a connection of our own', s7.role == 'send' and s7.idx_tx == 0)
    n_recv, n_obj = len(s7.received), s7.tx_obj

    tail_sent.clear()
    s7.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK | sp_yy.PSH | sp_yy.URG, OBJ - 80,
                                           0, b'z' * 80)))
    chk('a repeated tail does not invent an object', len(s7.received) == n_recv,
        len(s7.received))
    chk('it is answered with the FULL length of that object, not 0',
        tail_sent == [(sp_yy.ACK, 0, OBJ, b'')], tail_sent)
    chk('and our own in-flight object is left alone',
        s7.tx_obj is n_obj and s7.role == 'send')
    chk('no second SYN is emitted for it',
        sum(1 for f, _s, _a, _p in tail_sent if f & sp_yy.SYN) == 0)
    chk('the repeat is counted', s7.stats['dup_tails'] == 1, s7.stats['dup_tails'])
    for _ in range(4):
        s7.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK | sp_yy.PSH | sp_yy.URG, OBJ - 80,
                                               0, b'z' * 80)))
    chk('five repeats produce five re-ACKs and no objects',
        s7.stats['dup_tails'] == 5 and len(s7.received) == n_recv,
        (s7.stats['dup_tails'], len(s7.received)))

    s8 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [b'\xAA' * 8])
    s8.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN, 0, 0)))
    s8.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK | sp_yy.PSH | sp_yy.URG, 1452,
                                           0, b'q' * 100)))
    chk('a gap inside an incoming object completes nothing', s8.received == [], s8.received)
    chk('and leaves us in recv, waiting', s8.role == 'recv')

    chk('object_length decodes the "cc" wrapper (16 + [0x0C])',
        object_length(struct.pack('<HHIII', 0x6363, 0, 0x81, 0, 196) + b'x' * 196) == 212)
    chk('object_length decodes the "aa" container ([0x04] is already the total)',
        object_length(struct.pack('<HHI', 0x6161, 0, 32732) + b'x' * 64) == 32732)
    chk('object_length refuses an unknown magic',
        object_length(b'\xDE\xAD' + b'\x00' * 32) is None)
    chk('object_length refuses an absurd length',
        object_length(struct.pack('<HHI', 0x6161, 0, MAX_OBJECT + 1) + b'x' * 64) is None)
    chk('object_length refuses a header it has not fully received',
        object_length(struct.pack('<HHI', 0x6161, 0, 32732)[:6]) is None)

    TOTAL = 32732
    body = struct.pack('<HHI', 0x6161, 0, TOTAL) + bytes(range(256)) * 200
    body = body[:TOTAL]
    segs = [(o, body[o:o + MAX_SEG]) for o in range(0, TOTAL, MAX_SEG)]
    chk('the replayed object segments as the console did (23 segments)', len(segs) == 23,
        len(segs))

    def end_flag(off, payload):
        """END lands on the last segment of every window and on the last segment overall."""
        return (off + len(payload)) % WINDOW == 0 or off + len(payload) >= TOTAL

    rng_sent, rng_log = [], []
    s12 = YYSession(lambda f, sq, a, p=b'': (rng_sent.append((f, sq, a)), True)[1],
                    lambda m, l=1: rng_log.append(m), [b'\xAA' * 40])
    s12.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN, 0, 0)))
    for off, pay in segs[:10]:
        fl = sp_yy.ACK | (sp_yy.PSH | sp_yy.URG if end_flag(off, pay) else 0)
        s12.on_frame(sp_yy.parse(build_yy_frame(fl, off, 0, pay)))
    chk('window 1 leaves the object open at exactly one window',
        len(s12.rx_buf) == WINDOW and s12.received == [], len(s12.rx_buf))
    chk('and the declared length was learned from the first segment',
        s12.rx_expect == TOTAL, s12.rx_expect)

    LOST = 17
    rng_sent.clear()
    for i in range(10, 20):
        if i == LOST:
            continue
        off, pay = segs[i]
        fl = sp_yy.ACK | (sp_yy.PSH | sp_yy.URG if end_flag(off, pay) else 0)
        s12.on_frame(sp_yy.parse(build_yy_frame(fl, off, 0, pay)))
    chk('the lost segment is noticed as a gap', s12.rx_gap and s12.stats['gaps'] == 2,
        (s12.rx_gap, s12.stats['gaps']))
    chk('the gap is duplicate-ACKed with our contiguous length, as cecd does at 0x10A9D2',
        (sp_yy.ACK, 0, segs[LOST][0]) in rng_sent, rng_sent[:4])
    chk('THE BUG: a short object is NOT completed', s12.received == [], s12.received)
    chk('and we are still holding exactly what arrived in order',
        len(s12.rx_buf) == segs[LOST][0] == 24684, len(s12.rx_buf))
    chk('the hold is reported, not silent', s12.stats['short_holds'] >= 1,
        s12.stats['short_holds'])
    chk('under the OLD rule this length would have been called complete',
        len(s12.rx_buf) % WINDOW != 0)

    for i in range(10, 20):
        off, pay = segs[i]
        fl = sp_yy.ACK | (sp_yy.PSH | sp_yy.URG if end_flag(off, pay) else 0)
        s12.on_frame(sp_yy.parse(build_yy_frame(fl, off, 0, pay)))
    chk('the retransmission fills the hole', len(s12.rx_buf) == 2 * WINDOW, len(s12.rx_buf))
    chk('two whole windows are still not the object', s12.received == [], s12.received)

    for i in range(20, 23):
        off, pay = segs[i]
        fl = sp_yy.ACK | (sp_yy.PSH | sp_yy.URG if end_flag(off, pay) else 0)
        s12.on_frame(sp_yy.parse(build_yy_frame(fl, off, 0, pay)))
    chk('the object completes, whole, after one lost frame and one retransmission',
        s12.received == [body], len(s12.received[0]) if s12.received else None)
    chk('and it is exactly the length its own header declared',
        len(s12.received[0]) == TOTAL, len(s12.received[0]))

    wm_body = struct.pack('<HHI', 0x6161, 0, WINDOW) + b'w' * (WINDOW - 8)
    s13 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [b'\xAA' * 8])
    s13.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN, 0, 0)))
    for off in range(0, WINDOW, MAX_SEG):
        pay = wm_body[off:off + MAX_SEG]
        fl = sp_yy.ACK | (sp_yy.PSH | sp_yy.URG if (off + len(pay)) % WINDOW == 0 else 0)
        s13.on_frame(sp_yy.parse(build_yy_frame(fl, off, 0, pay)))
    chk('an object of exactly one window still completes, on its declared length',
        s13.received == [wm_body], len(s13.received[0]) if s13.received else None)

    over_body = struct.pack('<HHI', 0x6161, 0, 200) + b'v' * 192
    s15 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [b'\xAA' * 8])
    s15.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN, 0, 0)))
    s15.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK | sp_yy.PSH | sp_yy.URG, 0, 0,
                                            over_body + b'JUNK')))
    chk('an object is trimmed to the length it declares',
        s15.received == [over_body], len(s15.received[0]) if s15.received else None)

    s14 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [b'\xAA' * 8])
    s14.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN, 0, 0)))
    for i in (0, 2):
        off, pay = segs[i]
        s14.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK | sp_yy.PSH | sp_yy.URG, off, 0, pay)))
    chk('a peer that goes silent mid-object leaves NOTHING, not a fragment',
        s14.received == [] and not s14.done, s14.received)

    syn_sent = []
    s9 = YYSession(lambda f, sq, a, p=b'': (syn_sent.append(f), True)[1],
                   lambda m, l=1: None, [b'\xCC' * 64])
    s9.start_send()
    chk('poll() does not repeat a fresh SYN', s9.poll() is False and s9.stats['syn_resends'] == 0)
    s9.syn_at -= RETRANSMIT_AFTER + 0.1
    s9.poll()
    chk('an unanswered SYN is repeated', s9.stats['syn_resends'] == 1,
        s9.stats['syn_resends'])
    for _ in range(MAX_RESENDS + 4):
        s9.syn_at = (s9.syn_at or time.time()) - (RETRANSMIT_AFTER + 0.1)
        s9.poll()
    chk('SYN repetition is capped at MAX_RESENDS', s9.stats['syn_resends'] == MAX_RESENDS,
        s9.stats['syn_resends'])
    s9.syn_at = None
    s10 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [b'\xCC' * 64])
    s10.start_send()
    s10.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN | sp_yy.ACK, 0, 0)))
    chk('a SYN|ACK stops the SYN timer', s10.syn_at is None)
    s10.syn_at = time.time() - (RETRANSMIT_AFTER + 0.1)
    s10.syn_at = None
    chk('and poll() then has no SYN to repeat',
        s10.poll() is False and s10.stats['syn_resends'] == 0)

    dup_sent = []
    s11 = YYSession(lambda f, sq, a, p=b'': (dup_sent.append((f, sq)), True)[1],
                    lambda m, l=1: None, [b'\xDD' * 5000])
    s11.start_send()
    s11.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN | sp_yy.ACK, 0, 0)))
    first = list(dup_sent)
    s11.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN | sp_yy.ACK, 0, 0)))
    chk('a repeated SYN|ACK re-ACKs but sends no data again',
        [x for x in dup_sent[len(first):]] == [(sp_yy.ACK, 0)],
        dup_sent[len(first):])

    head_sent = []
    s13 = YYSession(lambda f, sq, a, p=b'': (head_sent.append((f, sq, a)), True)[1],
                    lambda m, l=1: None, [b'\xAB' * 4000])
    s13.start_send()
    s13.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN | sp_yy.ACK, 0, 0)))
    chk('the window is fully drained, as it is at 11 Mbps', s13.segs == [], len(s13.segs))
    for _ in range(4):
        s13.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK, 0, 0)))
    chk('ack=0 before any progress is NOT read as a duplicate', s13.stats['resends'] == 0,
        s13.stats['resends'])
    chk('and the object is not rewound', s13.tx_acked == 0 and s13.tx_seq == 4000, s13.tx_seq)
    s13.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK, 0, 1452)))
    for _ in range(DUP_ACK_RETRANSMIT):
        s13.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK, 0, 1452)))
    chk('a repeated ACK after real progress still retransmits', s13.stats['resends'] == 1,
        s13.stats['resends'])
    s14 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [b'\xAC' * 4000])
    s14.start_send()
    s14.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN | sp_yy.ACK, 0, 0)))
    s14.last_progress -= RETRANSMIT_AFTER + 0.1
    s14.poll()
    chk('a first window that really was lost is still resent, by the timer',
        s14.stats['resends'] == 1, s14.stats['resends'])

    s12 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [b'\xEE' * 4000])
    s12.start_send()
    s12.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN | sp_yy.ACK, 0, 0)))
    mid = s12.tx_seq
    chk('an object is in flight', mid > 0, mid)
    chk('start_send() refuses to restart it', s12.start_send() is False and s12.tx_seq == mid,
        s12.tx_seq)

    def mkobj(otype, body):
        import struct as _s
        return b'cc\x00\x00' + _s.pack('<I', otype) + _s.pack('<I', 0) \
               + _s.pack('<I', len(body)) + body
    man = mkobj(0x81, b'\x01' * 32)
    msg = b'\xDD' * 300
    rep_sent = []
    s15 = YYSession(lambda f, sq, a, p=b'': (rep_sent.append((f, sq)), True)[1],
                    lambda m, l=1: None, [man, msg])
    s15.repeat_slot, s15.repeat_max = 0, 2
    s15.start_send()
    s15.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN | sp_yy.ACK, 0, 0)))
    s15.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK, 0, len(man))))
    chk('the manifest is delivered', s15.idx_tx == 1, s15.idx_tx)
    chk('no repeat while the peer still has time', s15.repeats_done == 0)
    s15.idle_since -= 1.0
    s15.poll()
    chk('a silent peer gets the 0x81 again', s15.repeats_done == 1 and s15.tx_obj is man,
        s15.repeats_done)
    chk('the outbox grew by exactly one object', len(s15.outbox) == 3, len(s15.outbox))
    chk('the message still follows it', s15.outbox[2] is msg)
    s15.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN | sp_yy.ACK, 0, 0)))
    s15.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK, 0, len(man))))
    s15.idle_since -= 1.0
    s15.poll()
    chk('and again, up to the limit', s15.repeats_done == 2, s15.repeats_done)
    s15.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN | sp_yy.ACK, 0, 0)))
    s15.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK, 0, len(man))))
    s15.idle_since -= 1.0
    s15.poll()
    chk('the limit is honoured -- we move on to the message',
        s15.repeats_done == 2 and s15.tx_obj is msg, (s15.repeats_done, len(s15.tx_obj)))
    chk('the repeats are counted', s15.stats['manifest_repeats'] == 2)

    s16 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [man, msg])
    s16.start_send()
    s16.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN | sp_yy.ACK, 0, 0)))
    s16.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK, 0, len(man))))
    s16.idle_since -= 1.0
    s16.poll()
    chk('with no repeat configured the outbox is untouched',
        len(s16.outbox) == 2 and s16.tx_obj is msg, len(s16.outbox))

    s17 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [msg, man, msg])
    s17.repeat_slot, s17.repeat_max = 1, 3
    s17.start_send()
    s17.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN | sp_yy.ACK, 0, 0)))
    s17.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK, 0, len(msg))))
    s17.idle_since -= 1.0
    s17.poll()
    chk('a silent peer after some OTHER object triggers no repeat',
        s17.repeats_done == 0 and len(s17.outbox) == 3, s17.repeats_done)

    # The 2DS on 11 Nov 2026: objects 0-6 back, ending at its 0x34 verdict, then nothing.
    def cc(otype, body=b''):
        return b'cc\x00\x00' + struct.pack('<II', otype, 0) + struct.pack('<I', len(body)) + body
    s18 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [man])
    s18.received = [cc(t) for t in (0x42, 0x43, 0x12, 0x22, 0x24, 0x32, 0x34)]
    chk('a peer that stopped at its 0x34 verdict stored nothing', not s18.peer_sent_manifest())
    s18.received.append(cc(0x81))
    chk('a peer that sent its 0x81 list could store our messages', s18.peer_sent_manifest())
    s19 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [man])
    s19.received = [b'aa' + bytes(30)]
    chk('a peer that sent a message got past its list', s19.peer_sent_manifest())
    s20 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [man])
    s20.on_frame(sp_yy.parse(build_yy_frame(sp_yy.FIN, 0x7FDC, 0)))
    chk('a FIN from the peer counts even if its list was missed',
        s20.peer_fin and s20.peer_sent_manifest())

    # The silent send: hold our 0x81 after the peer's 0x34 instead of answering in ~4 ms.
    sent21 = []
    s21 = YYSession(lambda f, sq, a, p=b'': (sent21.append((f, sq, a, bytes(p))), True)[1],
                    lambda m, l=1: None, [bytes(24), man])
    s21.idx_tx = 1
    s21.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN, 0, 0)))
    v = cc(0x34, bytes(8))
    s21.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK | sp_yy.PSH | sp_yy.URG, 0, 0, v)))
    chk('the peer 0x34 is received', s21.received and s21.received[-1] == v)
    chk('no SYN for our 0x81 straight after its 0x34',
        not any(f == sp_yy.SYN for f, _s, _a, _p in sent21) and s21.send_at is not None)
    s21.poll()
    chk('still holding inside the hold', s21.send_at is not None
        and not any(f == sp_yy.SYN for f, _s, _a, _p in sent21))
    s21.send_at -= 1.0
    s21.poll()
    chk('poll() opens the 0x81 connection once the hold is over',
        s21.send_at is None and sent21[-1][0] == sp_yy.SYN and s21.role == 'send')
    sent22 = []
    s22 = YYSession(lambda f, sq, a, p=b'': (sent22.append((f, sq, a, bytes(p))), True)[1],
                    lambda m, l=1: None, [bytes(24), bytes(20)])
    s22.idx_tx = 1
    s22.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN, 0, 0)))
    s22.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK | sp_yy.PSH | sp_yy.URG, 0, 0,
                                            cc(0x32, bytes(8)))))
    chk('other objects are still answered at once',
        s22.send_at is None and sent22[-1][0] == sp_yy.SYN)
    s23 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [bytes(24), man])
    s23.verdict_hold = 0
    s23.idx_tx = 1
    s23.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN, 0, 0)))
    s23.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK | sp_yy.PSH | sp_yy.URG, 0, 0, v)))
    chk('a hold of 0 restores the old behaviour', s23.send_at is None and s23.role == 'send')

    print('\n%d/%d checks passed' % (ok, tot))
    return 0 if ok == tot else 1


if __name__ == '__main__':
    import sys
    sys.exit(_selftest())
