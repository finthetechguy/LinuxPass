#!/usr/bin/env python3
"""
STAGE 3 -- the YY object exchange that carries the actual StreetPass payload.

Stage 2 got us an encrypted link and a YY SYN|ACK. This is the layer above: the alternating
transfer of CEC objects that ends with the 32,732-byte Mii Plaza message, and, if the console
accepts it, the green notification LED.

HOW THE EXCHANGE REALLY RUNS  (measured from sweep_new, 108 decrypted frames)
----------------------------------------------------------------------------
Each CEC object gets its OWN YY connection, and the two consoles ALTERNATE -- A sends object 0,
then B sends object 0, then A object 1, and so on. A connection is:

    ->  SYN                 seq=0 ack=0
    <-  SYN|ACK             seq=0 ack=0
    ->  ACK                 seq=0 ack=0
    ->  PSH|ACK|END         seq=0 len=N          the object
    <-  ACK                 ack=N

Sequence numbers are BYTE offsets within the object and restart at 0 in every connection -- which
is why pooling a whole direction by seq destroys all but one object.

For an object larger than one segment the data frames carry plain ACK (0x10) and the last segment
of each window carries PSH|ACK|END. MAX_SEG is 1452 and the advertised window is 14520 = exactly
10 segments, so END lands every 10 frames and again on the final segment. Verified against the
real transfer: END-flagged segments end at 0x38B8, 0x7170 and 0x7FDC, and the peer ACKs exactly
those values.

WHAT WE SEND
------------
The six objects captured from a real console, replayed verbatim. They are a CEC negotiation --
each begins `63 63` ("cc") with a type at +0x04 (0x21, 0x23, 0x31, 0x33, 0x81) -- ending with the
Mii Plaza container. Replaying real objects rather than synthesising them matters for one concrete
reason: the container carries a 32-byte high-entropy trailer that we cannot recompute. cecd verifies
it as HMAC-SHA256 over exactly the body with a key the application supplies (MESSAGE_HMAC.md), and
static RE says Mii Plaza never sets that key -- yet the trailer is present and has 4.88 bits/byte of
entropy. That contradiction is unresolved, so the only safe move is not to disturb the bytes it
covers. Editing the greeting text would invalidate it; replay keeps it whatever it is.
"""
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
    """Split an object into (flags, seq, payload) exactly as a console does.

    Data segments carry ACK; the last segment of every window, and the final segment of the
    object, additionally carry PSH|END. With window == 10*max_seg that puts END on every tenth
    segment -- matching the observed END offsets 0x38B8 / 0x7170 / 0x7FDC.
    """
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
    if not out:                                      # zero-length object
        out.append((sp_yy.ACK | sp_yy.PSH | sp_yy.URG, 0, b''))
    return out


#: cecd's YY carries no SACK, so a repeated cumulative ACK is the only loss signal there is.
#: Two of them is the classic "it is missing something" threshold and costs one round trip.
DUP_ACK_RETRANSMIT = 2
#: Resend if nothing has been acknowledged for this long, as the backstop for the case where the
#: peer stops ACKing altogether rather than repeating an ACK.
RETRANSMIT_AFTER = 0.75
#: Give up on an object rather than looping forever against a peer that has genuinely gone.
MAX_RESENDS = 8
#: Sanity bound on a declared object length. The largest object this project has ever seen on the
#: wire is 101,720 B; a megabyte is far beyond anything real and rejects a corrupt header.
MAX_OBJECT = 1 << 20


def object_length(buf):
    """The total length an object declares in its own first 16 bytes, or None if not decodable.

    EVERY object carries its own length, and this is the only trustworthy end-of-object signal.
    Two families appear on the wire, both verified against 74 objects across the whole run-log
    corpus (73 matched exactly; the single mismatch WAS the corrupted object this function exists
    to catch, relay_1788440865.log object 9: header said 32,732, we had committed 24,684):

        0x6363 'cc'  the CEC object wrapper built at cecd 0x1076BA -- u32 at +0x0C is the PAYLOAD
                     length and the header itself is 16 B, so total = 16 + [+0x0C].
        0x6161 'aa'  the message container the console sends for a title -- u32 at +0x04 is
                     already the TOTAL, header included.

    Anything else returns None and the caller falls back to the window heuristic.
    """
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


class YYSession:
    """The alternating object exchange.

    Deliberately reactive: every transition is driven by a frame that actually arrived, never by a
    timer, because the console sets the pace and a timer-driven sender desynchronises the moment
    one frame is lost.
    """

    def __init__(self, send_yy, log, outbox, on_received=None):
        self.send_yy = send_yy          # send_yy(flags, seq, ack, payload) -> bool
        self.log = log
        self.outbox = list(outbox)      # objects we will send, in order
        self.on_received = on_received  # hook(idx, obj) -> may rewrite self.outbox
        self.idx_tx = 0                 # which of our objects is next
        self.received = []              # complete objects from the console
        self.role = None                # 'send' or 'recv' for the current connection
        self.tx_seq = 0                 # bytes of the current object handed to the peer
        self.tx_acked = 0
        self.rx_buf = bytearray()
        self.segs = []                  # pending segments of the object being sent
        self.tx_obj = b''               # the object being sent, kept so it can be RESENT
        self.dup_acks = 0               # consecutive ACKs that did not advance
        self.resends = 0                # retransmissions of the current object
        self.last_progress = time.time()
        self.done = False
        self.last_activity = time.time()
        # Time of the last completed object, used to break the alternation deadlock below.
        self.idle_since = None
        #: Length of the object we most recently finished receiving. The peer repeats that
        #: object's END segment until it sees a cumulative ACK for it, so this is the number we
        #: must be able to repeat back after `rx_buf` has already been cleared.
        self.rx_done_len = 0
        #: When our connection-opening SYN went out, and how many times it has been repeated.
        #: A SYN carries no data, so the tx_seq > tx_acked backstop in poll() cannot see it.
        self.syn_at = None
        self.syn_resends = 0
        #: Total length the object now arriving declared in its own header, once we have enough
        #: of it to read that (see `object_length`). None means "not decodable, use the window
        #: heuristic". This is what makes a short object impossible to mistake for a finished one.
        self.rx_expect = None
        #: Set when a segment arrived beyond the contiguous end of `rx_buf`, i.e. something was
        #: lost. It is cleared only by a completed object, never by later in-order data, because
        #: the hole stays a hole until the peer retransmits into it.
        self.rx_gap = False
        #: Index in `outbox` of our 0x81 manifest, and how many extra copies of it we may send
        #: when the peer answers it with nothing. See `_maybe_repeat_manifest`. Off by default:
        #: the caller sets both, because only the caller can find the 0x81 by type.
        self.repeat_slot = None
        #: Which object to repeat. Defaults to the manifest itself; set it to a negotiation
        #: object to probe WHICH STATE the console is in, since cecd routes an incoming object
        #: by its exchange state and answers only the one that state expects.
        self.repeat_obj = None
        self.repeat_max = 0
        self.repeats_done = 0
        self.repeat_worked = False
        self.stats = {'sent_objects': 0, 'recv_objects': 0, 'tx_frames': 0, 'rx_frames': 0,
                      'resends': 0, 'dup_tails': 0, 'syn_resends': 0, 'gaps': 0,
                      'short_holds': 0, 'manifest_repeats': 0}

    # -- helpers ---------------------------------------------------------------------------
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
        # Re-entry guard. Restarting an object that is already in flight throws away the segments
        # still queued for it and rewinds tx_seq to 0, so the object never finishes. Nothing in a
        # healthy exchange calls this twice; a peer repeating a frame we mishandled did.
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
                break                                    # window full; wait for an ACK
            self.segs.pop(0)
            self._emit(flags, seq, 0, chunk)
            self.tx_seq = max(self.tx_seq, seq + len(chunk))
            sent_any = True
            if flags & sp_yy.URG:
                break                                    # END -> wait for the peer's ACK
        return sent_any

    def _retransmit(self, why):
        """Re-queue the current object from the last acknowledged offset.

        Without this a single lost frame ends the transfer: `segment()` output was consumed as it
        was emitted, so there was nothing left to resend, and the session simply waited for an ACK
        that could never come. Measured 2 Sep 2026 on a two-title exchange -- the console
        acknowledged 24,684 of a 32,732 B message, repeated that same ACK four times, and the
        attempt timed out with 8,048 bytes never resent.

        `segment()` is a pure function of the object and its seq numbers are absolute, so
        re-segmenting and dropping everything already acknowledged reproduces the original frames
        exactly -- same seq, same END placement, which the peer's object-boundary rule depends on.
        """
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
        self.log('  RETRANSMIT object %d from %#x (%d of %d B acknowledged, %d segment(s)) -- %s'
                 % (self.idx_tx, self.tx_acked, self.tx_acked, len(self.tx_obj),
                    len(self.segs), why))
        return True

    # -- the one entry point ---------------------------------------------------------------
    def on_frame(self, y):
        """Feed every decrypted YY frame here. Returns True if we transmitted something."""
        if not y or not y.get('ok'):
            return False
        self.stats['rx_frames'] += 1
        self.last_activity = time.time()
        f = y['flags']

        # --- the peer opens a connection to send us an object -----------------------------
        if (f & sp_yy.SYN) and not (f & sp_yy.ACK):
            self.role = 'recv'
            self.rx_buf = bytearray()
            self.rx_expect = None
            self.rx_gap = False
            self.log('  <-- peer opened a connection (object %d incoming)'
                     % len(self.received))
            return self._emit(sp_yy.SYN | sp_yy.ACK, 0, 0)

        # --- our SYN was accepted: ACK it, then start streaming ---------------------------
        if (f & sp_yy.SYN) and (f & sp_yy.ACK):
            if self.role != 'send':
                return False
            self.syn_at = None
            self._emit(sp_yy.ACK, 0, 0)
            # A repeated SYN|ACK (ours crossed with theirs, or our ACK was lost) must not restart
            # the stream: re-ACK the handshake and leave the in-flight segments where they are.
            if self.tx_seq == 0:
                self._pump_send(0, y['window'])
            return True

        # --- the peer repeating the tail of the object we already finished -----------------
        # An object always begins at seq 0, so a non-zero seq against an EMPTY buffer cannot be
        # the start of anything. It is the peer resending the END of the object we just
        # completed because it never saw our ACK for it. The answer is to repeat that ACK.
        #
        # This branch used to fall through to the gap handler below, and the damage compounded
        # three ways: nothing was appended, so `_object_complete` saw a zero-length buffer and
        # invented a 0-byte object; the ACK went out carrying `len(rx_buf)` == 0, which told the
        # peer we had received none of it and guaranteed it would ask again; and the phantom
        # completion called `start_send` a second time, rewinding our own in-flight object to
        # zero. Measured 3 Sep 2026 (relay_1788391051.log): five phantom objects 505 ms apart
        # after a 101,720 B object, our fourth title never delivered, and the console gave up.
        # `role == 'recv'` means the peer opened a NEW connection and the first segment was
        # genuinely lost, which is a different thing and is left to the gap handler.
        if y['payload_len'] > 0 and not self.rx_buf and y['seq'] > 0 and self.role != 'recv':
            self.stats['dup_tails'] += 1
            self.log('  peer repeated the tail of object %d (seq %#x) -- re-ACKing %d B'
                     % (len(self.received) - 1, y['seq'], self.rx_done_len))
            if f & sp_yy.URG:
                self._emit(sp_yy.ACK, 0, self.rx_done_len)
            return True

        # --- data from the peer ------------------------------------------------------------
        if y['payload_len'] > 0:
            if y['seq'] == len(self.rx_buf):
                self.rx_buf += y['payload']
                if self.rx_expect is None:
                    self.rx_expect = object_length(self.rx_buf)
            elif y['seq'] < len(self.rx_buf):
                pass                                     # retransmission, already have it
            else:
                # A hole. cecd's own receiver does exactly this (0x10A9D2, reached when
                # `rx.seq > rcv_nxt`): it drops the out-of-order segment and re-sends an ACK
                # carrying the UNCHANGED receive pointer, so the sender learns where to resume.
                # We now do the same instead of silently discarding it, and -- critically -- we
                # remember that the hole exists so `_object_complete` cannot call the object done.
                self.rx_gap = True
                self.stats['gaps'] += 1
                self.log('  gap in peer data: expected %d, got %d -- duplicate-ACKing %d'
                         % (len(self.rx_buf), y['seq'], len(self.rx_buf)))
                self._emit(sp_yy.ACK, 0, len(self.rx_buf))
            if f & sp_yy.URG:                            # END -> window flush or object end
                self._emit(sp_yy.ACK, 0, len(self.rx_buf))
                if not self._object_complete() and self.rx_expect is not None \
                        and len(self.rx_buf) < self.rx_expect and self.rx_gap:
                    # Say so out loud: this is the exact moment the old code committed a
                    # truncated object and desynchronised the session.
                    self.stats['short_holds'] += 1
                    self.log('  object %d is %d B of a declared %d B and something was lost -- '
                             'NOT completing it, waiting for the retransmission'
                             % (len(self.received), len(self.rx_buf), self.rx_expect))
                if self._object_complete():
                    # The declared length is the truth: take exactly that many bytes, so a peer
                    # that overshoots cannot append trailing junk to a message. In the whole
                    # run-log corpus the buffer lands exactly on it, so this never trims anything
                    # real -- it just means it cannot.
                    obj = (bytes(self.rx_buf[:self.rx_expect]) if self.rx_expect is not None
                           else bytes(self.rx_buf))
                    if self.rx_expect is not None and len(self.rx_buf) > self.rx_expect:
                        self.log('  object %d overshot its declared length by %d B -- trimmed'
                                 % (len(self.received), len(self.rx_buf) - self.rx_expect))
                    self.received.append(obj)
                    self.stats['recv_objects'] += 1
                    self.rx_done_len = len(obj)
                    self.log('  <== received object %d complete: %d B'
                             % (len(self.received) - 1, len(obj)))
                    if self.repeats_done and not self.repeat_worked:
                        self.repeat_worked = True
                        self.log('  *** the peer answered only AFTER %d repeat(s) of our 0x81 '
                                 '-- its send thread was asleep, not absent ***'
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
                    return self.start_send()             # our turn
            return True

        # --- a pure ACK ---------------------------------------------------------------------
        if f & sp_yy.ACK:
            if self.role != 'send':
                return False
            before = self.tx_acked
            self.tx_acked = max(self.tx_acked, y['ack'])
            if self.tx_acked > before:
                self.dup_acks = 0
                self.last_progress = time.time()
            elif self.tx_seq > self.tx_acked and self.tx_acked > 0:
                # No SACK in this protocol: a repeated cumulative ACK is the peer saying it has a
                # hole. Resend once we have nothing left to push and it has said so twice.
                #
                # `tx_acked > 0` matters. At the start of an object tx_acked is 0 and the peer's
                # connection-handshake ACK also carries ack=0, so the two are indistinguishable by
                # value. At 1 Mbps a window took ~130 ms to drain, `not self.segs` was still false
                # while those ACKs arrived, and nothing fired. At 11 Mbps it drains in ~13 ms, the
                # guard stops helping, and the object gets resent from zero -- measured 3 Sep 2026
                # (relay_1788439266.log): four retransmits of a 14,224 B object inside 26 ms, all
                # spurious, all at offset 0. A first window that really was lost is still covered,
                # 750 ms later, by the RETRANSMIT_AFTER backstop in poll().
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
                return False                             # the peer MAY open the next connection
            return self._pump_send(self.tx_acked, y['window'])
        return False

    def poll(self, idle_timeout=0.4):
        """Break the alternation deadlock when the peer has nothing to send.

        The captured exchange alternates strictly A,B,A,B -- but that is a CONSEQUENCE of both
        consoles having something to send, not a rule. A console whose outbox is empty simply never
        opens a connection, and a sender that waits for its turn waits forever. Measured: the
        console's object 2 (type 0x32) came back with an `ee` record of length 0x2C containing no
        entries, i.e. "I have nothing for you", after which it went silent and our transfer stalled
        at object 3 on every single attempt.

        So: if we finished an object and the peer has not opened a connection within
        `idle_timeout`, take the initiative and send the next one.
        """
        if self.done:
            return False
        # A SYN that is never answered. It carries no data, so tx_seq is still 0 and the
        # acknowledgement backstop below cannot see it: before this, one lost SYN stalled the
        # session until the caller's whole attempt timed out, losing every object after it.
        if (self.role == 'send' and self.syn_at is not None
                and time.time() - self.syn_at > RETRANSMIT_AFTER):
            if self.syn_resends >= MAX_RESENDS:
                if self.syn_resends == MAX_RESENDS:
                    self.syn_resends += 1
                    self.log('  no SYN|ACK for object %d after %d attempt(s) -- giving up on it'
                             % (self.idx_tx, MAX_RESENDS))
                return False
            self.syn_resends += 1
            self.stats['syn_resends'] += 1
            self.syn_at = time.time()
            self.log('  no SYN|ACK for object %d in %.0f ms -- repeating the SYN (%d)'
                     % (self.idx_tx, RETRANSMIT_AFTER * 1000, self.syn_resends))
            return self._emit(sp_yy.SYN, 0, 0)
        # Backstop for a peer that stops acknowledging altogether instead of repeating an ACK.
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
        self.log('  peer did not open a connection in %.0f ms -- continuing on our own'
                 % (idle_timeout * 1000))
        self._maybe_repeat_manifest()
        return self.start_send()

    def _maybe_repeat_manifest(self):
        """Send our 0x81 again when the console answers it with nothing.

        WHY THE 0x81 IS THE ONLY THING WORTH REPEATING -- read out of cecd, 3 September 2026.

        cecd runs the send half of an exchange on a dedicated thread whose entry point is
        0x104A5E. That is not a guess: 0x103130 loads the literal `0x104a5d` into r1, passes it
        to the thread-create at 0x103178, and on success sets [0x124298+0x0E]. The thread is
        purely event-driven -- it parks on svcWaitSynchronizationN and publishes "I am parked"
        through a LightEvent at 0x1282D0 (Signal at its loop head 0x104A96, Clear at 0x104AC4
        once it has picked work up).

        The ONLY routine in the whole module that signals its work event 0x1282c8 from outside
        the thread is 0x112460 (the other two signallers, 0x104C9A and 0x1071FA, are inside the
        thread itself). During the object phase 0x112460 is reachable only from the object
        handler 0x1073F0, and for the console's role ([0x124298+0x54] == 1) from exactly one
        site, 0x107538 -- which runs when OUR 0x81 arrives.

        0x112460 polls the park token 64 times at 2 ms and gives up. When it gives up the caller
        sleeps 50 ms and returns, and **nothing retries**. The send thread is never told, it
        stays parked in state 0x31 SEND_RECV_INIT, and the console sends nothing for the rest of
        the pass. That is exactly what we measure: in 25 of 25 silent passes the console
        transmits no frame at all between our 0x81 being acknowledged and our next object, over a
        gap-free CCMP packet-number sequence that proves none was missed.

        In state 0x31 cecd will act on nothing else. 0x1073F0 drops any object whose body exceeds
        0x5DC bytes (0x107404) and, past that, anything whose type is not 0x81 (0x10748E). So
        repeating the 0x81 is both the only legal way to poke the console again and completely
        safe -- in that state there is no other object it could be confused with, and the handler
        resets only the receive bookkeeping ([0x124298+0x38]/[+0x48]/[+0x50] at 0x1074FE) which
        has not been used yet.

        Each repeat buys another 0x112460 call, i.e. another 128 ms of waiting for the send
        thread to park. The outcome discriminates:
          * the console answers a repeat with its own 0x81  -> it was parked in 0x31 and the
            wake-up simply never reached it; the exchange then proceeds normally;
          * it never answers, however many repeats  -> it was not in 0x31, so the decision was
            taken earlier, at the pre-connect check at 0x104B98 (stop flag / state >= 0x36 /
            loop flag), and this is not the fix.
        """
        if self.repeat_slot is None or self.repeats_done >= self.repeat_max:
            return
        if self.repeat_worked:
            # It already answered one. Belt and braces: a further 0x81 sent after the console has
            # reached state 0x35 would be fed to the RECEIVE handler 0x106E80 as message bytes and
            # corrupt the transfer. The idx_tx test below should already prevent it.
            return
        if self.idx_tx != self.repeat_slot + 1:
            return                                   # we are not right after the manifest
        obj = self.repeat_obj if self.repeat_obj is not None else self.outbox[self.repeat_slot]
        self.repeats_done += 1
        self.stats['manifest_repeats'] += 1
        self.outbox.insert(self.idx_tx, obj)
        self.repeat_slot = self.idx_tx               # the copy is now the manifest slot
        self.log('  the peer answered our 0x81 with nothing -- repeating a %d B object '
                 '(attempt %d of %d)' % (len(obj), self.repeats_done, self.repeat_max))

    def _object_complete(self):
        """Is the object in `rx_buf` finished?

        THE LENGTH THE OBJECT DECLARES WINS. Every object states its own total in its first 16
        bytes (`object_length`), and when that is readable it is the whole test: short means keep
        waiting, no matter what the flags say.

        The fallback, for an object whose header we cannot decode, is the window rule: a window
        flush also carries END, so END alone never means 'done'. The console's rule, read off the
        wire: END at a multiple of 14520 is a flush; anywhere else it is the end of the object.
        That rule is only sound when nothing was lost, because it tests the number of bytes we
        HOLD rather than the number the peer SENT -- so it is now guarded by `rx_gap`.

        Why this matters, measured (relay_1788440865.log, the 2DS XL two rooms away behind a shoe
        box, 3 Sep 2026). One 1452 B segment at offset 0x606C was lost out of a full 10-segment
        window. The two segments behind it were discarded as out-of-order, so `rx_buf` stopped at
        24,684 -- and 24,684 is not a multiple of 14,520, so the old rule declared a 32,732 B Mii
        Plaza message COMPLETE at 24,684 B. We stored a message whose own header says 32,712 and
        which is 8,048 bytes short, then moved on to the next object while the console was still
        retransmitting the one before it. It repeated the missing segment ten times over 3.3 s and
        never got a reply that made sense; we sent nine SYNs it never answered; both sides gave up
        with two of four titles delivered. A single lost frame did all of that.

        An EMPTY buffer is never complete. That is reachable when a segment carrying END is the
        first thing to arrive on a connection (a lost first segment), and answering it as a
        finished 0-byte object is what bug 17 did.
        """
        n = len(self.rx_buf)
        if n == 0:
            return False
        if self.rx_expect is not None:
            return n >= self.rx_expect
        if self.rx_gap:
            return False
        return (n % WINDOW) != 0


# -------------------------------------------------------------------------------------------

def _selftest():
    ok = tot = 0

    def chk(n, c, g=''):
        nonlocal ok, tot
        tot += 1
        ok += bool(c)
        print('  [%s] %s%s' % ('PASS' if c else 'FAIL', n, ('  %s' % (g,)) if g else ''))

    # segmentation must reproduce the END offsets observed on the wire
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

    # frame builder round-trips through the real parser
    fr = build_yy_frame(sp_yy.SYN, 0, 0)
    y = sp_yy.parse(fr)
    chk('SYN frame parses', y and y['ok'] and y['flags'] == sp_yy.SYN and y['length'] == 0x30)
    fr2 = build_yy_frame(sp_yy.ACK, 1452, 0, b'x' * 1452)
    y2 = sp_yy.parse(fr2)
    chk('data frame parses with the right seq/len',
        y2 and y2['ok'] and y2['seq'] == 1452 and y2['payload_len'] == 1452)
    chk('data frame never exceeds MAX_FRAME', y2['length'] <= sp_yy.MAX_FRAME, y2['length'])

    # a full scripted exchange against a peer that behaves like the captured console
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

    # the peer now sends us an object
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

    # multi-segment object
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

    # --- the whole six-object exchange, with the REAL captured objects and a scripted peer ---
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

        # A scripted console: SYN|ACK our connections, ACK each window, then send its own object.
        for i in range(len(objs)):
            rx(sp_yy.SYN | sp_yy.ACK)                       # accept our connection
            guard = 0
            while sess.role == 'send' and guard < 200:      # ACK each window until delivered
                guard += 1
                acked = sess.tx_seq
                rx(sp_yy.ACK, ak=acked)
                if sess.role is None:
                    break
            if i < len(peer_objs):                          # the peer's turn
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

    # --- regression: a peer with an EMPTY outbox must not deadlock us ------------------------
    # This is the real failure. The console answered our type-0x31 with a type-0x32 carrying an
    # empty `ee` list ("nothing for you") and then never opened another connection; a strictly
    # alternating sender waits forever. Every attempt stalled at object 3.
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
    # drive it to completion with a peer that only ever ACKs
    for _ in range(6):
        r3(sp_yy.SYN | sp_yy.ACK)
        r3(sp_yy.ACK, ak=s3.tx_seq)
        s3.idle_since = time.time() - 5
        s3.poll(idle_timeout=0.4)
    chk('all 3 objects delivered against a silent peer',
        s3.stats['sent_objects'] == 3, s3.stats['sent_objects'])
    # ---- retransmission: the two-title failure of 2 Sep 2026 ----
    # The console acknowledged 24,684 of a 32,732 B message, repeated that ACK four times and the
    # attempt died with 8,048 bytes never resent, because segment() output was thrown away as it
    # was emitted. Model that peer: it ACKs once, then never advances.
    big = bytes(range(256)) * 128                          # 32,768 B, 23 segments
    stalled = 0x606C                                        # exactly where the console stopped

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
    # let it finish: the peer starts acknowledging again
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

    # the time-based backstop, for a peer that goes silent instead of repeating an ACK
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

    # and it must give up rather than loop for ever
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

    # ---------------------------------------------------------------------------------------
    # The peer repeating the tail of an object it has already finished sending.
    # Replayed from relay_1788391051.log, where this cost the fourth title of the exchange:
    # after a 101,720 B object the console repeated its final END segment five times, 505 ms
    # apart, because it had not seen our ACK.
    OBJ = 1400                                   # one whole segment, and not a window multiple
    tail_log, tail_sent = [], []
    s7 = YYSession(lambda f, sq, a, p=b'': (tail_sent.append((f, sq, a, bytes(p))), True)[1],
                   lambda m, l=1: tail_log.append(m), [b'\xAA' * 40, b'\xBB' * 40])
    s7.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN, 0, 0)))          # peer opens
    s7.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK | sp_yy.PSH | sp_yy.URG, 0,
                                           0, b'z' * OBJ)))            # ... and sends an object
    chk('the peer object is received', s7.received == [b'z' * OBJ], len(s7.received))
    chk('and its length is remembered for a repeat', s7.rx_done_len == OBJ, s7.rx_done_len)
    chk('we then open a connection of our own', s7.role == 'send' and s7.idx_tx == 0)
    n_recv, n_obj = len(s7.received), s7.tx_obj

    # the repeat: the same END segment, at its original non-zero offset, against an empty buffer
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
    for _ in range(4):                                   # the console repeated it five times
        s7.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK | sp_yy.PSH | sp_yy.URG, OBJ - 80,
                                               0, b'z' * 80)))
    chk('five repeats produce five re-ACKs and no objects',
        s7.stats['dup_tails'] == 5 and len(s7.received) == n_recv,
        (s7.stats['dup_tails'], len(s7.received)))

    # a genuinely lost FIRST segment is a different thing: the peer opened a connection, so we
    # are in 'recv', and the answer is to wait for the retransmission -- not to finish an object
    s8 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [b'\xAA' * 8])
    s8.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN, 0, 0)))
    s8.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK | sp_yy.PSH | sp_yy.URG, 1452,
                                           0, b'q' * 100)))
    chk('a gap inside an incoming object completes nothing', s8.received == [], s8.received)
    chk('and leaves us in recv, waiting', s8.role == 'recv')

    # ---------------------------------------------------------------------------------------
    # THE RANGE FAILURE, replayed segment for segment from relay_1788440865.log (2DS XL two
    # rooms away, behind a shoe box, 3 Sep 2026). One segment of a 32,732 B object was lost and
    # the old completion rule committed the object 8,048 bytes short.
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

    TOTAL = 32732                                    # the real Mii Plaza object, to the byte
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
    for off, pay in segs[:10]:                       # window 1, intact
        fl = sp_yy.ACK | (sp_yy.PSH | sp_yy.URG if end_flag(off, pay) else 0)
        s12.on_frame(sp_yy.parse(build_yy_frame(fl, off, 0, pay)))
    chk('window 1 leaves the object open at exactly one window',
        len(s12.rx_buf) == WINDOW and s12.received == [], len(s12.rx_buf))
    chk('and the declared length was learned from the first segment',
        s12.rx_expect == TOTAL, s12.rx_expect)

    LOST = 17                                        # offset 0x606C, the segment that was lost
    rng_sent.clear()
    for i in range(10, 20):                          # window 2, with segment 17 missing
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

    for i in range(10, 20):                          # the console resends the whole window
        off, pay = segs[i]
        fl = sp_yy.ACK | (sp_yy.PSH | sp_yy.URG if end_flag(off, pay) else 0)
        s12.on_frame(sp_yy.parse(build_yy_frame(fl, off, 0, pay)))
    chk('the retransmission fills the hole', len(s12.rx_buf) == 2 * WINDOW, len(s12.rx_buf))
    chk('two whole windows are still not the object', s12.received == [], s12.received)

    for i in range(20, 23):                          # window 3, the tail
        off, pay = segs[i]
        fl = sp_yy.ACK | (sp_yy.PSH | sp_yy.URG if end_flag(off, pay) else 0)
        s12.on_frame(sp_yy.parse(build_yy_frame(fl, off, 0, pay)))
    chk('the object completes, whole, after one lost frame and one retransmission',
        s12.received == [body], len(s12.received[0]) if s12.received else None)
    chk('and it is exactly the length its own header declared',
        len(s12.received[0]) == TOTAL, len(s12.received[0]))

    # the declared length also ends an object whose size is an exact multiple of the window --
    # the old rule could never terminate one of those at all
    wm_body = struct.pack('<HHI', 0x6161, 0, WINDOW) + b'w' * (WINDOW - 8)
    s13 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [b'\xAA' * 8])
    s13.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN, 0, 0)))
    for off in range(0, WINDOW, MAX_SEG):
        pay = wm_body[off:off + MAX_SEG]
        fl = sp_yy.ACK | (sp_yy.PSH | sp_yy.URG if (off + len(pay)) % WINDOW == 0 else 0)
        s13.on_frame(sp_yy.parse(build_yy_frame(fl, off, 0, pay)))
    chk('an object of exactly one window still completes, on its declared length',
        s13.received == [wm_body], len(s13.received[0]) if s13.received else None)

    # a peer that overshoots its own declared length must not smuggle trailing bytes in
    over_body = struct.pack('<HHI', 0x6161, 0, 200) + b'v' * 192
    s15 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [b'\xAA' * 8])
    s15.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN, 0, 0)))
    s15.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK | sp_yy.PSH | sp_yy.URG, 0, 0,
                                            over_body + b'JUNK')))
    chk('an object is trimmed to the length it declares',
        s15.received == [over_body], len(s15.received[0]) if s15.received else None)

    # a peer that never fills the hole must not leave a truncated object behind
    s14 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [b'\xAA' * 8])
    s14.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN, 0, 0)))
    for i in (0, 2):
        off, pay = segs[i]
        s14.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK | sp_yy.PSH | sp_yy.URG, off, 0, pay)))
    chk('a peer that goes silent mid-object leaves NOTHING, not a fragment',
        s14.received == [] and not s14.done, s14.received)

    # an unanswered SYN must be repeated, then given up on
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

    # a duplicate SYN|ACK must not rewind a stream that is already running
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

    # a handshake ACK at the head of an object must not read as a duplicate cumulative ACK.
    # Replayed from relay_1788439266.log, where raising the payload rate to 11 Mbps drained the
    # send window fast enough to expose this: four retransmits of a 14,224 B object in 26 ms.
    head_sent = []
    s13 = YYSession(lambda f, sq, a, p=b'': (head_sent.append((f, sq, a)), True)[1],
                    lambda m, l=1: None, [b'\xAB' * 4000])
    s13.start_send()
    s13.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN | sp_yy.ACK, 0, 0)))
    chk('the window is fully drained, as it is at 11 Mbps', s13.segs == [], len(s13.segs))
    for _ in range(4):                              # the peer's ack=0 handshake ACKs
        s13.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK, 0, 0)))
    chk('ack=0 before any progress is NOT read as a duplicate', s13.stats['resends'] == 0,
        s13.stats['resends'])
    chk('and the object is not rewound', s13.tx_acked == 0 and s13.tx_seq == 4000, s13.tx_seq)
    # once real progress exists, a genuinely repeated ACK still triggers the resend
    s13.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK, 0, 1452)))
    for _ in range(DUP_ACK_RETRANSMIT):
        s13.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK, 0, 1452)))
    chk('a repeated ACK after real progress still retransmits', s13.stats['resends'] == 1,
        s13.stats['resends'])
    # and total silence at the head of an object is still covered by the timer backstop
    s14 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [b'\xAC' * 4000])
    s14.start_send()
    s14.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN | sp_yy.ACK, 0, 0)))
    s14.last_progress -= RETRANSMIT_AFTER + 0.1
    s14.poll()
    chk('a first window that really was lost is still resent, by the timer',
        s14.stats['resends'] == 1, s14.stats['resends'])

    # start_send() must never restart an object that is already in flight
    s12 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [b'\xEE' * 4000])
    s12.start_send()
    s12.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN | sp_yy.ACK, 0, 0)))
    mid = s12.tx_seq
    chk('an object is in flight', mid > 0, mid)
    chk('start_send() refuses to restart it', s12.start_send() is False and s12.tx_seq == mid,
        s12.tx_seq)

    # -- repeating our 0x81 when the console answers it with nothing ------------------------
    # The console's send thread is woken only by cecd 0x112460, called from 0x107538 when our
    # 0x81 arrives; if that wake-up misses, nothing retries and the console stays parked in
    # state 0x31 for the rest of the pass. Repeating the 0x81 buys another wake-up attempt.
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
    s15.idle_since -= 1.0                            # the peer's turn expires
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

    # off by default: an unconfigured session must behave exactly as before
    s16 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [man, msg])
    s16.start_send()
    s16.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN | sp_yy.ACK, 0, 0)))
    s16.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK, 0, len(man))))
    s16.idle_since -= 1.0
    s16.poll()
    chk('with no repeat configured the outbox is untouched',
        len(s16.outbox) == 2 and s16.tx_obj is msg, len(s16.outbox))

    # the repeat must not fire anywhere except immediately after the manifest
    s17 = YYSession(lambda f, sq, a, p=b'': True, lambda m, l=1: None, [msg, man, msg])
    s17.repeat_slot, s17.repeat_max = 1, 3
    s17.start_send()
    s17.on_frame(sp_yy.parse(build_yy_frame(sp_yy.SYN | sp_yy.ACK, 0, 0)))
    s17.on_frame(sp_yy.parse(build_yy_frame(sp_yy.ACK, 0, len(msg))))
    s17.idle_since -= 1.0
    s17.poll()
    chk('a silent peer after some OTHER object triggers no repeat',
        s17.repeats_done == 0 and len(s17.outbox) == 3, s17.repeats_done)

    print('\n%d/%d checks passed' % (ok, tot))
    return 0 if ok == tot else 1


if __name__ == '__main__':
    import sys
    sys.exit(_selftest())
