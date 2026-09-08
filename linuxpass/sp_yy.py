#!/usr/bin/env python3
"""sp_yy.py - the StreetPass exchange transport ("YY") that lives inside the CCMP payload.

Reconstructed from cecd/code.bin, 29 Aug 2026 (see YY_TRANSPORT.md).  Every frame cecd
sends over nwm::CEC cmd 0x18 is one 802.3 frame:

    +0x00  dst MAC (6)                 the peer
    +0x06  src MAC (6)                 own MAC, from nwm::CEC cmd 0x16/0x17
    +0x0C  03 e8                       constant; role unresolved (see notes)
    +0x0E  aa aa 03 00 00 00           LLC/SNAP
    +0x14  08 00                       constant SNAP protocol id
    +0x16  00 00                       always zero (aligns the header below to 4)
    +0x18  YY header, 24 bytes:
             +0x00 u16  magic  = 0x5959          ("YY", little-endian on the wire)
             +0x02 u16  length = whole frame incl. this 0x18 prefix
             +0x04 u16  0xDEAD                   constant
             +0x06 u16  0xBEAF                   constant
             +0x08 u32  seq                      first payload byte of this segment
             +0x0C u32  ack                      next byte expected from the peer
             +0x10 u8   data_offset / 4          always 12 -> payload at frame+0x30
             +0x11 u8   flags                    TCP bit values, see FLAGS
             +0x12 u16  window                   receiver's free buffer space
             +0x14 u32  zero
    +0x30  payload, at most 0x5AC (1452) bytes

All YY fields are LITTLE-endian.  On air the chip strips the 14-byte 802.3 header, so the
decrypted 802.11 MSDU begins at +0x0E:  aa aa 03 00 00 00 08 00 00 00 59 59 ...
The parser below anchors on the 8-byte signature `59 59 ?? ?? ad de af be` rather than on a
fixed offset, so it decodes whichever of those framings the capture actually shows.
"""
import struct

MAGIC = 0x5959
SIG_A = b'\x59\x59'
SIG_B = b'\xad\xde\xaf\xbe'          # the 0xDEAD / 0xBEAF constants, little-endian

HDR_LEN = 0x18                        # the YY header itself
FRAME_HDR = 0x30                      # data_offset*4 as cecd always emits it
MAX_SEG = 0x5AC                       # 1452, the largest payload cecd puts in one frame
MAX_FRAME = FRAME_HDR + MAX_SEG       # 1500

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
FLAG_NAMES = [(FIN, 'FIN'), (SYN, 'SYN'), (RST, 'RST'),
              (PSH, 'PSH'), (ACK, 'ACK'), (URG, 'END')]
# FIN/SYN/PSH/ACK are used exactly as in TCP.  0x20 is NOT "urgent": cecd sets it on the last
# segment of a CEC message and the receiver treats it as the message delimiter, so it is
# reported as END.  0x04 is never emitted; a frame carrying it is dropped by cecd unprocessed.


def flagstr(f):
    s = '|'.join(n for b, n in FLAG_NAMES if f & b)
    rest = f & ~0x3F
    return (s or '-') + (' +%#04x' % rest if rest else '')


def find_yy(buf, search=True):
    """Offset of the YY header in `buf`, or None.

    Tries the framings we expect first (802.11 MSDU, full 802.3 frame, bare header), then
    falls back to a scan so an unexpected outer layer still decodes.
    """
    for off in (0x0A, 0x18, 0x00, 0x08):
        if off + HDR_LEN <= len(buf) and buf[off:off+2] == SIG_A and buf[off+4:off+8] == SIG_B:
            return off
    if not search:
        return None
    i = buf.find(SIG_A)
    while i >= 0:
        if i + HDR_LEN <= len(buf) and buf[i+4:i+8] == SIG_B:
            return i
        i = buf.find(SIG_A, i + 1)
    return None


def parse(buf, yy_off=None):
    """Parse one frame. Returns a dict, or None if no YY header is present."""
    if yy_off is None:
        yy_off = find_yy(buf)
    if yy_off is None:
        return None
    h = buf[yy_off:yy_off + HDR_LEN]
    magic, length, c1, c2 = struct.unpack_from('<HHHH', h, 0)
    seq, ack = struct.unpack_from('<II', h, 8)
    doff4, flags, window = h[0x10], h[0x11], struct.unpack_from('<H', h, 0x12)[0]
    # frame_start is where the length field counts from: the header sits 0x18 into the frame
    frame_start = yy_off - 0x18
    hdr_bytes = doff4 * 4
    pay_len = length - hdr_bytes
    # payload begins hdr_bytes from frame_start; when the capture only holds the MSDU,
    # frame_start is negative and the payload still lands right after the YY header.
    pay_off = (frame_start + hdr_bytes) if frame_start >= 0 else (yy_off + HDR_LEN)
    payload = buf[pay_off:pay_off + pay_len] if 0 <= pay_len else b''
    return {
        'yy_off': yy_off, 'magic': magic, 'length': length,
        'const1': c1, 'const2': c2, 'seq': seq, 'ack': ack,
        'data_offset': hdr_bytes, 'flags': flags, 'window': window,
        'payload': payload, 'payload_len': pay_len,
        'truncated': len(payload) != max(pay_len, 0),
        'ok': (magic == MAGIC and c1 == 0xDEAD and c2 == 0xBEAF
               and hdr_bytes >= HDR_LEN and 0 <= pay_len <= MAX_SEG),
    }


def reassemble(frames):
    """frames: iterable of parsed dicts (one direction).  -> (messages, stats)

    Ordering is by the YY sequence number, NOT by capture order or CCMP PN: a retransmission
    repeats a sequence number, and cecd will resend a segment whose ACK did not arrive.
    Segmentation is BY CONNECTION, not by the END flag.  cecd opens a fresh YY connection for
    every CEC object and sequence numbers restart at 0 in each one, so pooling a whole direction
    by seq destroys all but one object -- measured on sweep_new: seq 0 occurs **33 times** in a
    single direction.  A connection begins at the frame carrying SYN.

    END (0x20) is a FLUSH/ACK point, not a message delimiter.  Measured on the same capture, the
    END-flagged segments of one 32,732-byte object end at 0x38B8, 0x7170 and 0x7FDC, and the peer
    ACKs exactly those values; 0x38B8 == 14520 == the advertised window and 0x7170 == 2*14520.
    So END lands on every window boundary, and only coincides with end-of-object for objects that
    fit in one window.  A connection is COMPLETE when its highest-seq data segment carries END;
    otherwise its bytes are returned as `tail`.
    """
    conns, cur_conn = [], []
    ctrl_all, dupes = [], 0
    for f in frames:
        if not f or not f['ok']:
            continue
        if (f['flags'] & SYN) and cur_conn:
            conns.append(cur_conn)
            cur_conn = []
        cur_conn.append(f)
    if cur_conn:
        conns.append(cur_conn)

    msgs, gaps, tail = [], [], b''
    ndata = 0
    incomplete = 0
    for c in conns:
        data = {}
        for f in c:
            if f['payload_len'] == 0:
                ctrl_all.append(f)
                continue
            prev = data.get(f['seq'])
            if prev is not None:
                dupes += 1
                if len(prev['payload']) >= len(f['payload']):
                    continue
            data[f['seq']] = f
        if not data:
            continue
        ndata += len(data)
        buf, expect = bytearray(), None
        for seq in sorted(data):
            f = data[seq]
            if expect is not None and seq != expect:
                gaps.append((expect, seq))
            buf += f['payload']
            expect = seq + len(f['payload'])
        last = data[max(data)]
        if last['flags'] & URG:
            msgs.append(bytes(buf))          # final segment flushed -> object is whole
        else:
            incomplete += 1
            tail = bytes(buf)                # truncated: peer's tail was not captured

    stats = {
        'data_frames': ndata, 'ctrl_frames': len(ctrl_all), 'dupes': dupes,
        'gaps': gaps, 'missing': sum(hi - lo for lo, hi in gaps),
        'complete_messages': len(msgs), 'tail_bytes': len(tail),
        'connections': len(conns), 'incomplete': incomplete,
        'syn': sum(1 for f in ctrl_all if f['flags'] & SYN),
        'fin': sum(1 for f in ctrl_all if f['flags'] & FIN),
    }
    return msgs, tail, stats


def describe(f):
    return ('seq=0x%08X ack=0x%08X %-16s win=%-6d len=%-5d payload=%d'
            % (f['seq'], f['ack'], flagstr(f['flags']), f['window'],
               f['length'], f['payload_len']))
