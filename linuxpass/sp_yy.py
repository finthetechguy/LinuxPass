#!/usr/bin/env python3
"""The StreetPass exchange transport (YY) inside the CCMP payload."""
import struct

MAGIC = 0x5959
SIG_A = b'\x59\x59'
SIG_B = b'\xad\xde\xaf\xbe'          # the 0xDEAD / 0xBEAF constants, little-endian

HDR_LEN = 0x18
FRAME_HDR = 0x30                      # data_offset*4 as cecd always emits it
MAX_SEG = 0x5AC                       # 1452, the largest payload cecd puts in one frame
MAX_FRAME = FRAME_HDR + MAX_SEG

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
FLAG_NAMES = [(FIN, 'FIN'), (SYN, 'SYN'), (RST, 'RST'),
              (PSH, 'PSH'), (ACK, 'ACK'), (URG, 'END')]
# 0x20 marks the last segment of a CEC message. cecd drops frames carrying 0x04.


def flagstr(f):
    s = '|'.join(n for b, n in FLAG_NAMES if f & b)
    rest = f & ~0x3F
    return (s or '-') + (' +%#04x' % rest if rest else '')


def find_yy(buf, search=True):
    """Offset of the YY header in `buf`, or None."""
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
    frame_start = yy_off - 0x18
    hdr_bytes = doff4 * 4
    pay_len = length - hdr_bytes
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
    """frames: iterable of parsed dicts (one direction)."""
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
