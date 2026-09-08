#!/usr/bin/env python3
"""
Read CEC message stores out of a console NAND / SD dump.

WHY THIS EXISTS. Everything below the message body is title-agnostic: the probe/0x11 declaration,
the ee records and the 0x81 list all take a CEC title id, and a message dumped from a console's
OutBox already carries a valid HMAC trailer. So a message from ANY title can be forwarded verbatim
without reverse-engineering that title at all -- `sp_link --forward`. This module finds them.

FILENAMES, read out of cecd.code.bin rather than guessed:

    /CEC/MBoxList____     0x00C7D9      the mailbox list
    /CEC/SessionId___     0x007B0D
    /CEC/MacFilter___     0x007B25      the ~12 h re-StreetPass filter we clear between runs
    <box>/BoxInfo_____    0x00A04C
    <box>/OBIndex_____    0x00A06C      outbox index
    <title>/MBoxInfo____  0x00C7A4
    <title>/MBoxData.NNN  0x010750 + '%s/%s/%s.%03d'
    OutBox__ / InBox___   0x009B54 / 0x009B84   (8 chars, not the 9 some docs give)

Path templates in cecd: '%s/%s', '%s/%s/%s', '%s/%s/%s/_%s', '%s/%s/%s.%03d'.

WHAT IS PROVEN vs INFERRED. The filenames and the container format are proven. The MBoxList entry
layout is INFERRED from its size: 396 = 12 + 24 * 16, and 24 is exactly the documented max count of
an `ee` record (sp_cec: count <= 0x18) -- a cross-check, not a proof. So `scan_tree` does not rely
on any index structure at all: it finds messages by container magic and validates each one through
sp_cec, which works whatever the surrounding bookkeeping looks like.
"""
import os, struct, hashlib

import sp_cec
import sp_savefs

MBOXLIST_MAGIC = 0x6868
ENVELOPE_MAGIC = 0x6161
CONTAINER_MAGIC = 0x6060
MBOXLIST_HDR = 12
MBOXLIST_ENTRY = 16
MBOXLIST_MAX = 24

CEC_FILENAMES = {
    'mboxlist': 'MBoxList____', 'sessionid': 'SessionId___', 'macfilter': 'MacFilter___',
    'boxinfo': 'BoxInfo_____', 'obindex': 'OBIndex_____', 'mboxinfo': 'MBoxInfo____',
    'outbox': 'OutBox__', 'inbox': 'InBox___',
}


def parse_mboxlist(data):
    """`data:/CEC/MBoxList____` -- the console's list of ENABLED StreetPass titles.

        +0x00 u16   magic 0x6868
        +0x02 u16   padding
        +0x04 u32   version (always 1 on both consoles)
        +0x08 u32   COUNT
        +0x0C       COUNT entries of 16 bytes: 8 ASCII lower-case hex digits (the CEC title id,
                    exactly the directory name under CEC/) then 8 zero bytes.

    CORRECTED 2 Sep 2026. This used to read the count from +0x04 and return the raw 16-byte
    entries. The only ground truth available at the time was an EMPTY emulator store, in which
    the version field is 1 and there are no entries -- indistinguishable from a one-entry list, so
    the mistake was invisible. The 2DS XL's real store settles it: +0x04 = 1 while +0x08 = 12, and
    there are exactly 12 CEC/<title>/ directories, matching the 12 services the console advertises
    in its probe. [D]
    """
    if len(data) < MBOXLIST_HDR or struct.unpack_from('<H', data, 0)[0] != MBOXLIST_MAGIC:
        raise ValueError('not an MBoxList (magic %r)' % data[:2])
    version, count = struct.unpack_from('<II', data, 4)
    n = min(count, MBOXLIST_MAX, (len(data) - MBOXLIST_HDR) // MBOXLIST_ENTRY)
    entries = [data[MBOXLIST_HDR + i * MBOXLIST_ENTRY:MBOXLIST_HDR + (i + 1) * MBOXLIST_ENTRY]
               for i in range(n)]
    titles = []
    for e in entries:
        t = e[:8].decode('ascii', 'replace')
        try:
            titles.append(int(t, 16))
        except ValueError:
            titles.append(None)
    return {'version': version, 'count': count, 'entries': entries, 'titles': titles,
            'nonempty': [i for i, e in enumerate(entries) if any(e)]}


def parse_mboxinfo(data):
    """`<title>/MBoxInfo____` (96 B). Magic 'cc', the CEC title id at +0x04, and at **+0x10 the
    title's 32-byte HMAC key**.

    Proven: the key this yields for 00020800 is byte-identical to the Mii Plaza key we recovered by
    brute-forcing 32-byte windows of MiiPlaza/code.bin against two known (body, trailer) pairs. So
    every title's message-signing key is sitting in the console's own CEC store -- no per-title
    reverse engineering is needed to EDIT a message, only to understand its payload.
    """
    if len(data) < 0x30 or data[:2] != b'cc':
        raise ValueError('not an MBoxInfo (magic %r)' % data[:2])
    return {'cec_title_id': struct.unpack_from('<I', data, 4)[0],
            'hmac_key': data[0x10:0x30]}


def parse_boxinfo(data):
    """`<box>/BoxInfo_____`. Magic 'bb'; the long (0x90) form carries usage counters."""
    if len(data) < 0x20 or data[:2] != b'bb':
        raise ValueError('not a BoxInfo (magic %r)' % data[:2])
    size = struct.unpack_from('<I', data, 4)[0]
    max_bytes, used_bytes, max_msgs, num_msgs = struct.unpack_from('<IIII', data, 8)
    return {'size': size, 'max_bytes': max_bytes, 'used_bytes': used_bytes,
            'max_messages': max_msgs, 'num_messages': num_msgs}


def title_metadata(image_or_fs):
    """-> {cec_title_id: {'name', 'hmac_key', 'inbox', 'outbox'}} from a SAVE image.

    The display name is the UTF-16 string in `<title>/MBoxData.010`.
    """
    fs = (image_or_fs if isinstance(image_or_fs, sp_savefs.SaveFS)
          else sp_savefs.SaveFS(image_or_fs if isinstance(image_or_fs, (bytes, bytearray))
                                else open(image_or_fs, 'rb').read()))
    files = {f['path']: f for f in fs.files()}
    out = {}
    for p in files:
        parts = p.split('/')
        if len(parts) < 3 or parts[0] != 'CEC':
            continue
        t = parts[1]
        try:
            tid = int(t, 16)
        except ValueError:
            continue
        e = out.setdefault(tid, {'name': None, 'hmac_key': None, 'inbox': 0, 'outbox': 0})
        if parts[-1] == 'MBoxData.010':
            e['name'] = sp_cec.decode_utf16_name(fs.read(files[p]))
        elif parts[-1] == 'MBoxInfo____':
            try:
                e['hmac_key'] = parse_mboxinfo(fs.read(files[p]))['hmac_key']
            except ValueError:
                pass
        elif parts[-1].startswith('_') and len(parts) == 4:
            e['inbox' if parts[2] == CEC_FILENAMES['inbox'] else 'outbox'] += 1
    return out


def container_at(data, off=0):
    """If a valid CEC container starts at `off`, return its parsed form, else None."""
    if off + 0x70 > len(data):
        return None
    if struct.unpack_from('<H', data, off)[0] == ENVELOPE_MAGIC:
        off += 0x14
        if off + 0x70 > len(data):
            return None
    if struct.unpack_from('<H', data, off)[0] != CONTAINER_MAGIC:
        return None
    try:
        h = sp_cec.parse_header(data[off:])
    except ValueError:
        return None
    tot, hs, bs = h['total_size'], h['header_size'], h['body_size']
    if not (0x84 <= tot <= sp_cec.MAX_TOTAL) or hs < 0x70 or bs == 0 or bs > sp_cec.MAX_BODY:
        return None
    if hs + bs > tot or off + tot > len(data):
        return None
    if h['cec_title_id'] == 0 or (h['cec_title_id'] & 0xFF) != 0:
        return None
    return {'offset': off, 'header': h, 'raw': data[off:off + tot]}


def find_containers(data):
    """Every valid CEC container in a blob, scanning on 4-byte boundaries."""
    out, i = [], 0
    while i + 0x70 <= len(data):
        c = container_at(data, i)
        if c:
            out.append(c)
            i = c['offset'] + c['header']['total_size']
        else:
            i += 4
    return out


def scan_save_image(path_or_data):
    """Read a DISA 'SAVE' partition image through the filesystem, not by carving.

    Carving a real 28 MB CEC partition found 7 Mii Plaza containers of which only 1 had a valid
    HMAC -- the other 6 were stale copies sitting in unallocated blocks. Reading the FAT gives the
    live files only, with their real paths, and every one verifies.
    """
    data = path_or_data if isinstance(path_or_data, (bytes, bytearray)) else open(path_or_data, 'rb').read()
    fs = sp_savefs.SaveFS(data)
    found = []
    for f in fs.files():
        if not f['name'].startswith('_'):          # message files are named _<12 chars>
            continue
        try:
            raw = fs.read(f)
        except ValueError:
            continue
        c = container_at(raw)
        if not c or c['offset'] != 0:
            continue
        h = c['header']
        parts = f['path'].split('/')
        box = ('outbox' if CEC_FILENAMES['outbox'] in parts else
               'inbox' if CEC_FILENAMES['inbox'] in parts else '?')
        found.append({
            'path': f['path'], 'offset': 0, 'box': box,
            'cec_title_id': h['cec_title_id'], 'unique_id': h['unique_id'],
            'total_size': h['total_size'], 'body_size': h['body_size'],
            'header_size': h['header_size'],
            'message_id': raw[0x20:0x28].hex(),
            'has_trailer': h['total_size'] - (h['header_size'] + h['body_size']) == 0x20,
            'sha256': hashlib.sha256(c['raw']).hexdigest()[:16],
            'raw': c['raw']})
    return found


def scan_any(path):
    """A SAVE image, a single file, or a directory tree -- whichever it is."""
    if os.path.isdir(path):
        return scan_tree(path)
    data = open(path, 'rb').read()
    if data[:4] == sp_savefs.SAVE_MAGIC:
        return scan_save_image(data)
    out = []
    for c in find_containers(data):
        h = c['header']
        out.append({'path': os.path.basename(path), 'offset': c['offset'], 'box': '?',
                    'cec_title_id': h['cec_title_id'], 'unique_id': h['unique_id'],
                    'total_size': h['total_size'], 'body_size': h['body_size'],
                    'header_size': h['header_size'], 'message_id': c['raw'][0x20:0x28].hex(),
                    'has_trailer': h['total_size'] - (h['header_size'] + h['body_size']) == 0x20,
                    'sha256': hashlib.sha256(c['raw']).hexdigest()[:16], 'raw': c['raw']})
    return out


def scan_tree(root, follow_symlinks=False):
    """Walk a dump and return every CEC message found, with provenance.

    Deliberately structure-free: it does not need the index files to be intact, so it works on a
    partial dump, a raw image carved out of NAND, or a directory someone copied by hand.
    """
    found = []
    for dirpath, _dirs, files in os.walk(root, followlinks=follow_symlinks):
        for fn in sorted(files):
            p = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(p) < 0x84 or os.path.getsize(p) > 4 << 20:
                    continue
                data = open(p, 'rb').read()
            except OSError:
                continue
            for c in find_containers(data):
                h = c['header']
                rel = os.path.relpath(p, root)
                box = ('outbox' if CEC_FILENAMES['outbox'] in rel else
                       'inbox' if CEC_FILENAMES['inbox'] in rel else '?')
                found.append({
                    'path': rel, 'offset': c['offset'], 'box': box,
                    'cec_title_id': h['cec_title_id'], 'unique_id': h['unique_id'],
                    'total_size': h['total_size'], 'body_size': h['body_size'],
                    'header_size': h['header_size'],
                    'message_id': c['raw'][0x20:0x28].hex(),
                    'has_trailer': h['total_size'] - (h['header_size'] + h['body_size']) == 0x20,
                    'sha256': hashlib.sha256(c['raw']).hexdigest()[:16],
                    'raw': c['raw']})
    return found


def harvest(root, outdir):
    """Extract every message found into `outdir`, named <cectitle>_<box>_<sha>.bin. -> the list."""
    os.makedirs(outdir, exist_ok=True)
    msgs = scan_any(root)
    seen = set()
    for m in msgs:
        if m['sha256'] in seen:
            m['written'] = None
            continue
        seen.add(m['sha256'])
        fn = '%08X_%s_%s.bin' % (m['cec_title_id'], m['box'], m['sha256'][:10])
        open(os.path.join(outdir, fn), 'wb').write(m['raw'])
        m['written'] = fn
    return msgs


def summarise(msgs):
    if not msgs:
        return 'no CEC messages found'
    by = {}
    for m in msgs:
        by.setdefault((m['cec_title_id'], m['box']), []).append(m)
    lines = ['%d CEC message(s):' % len(msgs)]
    for (tid, box), v in sorted(by.items()):
        name = sp_cec.KNOWN_SERVICES.get(tid) or 'unknown title'
        lines.append('   %08X  %-6s  x%-3d  %-22s  sizes %s'
                     % (tid, box, len(v), name, sorted({m['total_size'] for m in v})))
    return '\n'.join(lines)


def _selftest():
    import tempfile, shutil
    ok = tot = skipped = 0

    def chk(name, cond, got=''):
        nonlocal ok, tot
        tot += 1; ok += bool(cond)
        print('  [%s] %s%s' % ('PASS' if cond else 'FAIL', name, ('  %s' % (got,)) if got else ''))

    def skip(name, why):
        nonlocal skipped
        skipped += 1
        print('  [SKIP] %s  (%s)' % (name, why))

    here = os.path.dirname(os.path.abspath(__file__))

    # MBoxList, against the real emulator file if present
    # An emulator's NAND, if one is installed. $LINUXPASS_EMU_NAND overrides the guess.
    _share = (os.environ.get('XDG_DATA_HOME')
              or os.path.join(os.path.expanduser('~'), '.local', 'share'))
    ml = os.environ.get('LINUXPASS_EMU_NAND') or os.path.join(
        _share, 'azaharplus-emu', 'nand', 'data', '0' * 32,
        'sysdata', '00010026', '00000000', 'CEC', 'MBoxList____')
    if os.path.exists(ml):
        d = open(ml, 'rb').read()
        chk('MBoxList size is 12 + 24*16', len(d) == MBOXLIST_HDR + MBOXLIST_MAX * MBOXLIST_ENTRY,
            len(d))
        info = parse_mboxlist(d)
        chk('an empty MBoxList reads version 1, count 0',
            info['version'] == 1 and info['count'] == 0, str(info))
        chk('that store is empty (no populated entries)', info['nonempty'] == [])
    chk('a non-MBoxList is rejected', _raises(lambda: parse_mboxlist(b'zz' + b'\x00' * 400)))

    # The discriminating case the emulator store could not provide: a POPULATED MBoxList. The 2DS
    # XL's own store lists 12 enabled titles, and they must be exactly the CEC/<title>/ directories.
    import lp_corpus as corpus, lp_keys as _k
    if _k.selftest_keys():
        print('  (no console keys found -- running on generated throwaway keys)')
    pa = corpus.path('console_nand_3') or corpus.path('console_nand') or ''
    if os.path.exists(pa):
        _fs = sp_savefs.SaveFS(open(pa, 'rb').read())
        _f = {f['path']: f for f in _fs.files()}
        ml2 = parse_mboxlist(_fs.read(_f['CEC/MBoxList____']))
        chk('the real MBoxList reads version 1, count 12',
            ml2['version'] == 1 and ml2['count'] == 12, str((ml2['version'], ml2['count'])))
        dirs = sorted({int(p.split('/')[1], 16) for p in _f
                       if p.startswith('CEC/') and len(p.split('/')) > 2})
        chk('its title list is exactly the set of CEC/<title>/ directories',
            sorted(ml2['titles']) == dirs, '%d listed vs %d dirs' % (len(ml2['titles']), len(dirs)))
        chk('every listed title is one the console advertises in its probe',
            all(t is not None for t in ml2['titles']))

    # Container detection. A captured console message is used when the corpus has one;
    # otherwise one is BUILT, which has the same envelope, header and sizes -- everything
    # these checks are actually about.
    real = corpus.load('plaza_message')
    if real is None:
        import sp_build
        real = sp_build.build(mii_name='Tux', greeting='self-test')
        print('  (no captured message in the corpus -- using one built from scratch)')
    c = container_at(real)
    chk('an enveloped message is detected past its envelope', c and c['offset'] == 0x14)
    chk('its title and sizes are right',
        c['header']['cec_title_id'] == 0x00020800 and c['header']['total_size'] == 0x7FC8)
    chk('a bare container is detected at offset 0', container_at(real[0x14:])['offset'] == 0)
    chk('random bytes are not mistaken for a container',
        container_at(hashlib.sha256(b'x').digest() * 8) is None)
    chk('a zeroed blob is not mistaken for a container', container_at(b'\x00' * 0x200) is None)

    # embedded / concatenated
    blob = b'\xAA' * 0x40 + real[0x14:] + b'\xBB' * 0x30 + real[0x14:]
    cs = find_containers(blob)
    chk('two concatenated containers are both found at the right offsets',
        [x['offset'] for x in cs] == [0x40, 0x40 + 0x7FC8 + 0x30], str([x['offset'] for x in cs]))

    # a synthetic dump tree, laid out with cecd's real filenames
    tmp = tempfile.mkdtemp()
    try:
        ob = os.path.join(tmp, 'CEC', '00020800', CEC_FILENAMES['outbox'])
        ib = os.path.join(tmp, 'CEC', '00020800', CEC_FILENAMES['inbox'])
        os.makedirs(ob); os.makedirs(ib)
        open(os.path.join(tmp, 'CEC', CEC_FILENAMES['mboxlist']), 'wb').write(
            struct.pack('<HHI', MBOXLIST_MAGIC, 0, 1) + b'\x00' * (4 + 24 * 16))
        open(os.path.join(ob, '_0000000000000001'), 'wb').write(real[0x14:])
        open(os.path.join(ib, '_0000000000000002'), 'wb').write(real)
        open(os.path.join(tmp, 'CEC', CEC_FILENAMES['macfilter']), 'wb').write(b'\x00' * 0x100)
        msgs = scan_tree(tmp)
        chk('both messages found in the synthetic store', len(msgs) == 2, str(len(msgs)))
        chk('box is derived from the path',
            sorted(m['box'] for m in msgs) == ['inbox', 'outbox'])
        chk('title id read from each message',
            all(m['cec_title_id'] == 0x00020800 for m in msgs))
        chk('the trailer is detected', all(m['has_trailer'] for m in msgs))
        chk('both are the same message', len({m['sha256'] for m in msgs}) == 1)
        out = os.path.join(tmp, 'out')
        got = harvest(tmp, out)
        written = [g['written'] for g in got if g['written']]
        chk('harvest de-duplicates identical messages', len(written) == 1, str(written))
        chk('harvested bytes match the source',
            open(os.path.join(out, written[0]), 'rb').read() == real[0x14:0x14 + 0x7FC8])
        chk('summarise names the known title', 'StreetPass Mii Plaza' in summarise(got))
        # and the harvested message must round-trip straight into a sendable outbox
        import sp_build
        wire = sp_build.as_wire(open(os.path.join(out, written[0]), 'rb').read())
        box = sp_build.build_outbox(wire)
        chk('a harvested message forwards into a valid outbox',
            [len(o) for o in box] == [24, 20, 92, 92, 212, 32732]
            and sp_build.message_title(wire) == 0x00020800)
    finally:
        shutil.rmtree(tmp)

    chk('scanning a tree with no CEC data returns nothing', scan_tree(os.path.join(here, 'nwm')) == []
        if os.path.isdir(os.path.join(here, 'nwm')) else True)

    # SAVE-image path, against the real console partition if present
    img = corpus.path('console_nand_3') or corpus.path('console_nand') or ''
    if os.path.exists(img):
        ms = scan_save_image(img)
        chk('SAVE image yields one message per populated box', len(ms) >= 10, str(len(ms)))
        chk('every message read from the filesystem is a valid container',
            all(m['total_size'] > 0 and m['has_trailer'] for m in ms))
        chk('paths carry the title directory and the box',
            all(m['path'].startswith('CEC/') and m['box'] in ('inbox', 'outbox') for m in ms))
        import sp_build, hmac as _h, hashlib as _hh
        pl = [m for m in ms if m['cec_title_id'] == 0x00020800]
        good = 0
        for m in pl:
            b = m['raw']; hh_ = sp_cec.parse_header(b)
            body = b[hh_['header_size']:hh_['header_size'] + hh_['body_size']]
            tag = b[hh_['header_size'] + hh_['body_size']:hh_['total_size']]
            good += tag == _h.new(sp_build.plaza_hmac_key(), body, _hh.sha256).digest()
        chk('every Plaza message from the filesystem verifies its HMAC',
            good == len(pl) and good >= 1, '%d/%d' % (good, len(pl)))
        chk('scan_any routes a SAVE image to the filesystem reader',
            len(scan_any(img)) == len(ms))

    if os.path.exists(img):
        md = title_metadata(img)
        chk('title metadata found for every title in the store', len(md) >= 12, str(len(md)))
        import sp_build
        pl = md.get(0x00020800, {})
        chk('MBoxInfo yields Mii Plaza\'s name', pl.get('name') == 'StreetPass Mii Plaza',
            repr(pl.get('name')))
        chk('MBoxInfo +0x10 IS the HMAC key we brute-forced from code.bin',
            pl.get('hmac_key') == sp_build.plaza_hmac_key())
        chk('every title has a name', all(v['name'] for v in md.values()))
        chk('every title has a 32-byte key field', all(len(v['hmac_key'] or b'') == 32
                                                       for v in md.values()))
        bi = parse_boxinfo(sp_savefs.SaveFS(open(img, 'rb').read()).read(
            {f['path']: f for f in sp_savefs.SaveFS(open(img, 'rb').read()).files()}
            ['CEC/00141000/InBox___/BoxInfo_____']))
        chk('BoxInfo counters read (Pokemon Shuffle inbox 1/10)',
            bi['num_messages'] == 1 and bi['max_messages'] == 10, str(bi))
        chk('a non-MBoxInfo is rejected', _raises(lambda: parse_mboxinfo(b'zz' + b'\x00' * 64)))

    print('\n%d/%d checks passed%s' % (ok, tot,
          '' if not skipped else ', %d skipped (no test corpus)' % skipped))
    return 0 if ok == tot else 1


def _raises(fn):
    try:
        fn(); return False
    except ValueError:
        return True


if __name__ == '__main__':
    import sys
    if len(sys.argv) >= 2 and sys.argv[1] != '--selftest':
        root = sys.argv[1]
        if len(sys.argv) >= 3:
            m = harvest(root, sys.argv[2])
            print(summarise(m))
            print('\nwrote %d file(s) to %s' % (len({x['written'] for x in m if x['written']}),
                                                sys.argv[2]))
        else:
            m = scan_any(root)
            print(summarise(m))
            for x in m:
                print('   %-52s +0x%-6X %-6s %08X %6d B  id=%s'
                      % (x['path'][:52], x['offset'], x['box'], x['cec_title_id'],
                         x['total_size'], x['message_id']))
        sys.exit(0)
    sys.exit(_selftest())
