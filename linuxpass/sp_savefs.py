#!/usr/bin/env python3
"""
Reader for the 3DS "SAVE" inner filesystem (the inner FAT of a DISA container).

WHY. Carving a save image for CEC messages by magic finds only the ones stored contiguously: of the
7 Mii Plaza containers carved out of a real 28 MB CEC partition, **only 1 had a valid HMAC** -- the
other 6 were fragmented across non-adjacent blocks. Reading the filesystem properly fixes that and
also recovers the real paths, which is what tells inbox from outbox and names the title.

FORMAT, derived from the image and validated against known-good data:

  SAVE header
    +0x00  "SAVE"            +0x08 u64 fs-info offset      +0x18 u32 image block size
    +0x04  u32 0x00040000    +0x10 u64 image size (blocks)

  filesystem info (at the fs-info offset)
    +0x04 u32 data region block size     +0x28 u64 FAT offset       +0x38 u64 data region offset
    +0x08 u64 dir hash table offset      +0x30 u32 FAT entry count  +0x40 u32 data region blocks
    +0x18 u64 file hash table offset
    +0x48/+0x58  directory / file entry table. In the DUPLICATE_DATA layout these live inside the
                 data region and the low u32 is a data-region BLOCK index (0 and 1 here).

  directory entry, 0x28 bytes:  +0x00 u32 parent, +0x04 char name[16]
  file entry,      0x30 bytes:  +0x00 u32 parent, +0x04 char name[16],
                                +0x1C u32 first block, +0x20 u64 size
  Entry 0 of each table is a header, not an entry.

  FAT: 8 bytes per node, **node index = data block index + 1**.
    u: bit31 = start-of-chain, low31 = previous node
    v: bit31 = this node heads a multi-block run, low31 = next node (0 = end)
    when v's bit31 is set, fat[node+1] = {run start, run end} (inclusive, in node indices)

VALIDATED three independent ways in `--selftest`:
  * `eventlog.dat` reads as exactly 200020 bytes over 49 blocks -- and 200020 is the size of the
    same file in an unrelated emulator NAND;
  * `MBoxList____` reads as 396 bytes starting with the `hh` magic;
  * a Mii Plaza OutBox message reassembled from a fragmented 8-block chain **verifies its
    HMAC-SHA256** -- a 1-in-2^256 oracle that the chain walk is right.
"""
import struct

SAVE_MAGIC = b'SAVE'
DIR_ENTRY = 0x28
FILE_ENTRY = 0x30


class SaveFS:
    def __init__(self, data):
        self.d = data
        if data[:4] != SAVE_MAGIC:
            raise ValueError('not a SAVE image (magic %r)' % data[:4])
        fi = struct.unpack_from('<Q', data, 8)[0]
        self.block_size = struct.unpack_from('<I', data, fi + 0x04)[0]
        self.fat_off = struct.unpack_from('<Q', data, fi + 0x28)[0]
        self.fat_count = struct.unpack_from('<I', data, fi + 0x30)[0]
        self.data_off = struct.unpack_from('<Q', data, fi + 0x38)[0]
        self.data_blocks = struct.unpack_from('<I', data, fi + 0x40)[0]
        self.dir_tab = self.data_off + struct.unpack_from('<I', data, fi + 0x48)[0] * self.block_size
        self.max_dirs = struct.unpack_from('<I', data, fi + 0x50)[0]
        self.file_tab = self.data_off + struct.unpack_from('<I', data, fi + 0x58)[0] * self.block_size
        self.max_files = struct.unpack_from('<I', data, fi + 0x60)[0]

    # ---- raw tables ----
    def _fat(self, node):
        return struct.unpack_from('<II', self.d, self.fat_off + node * 8)

    def dir_entry(self, i):
        o = self.dir_tab + i * DIR_ENTRY
        return {'parent': struct.unpack_from('<I', self.d, o)[0],
                'name': self.d[o + 4:o + 0x14].split(b'\0')[0].decode('latin1')}

    def file_entry(self, i):
        o = self.file_tab + i * FILE_ENTRY
        return {'parent': struct.unpack_from('<I', self.d, o)[0],
                'name': self.d[o + 4:o + 0x14].split(b'\0')[0].decode('latin1'),
                'block': struct.unpack_from('<I', self.d, o + 0x1C)[0],
                'size': struct.unpack_from('<Q', self.d, o + 0x20)[0]}

    # ---- block chains ----
    def chain(self, first_block, limit=None):
        """Data-region block indices for a file, following the FAT. Node = block + 1."""
        limit = limit or self.data_blocks + 2
        node, blocks, seen = first_block + 1, [], set()
        while node:
            if node in seen or node > self.fat_count or len(blocks) > limit:
                raise ValueError('bad FAT chain at node %d' % node)
            seen.add(node)
            _u, v = self._fat(node)
            nxt = v & 0x7FFFFFFF
            if v & 0x80000000:                      # multi-block run
                _su, sv = self._fat(node + 1)
                end = sv & 0x7FFFFFFF
                if not (node <= end <= self.fat_count):
                    raise ValueError('bad run %d..%d' % (node, end))
                blocks.extend(range(node - 1, end))
            else:
                blocks.append(node - 1)
            node = nxt
        return blocks

    def read(self, entry):
        out = bytearray()
        for b in self.chain(entry['block']):
            o = self.data_off + b * self.block_size
            out += self.d[o:o + self.block_size]
            if len(out) >= entry['size']:
                break
        if len(out) < entry['size']:
            raise ValueError('short read for %r' % entry['name'])
        return bytes(out[:entry['size']])

    # ---- tree ----
    def path_of_dir(self, i, _depth=0):
        parts = []
        while i and _depth < 32:
            e = self.dir_entry(i)
            if not e['name']:
                break
            parts.append(e['name'])
            if e['parent'] == i:
                break
            i = e['parent']; _depth += 1
        return '/'.join(reversed(parts))

    def files(self):
        """-> [{'path', 'name', 'size', 'block', 'index'}] for every non-empty file entry."""
        out = []
        for i in range(1, self.max_files):
            try:
                e = self.file_entry(i)
            except struct.error:
                break
            if not e['name'] or not e['size'] or e['size'] > (1 << 32):
                continue
            e['index'] = i
            e['path'] = (self.path_of_dir(e['parent']) + '/' + e['name']).lstrip('/')
            out.append(e)
        return out


def _selftest():
    import os, hashlib, hmac
    ok = tot = 0

    def chk(name, cond, got=''):
        nonlocal ok, tot
        tot += 1; ok += bool(cond)
        print('  [%s] %s%s' % ('PASS' if cond else 'FAIL', name, ('  %s' % (got,)) if got else ''))

    import lp_corpus as corpus
    img = corpus.path('console_nand_3') or corpus.path('console_nand') or ''
    if not os.path.exists(img):
        print('  no console save image in the corpus -- structural checks only')
        chk('a non-SAVE blob is rejected', _raises(lambda: SaveFS(b'XXXX' + b'\0' * 64)))
        print('\n%d/%d checks passed' % (ok, tot)); return 0 if ok == tot else 1

    fs = SaveFS(open(img, 'rb').read())
    chk('header parses', fs.block_size == 0x1000 and fs.data_off == 0x13000,
        '%#x %#x' % (fs.block_size, fs.data_off))
    files = {f['path']: f for f in fs.files()}
    chk('the tree is a plausible CEC store (50..500 files)', 50 <= len(files) <= 500, str(len(files)))

    ev = files.get('eventlog.dat')
    chk('eventlog.dat found', ev is not None)
    if ev:
        chk('its size matches the same file in an unrelated emulator NAND',
            ev['size'] == 200020, str(ev['size']))
        chk('its chain is 49 blocks (ceil(200020/4096))', len(fs.chain(ev['block'])) == 49)
        chk('it reads to exactly its stated size', len(fs.read(ev)) == 200020)

    ml = files.get('CEC/MBoxList____')
    chk('CEC/MBoxList____ found', ml is not None)
    if ml:
        d = fs.read(ml)
        chk('it is 396 bytes and starts with the hh magic',
            len(d) == 396 and d[:2] == b'hh', '%d %r' % (len(d), d[:2]))

    # the decisive one: a fragmented Plaza message must verify its HMAC
    import sp_cec, sp_build
    plaza = [f for p, f in files.items()
             if p.startswith('CEC/00020800/') and f['name'].startswith('_')]
    chk('Mii Plaza box messages found', len(plaza) >= 1, str(len(plaza)))
    good = 0
    for f in plaza:
        try:
            m = fs.read(f)
            h = sp_cec.parse_header(m)
            body = m[h['header_size']:h['header_size'] + h['body_size']]
            tag = m[h['header_size'] + h['body_size']:h['total_size']]
            if tag == hmac.new(sp_build.plaza_hmac_key(), body, hashlib.sha256).digest():
                good += 1
        except Exception:
            pass
    chk('EVERY Mii Plaza message verifies its HMAC (carving got 1 of 7)',
        good == len(plaza), '%d/%d' % (good, len(plaza)))
    chk('a corrupt chain raises rather than returning junk',
        _raises(lambda: fs.chain(fs.fat_count + 10)))
    print('\n%d/%d checks passed' % (ok, tot))
    return 0 if ok == tot else 1


def _raises(fn):
    try:
        fn(); return False
    except (ValueError, struct.error):
        return True


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] != '--selftest':
        fs = SaveFS(open(sys.argv[1], 'rb').read())
        for f in sorted(fs.files(), key=lambda x: x['path']):
            print('%9d  %s' % (f['size'], f['path']))
        sys.exit(0)
    sys.exit(_selftest())
