#!/usr/bin/env python3
"""A CEC message store on disk, shaped like a console's."""
import os, json, stat, time, struct, base64, hashlib, hmac as _hmac

import sp_cec

MBOXLIST_MAGIC, MBOXINFO_MAGIC, BOXINFO_MAGIC = 0x6868, 0x6363, 0x6262
# Kept outside CEC/ so the tree stays byte-comparable with a console's.
META_FILE = 'store_meta.json'
MBOXLIST_HDR, MBOXLIST_ENTRY, MBOXLIST_MAX = 12, 16, 24
BOXES = {'inbox': 'InBox___', 'outbox': 'OutBox__'}
DEFAULT_MAX_BYTES, DEFAULT_MAX_MESSAGES = 0x100000, 24


def _write_private(path, data):
    """Write `data` to `path`, readable only by its owner even if the file already existed."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(data)


def message_filename(container):
    """`_` + base64 of the 8-byte message id, '/' -> '-', unpadded."""
    mid = container[0x20:0x28]
    return '_' + base64.b64encode(mid).decode().rstrip('=').replace('/', '-')


class Store:
    """A directory holding CEC messages, in the console's own shape."""

    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.last_evicted = 0
        self.cec = os.path.join(self.root, 'CEC')
        os.makedirs(self.cec, mode=0o700, exist_ok=True)
        self._lock_down()
        if not os.path.exists(self._mboxlist_path()):
            self._write_mboxlist([])
        if not os.path.exists(self._meta_path()):
            self._save_meta({'keyed_titles': ['%08x' % t for t in self.titles()], 'origins': {}})

    def _lock_down(self):
        """Close up a store written before its files were private."""
        if stat.S_IMODE(os.stat(self.cec).st_mode) == 0o700:
            return
        try:
            for d, _dirs, files in os.walk(self.cec):
                os.chmod(d, 0o700)
                for f in files:
                    os.chmod(os.path.join(d, f), 0o600)
            if os.path.exists(self._meta_path()):
                os.chmod(self._meta_path(), 0o600)
        except PermissionError:
            pass

    def _meta_path(self):
        return os.path.join(self.root, META_FILE)

    def _load_meta(self):
        try:
            m = json.load(open(self._meta_path()))
        except (OSError, ValueError):
            m = {}
        m.setdefault('keyed_titles', [])
        m.setdefault('origins', {})
        legacy = [k for k in m['origins'] if '/' not in k]
        if legacy:
            for k in legacy:
                v = m['origins'].pop(k)
                m['origins'].setdefault('%s/%s' % (v.get('box', 'inbox'), k), v)
            self._save_meta(m)
        return m

    def _save_meta(self, m):
        tmp = self._meta_path() + '.tmp'
        _write_private(tmp, json.dumps(m, indent=1, sort_keys=True).encode())
        os.replace(tmp, self._meta_path())

    @staticmethod
    def _okey(mid, box):
        return '%s/%s' % (box, mid.hex() if isinstance(mid, (bytes, bytearray)) else mid)

    def origin(self, container_or_id, box='outbox'):
        """-> {'source', 'when', 'box'} for one message IN ONE BOX, or None if never recorded."""
        mid = (container_or_id[0x20:0x28] if len(container_or_id) > 0x28 else container_or_id)
        m = self._load_meta()['origins']
        return m.get(self._okey(mid, box))

    def origins(self):
        return self._load_meta()['origins']

    def is_from_air(self, container_or_id, box='outbox'):
        o = self.origin(container_or_id, box)
        return bool(o) and str(o.get('source', '')).startswith('air:')

    def _mboxlist_path(self):
        return os.path.join(self.cec, 'MBoxList____')

    def _title_dir(self, tid):
        return os.path.join(self.cec, '%08x' % tid)

    def _box_dir(self, tid, box):
        return os.path.join(self._title_dir(tid), BOXES[box])

    def _make_title_dirs(self, tid):
        os.makedirs(self._title_dir(tid), mode=0o700, exist_ok=True)
        for box in BOXES:
            os.makedirs(self._box_dir(tid, box), mode=0o700, exist_ok=True)

    def _write_mboxlist(self, titles):
        if len(titles) > MBOXLIST_MAX:
            raise ValueError('a store holds at most %d titles, got %d'
                             % (MBOXLIST_MAX, len(titles)))
        b = bytearray(MBOXLIST_HDR + MBOXLIST_MAX * MBOXLIST_ENTRY)
        struct.pack_into('<HHII', b, 0, MBOXLIST_MAGIC, 0, 1, len(titles))
        for i, t in enumerate(titles):
            b[MBOXLIST_HDR + i * MBOXLIST_ENTRY:
              MBOXLIST_HDR + i * MBOXLIST_ENTRY + 8] = ('%08x' % t).encode()
        _write_private(self._mboxlist_path(), bytes(b))

    def titles(self):
        d = open(self._mboxlist_path(), 'rb').read()
        n = struct.unpack_from('<I', d, 8)[0]
        out = []
        for i in range(min(n, MBOXLIST_MAX)):
            s = d[MBOXLIST_HDR + i * MBOXLIST_ENTRY:MBOXLIST_HDR + i * MBOXLIST_ENTRY + 8]
            try:
                out.append(int(s.decode('ascii'), 16))
            except ValueError:
                pass
        return out

    def add_title(self, tid, name=None, hmac_key=None):
        """Register a title. Idempotent; a later call may fill in a name or key."""
        # Checked first, so a refused title leaves no directories behind.
        if tid not in self.titles() and len(self.titles()) >= MBOXLIST_MAX:
            raise ValueError('a store holds at most %d titles' % MBOXLIST_MAX)
        self._make_title_dirs(tid)
        if tid not in self.titles():
            ts = self.titles() + [tid]
            self._write_mboxlist(ts)
        info = bytearray(0x60)
        p = os.path.join(self._title_dir(tid), 'MBoxInfo____')
        if os.path.exists(p):
            info = bytearray(open(p, 'rb').read().ljust(0x60, b'\x00'))
        struct.pack_into('<HHI', info, 0, MBOXINFO_MAGIC, 0, 0)
        struct.pack_into('<I', info, 4, tid)
        if hmac_key is not None:
            if len(hmac_key) != 0x20:
                raise ValueError('an HMAC key is 32 bytes, got %d' % len(hmac_key))
            info[0x10:0x30] = hmac_key
            m = self._load_meta()
            if '%08x' % tid not in m['keyed_titles']:
                m['keyed_titles'].append('%08x' % tid)
                self._save_meta(m)
        _write_private(p, bytes(info))
        if name is not None:
            _write_private(os.path.join(self._title_dir(tid), 'MBoxData.010'),
                           name.encode('utf-16-le') + b'\x00\x00')
        for box in BOXES:
            self._write_boxinfo(tid, box)
        return tid

    def title_key(self, tid):
        """The title's 32-byte HMAC key, or None if we have no MBoxInfo for it."""
        p = os.path.join(self._title_dir(tid), 'MBoxInfo____')
        if not os.path.exists(p):
            return None
        if '%08x' % tid not in self._load_meta()['keyed_titles']:
            return None
        k = open(p, 'rb').read()[0x10:0x30]
        return k if len(k) == 0x20 else None

    def title_name(self, tid):
        p = os.path.join(self._title_dir(tid), 'MBoxData.010')
        if not os.path.exists(p):
            return None
        return sp_cec.decode_utf16_name(open(p, 'rb').read())

    def _write_boxinfo(self, tid, box):
        msgs = self.messages(tid, box)
        used = sum(len(c) for _t, _b, c in msgs)
        b = bytearray(0x20)
        struct.pack_into('<HHI', b, 0, BOXINFO_MAGIC, 0, 0x20)
        struct.pack_into('<IIII', b, 8, DEFAULT_MAX_BYTES, used, DEFAULT_MAX_MESSAGES, len(msgs))
        _write_private(os.path.join(self._box_dir(tid, box), 'BoxInfo_____'), bytes(b))

    def add_message(self, container, box='inbox', name=None, key=None, origin=None):
        """File one bare 0x6060 container."""
        if container[:2] != b'\x60\x60':
            raise ValueError('add_message takes a bare 0x6060 container; unwrap the envelope first')
        h = sp_cec.parse_header(container)
        tid = h['cec_title_id']
        container = container[:h['total_size']]
        if box == 'inbox' and len(container) > sp_cec.MAX_TOTAL:
            raise ValueError('a CEC message is at most %d B, got %d'
                             % (sp_cec.MAX_TOTAL, len(container)))
        if tid not in self.titles():
            self.add_title(tid, name=name, hmac_key=key)
        else:
            self._make_title_dirs(tid)
        p = os.path.join(self._box_dir(tid, box), message_filename(container))
        _write_private(p, container)
        self.last_evicted = self._trim_inbox(tid, p) if box == 'inbox' else 0
        self._write_boxinfo(tid, box)
        if origin is not None:
            m = self._load_meta()
            m['origins'][self._okey(container[0x20:0x28], box)] = {
                'source': str(origin), 'when': time.time(), 'box': box}
            self._save_meta(m)
        return p

    def _trim_inbox(self, tid, keep):
        """Hold a title's inbox to the limits BoxInfo declares, dropping the oldest. -> dropped."""
        d = self._box_dir(tid, 'inbox')
        found = []
        for fn in os.listdir(d):
            p = os.path.join(d, fn)
            if fn.startswith('_') and p != keep:
                st = os.stat(p)
                found.append((st.st_mtime_ns, fn, st.st_size, p))
        found.sort()
        count, used, dropped = len(found) + 1, os.stat(keep).st_size, 0
        used += sum(e[2] for e in found)
        for _t, _fn, size, p in found:
            if count <= DEFAULT_MAX_MESSAGES and used <= DEFAULT_MAX_BYTES:
                break
            with open(p, 'rb') as f:
                mid = f.read(0x28)[0x20:]
            self.remove_message(tid, 'inbox', mid)
            count, used, dropped = count - 1, used - size, dropped + 1
        return dropped

    def messages(self, tid=None, box=None):
        """-> [(title, box, container)] for every stored message matching the filters."""
        out = []
        for t in ([tid] if tid is not None else self.titles()):
            for b in ([box] if box is not None else sorted(BOXES)):
                d = self._box_dir(t, b)
                if not os.path.isdir(d):
                    continue
                for fn in sorted(os.listdir(d)):
                    if not fn.startswith('_'):
                        continue
                    out.append((t, b, open(os.path.join(d, fn), 'rb').read()))
        return out

    def remove_message(self, tid, box, container_or_id):
        mid = (container_or_id[0x20:0x28] if len(container_or_id) > 0x28 else container_or_id)
        fn = '_' + base64.b64encode(mid).decode().rstrip('=').replace('/', '-')
        p = os.path.join(self._box_dir(tid, box), fn)
        if os.path.exists(p):
            os.remove(p)
            self._write_boxinfo(tid, box)
            m = self._load_meta()
            if m['origins'].pop(self._okey(mid, box), None) is not None:
                self._save_meta(m)
            return True
        return False

    def remove_title(self, tid):
        """Forget a title entirely: its messages, its name, its key, its MBoxList entry."""
        import shutil
        n = 0
        for box in BOXES:
            for t, b, c in self.messages(tid, box):
                n += bool(self.remove_message(t, b, c))
        d = self._title_dir(tid)
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)
        self._write_mboxlist([t for t in self.titles() if t != tid])
        m = self._load_meta()
        key = '%08x' % tid
        if key in m['keyed_titles']:
            m['keyed_titles'].remove(key)
            self._save_meta(m)
        return n

    def clear_box(self, box):
        """Empty one box across every title."""
        n = 0
        for t, b, c in self.messages(box=box):
            if self.remove_message(t, b, c):
                n += 1
        return n

    def verify(self, tid, container):
        """-> True/False if we hold the title's key, None if we do not."""
        k = self.title_key(tid)
        if k is None:
            return None
        h = sp_cec.parse_header(container)
        body = container[h['header_size']:h['header_size'] + h['body_size']]
        tag = container[h['header_size'] + h['body_size']:h['total_size']]
        return len(tag) == 0x20 and _hmac.new(k, body, hashlib.sha256).digest() == tag

    def summary(self):
        og = self.origins()
        lines = []
        for t in self.titles():
            ms = self.messages(t)
            lines.append('  %08X  %-24s %s%d message(s): %s'
                         % (t, (self.title_name(t) or '?')[:24],
                            '' if self.title_key(t) is not None else '(no key) ', len(ms),
                            ', '.join('%s %d B' % (b, len(c)) for _t, b, c in ms) or '-'))
            for _t, b, c in ms:
                o = og.get(self._okey(c[0x20:0x28], b))
                if o:
                    lines.append('              %-6s %s' % (b, o.get('source')))
        return 'store %s, %d title(s)\n%s' % (self.root, len(self.titles()), '\n'.join(lines))


def _selftest():
    import tempfile, shutil, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import sp_cecstore, sp_savefs
    ok = tot = 0

    def chk(n, c, g=''):
        nonlocal ok, tot
        tot += 1; ok += bool(c)
        print('  [%s] %s%s' % ('PASS' if c else 'FAIL', n, ('  %s' % (g,)) if g else ''))

    tmp = tempfile.mkdtemp()
    try:
        def mode(p):
            return stat.S_IMODE(os.stat(p).st_mode)

        p0 = Store(os.path.join(tmp, 'private'))
        p0.add_title(0x00020800, name='Mii Plaza', hmac_key=b'k' * 32)
        p0.add_message(_synthetic(0x00020800, 1), 'inbox', origin='air:test')
        tdir = p0._title_dir(0x00020800)
        chk('the CEC tree is closed to other users', mode(p0.cec) == 0o700)
        chk('a title directory is private', mode(tdir) == 0o700)
        chk('a box directory is private', mode(p0._box_dir(0x00020800, 'inbox')) == 0o700)
        chk('the file holding the HMAC key is private',
            mode(os.path.join(tdir, 'MBoxInfo____')) == 0o600)
        chk('MBoxList, the sidecar and BoxInfo are private',
            {mode(p0._mboxlist_path()), mode(p0._meta_path()),
             mode(os.path.join(p0._box_dir(0x00020800, 'inbox'), 'BoxInfo_____'))} == {0o600})
        msg0 = [n for n in os.listdir(p0._box_dir(0x00020800, 'inbox')) if n.startswith('_')][0]
        chk('a stored message is private',
            mode(os.path.join(p0._box_dir(0x00020800, 'inbox'), msg0)) == 0o600)
        os.chmod(p0.cec, 0o755); os.chmod(tdir, 0o755); os.chmod(p0._meta_path(), 0o644)
        os.chmod(os.path.join(tdir, 'MBoxInfo____'), 0o644)
        Store(p0.root)
        chk('a store from an older version is closed up when it is opened',
            mode(p0.cec) == 0o700 and mode(tdir) == 0o700 and mode(p0._meta_path()) == 0o600
            and mode(os.path.join(tdir, 'MBoxInfo____')) == 0o600)

        lim = Store(os.path.join(tmp, 'limit'))
        for i in range(1, DEFAULT_MAX_MESSAGES + 7):
            lim.add_message(_synthetic(0x00030600, i), 'inbox', origin='air:test')
            time.sleep(0.005)
        ids = {int.from_bytes(c[0x20:0x28], 'little') for _t, _b, c in lim.messages(box='inbox')}
        chk('an inbox stops at its message limit', len(ids) == DEFAULT_MAX_MESSAGES, len(ids))
        chk('and the oldest messages are the ones dropped', min(ids) == 7 and max(ids) == 30, ids)
        chk('and the last add reports what it dropped', lim.last_evicted == 1, lim.last_evicted)
        chk('a dropped message loses its origin record too',
            len(lim.origins()) == DEFAULT_MAX_MESSAGES)
        lim.add_message(_synthetic(0x00030600, 30), 'inbox', origin='air:test')
        chk('receiving the same message again drops nothing',
            lim.last_evicted == 0 and len(lim.messages(box='inbox')) == DEFAULT_MAX_MESSAGES)
        for i in range(1, DEFAULT_MAX_MESSAGES + 7):
            lim.add_message(_synthetic(0x00030600, i), 'outbox')
        chk('the outbox is not limited', len(lim.messages(box='outbox')) == DEFAULT_MAX_MESSAGES + 6)
        big = Store(os.path.join(tmp, 'limit-bytes'))
        for i in range(1, 13):
            big.add_message(_synthetic(0x00030600, i, sp_cec.MAX_TOTAL), 'inbox')
            time.sleep(0.005)
        used = sum(len(c) for _t, _b, c in big.messages(box='inbox'))
        chk('an inbox stops at its byte limit', used <= DEFAULT_MAX_BYTES, used)
        chk('and still holds the newest message',
            12 in {int.from_bytes(c[0x20:0x28], 'little') for _t, _b, c in big.messages(box='inbox')})
        chk('an oversized message is refused for the inbox',
            _raises(lambda: big.add_message(_synthetic(0x00030600, 99, sp_cec.MAX_TOTAL + 4), 'inbox')))
        cap = Store(os.path.join(tmp, 'limit-titles'))
        for i in range(MBOXLIST_MAX):
            cap.add_message(_synthetic(0x00100000 + i, 1), 'inbox')
        over = 0x00100000 + MBOXLIST_MAX
        chk('a title past the store limit is refused',
            _raises(lambda: cap.add_message(_synthetic(over, 1), 'inbox')))
        chk('and leaves no directories behind', not os.path.exists(cap._title_dir(over)))

        import lp_corpus as corpus
        src = corpus.path('console_nand') or ''
        if not os.path.exists(src):
            print('  [SKIP] the rest of the suite: it is about importing a real console\n'
                  '         save image, and none is in the corpus (%s)' % corpus.why_skipped())
            print('\n%d/%d checks passed' % (ok, tot))
            return 0 if ok == tot else 1
        fs = sp_savefs.SaveFS(open(src, 'rb').read())
        meta = sp_cecstore.title_metadata(fs)
        files = {x['path']: x for x in fs.files()}

        s = Store(tmp)
        chk('a fresh store has no titles', s.titles() == [])
        chk('and its MBoxList parses as version 1, count 0',
            sp_cecstore.parse_mboxlist(open(s._mboxlist_path(), 'rb').read())
            == {'version': 1, 'count': 0, 'entries': [], 'titles': [], 'nonempty': []})

        n = 0
        for p in sorted(x for x in files if '/OutBox__/_' in x or '/InBox___/_' in x):
            c = fs.read(files[p])
            c = c if c[:2] == b'\x60\x60' else c[0x14:]
            t = sp_cec.parse_header(c)['cec_title_id']
            box = 'inbox' if '/InBox___/' in p else 'outbox'
            s.add_message(c, box, name=meta.get(t, {}).get('name'),
                          key=meta.get(t, {}).get('hmac_key'))
            n += 1
        chk('every message from the dump was filed', len(s.messages()) == n, len(s.messages()))
        chk('the title list matches the dump',
            sorted(s.titles()) == sorted(t for t in meta if meta[t]['inbox'] or meta[t]['outbox']),
            len(s.titles()))

        found = sp_cecstore.scan_tree(tmp)
        chk('sp_cecstore reads the store back', len(found) == n, len(found))
        chk('MBoxList round-trips through the reader',
            sorted(sp_cecstore.parse_mboxlist(open(s._mboxlist_path(), 'rb').read())['titles'])
            == sorted(s.titles()))

        bad = [(t, b) for t, b, c in s.messages() if s.verify(t, c) is False]
        chk('every stored message still verifies its HMAC', not bad, bad)
        chk('every title has its 32-byte key, all-zero ones included',
            all(s.title_key(t) is not None and len(s.title_key(t)) == 0x20 for t in s.titles()))
        chk('the keys are byte-identical to the dump\'s',
            all(s.title_key(t) == meta[t]['hmac_key'] for t in s.titles() if meta[t]['hmac_key']))
        chk("nintendogs' all-zero key is kept, and its message verifies under it",
            s.title_key(0x00030B00) == b'\x00' * 0x20 and
            all(s.verify(t, c) for t, _b, c in s.messages(0x00030B00)))
        chk('so did the names', s.title_name(0x00020800) == 'StreetPass Mii Plaza',
            s.title_name(0x00020800))
        s_odd = Store(os.path.join(tmp, 'oddname'))
        s_odd.add_title(0x001A0400, name=sp_cec.decode_utf16_name(
            'Super Mario Maker'.encode('utf-16-le') + b'\x00'))
        chk('an odd-length name file does not gain a replacement character',
            s_odd.title_name(0x001A0400) == 'Super Mario Maker',
            repr(s_odd.title_name(0x001A0400)))
        chk('and the name survives a rewrite unchanged',
            '\ufffd' not in (s_odd.title_name(0x001A0400) or ''))

        orig = {p.split('/')[-1] for p in files if '/OutBox__/_' in p or '/InBox___/_' in p}
        ours = set()
        for t in s.titles():
            for b in BOXES:
                d = s._box_dir(t, b)
                ours |= {f for f in os.listdir(d) if f.startswith('_')}
        chk('filenames are byte-identical to the console\'s', ours == orig,
            sorted(ours ^ orig)[:4])

        c0 = s.messages(0x00030600, 'outbox')[0][2]
        s.add_message(c0, 'outbox')
        chk('re-filing the same message does not duplicate it',
            len(s.messages(0x00030600, 'outbox')) == 1)
        bi = sp_cecstore.parse_boxinfo(
            open(os.path.join(s._box_dir(0x00030600, 'outbox'), 'BoxInfo_____'), 'rb').read())
        chk('BoxInfo counts the message and its bytes',
            bi['num_messages'] == 1 and bi['used_bytes'] == len(c0), bi)
        chk('a message can be removed', s.remove_message(0x00030600, 'outbox', c0)
            and s.messages(0x00030600, 'outbox') == [])
        chk('removing it again reports nothing to do',
            s.remove_message(0x00030600, 'outbox', c0) is False)
        chk('an enveloped message is refused', _raises(lambda: s.add_message(b'\x61\x61' + b'\x00' * 200)))
        chk('more than 24 titles is refused',
            _raises(lambda: s._write_mboxlist(list(range(25)))))

        s2 = Store(os.path.join(tmp, 'prov'))
        plaza = [c for _t, _b, c in s.messages(0x00020800)][0]
        s2.add_message(plaza, 'inbox', key=meta[0x00020800]['hmac_key'],
                       origin='air:96:58:cb:11:22:33')
        chk('a message records where it came from',
            s2.origin(plaza, 'inbox')['source'] == 'air:96:58:cb:11:22:33', s2.origin(plaza, 'inbox'))
        chk('and an air-sourced message is recognisable as one', s2.is_from_air(plaza, 'inbox'))
        chk('provenance survives reopening the store',
            Store(os.path.join(tmp, 'prov')).is_from_air(plaza, 'inbox'))
        mk7c = [c for _t, _b, c in s.messages(0x0008C500)][0]
        s2.add_message(mk7c, 'outbox', key=meta[0x0008C500]['hmac_key'],
                       origin='console_nand')
        chk('an imported message is NOT air-sourced', not s2.is_from_air(mk7c))
        chk('a message with no recorded origin reports None',
            Store(os.path.join(tmp, 'noprov')).origin(plaza, 'inbox') is None)
        s2.add_message(plaza, 'outbox', origin='/operator/dump.bin')
        chk('importing a copy does NOT erase the air record on the other box',
            s2.is_from_air(plaza, 'inbox') and not s2.is_from_air(plaza, 'outbox'),
            (s2.origin(plaza, 'inbox'), s2.origin(plaza, 'outbox')))
        s2.remove_message(0x00020800, 'inbox', plaza)
        chk('removing a message drops its provenance', s2.origin(plaza, 'inbox') is None)
        chk('and leaves the other box\'s record intact',
            s2.origin(plaza, 'outbox')['source'] == '/operator/dump.bin')

        s3 = Store(os.path.join(tmp, 'nokey'))
        s3.add_message(plaza, 'inbox')
        chk('a title we were never given a key for reports no key',
            s3.title_key(0x00020800) is None, s3.title_key(0x00020800))
        chk('and its message verifies as UNKNOWN, not as forged',
            s3.verify(0x00020800, plaza) is None, s3.verify(0x00020800, plaza))
        s3.add_title(0x00020800, hmac_key=meta[0x00020800]['hmac_key'])
        chk('supplying the key later makes it real',
            s3.title_key(0x00020800) == meta[0x00020800]['hmac_key'])
        chk('and the message now verifies', s3.verify(0x00020800, plaza) is True)
        chk("nintendogs' all-zero key still counts as a real key after the change",
            s.title_key(0x00030B00) == b'\x00' * 0x20)
        s4 = Store(os.path.join(tmp, 'migrate'))
        s4.add_message(plaza, 'outbox', key=meta[0x00020800]['hmac_key'])
        os.remove(s4._meta_path())
        chk('a pre-sidecar store keeps its keys when reopened',
            Store(os.path.join(tmp, 'migrate')).title_key(0x00020800)
            == meta[0x00020800]['hmac_key'])

        s6 = Store(os.path.join(tmp, 'rmtitle'))
        for t, b, c in s.messages():
            s6.add_message(c, b, key=meta.get(t, {}).get('hmac_key'))
        n_t = len(s6.titles())
        n_m = len(s6.messages(0x00020800))
        chk('removing a title reports the messages that went with it',
            s6.remove_title(0x00020800) == n_m, n_m)
        chk('the title is gone from the list',
            0x00020800 not in s6.titles() and len(s6.titles()) == n_t - 1)
        chk('its directory is gone from disk',
            not os.path.exists(s6._title_dir(0x00020800)))
        chk('and the reader agrees the store shrank',
            len(sp_cecstore.parse_mboxlist(open(s6._mboxlist_path(), 'rb').read())['titles'])
            == n_t - 1)
        other = [t for t in s6.titles() if meta.get(t, {}).get('hmac_key')][0]
        chk('other titles keep their keys', s6.title_key(other) == meta[other]['hmac_key'],
            '%08X' % other)
        chk('and their messages', len(s6.messages(other)) == len(s.messages(other)))
        chk('removing a title that is not there is not an error', s6.remove_title(0x00999900) == 0)

        sm = Store(os.path.join(tmp, 'legacy'))
        sm.add_message(plaza, 'inbox', origin='air:11:22:33:44:55:66')
        raw = json.load(open(sm._meta_path()))
        raw['origins'] = {k.split('/', 1)[1]: v for k, v in raw['origins'].items()}
        json.dump(raw, open(sm._meta_path(), 'w'))
        chk('an id-only origin record migrates to a per-box one instead of vanishing',
            Store(os.path.join(tmp, 'legacy')).is_from_air(plaza, 'inbox'),
            json.load(open(sm._meta_path()))['origins'])

        s5 = Store(os.path.join(tmp, 'swap'))
        for t, b, c in s.messages():
            s5.add_message(c, b)
        n_out = len(s5.messages(box='outbox'))
        n_in = len(s5.messages(box='inbox'))
        chk('clear_box empties one box and reports the count',
            s5.clear_box('outbox') == n_out and s5.messages(box='outbox') == [], n_out)
        chk('and leaves the other box alone', len(s5.messages(box='inbox')) == n_in, n_in)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print('\n%d/%d checks passed' % (ok, tot))
    return 0 if ok == tot else 1


def _synthetic(tid, n, size=0x200):
    """A bare container with just the header fields the store reads."""
    b = bytearray(size)
    struct.pack_into('<HH', b, 0, 0x6060, 0)
    struct.pack_into('<III', b, 4, size, 0x70, size - 0x90)
    struct.pack_into('<I', b, 0x10, tid)
    b[0x20:0x28] = n.to_bytes(8, 'little')
    return bytes(b)


def _raises(fn):
    try:
        fn(); return False
    except ValueError:
        return True


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2 or sys.argv[1] == '--selftest':
        sys.exit(_selftest())
    print(Store(sys.argv[1]).summary())
