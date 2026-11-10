#!/usr/bin/env python3
"""LinuxPass: a daemon that exchanges with any 3DS that passes."""
import os, sys, json, time, socket, stat, struct, threading, random, argparse, re, pwd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sp_store, sp_cecstore, sp_cec, sp_harvest_air, sp_build

# A console's inbox holds about 9 messages per title, so frequent exchanges only fill it.
DEFAULT_COOLDOWN = 12 * 3600.0
CONTROL_SOCKET = 'relay.sock'
STATE_FILE = 'relay_state.json'
# Kept apart from the peer book so a restart resumes the schedule, not the blocked fixed MAC.
ROTATION_FILE = 'rotation.json'
# The identity only changes between passes, and each change takes the interface down.
MIN_ROTATE_SECONDS = 60
MAC_RE = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')
# `sun_path` is 108 bytes on Linux, NUL included.
SOCK_PATH_MAX = 100


def control_socket_path(store):
    """-> where this store's control socket lives."""
    p = os.path.join(os.path.abspath(store), CONTROL_SOCKET)
    if len(p.encode()) <= SOCK_PATH_MAX:
        return p
    import hashlib
    h = hashlib.sha256(os.path.abspath(store).encode()).hexdigest()[:16]
    base = os.environ.get('XDG_RUNTIME_DIR') or '/tmp'
    return os.path.join(base, 'linuxpass-%s.sock' % h)


def sp_identity_seed():
    """The one seed string, read from sp_identity so the two can never drift apart."""
    import sp_identity
    return sp_identity.SEED_PREFIX


ADAPTER_RE = re.compile(r'[A-Za-z0-9_.-]{1,15}')


def read_env_file(path):
    """-> {KEY: value}. A missing file is not an error; the unit marks it optional too."""
    d = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, _, v = line.partition('=')
                d[k.strip()] = v.strip()
    except OSError:
        pass
    return d


def write_env_key(path, key, value):
    """Set one KEY, keeping the others. Renamed into place so systemd never reads half a file. -> None or error."""
    d = read_env_file(path)
    d[key] = value
    body = ['# Written by the LinuxPass daemon. Change these from the GUI or `sp_relay.py ctl`.']
    body += ['%s=%s' % (k, d[k]) for k in sorted(d)]
    try:
        tmp = path + '.tmp'
        with open(tmp, 'w') as f:
            f.write('\n'.join(body) + '\n')
        os.replace(tmp, path)
        return None
    except OSError as e:
        return str(e)


def peer_can_read(path, uid):
    """Could `uid` read `path` itself? The daemon is root and must not read on behalf of someone who cannot."""
    if uid == 0:
        return True
    try:
        user = pwd.getpwuid(uid)
        groups = set(os.getgrouplist(user.pw_name, user.pw_gid))
    except KeyError:
        groups = set()

    def allowed(st, bit):
        if st.st_uid == uid:
            return bool((st.st_mode >> 6) & bit)
        if st.st_gid in groups:
            return bool((st.st_mode >> 3) & bit)
        return bool(st.st_mode & bit)

    real = os.path.realpath(path)
    try:
        parent = os.path.dirname(real)
        while True:
            if not allowed(os.stat(parent), 1):
                return False
            if parent == os.path.dirname(parent):
                break
            parent = os.path.dirname(parent)
        st = os.stat(real)
    except OSError:
        return False
    return allowed(st, 4) and (not stat.S_ISDIR(st.st_mode) or allowed(st, 1))


def sd_notify(state):
    """Tell systemd how we are doing, if systemd started us."""
    addr = os.environ.get('NOTIFY_SOCKET')
    if not addr:
        return False
    if addr.startswith('@'):
        addr = '\0' + addr[1:]
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.connect(addr)
        s.sendall(state.encode())
        s.close()
        return True
    except OSError:
        return False


def declared_length(msg):
    """The total length a CEC message states in its own header at +0x04, or -1 if unreadable."""
    return struct.unpack_from('<I', msg, 4)[0] if len(msg) >= 8 else -1


def message_is_whole(msg):
    """Does a CEC message contain exactly as many bytes as its header claims?"""
    return declared_length(msg) == len(msg)


class PeerBook:
    """Per-peer history: when we last exchanged, and what we have already given them."""

    def __init__(self, path, cooldown=DEFAULT_COOLDOWN, retry=60.0):
        self.path = path
        self.cooldown = cooldown
        self.retry = retry
        self.peers = {}
        self.blocked = {}
        if os.path.exists(path):
            try:
                d = json.load(open(path))
                self.peers = d.get('peers', {})
                self.blocked = d.get('blocked', {})
            except (ValueError, OSError):
                self.peers, self.blocked = {}, {}

    def save(self):
        tmp = self.path + '.tmp'
        with open(tmp, 'w') as f:
            json.dump({'peers': self.peers, 'blocked': self.blocked}, f, indent=1, sort_keys=True)
        os.replace(tmp, self.path)

    def is_blocked(self, mac):
        return mac.lower() in self.blocked

    def block(self, mac, note='', now=None):
        self.blocked[mac.lower()] = {'when': time.time() if now is None else now,
                                     'note': str(note)}
        self.save()
        return True

    def unblock(self, mac):
        gone = self.blocked.pop(mac.lower(), None) is not None
        self.save()
        return gone

    def set_wait(self, mac, seconds, now=None):
        """Make this peer due in exactly `seconds`."""
        now = time.time() if now is None else now
        e = self.peers.get(mac.lower())
        if e is None:
            return False
        e['last'] = now - max(0.0, self.cooldown - max(0.0, float(seconds)))
        e['last_attempt'] = 0
        self.save()
        return True

    def due(self, mac, now=None):
        """-> True if this peer may be engaged now."""
        now = time.time() if now is None else now
        e = self.peers.get(mac.lower())
        if not e:
            return True
        if (now - e.get('last', 0)) < self.cooldown:
            return False
        la = e.get('last_attempt') or 0
        return la <= 0 or (now - la) >= self.retry

    def note_attempt(self, mac, now=None):
        """Record an engagement that did not complete, so we back off briefly, not for hours."""
        now = time.time() if now is None else now
        e = self.peers.setdefault(mac.lower(), {'first': now, 'exchanges': 0,
                                                'sent': [], 'received': []})
        e['last_attempt'] = now
        e['attempts'] = e.get('attempts', 0) + 1
        self.save()

    def wait(self, mac, now=None):
        """-> seconds until this peer is due, 0 if it is due now."""
        now = time.time() if now is None else now
        e = self.peers.get(mac.lower())
        if not e:
            return 0.0
        la = e.get('last_attempt') or 0
        backoff = (self.retry - (now - la)) if la > 0 else 0.0
        return max(0.0, self.cooldown - (now - e.get('last', 0)), backoff)

    def record(self, mac, sent_ids=(), got_ids=(), now=None):
        now = time.time() if now is None else now
        e = self.peers.setdefault(mac.lower(), {'first': now, 'exchanges': 0,
                                                'sent': [], 'received': []})
        e['last'] = now
        e['exchanges'] = e.get('exchanges', 0) + 1
        for k, ids in (('sent', sent_ids), ('received', got_ids)):
            have = set(e.get(k, []))
            e[k] = sorted(have | {i.hex() if isinstance(i, (bytes, bytearray)) else i for i in ids})
        self.save()

    def forget(self, mac=None):
        """Drop one peer's history, or all of it."""
        if mac is None:
            n = len(self.peers)
            self.peers = {}
        else:
            n = 1 if self.peers.pop(mac.lower(), None) is not None else 0
        self.save()
        return n

    def already_sent(self, mac, msgid):
        h = msgid.hex() if isinstance(msgid, (bytes, bytearray)) else msgid
        return h in set(self.peers.get(mac.lower(), {}).get('sent', []))

    def came_from(self, mac, msgid):
        h = msgid.hex() if isinstance(msgid, (bytes, bytearray)) else msgid
        return h in set(self.peers.get(mac.lower(), {}).get('received', []))


def select_for_peer(store, peer_titles, book=None, mac=None, max_titles=None, log=None):
    """-> [container] to serve this peer, newest first."""
    want = {t for t in peer_titles}
    out, seen_titles, seen_ids = [], set(), set()
    for tid, box, c in sorted(store.messages(box='outbox'),
                              key=lambda r: sp_cec.parse_header(r[2])['created']['text'],
                              reverse=True):
        if tid not in want:
            continue
        mid = c[0x20:0x28]
        if mid in seen_ids:
            continue
        seen_ids.add(mid)
        if store.is_from_air(mid, box):
            if log:
                log('  NOT serving %08X/%s: it came from a console over the air, and this relay '
                    'only exchanges its own data' % (tid, mid.hex()))
            continue
        if book is not None and mac is not None:
            if book.came_from(mac, mid) or book.already_sent(mac, mid):
                continue
        if max_titles is not None and tid not in seen_titles and len(seen_titles) >= max_titles:
            continue
        seen_titles.add(tid)
        out.append(c)
    return out


def title_metadata_any(path):
    """-> {title: {'name', 'hmac_key'}} from a save image OR a directory tree."""
    if not os.path.isdir(path):
        import sp_savefs
        try:
            return sp_cecstore.title_metadata(sp_savefs.SaveFS(open(path, 'rb').read()))
        except Exception:
            return {}
    out = {}
    for dirpath, _d, files in os.walk(path):
        parts = os.path.normpath(dirpath).split(os.sep)
        if len(parts) < 2 or parts[-2].upper() != 'CEC':
            continue
        try:
            tid = int(parts[-1], 16)
        except ValueError:
            continue
        e = out.setdefault(tid, {'name': None, 'hmac_key': None})
        if sp_cecstore.CEC_FILENAMES['mboxinfo'] in files:
            try:
                e['hmac_key'] = sp_cecstore.parse_mboxinfo(
                    open(os.path.join(dirpath, sp_cecstore.CEC_FILENAMES['mboxinfo']),
                         'rb').read())['hmac_key']
            except (ValueError, OSError):
                pass
        if 'MBoxData.010' in files:
            try:
                e['name'] = sp_cec.decode_utf16_name(
                    open(os.path.join(dirpath, 'MBoxData.010'), 'rb').read())
            except OSError:
                pass
    return out


def import_into(store, path, log=print, replace=False):
    """Ingest CEC data from a save image, a mounted directory, or an emulator NAND."""
    found = sp_cecstore.scan_any(path)
    meta = title_metadata_any(path)
    if replace:
        log('  cleared %d message(s) from the outbox first' % store.clear_box('outbox'))
    n = 0
    for m in found:
        c = m.get('raw')
        if not c:
            continue
        t = m['cec_title_id']
        md = meta.get(t) or {}
        if md.get('name') or md.get('hmac_key'):
            store.add_title(t, name=md.get('name'), hmac_key=md.get('hmac_key'))
        store.add_message(c, m['box'] if m['box'] in ('inbox', 'outbox') else 'outbox',
                          name=md.get('name'), key=md.get('hmac_key'),
                          origin=os.path.abspath(path))
        n += 1
    log('  imported %d message(s) from %s' % (n, path))
    return n


def backfill_air_provenance(store, book, log=print):
    """Stamp messages the peer book knows a console gave us, but the store has no origin for."""
    known = {}
    for t, b, c in store.messages():
        known.setdefault(c[0x20:0x28].hex(), []).append((t, b))
    have = store.origins()
    n = 0
    for mac, e in (book.peers or {}).items():
        for mid in e.get('received', []):
            for (t, b) in known.get(mid, ()):
                if store._okey(bytes.fromhex(mid), b) in have:
                    continue
                c = [x for _t, _b, x in store.messages(t, b) if x[0x20:0x28].hex() == mid]
                if c:
                    store.add_message(c[0], b, origin='air:%s' % mac)
                    n += 1
    if n:
        log('  marked %d message(s) as received from a console, from the peer book' % n)
    return n


def import_from_log(store, log_path, log=print):
    """Ingest the messages a console sent us during a run."""
    n = 0
    for _t, c in sp_harvest_air.messages_from_log(log_path):
        store.add_message(c, 'inbox', origin='air:log:' + os.path.basename(log_path))
        n += 1
    log('  imported %d message(s) off the air from %s' % (n, log_path))
    return n


class Control:
    """A line protocol over a unix socket: one JSON request per line, one JSON reply."""

    def __init__(self, path, relay, owner=None):
        self.path = path
        self.relay = relay
        self.owner = owner
        self.sock = None
        self.thread = None
        self.failed = None
        self.stop = threading.Event()

    def handle(self, req, peer_uid=None):
        cmd = (req.get('cmd') or '').lower()
        r = self.relay
        if cmd == 'status':
            return {'ok': True, 'status': r.status()}
        if cmd == 'pause':
            r.enabled = False
            return {'ok': True, 'enabled': False}
        if cmd == 'resume':
            r.enabled = True
            return {'ok': True, 'enabled': True}
        if cmd == 'toggle':
            r.enabled = not r.enabled
            return {'ok': True, 'enabled': r.enabled}
        if cmd == 'stop':
            r.running = False
            return {'ok': True, 'stopping': True}
        if cmd == 'store':
            return {'ok': True, 'store': r.describe_store()}
        if cmd == 'encounters':
            return {'ok': True, 'encounters': r.encounters(int(req.get('limit', 200)))}
        if cmd == 'denylist':
            now = time.time()
            return {'ok': True,
                    'blocked': [{'mac': m, **v} for m, v in sorted(r.book.blocked.items())],
                    'cooldowns': [{'mac': m, 'exchanges': e.get('exchanges', 0),
                                   'attempts': e.get('attempts', 0),
                                   'last': e.get('last', 0),
                                   'remaining_s': round(r.book.wait(m, now), 1)}
                                  for m, e in sorted(r.book.peers.items())]}
        if cmd == 'log':
            return {'ok': True, 'log': r.recent_log(int(req.get('limit', 300)))}

        if cmd == 'block':
            if not req.get('mac'):
                return {'ok': False, 'error': 'block needs a mac'}
            r.book.block(req['mac'], req.get('note', ''))
            r.log('  %s added to the denylist -- it will never be served' % req['mac'])
            return {'ok': True, 'blocked': req['mac']}
        if cmd == 'unblock':
            gone = r.book.unblock(req.get('mac', ''))
            r.log('  %s removed from the denylist' % req.get('mac'))
            return {'ok': True, 'unblocked': gone}
        if cmd == 'cooldown':
            if not req.get('mac'):
                return {'ok': False, 'error': 'cooldown needs a mac'}
            known = r.book.set_wait(req['mac'], float(req.get('seconds', 0)))
            r.log('  %s is now due in %.0f s' % (req['mac'], float(req.get('seconds', 0))))
            return {'ok': True, 'known': known,
                    'remaining_s': round(r.book.wait(req['mac']), 1)}

        if cmd == 'rotate':
            if 'seconds' in req:
                try:
                    n = int(float(req['seconds']))
                except (TypeError, ValueError):
                    return {'ok': False, 'error': 'seconds must be a number'}
                if n < 0:
                    return {'ok': False, 'error': 'seconds must not be negative'}
                r.a.rotate_every = n
                if n and not r.a.rotate_identity and not os.path.exists(r.rotation_path()):
                    # Only at a pass boundary, because changing identity takes the interface down.
                    r.identity_since = 0.0
                elif not n:
                    try:
                        os.remove(r.rotation_path())
                    except OSError:
                        pass
                r.log('  rotation set to %s' % ('every %d s' % r.rotate_seconds() if n else 'OFF'))
                err = r.save_setting('SP_ROTATE', str(n))
                if err:
                    return {'ok': False, 'error': 'applied, but not saved for restarts: %s' % err}
            if req.get('now'):
                r.identity_since = 0.0
                r.log('  a rotation is due at the next pass boundary')
            return {'ok': True, 'identity': r.identity,
                    'rotate_every_s': r.rotate_seconds(),
                    'next_rotation_s': (None if (r.a.rotate_identity or not r.rotate_seconds())
                                        else max(0.0, round(r.identity_since
                                                            + r.rotate_seconds() - time.time(), 1)))}

        if cmd == 'set_adapter':
            name = req.get('name')
            if not isinstance(name, str) or not ADAPTER_RE.fullmatch(name):
                return {'ok': False, 'error': 'not an interface name: %r' % (name,)}
            if not r.settings_file():
                return {'ok': False, 'error': 'only the systemd service saves settings; '
                                              'set SP_IFACE yourself for a foreground run'}
            err = r.save_setting('SP_IFACE', name)
            if err:
                return {'ok': False, 'error': err}
            r.log('  adapter %s will be used from the next service restart' % name)
            return {'ok': True, 'adapter': name}
        if cmd == 'title_remove':
            try:
                with r.lock:
                    n = r.store.remove_title(int(req['title'], 16)
                                             if isinstance(req['title'], str) else req['title'])
                r.log('  removed title %s and its %d message(s)' % (req['title'], n))
                return {'ok': True, 'messages_removed': n}
            except Exception as e:
                return {'ok': False, 'error': '%s: %s' % (type(e).__name__, e)}
        if cmd == 'message_remove':
            try:
                tid = int(req['title'], 16) if isinstance(req['title'], str) else req['title']
                with r.lock:
                    hit = r.store.remove_message(tid, req.get('box', 'outbox'),
                                                 bytes.fromhex(req['id']))
                r.log('  removed message %s from %s/%s' % (req['id'], req['title'],
                                                           req.get('box', 'outbox')))
                return {'ok': True, 'removed': bool(hit)}
            except Exception as e:
                return {'ok': False, 'error': '%s: %s' % (type(e).__name__, e)}
        if cmd == 'forget':
            n = r.book.forget(req.get('mac'))
            r.log('  forgot %d peer(s)%s' % (n, ' (%s)' % req['mac'] if req.get('mac') else ''))
            return {'ok': True, 'forgotten': n}
        if cmd == 'seed':
            try:
                import sp_identity
                kw = {k: v for k, v in req.items()
                      if k in ('mii_name', 'author_name', 'greeting', 'hits', 'population', 'pet')}
                with r.lock:
                    sp_identity.seed(r.store, r.a.store, replace=bool(req.get('replace')),
                                     log=r.log, **kw)
                return {'ok': True, 'servable': len(r.servable())}
            except Exception as e:
                return {'ok': False, 'error': '%s: %s' % (type(e).__name__, e)}
        if cmd == 'import':
            if peer_uid is not None and not peer_can_read(req.get('path', ''), peer_uid):
                return {'ok': False, 'error': 'you cannot read %s' % req.get('path', '')}
            try:
                with r.lock:
                    n = import_into(r.store, req['path'], r.log,
                                    replace=bool(req.get('replace')))
                return {'ok': True, 'imported': n}
            except Exception as e:
                return {'ok': False, 'error': '%s: %s' % (type(e).__name__, e)}
        return {'ok': False, 'error': 'unknown command %r' % cmd}

    def serve_forever(self):
        try:
            if os.path.exists(self.path):
                os.remove(self.path)
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind(self.path)
        except OSError as e:
            self.failed = '%s: %s' % (type(e).__name__, e)
            self.relay.log('  CONTROL SOCKET UNAVAILABLE at %s -- %s' % (self.path, self.failed))
            self.relay.log('  the daemon will keep exchanging, but nothing can pause or query it')
            return
        # Done before listen(), so nobody can connect while the permissions are still open.
        try:
            os.chmod(self.path, 0o600)
            if self.owner and os.geteuid() == 0:
                os.chown(self.path, pwd.getpwnam(self.owner).pw_uid, -1)
        except (OSError, KeyError) as e:
            self.relay.log('  control socket stays root-only: cannot give it to %r (%s)'
                           % (self.owner, e))
        self.sock.listen(4)
        self.sock.settimeout(0.5)
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
                peer_uid = struct.unpack('3i', conn.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))[1]
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                try:
                    data = conn.recv(65536).decode('utf-8', 'replace').strip()
                    reply = self.handle(json.loads(data) if data else {}, peer_uid)
                except Exception as e:
                    reply = {'ok': False, 'error': '%s: %s' % (type(e).__name__, e)}
                try:
                    conn.sendall((json.dumps(reply) + '\n').encode())
                except OSError:
                    pass
        try:
            self.sock.close(); os.remove(self.path)
        except OSError:
            pass

    def start(self):
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def shutdown(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=2.0)


def recovery_argv(a):
    """The --manifest-repeat/--repeat-type pair to hand sp_link, honouring --no-silent-recovery."""
    rep = int(getattr(a, 'manifest_repeat', 0) or 0)
    if not getattr(a, 'silent_recovery', True):
        rep = 0
    return ['--manifest-repeat', str(rep),
            '--repeat-type', str(getattr(a, 'repeat_type', '0xf2'))]


def send_command(sock_path, cmd, **kw):
    """-> the daemon's reply dict."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(sock_path)
    s.sendall((json.dumps(dict(cmd=cmd, **kw)) + '\n').encode())
    buf = b''
    while not buf.endswith(b'\n'):
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    s.close()
    return json.loads(buf.decode('utf-8', 'replace') or '{}')


class Relay:
    def __init__(self, args):
        self.a = args
        self.store = sp_store.Store(args.store)
        self.book = PeerBook(os.path.join(args.store, STATE_FILE), cooldown=args.cooldown,
                             retry=getattr(args, 'retry', 60.0))
        self.enabled = not args.start_paused
        self.running = True
        self.started = time.time()
        self.exchanges = 0
        self.last_peer = None
        self.last_error = None
        self.identity = args.mac or self.fixed_identity()
        self.identity_since = time.time()
        self.rotations = 0
        self.exchange_gap = getattr(args, 'exchange_gap', 0.0)
        # The fix is rebuilding the interface, so exit and let systemd restart us.
        self.iface_failures = 0
        # The control thread can change the store while a pass reads it.
        self.lock = threading.RLock()
        self.last_success = 0.0
        self.passes = 0
        self.last_tick = time.time()
        self._pending_sent = []
        self._pending_map = {}
        self.iface_mismatch = None

    def log(self, msg):
        print('[%s] %s' % (time.strftime('%H:%M:%S'), msg), flush=True)

    def fixed_identity(self):
        """A stable MAC derived from the store path, so a restart keeps the same identity."""
        import hashlib
        h = hashlib.sha256((sp_identity_seed() + os.path.abspath(self.a.store)).encode()).digest()
        return 'ba:ae:6e:%02x:%02x:%02x' % (h[0], h[1], h[2])

    def random_identity(self):
        """A fresh locally-administered MAC in the prefix real consoles use."""
        return 'ba:ae:6e:%02x:%02x:%02x' % tuple(random.getrandbits(8) for _ in range(3))

    def rotate_seconds(self):
        """The configured rotation period in seconds, or 0 for never."""
        raw = getattr(self.a, 'rotate_every', 0)
        if raw in (None, '', 0, '0'):
            return 0
        try:
            n = int(float(raw))
        except (TypeError, ValueError):
            self.log('  ignoring --rotate-every %r: not a number. Rotation is OFF.' % (raw,))
            return 0
        if n < 0:
            self.log('  ignoring --rotate-every %r: negative. Rotation is OFF.' % (raw,))
            return 0
        if 0 < n < MIN_ROTATE_SECONDS:
            self.log('  --rotate-every %d is below the %d s floor; using %d. Rotating faster than '
                     'a pass is pointless -- the identity only ever changes between passes.'
                     % (n, MIN_ROTATE_SECONDS, MIN_ROTATE_SECONDS))
            return MIN_ROTATE_SECONDS
        return n

    def rotation_due(self):
        """Is a new identity due? Asked ONLY at a pass boundary, never inside an exchange."""
        if self.a.rotate_identity:
            return True
        every = self.rotate_seconds()
        return bool(every) and (time.time() - self.identity_since) >= every

    def next_identity(self):
        if self.rotation_due():
            return self.random_identity()
        return self.identity

    def settings_file(self):
        return getattr(self.a, 'settings_file', None)

    def save_setting(self, key, value):
        """Keep a setting for the next service start. -> None, or why it could not be saved."""
        path = self.settings_file()
        return write_env_key(path, key, value) if path else None

    def rotation_path(self):
        return os.path.join(self.a.store, ROTATION_FILE)

    def save_rotation(self):
        """Persist the identity in use so a restart resumes the schedule. Never fatal."""
        try:
            tmp = self.rotation_path() + '.tmp'
            with open(tmp, 'w') as f:
                json.dump({'mac': self.identity, 'since': self.identity_since}, f)
            os.replace(tmp, self.rotation_path())
        except OSError as e:
            self.log('  could not save the rotation state (%s); the schedule will restart if this '
                     'service does' % e)

    def load_rotation(self):
        """-> {'mac', 'since'} from a previous run, or None."""
        try:
            d = json.load(open(self.rotation_path()))
        except (OSError, ValueError):
            return None
        mac, since = d.get('mac'), d.get('since')
        if not isinstance(mac, str) or not MAC_RE.match(mac):
            return None
        try:
            since = float(since)
        except (TypeError, ValueError):
            return None
        return {'mac': mac, 'since': min(since, time.time())}

    def begin_rotation(self):
        """Set up the identity for a timed-rotation run."""
        st = self.load_rotation()
        if st:
            self.identity, self.identity_since = st['mac'], st['since']
            age = time.time() - self.identity_since
            self.log('  rotating identity every %d s; resuming %s, adopted %d s ago'
                     % (self.rotate_seconds(), self.identity, age))
        else:
            self.identity, self.identity_since = self.random_identity(), time.time()
            self.log('  rotating identity every %d s; starting on a fresh %s (the store\'s fixed '
                     'MAC is the one consoles have already blocked)'
                     % (self.rotate_seconds(), self.identity))
            self.save_rotation()

    def set_iface_mac(self, mac):
        """Point the monitor vif at `mac`."""
        import subprocess
        for args in (['ip', 'link', 'set', self.a.iface, 'down'],
                     ['ip', 'link', 'set', self.a.iface, 'address', mac],
                     ['ip', 'link', 'set', self.a.iface, 'up']):
            r = subprocess.run(['timeout', '10'] + args, capture_output=True)
            if r.returncode != 0:
                self.log('  could not set %s to %s (%s) -- keeping the current identity'
                         % (self.a.iface, mac, (r.stderr or b'').decode().strip()))
                return False
        self._adopt(mac)
        return True

    def _adopt(self, mac):
        """Record that we now transmit from `mac`. Only ever called once the vif agrees."""
        if mac != self.identity:
            self.rotations += 1
        self.identity = mac
        self.identity_since = time.time()
        if self.rotate_seconds():
            self.save_rotation()

    def apply_rotation(self):
        """Take the identity that is due now, moving the vif with it."""
        mac = self.next_identity()
        if mac != self.identity:
            if self.set_iface_mac(mac):
                self.log('  identity rotated to %s' % mac)
            else:
                mac = self.identity
        return mac

    def iface_mac(self):
        """The vif's own hardware address, lower-case, or None if it cannot be read."""
        try:
            with open('/sys/class/net/%s/address' % self.a.iface) as f:
                return (f.read().strip().lower() or None)
        except OSError:
            return None

    def align_iface_identity(self):
        """Point the interface at the address we transmit from, or say so loudly."""
        self.iface_mismatch = None
        if self.a.rotate_identity:
            return True
        have = self.iface_mac()
        if have is None:
            self.log('  NOTE: cannot read the %s hardware address; not checking it against our '
                     'identity' % self.a.iface)
            return True
        want = self.identity.lower()
        if have == want:
            return True
        self.log('  interface %s is %s but we transmit as %s -- realigning the interface'
                 % (self.a.iface, have, want))
        if self.set_iface_mac(self.identity) and self.iface_mac() == want:
            self.log('  interface is now %s; the hardware will ACK frames addressed to us' % want)
            return True
        self.iface_mismatch = {'iface': self.a.iface, 'iface_mac': self.iface_mac(),
                               'identity': want}
        self.log('  WARNING: %s is %s but we transmit as %s, and it could not be changed.'
                 % (self.a.iface, self.iface_mac(), want))
        self.log('           The card will NOT ACK the console, so no exchange can complete and')
        self.log('           this relay will look healthy while being ignored.')
        self.log('           Fix: put SP_MAC=%s in /etc/default/linuxpass (or drop --mac), '
                 'then restart.' % want)
        return False

    def status(self):
        return {
            'enabled': self.enabled, 'running': self.running,
            'uptime_s': round(time.time() - self.started, 1),
            'exchanges': self.exchanges, 'last_peer': self.last_peer,
            'last_error': self.last_error,
            'identity': self.identity,
            'iface_mismatch': self.iface_mismatch,
            'can_save_settings': bool(self.settings_file()),
            'adapter': (read_env_file(self.settings_file()).get('SP_IFACE', '')
                        if self.settings_file() else ''),
            'rotate_identity': bool(self.a.rotate_identity),
            'rotate_every_s': self.rotate_seconds(),
            'identity_age_s': round(time.time() - self.identity_since, 1),
            'next_rotation_s': (None if (self.a.rotate_identity or not self.rotate_seconds())
                                else max(0.0, round(self.identity_since + self.rotate_seconds()
                                                    - time.time(), 1))),
            'rotations': self.rotations,
            'cooldown_s': self.a.cooldown,
            'exchange_gap_s': self.exchange_gap,
            'iface_failures': self.iface_failures,
            'passes': self.passes,
            'store': self.a.store,
            'titles': ['%08X' % t for t in self.store.titles()],
            'messages': len(self.store.messages()),
            # Counted by set difference, because older stored messages have no provenance tag.
            'servable': len(self.servable()),
            'held_but_never_served': len({c[0x20:0x28] for _t, _b, c in self.store.messages()}
                                         - {c[0x20:0x28] for c in self.servable()}),
            'peers': {m: {'exchanges': e.get('exchanges', 0),
                          'due_in_s': round(self.book.wait(m), 1)}
                      for m, e in self.book.peers.items()},
        }

    def describe_store(self):
        """Everything the GUI needs to draw the Outbox and Inbox tabs, in one round trip."""
        with self.lock:
            serv = {c[0x20:0x28] for c in self.servable()}
            out = {'titles': [], 'max_titles': sp_store.MBOXLIST_MAX}
            for t in self.store.titles():
                ms = []
                for tid, box, c in self.store.messages(t):
                    h = sp_cec.parse_header(c)
                    mid = c[0x20:0x28]
                    ms.append({
                        'id': mid.hex(), 'box': box, 'bytes': len(c),
                        'created': h['created']['text'],
                        'send_mode': h['send_mode'], 'flags': h['field_34'],
                        'origin': (self.store.origin(mid, box) or {}).get('source'),
                        'servable': mid in serv,
                        'hmac': {True: 'verified', False: 'FAILED',
                                 None: 'no key'}[self.store.verify(t, c)],
                    })
                out['titles'].append({
                    'title': '%08X' % t, 'name': self.store.title_name(t),
                    'has_key': self.store.title_key(t) is not None,
                    'messages': ms,
                })
            return out

    def recent_log(self, limit=300):
        """-> the daemon's own recent output, newest last."""
        import subprocess
        try:
            r = subprocess.run(['journalctl', '-u', 'linuxpass', '-n', str(limit),
                                '--no-pager', '-o', 'cat'],
                               capture_output=True, timeout=10)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.decode('utf-8', 'replace').splitlines()
        except (OSError, subprocess.SubprocessError):
            pass
        d = os.path.join(self.a.store, 'runs')
        try:
            newest = max((os.path.getmtime(os.path.join(d, f)), f) for f in os.listdir(d))[1]
            return open(os.path.join(d, newest)).read().splitlines()[-limit:]
        except (OSError, ValueError):
            return []

    def servable(self):
        """Every message this relay could offer to a console that declared every title."""
        with self.lock:                      # RLock: describe_store() already holds it
            return select_for_peer(self.store, self.store.titles())

    @staticmethod
    def peer_titles(peer_services):
        """The CEC title ids a console declared. sp_parse gives dicts of hex strings."""
        out = []
        for s in peer_services or []:
            try:
                out.append(int(s['titleID'], 16) if isinstance(s, dict) else int(s))
            except (KeyError, ValueError, TypeError):
                continue
        return out

    def encounters_path(self):
        return os.path.join(self.a.store, 'encounters.jsonl')

    def note_encounter(self, rec, keep=500):
        """Append one line of history, so the GUI can show what happened and when."""
        rec = dict(rec)
        rec.setdefault('when', time.time())
        try:
            with open(self.encounters_path(), 'a') as f:
                f.write(json.dumps(rec, sort_keys=True) + '\n')
            lines = open(self.encounters_path()).read().splitlines()
            if len(lines) > keep * 2:
                with open(self.encounters_path() + '.tmp', 'w') as f:
                    f.write('\n'.join(lines[-keep:]) + '\n')
                os.replace(self.encounters_path() + '.tmp', self.encounters_path())
        except OSError as e:
            self.log('  could not record the encounter: %s' % e)

    def encounters(self, limit=200):
        try:
            lines = open(self.encounters_path()).read().splitlines()
        except OSError:
            return []
        out = []
        for ln in lines[-limit:]:
            try:
                out.append(json.loads(ln))
            except ValueError:
                continue
        return out

    def _decline(self, link, reason, msg):
        """Serve this peer nothing, and make sure the reason reaches both logs."""
        self.log(msg)
        self._declined = reason
        if link is not None:
            link.declined = reason
            lg = getattr(link, 'log', None)
            if callable(lg):
                lg('      %s' % msg.strip())
        return None

    def peer_hook(self, link, mac, peer_services):
        """Called the instant a console engages: choose what to serve this console."""
        import sp_link
        if self.book.is_blocked(mac):
            r = self._decline(link, 'blocked',
                              '  %s is on the denylist -- refusing to exchange with it' % mac)
            self.note_encounter({'peer': mac, 'result': 'blocked'})
            return r
        if not self.book.due(mac):
            return self._decline(link, 'cooldown',
                                 '  %s is inside its cooldown (%.0f s to go) -- serving it '
                                 'nothing so the next pass can reach a different console'
                                 % (mac, self.book.wait(mac)))
        titles = self.peer_titles(peer_services)
        with self.lock:
            picked = select_for_peer(self.store, titles, self.book, mac, log=self.log)
            held = ['%08X' % sp_cec.parse_header(c)['cec_title_id']
                    for _t, _b, c in self.store.messages(box='outbox')]
        if not picked:
            r = self._decline(link, 'nothing to serve',
                              '  nothing to serve %s (it declares %s; our outbox holds %s)'
                              % (mac, ['%08X' % t for t in titles], held))
            self.note_encounter({'peer': mac, 'result': 'nothing to serve',
                                 'peer_titles': ['%08X' % t for t in titles]})
            return r
        for i, c in enumerate(picked):
            picked[i] = sp_build.set_message_id(c)          # never a duplicate id
        known = {t: (f, tr) for t, f, tr in sp_link.T.SERVICES_FULL}
        tids = list(dict.fromkeys(sp_build.message_title(c) for c in picked))
        services = [(t,) + known.get(t, (0x30, b'')) for t in tids]
        prefix = [sp_link.build_obj_41(link.src),
                  sp_link.cec_object(0x43, sp_link.OBJ_43_PAYLOAD, flags=0x0000),
                  sp_link.build_obj_11(link.token, services)]
        objects = prefix + sp_build.build_outbox(picked)
        ids = [c[sp_build.ENVELOPE_LEN + 0x20:sp_build.ENVELOPE_LEN + 0x28] for c in picked]
        self._pending_sent = list(ids)
        # One envelope can hold several messages, so map objects to messages explicitly.
        groups, order = {}, []
        for c, mid in zip(picked, ids):
            t = sp_build.message_title(c)
            if t not in groups:
                groups[t] = []
                order.append(t)
            groups[t].append(mid)
        env_idx = [i for i, o in enumerate(objects) if o[:2] == b'\x61\x61']
        self._pending_map = {i: groups[t] for i, t in zip(env_idx, order)}
        self._detail = {mid: {'title': '%08X' % sp_build.message_title(c), 'bytes': len(c)}
                        for c, mid in zip(picked, ids)}
        return services, objects

    def one_pass(self):
        """One listening window: engage whoever answers, exchange, file what we got."""
        import sp_link
        runs = os.path.join(self.a.store, 'runs')
        os.makedirs(runs, exist_ok=True)
        stamp = int(time.time())
        # The identity changes only here, before any socket opens, so it cannot land mid-exchange.
        mac = self.apply_rotation()
        argv = ['--iface', self.a.iface, '--channel', self.a.channel,
                '--mac', mac, '--secs', str(self.a.window),
                '--full-sequence', '--mirror-offer', '--verbose', str(self.a.verbose),
                '--yy-rate', str(getattr(self.a, 'yy_rate', 11.0)),
                '--log', os.path.join(runs, 'relay_%d.log' % stamp)]
        argv += recovery_argv(self.a)
        if self.a.pcap:
            argv += ['--pcap', os.path.join(runs, 'relay_%d.pcap' % stamp)]
        a = sp_link.build_parser().parse_args(argv)
        self._pending_sent, self._pending_map, self._declined = [], {}, None
        link = sp_link.Link(a)
        link.tick_hook = self.tick
        # The broadcast probe must advertise every title held. The peer hook narrows it later.
        known = {t: (f, tr) for t, f, tr in sp_link.T.SERVICES_FULL}
        held = [t for t in self.store.titles()]
        if held:
            link.services = [(t,) + known.get(t, (0x30, b'')) for t in held]
        link.peer_hook = self.peer_hook
        try:
            rc = link.run()
        except Exception as e:
            self.last_error = '%s: %s' % (type(e).__name__, e)
            self.log('  exchange failed: %s' % self.last_error)
            return False
        # rc 1 is a quiet pass. rc 2 means the interface is gone or no longer a monitor.
        if rc == 2:
            self.iface_failures += 1
            self.last_error = '%s is not a usable monitor interface (%d in a row)' \
                              % (self.a.iface, self.iface_failures)
            self.log('  ' + self.last_error)
            return False
        self.iface_failures = 0
        peer = sp_link.T.macstr(link.peer) if link.peer else None
        got = []
        sess = getattr(link, 'session', None)
        # Record only what was delivered, or a failed exchange would use up its messages.
        delivered = (sess.stats.get('sent_objects', 0) if sess else 0)
        self._pending_sent = [mid for i, ids in sorted(self._pending_map.items())
                              if i < delivered for mid in ids]
        got_detail = []
        for obj in (getattr(sess, 'received', None) or []):
            if len(obj) > 0x14 + 0x70 and obj[:2] == b'\x61\x61':
                try:
                    for c in sp_build.unwrap(obj):
                        # Second check: a short message must never reach the store.
                        if not message_is_whole(c):
                            self.log('  DISCARDING a truncated message from %s: %d B on the wire, '
                                     'its own header declares %d. Not stored.'
                                     % (peer or '?', len(c), declared_length(c)))
                            continue
                        # Filed in the inbox with its origin, which keeps it from being offered to a console.
                        with self.lock:
                            self.store.add_message(c, 'inbox', origin='air:%s' % (peer or '?'))
                        got.append(c[0x20:0x28])
                        got_detail.append({'title': '%08X' % sp_cec.parse_header(c)['cec_title_id'],
                                           'bytes': len(c)})
                except ValueError:
                    continue
        if not peer:
            return False
        self.last_peer = peer
        detail = getattr(self, '_detail', {})
        if self._pending_sent or got:
            self.book.record(peer, self._pending_sent, got)
            self.exchanges += 1
            self.last_success = time.time()
            self.note_encounter({'peer': peer, 'result': 'exchanged',
                                 'sent': [detail.get(m, {}) for m in self._pending_sent],
                                 'received': got_detail})
            self.log('  exchanged with %s: sent %d, received %d (store now holds %d)'
                     % (peer, len(self._pending_sent), len(got), len(self.store.messages())))
            return True
        # A declined peer did not fail, so do not re-arm its retry backoff.
        if self._declined or self.book.is_blocked(peer):
            return False
        self.book.note_attempt(peer)
        self.note_encounter({'peer': peer, 'result': 'engaged but nothing moved'})
        self.log('  %s engaged but nothing moved -- backing off %.0f s, not the full cooldown'
                 % (peer, self.book.retry))
        return False

    def tick(self, *_a):
        """Called from inside the sniffing loop: the daemon is alive and the radio is turning."""
        now = time.time()
        if now - self.last_tick >= 5.0:
            self.last_tick = now
            sd_notify('WATCHDOG=1')

    def prune_runs(self):
        """Keep the newest `--keep-runs` per-pass logs."""
        keep = int(getattr(self.a, 'keep_runs', 50) or 0)
        if keep <= 0:
            return
        d = os.path.join(self.a.store, 'runs')
        try:
            files = sorted((os.path.getmtime(os.path.join(d, f)), f) for f in os.listdir(d))
        except OSError:
            return
        for _mt, f in files[:max(0, len(files) - keep)]:
            try:
                os.remove(os.path.join(d, f))
            except OSError:
                pass

    def run(self):
        sock = control_socket_path(self.a.store)
        ctl = Control(sock, self, owner=getattr(self.a, 'control_user', None))
        ctl.start()
        if self.rotate_seconds() and not self.a.rotate_identity:
            self.begin_rotation()
        elif os.path.exists(self.rotation_path()):
            try:
                os.remove(self.rotation_path())
            except OSError:
                pass
        every = self.rotate_seconds()
        self.log('relay up: store=%s identity=%s%s control=%s'
                 % (self.a.store, self.identity,
                    ' (ROTATING every pass)' if self.a.rotate_identity
                    else ' (ROTATING every %d s)' % every if every else '', sock))
        self.log('  %d title(s), %d message(s) in the store'
                 % (len(self.store.titles()), len(self.store.messages())))
        self.align_iface_identity()
        backfill_air_provenance(self.store, self.book, self.log)
        n_serve = len(self.servable())
        self.log('  %d of those can be served; the rest came from consoles and stay put'
                 % n_serve)
        if not n_serve:
            self.log('  WARNING: nothing to serve. Give this relay some data of its own:')
            self.log('           sp_relay.py import <save image|dump dir|Azahar NAND> --replace')
        if not self.enabled:
            self.log('  exchanges are PAUSED (resume with: sp_relay.py ctl resume)')
        if sd_notify('READY=1'):
            self.log('  systemd is watching this process; a stall restarts THE SERVICE, '
                     'never the machine')
        rc_exit = 0
        try:
            while self.running:
                self.tick()
                if not self.enabled:
                    sd_notify('STATUS=paused')
                    time.sleep(0.5)
                    continue
                if self.iface_failures >= self.a.max_iface_failures:
                    self.log('  %s has been unusable for %d passes -- exiting so the service '
                             'restarts and rebuilds it. The MACHINE is not touched.'
                             % (self.a.iface, self.iface_failures))
                    self.last_error = 'monitor interface unusable; asked for a service restart'
                    rc_exit = 1
                    break
                gap = self.exchange_gap - (time.time() - self.last_success)
                if gap > 0:
                    # Independent of MAC, so a rotating peer cannot evade it.
                    sd_notify('STATUS=holding %.0fs after the last exchange' % gap)
                    time.sleep(min(gap, 1.0))
                    continue
                sd_notify('STATUS=listening (%d exchange(s), %d message(s) servable)'
                          % (self.exchanges, n_serve))
                self.passes += 1
                self.one_pass()
                self.prune_runs()
                n_serve = len(self.servable())
                time.sleep(self.a.idle)
        except KeyboardInterrupt:
            self.log('interrupted')
        finally:
            sd_notify('STOPPING=1')
            ctl.shutdown()
            self.book.save()
            self.log('relay down after %d exchange(s) in %d pass(es)'
                     % (self.exchanges, self.passes))
        return rc_exit


def _inspect_args(fn):
    import inspect
    return list(inspect.signature(fn).parameters)


def _timesout(fn):
    try:
        fn(); return False
    except (socket.timeout, OSError):
        return True


def _scan_code_for_machine_kill(path):
    """-> the machine-killing words that appear in EXECUTABLE code, ignoring prose."""
    import tokenize, io
    src = open(path, 'rb').read()
    kept = []
    for tok in tokenize.tokenize(io.BytesIO(src).readline):
        if tok.type not in (tokenize.COMMENT, tokenize.STRING):
            kept.append(tok.string)
    code = ' '.join(kept).lower()
    return [w for w in ('sysrq', 'reboot', 'poweroff', 'systemd-run') if w in code]


def _selftest():
    import tempfile, shutil
    ok = tot = 0

    def chk(n, c, g=''):
        nonlocal ok, tot
        tot += 1; ok += bool(c)
        print('  [%s] %s%s' % ('PASS' if c else 'FAIL', n, ('  %s' % (g,)) if g else ''))

    tmp = tempfile.mkdtemp()
    import lp_corpus as corpus, lp_keys as _k
    if _k.selftest_keys():
        print('  (no console keys found -- running on generated throwaway keys)')
    try:
        st = sp_store.Store(os.path.join(tmp, 'store'))
        src = corpus.path('console_nand')
        if src is None:
            import sp_build
            for tid, origin in ((0x00020800, None), (0x00030600, 'air:96:58:cb:00:11:22')):
                m = sp_build.build(mii_name='Tux', greeting='self-test', cec_title_id=tid)
                st.add_message(m[sp_build.ENVELOPE_LEN:], 'outbox', name='Self-test title',
                               key=b'\x11' * 32, origin=origin)
            chk('a store seeded from scratch has both titles',
                len(st.titles()) == 2, len(st.titles()))
        if src is not None:
            n = import_into(st, src, log=lambda m: None)
            chk('import reads a console save image', n == 15, n)
            chk('and brings the HMAC keys with it',
                st.title_key(0x00030600) == b'ctrd' + b'\x00' * 28)
            chk('and the display names', st.title_name(0x00030600) == 'MARIO KART 7',
                st.title_name(0x00030600))
            st2 = sp_store.Store(os.path.join(tmp, 'store2'))
            n2 = import_into(st2, os.path.join(tmp, 'store'), log=lambda m: None)
            chk('import reads a DIRECTORY tree too (an Azahar/Citra NAND is one)', n2 == 15, n2)
            chk('keys and names survive the directory round trip',
                st2.title_key(0x00030600) == st.title_key(0x00030600)
                and st2.title_name(0x00030600) == 'MARIO KART 7')

        book = PeerBook(os.path.join(tmp, 'peers.json'), cooldown=100.0)
        NS = argparse.Namespace
        chk('the silent-send recovery is armed by default',
            recovery_argv(NS(manifest_repeat=1, repeat_type='0xf2'))
            == ['--manifest-repeat', '1', '--repeat-type', '0xf2'])
        chk('--no-silent-recovery disarms it',
            recovery_argv(NS(manifest_repeat=1, repeat_type='0xf2', silent_recovery=False))
            == ['--manifest-repeat', '0', '--repeat-type', '0xf2'])
        chk('the flags are ALWAYS passed, so sp_link cannot re-arm a disarmed relay',
            recovery_argv(NS(manifest_repeat=0, repeat_type='0xf2'))[:2]
            == ['--manifest-repeat', '0'])
        chk('an explicit repeat count and type survive',
            recovery_argv(NS(manifest_repeat=4, repeat_type='0x33'))
            == ['--manifest-repeat', '4', '--repeat-type', '0x33'])
        import sp_link
        chk('sp_link arms the same recovery by default',
            (lambda d: d.manifest_repeat == 1 and d.repeat_type == '0xf2')(
                sp_link.build_parser().parse_args(['--iface', 'mon0'])))

        chk('an unknown peer is due immediately', book.due('AA:BB:CC:00:00:01'))
        book.record('AA:BB:CC:00:00:01', [b'\x01' * 8], [b'\x02' * 8], now=1000.0)
        chk('a peer just met is not due', not book.due('AA:BB:CC:00:00:01', now=1050.0))
        chk('and reports how long to wait', book.wait('AA:BB:CC:00:00:01', now=1050.0) == 50.0)
        chk('it is due again after the cooldown', book.due('AA:BB:CC:00:00:01', now=1101.0))
        chk('peer matching is case-insensitive', not book.due('aa:bb:cc:00:00:01', now=1050.0))
        chk('we remember what we sent it', book.already_sent('AA:BB:CC:00:00:01', b'\x01' * 8))
        chk('and what came from it', book.came_from('AA:BB:CC:00:00:01', b'\x02' * 8))
        book2 = PeerBook(os.path.join(tmp, 'peers.json'), cooldown=100.0)
        chk('the peer book survives a restart', not book2.due('AA:BB:CC:00:00:01', now=1050.0))
        b5 = PeerBook(os.path.join(tmp, 'p5.json'), cooldown=100.0, retry=10.0)
        b5.note_attempt('DE:AD:00:00:00:01', now=2000.0)
        b6 = PeerBook(os.path.join(tmp, 'p6.json'), cooldown=100.0)
        b6.record('AA:00:00:00:00:01', now=1000.0)
        b6.record('AA:00:00:00:00:02', now=1000.0)
        chk('a peer can be forgotten so it is due again',
            b6.forget('aa:00:00:00:00:01') == 1 and b6.due('AA:00:00:00:00:01', now=1050.0))
        chk('and the others are left alone', not b6.due('AA:00:00:00:00:02', now=1050.0))
        chk('forgetting an unknown peer is not an error', b6.forget('FF:FF:FF:FF:FF:FF') == 0)
        chk('forgetting everything works too',
            b6.forget() == 1 and PeerBook(os.path.join(tmp, 'p6.json')).peers == {})

        b7 = PeerBook(os.path.join(tmp, 'p7.json'), cooldown=100.0)
        chk('an unknown peer is not blocked', not b7.is_blocked('CA:FE:00:00:00:01'))
        b7.block('CA:FE:00:00:00:01', note='noisy neighbour')
        chk('a blocked peer reports blocked', b7.is_blocked('ca:fe:00:00:00:01'))
        chk('blocking is case-insensitive both ways', b7.is_blocked('CA:FE:00:00:00:01'))
        chk('the reason is kept',
            b7.blocked['ca:fe:00:00:00:01']['note'] == 'noisy neighbour')
        chk('a block survives a restart',
            PeerBook(os.path.join(tmp, 'p7.json')).is_blocked('CA:FE:00:00:00:01'))
        chk('and blocking is separate from the cooldown -- it is still "due"',
            b7.due('CA:FE:00:00:00:01'))
        chk('unblocking works', b7.unblock('CA:FE:00:00:00:01')
            and not b7.is_blocked('CA:FE:00:00:00:01'))
        chk('unblocking an unknown peer is not an error', b7.unblock('00:00:00:00:00:00') is False)
        old_state = json.load(open(os.path.join(tmp, 'p7.json')))
        chk('the state file carries both lists', {'peers', 'blocked'} <= set(old_state))
        json.dump({'peers': {'aa:bb:cc:dd:ee:ff': {'exchanges': 1}}},
                  open(os.path.join(tmp, 'p8.json'), 'w'))
        chk('a state file written before blocklists existed still loads',
            PeerBook(os.path.join(tmp, 'p8.json')).blocked == {}
            and 'aa:bb:cc:dd:ee:ff' in PeerBook(os.path.join(tmp, 'p8.json')).peers)

        b9 = PeerBook(os.path.join(tmp, 'p9.json'), cooldown=1000.0)
        b9.record('AB:CD:00:00:00:01', now=5000.0)
        chk('a fresh exchange leaves the full cooldown',
            abs(b9.wait('AB:CD:00:00:00:01', now=5000.0) - 1000.0) < 1)
        b9.set_wait('AB:CD:00:00:00:01', 30.0, now=5000.0)
        chk('the remaining time can be set to an exact value',
            abs(b9.wait('AB:CD:00:00:00:01', now=5000.0) - 30.0) < 1,
            b9.wait('AB:CD:00:00:00:01', now=5000.0))
        chk('and it is still not due until that elapses',
            not b9.due('AB:CD:00:00:00:01', now=5020.0))
        b9.set_wait('AB:CD:00:00:00:01', 0, now=5000.0)
        chk('setting it to zero makes it due now', b9.due('AB:CD:00:00:00:01', now=5000.0))
        chk('but does NOT discard what we already sent it',
            'sent' in b9.peers['ab:cd:00:00:00:01'])
        chk('setting the wait on an unknown peer says so',
            b9.set_wait('FF:FF:FF:FF:FF:FF', 10) is False)
        chk('a failed attempt backs off briefly', not b5.due('DE:AD:00:00:00:01', now=2005.0))
        chk('and is retried after the short backoff, not the cooldown',
            b5.due('DE:AD:00:00:00:01', now=2011.0))
        chk('a failed attempt does not count as an exchange',
            b5.peers['de:ad:00:00:00:01'].get('exchanges', 0) == 0)

        T0 = 1000.0
        b10 = PeerBook(os.path.join(tmp, 'p10.json'), cooldown=30.0, retry=60.0)
        b10.record('CA:FE:00:00:00:01', now=T0)
        b10.note_attempt('CA:FE:00:00:00:01', now=T0)
        chk('wait() reports the retry backoff when it outlasts the cooldown',
            abs(b10.wait('CA:FE:00:00:00:01', now=T0 + 44) - 16.0) < 1,
            b10.wait('CA:FE:00:00:00:01', now=T0 + 44))
        chk('and it is not due while wait() is non-zero',
            not b10.due('CA:FE:00:00:00:01', now=T0 + 44))
        chk('wait() reaching zero means due -- the two agree',
            b10.wait('CA:FE:00:00:00:01', now=T0 + 60) == 0.0
            and b10.due('CA:FE:00:00:00:01', now=T0 + 60))
        chk('a peer that never failed is not held by the retry rule at all',
            PeerBook(os.path.join(tmp, 'p10b.json'), cooldown=30.0, retry=60.0)
            .due('CA:FE:00:00:00:09', now=T0))
        ENG = (16.0, 31.0, 44.0, 80.0, 87.0, 100.0, 144.0, 157.0)
        b11 = PeerBook(os.path.join(tmp, 'p11.json'), cooldown=30.0, retry=60.0)
        b11.record('CA:FE:00:00:00:02', now=T0)
        for t in ENG:
            if not b11.due('CA:FE:00:00:00:02', now=T0 + t):
                b11.note_attempt('CA:FE:00:00:00:02', now=T0 + t)
        chk('re-arming the backoff on every refusal is what locked the peer out for ever',
            not b11.due('CA:FE:00:00:00:02', now=T0 + 157))
        b12 = PeerBook(os.path.join(tmp, 'p12.json'), cooldown=30.0, retry=60.0)
        b12.record('CA:FE:00:00:00:03', now=T0)
        for t in ENG:
            pass
        chk('declining to serve records nothing, so the peer is due when its cooldown expires',
            b12.due('CA:FE:00:00:00:03', now=T0 + 44)
            and b12.due('CA:FE:00:00:00:03', now=T0 + 157))
        chk('and the two refusals inside the cooldown are correctly refused',
            not b12.due('CA:FE:00:00:00:03', now=T0 + 16)
            and not b12.due('CA:FE:00:00:00:03', now=T0 + 29))
        chk('setting the wait clears the retry backoff too, so the number is the truth',
            (b10.set_wait('CA:FE:00:00:00:01', 5.0, now=T0 + 100)
             and abs(b10.wait('CA:FE:00:00:00:01', now=T0 + 100) - 5.0) < 1),
            b10.wait('CA:FE:00:00:00:01', now=T0 + 100))

        if src is not None:
            stb = sp_store.Store(os.path.join(tmp, 'backfill'))
            import_into(stb, src, log=lambda m: None)
            some = [c for _t, _b, c in stb.messages()][:3]
            for c in some:
                stb.add_message(c, 'inbox')
            bb = PeerBook(os.path.join(tmp, 'bf.json'))
            bb.record('96:58:CB:AA:BB:CC', got_ids=[c[0x20:0x28] for c in some])
            for c in some:
                m = stb._load_meta(); m['origins'].pop(c[0x20:0x28].hex(), None); stb._save_meta(m)
            chk('an unstamped message is not yet recognisable as received',
                not any(stb.is_from_air(c, 'inbox') for c in some))
            n_bf = backfill_air_provenance(stb, bb, log=lambda m: None)
            chk('the peer book can say which held messages a console gave us', n_bf == len(some),
                n_bf)
            chk('and they are then refused by the serving policy',
                all(stb.is_from_air(c, 'inbox') for c in some))
            chk('backfilling twice changes nothing',
                backfill_air_provenance(stb, bb, log=lambda m: None) == 0)

        if src is not None:
            both = select_for_peer(st, [0x00030600, 0x00020800])
            chk('we serve only titles the peer declares',
                {sp_cec.parse_header(c)['cec_title_id'] for c in both} == {0x00030600, 0x00020800},
                len(both))
            chk('a peer declaring nothing we hold gets nothing',
                select_for_peer(st, [0x00999900]) == [])
            b3 = PeerBook(os.path.join(tmp, 'p3.json'))
            mk7 = [c for c in both if sp_cec.parse_header(c)['cec_title_id'] == 0x00030600][0]
            b3.record('11:22:33:44:55:66', got_ids=[mk7[0x20:0x28]])
            chk('we never hand a console back what it gave us',
                all(sp_cec.parse_header(c)['cec_title_id'] != 0x00030600
                    for c in select_for_peer(st, [0x00030600, 0x00020800], b3, '11:22:33:44:55:66')))
            b4 = PeerBook(os.path.join(tmp, 'p4.json'))
            b4.record('11:22:33:44:55:66', sent_ids=[mk7[0x20:0x28]])
            chk('and we do not send the same message twice',
                all(sp_cec.parse_header(c)['cec_title_id'] != 0x00030600
                    for c in select_for_peer(st, [0x00030600, 0x00020800], b4, '11:22:33:44:55:66')))
            chk('Tomodachi Life\'s two messages both come out',
                len(select_for_peer(st, [0x0008C500])) == 2,
                len(select_for_peer(st, [0x0008C500])))
            st3 = sp_store.Store(os.path.join(tmp, 'store3'))
            inbound = [c for _t, _b, c in st.messages(0x00030600)][0]
            st3.add_message(inbound, 'inbox', key=st.title_key(0x00030600),
                            origin='air:96:58:cb:00:11:22')
            chk('gate 1: a message a console gave us is NEVER served on',
                select_for_peer(st3, [0x00030600]) == [])
            chk('and it is still filed, so it can be read and verified',
                len(st3.messages(0x00030600, 'inbox')) == 1
                and st3.verify(0x00030600, inbound) is True)
            st3.add_message(inbound, 'outbox', origin='air:96:58:cb:00:11:22')
            chk('gate 2: air-sourced data in the OUTBOX is refused as well',
                select_for_peer(st3, [0x00030600]) == [],
                len(select_for_peer(st3, [0x00030600])))
            st4 = sp_store.Store(os.path.join(tmp, 'store4'))
            st4.add_message(inbound, 'outbox', origin='/some/console/dump.bin')
            chk('while the operator\'s own imported data IS served',
                len(select_for_peer(st4, [0x00030600])) == 1)
            chk('there is no flag that turns forwarding back on',
                'forward' not in str(_inspect_args(select_for_peer)).lower(),
                _inspect_args(select_for_peer))
            n_before = len(select_for_peer(st, [0x00030600, 0x00020800]))
            st5 = sp_store.Store(os.path.join(tmp, 'store5'))
            import_into(st5, src, log=lambda m: None)
            import_into(st5, src, log=lambda m: None, replace=True)
            chk('import --replace leaves exactly one copy, not two',
                len(select_for_peer(st5, [0x00030600, 0x00020800])) == n_before,
                (len(select_for_peer(st5, [0x00030600, 0x00020800])), n_before))
            st6 = sp_store.Store(os.path.join(tmp, 'fixname'))
            import_into(st6, src, log=lambda m: None)
            st6.add_title(0x00030600, name='WRONG NAME')
            chk('a title name can be wrong on disk', st6.title_name(0x00030600) == 'WRONG NAME')
            import_into(st6, src, log=lambda m: None)
            chk('re-importing corrects a title name that was already stored',
                st6.title_name(0x00030600) == 'MARIO KART 7', st6.title_name(0x00030600))
            chk('and an import records where the data came from',
                st5.origin([c for _t, _b, c in st5.messages(0x00030600)][0])['source']
                == os.path.abspath(src))

        args = argparse.Namespace(store=os.path.join(tmp, 'store'), cooldown=100.0, mac=None,
                                  rotate_identity=False, rotate_every='0',
                                  start_paused=False, iface='sim',
                                  exchange_gap=0.0, keep_runs=3, max_iface_failures=3,
                                  channel='1,6,11', window=30, verbose=0, idle=1.0, pcap=False)
        r = Relay(args)
        chk('the identity is stable across restarts',
            r.fixed_identity() == Relay(args).fixed_identity(), r.fixed_identity())
        chk('and it is not rotating unless asked', r.next_identity() == r.identity)
        args2 = argparse.Namespace(**{**vars(args), 'rotate_identity': True})
        r2 = Relay(args2)
        chk('--rotate-identity gives a different MAC each time',
            len({r2.next_identity() for _ in range(20)}) > 1)

        def relay_every(name, every, **kw):
            return Relay(argparse.Namespace(**{**vars(args), 'store': os.path.join(tmp, name),
                                               'rotate_every': every, **kw}))

        rt = relay_every('rotA', '3600')
        chk('a timed rotation is not due the moment it is configured',
            not rt.rotation_due() and rt.next_identity() == rt.identity)
        chk('and status says how long is left, to the second',
            3590 <= rt.status()['next_rotation_s'] <= 3600, rt.status()['next_rotation_s'])
        rt.identity_since = time.time() - 3601
        chk('it IS due once the period has elapsed', rt.rotation_due())
        chk('and the new identity differs from the old one',
            rt.next_identity() != rt.identity)
        chk('status counts down to zero, never negative',
            rt.status()['next_rotation_s'] == 0.0, rt.status()['next_rotation_s'])

        chk('rotation is OFF by default, and status says so',
            relay_every('rotB', '0').rotation_due() is False
            and relay_every('rotB2', '0').status()['next_rotation_s'] is None)

        for bad in ('eight hours', '', None, '-1'):
            rb = relay_every('rotC', bad); rb.log = lambda m: None
            chk('a nonsense --rotate-every %r is ignored, not fatal' % (bad,),
                rb.rotate_seconds() == 0 and rb.rotation_due() is False)
        rfloor = relay_every('rotD', '5'); rfloor.log = lambda m: None
        chk('a period below the floor is raised to it, not honoured',
            rfloor.rotate_seconds() == MIN_ROTATE_SECONDS)

        rp = relay_every('rotE', '3600')
        touched = []
        rp.set_iface_mac = lambda mac: touched.append(mac) or True
        rp.log = lambda m: None
        ctlr = Control(os.path.join(tmp, 'unused.sock'), rp)
        out = ctlr.handle({'cmd': 'rotate', 'now': True})
        chk('`ctl rotate --now` does NOT touch the interface from the control thread',
            out['ok'] and touched == [], touched)
        chk('it schedules the change for the next pass boundary instead', rp.rotation_due())

        ron = relay_every('rotH', '0'); ron.log = lambda m: None
        seen = []
        ron.set_iface_mac = lambda mac: seen.append(mac) or True
        before = ron.identity
        envp = os.path.join(tmp, 'relay.env')
        write_env_key(envp, 'SP_EXTRA', '--keep-runs 5')
        sr = Relay(argparse.Namespace(**{**vars(args), 'store': os.path.join(tmp, 'storeS'),
                                         'settings_file': envp}))
        sr.log = lambda m: None
        sc = Control(os.path.join(tmp, 'unused3.sock'), sr)
        chk('saving the adapter works', sc.handle({'cmd': 'set_adapter', 'name': 'wlp3s0'})['ok'])
        chk('and status reports it', sr.status()['adapter'] == 'wlp3s0' and sr.status()['can_save_settings'])
        chk('a rotation period is saved for the next restart',
            sc.handle({'cmd': 'rotate', 'seconds': 3600})['ok']
            and read_env_file(envp).get('SP_ROTATE') == '3600')
        chk('other settings in the file survive', read_env_file(envp).get('SP_EXTRA') == '--keep-runs 5')
        for bad in ('wlan0\nSP_EXTRA=--evil', '../x', 'a' * 16, '', None, 7):
            chk('a bad adapter name is refused: %r' % (bad,),
                not sc.handle({'cmd': 'set_adapter', 'name': bad})['ok'])
        chk('the file still holds only the good value', read_env_file(envp).get('SP_IFACE') == 'wlp3s0'
            and '--evil' not in open(envp).read())
        chk('a foreground daemon refuses to save an adapter',
            not Control(os.path.join(tmp, 'unused4.sock'), r).handle(
                {'cmd': 'set_adapter', 'name': 'wlp3s0'})['ok'])
        rep = Control(os.path.join(tmp, 'unused2.sock'), ron).handle(
            {'cmd': 'rotate', 'seconds': 3600})
        chk('turning rotation on does not touch the interface from the control thread either',
            rep['ok'] and seen == [] and ron.identity == before, (seen, rep))
        chk('but it does make a rotation due at the next pass boundary', ron.rotation_due())
        got = ron.apply_rotation()
        chk('the pass boundary picks a new MAC and retunes the interface for it',
            got != before and seen == [got], (got, seen))
        ron._adopt(got)
        chk('adopting it resets the clock and counts the change',
            ron.identity == got and ron.rotations == 1 and ron.identity_since > 0)
        chk('and persists it, so a restart resumes this MAC',
            (ron.load_rotation() or {}).get('mac') == got)
        chk('the next pass does not rotate again', ron.apply_rotation() == got and seen == [got])

        rfail = relay_every('rotI', '3600'); rfail.log = lambda m: None
        rfail.identity_since = 0.0
        held = rfail.identity
        rfail.set_iface_mac = lambda mac: False
        chk('a vif that will not change leaves the OLD identity in place',
            rfail.apply_rotation() == held and rfail.identity == held)

        rs = relay_every('rotF', '3600'); rs.log = lambda m: None
        rs.begin_rotation()
        first = rs.identity
        chk('enabling rotation starts on a FRESH mac, not the store-derived fixed one',
            first != rs.fixed_identity())
        rs2 = relay_every('rotF', '3600'); rs2.log = lambda m: None
        rs2.begin_rotation()
        chk('and a restart resumes that identity rather than rotating again',
            rs2.identity == first and abs(rs2.identity_since - rs.identity_since) < 2)
        json.dump({'mac': first, 'since': time.time() + 86400}, open(rs2.rotation_path(), 'w'))
        rs3 = relay_every('rotF', '3600'); rs3.log = lambda m: None
        rs3.begin_rotation()
        chk('a saved time in the future (clock moved back) is clamped, not trusted',
            rs3.identity_since <= time.time() + 1 and not rs3.rotation_due())
        open(rs3.rotation_path(), 'w').write('not json')
        rs4 = relay_every('rotF', '3600'); rs4.log = lambda m: None
        chk('a corrupt rotation file reads as absent', rs4.load_rotation() is None)

        def rig(relay, iface_now, set_ok=True):
            box = {'mac': iface_now, 'calls': []}
            relay.iface_mac = lambda: box['mac']
            def fake_set(mac):
                box['calls'].append(mac)
                if set_ok:
                    box['mac'] = mac.lower()
                return set_ok
            relay.set_iface_mac = fake_set
            relay.log = lambda m: None
            return box

        rm = Relay(argparse.Namespace(**{**vars(args), 'store': os.path.join(tmp, 'macA'),
                                         'mac': 'ba:ae:6e:44:55:66'}))
        b = rig(rm, 'ba:ae:6e:77:88:99')
        chk('a --mac that the interface does not share is realigned, not ignored',
            rm.align_iface_identity() and b['calls'] == ['ba:ae:6e:44:55:66'], b)
        chk('and no mismatch is left recorded once it agrees', rm.iface_mismatch is None)

        rm2 = Relay(argparse.Namespace(**{**vars(args), 'store': os.path.join(tmp, 'macB'),
                                          'mac': 'ba:ae:6e:44:55:66'}))
        b2 = rig(rm2, 'ba:ae:6e:44:55:66')
        chk('an interface that already agrees is left alone',
            rm2.align_iface_identity() and b2['calls'] == [], b2)

        rm3 = Relay(argparse.Namespace(**{**vars(args), 'store': os.path.join(tmp, 'macC'),
                                          'mac': 'ba:ae:6e:44:55:66'}))
        rig(rm3, 'ba:ae:6e:77:88:99', set_ok=False)
        chk('a mismatch that cannot be fixed FAILS rather than passing quietly',
            rm3.align_iface_identity() is False)
        chk('and it is reported in status, naming both addresses',
            rm3.status()['iface_mismatch'] == {'iface': 'sim',
                                               'iface_mac': 'ba:ae:6e:77:88:99',
                                               'identity': 'ba:ae:6e:44:55:66'},
            rm3.status()['iface_mismatch'])

        rm4 = Relay(argparse.Namespace(**{**vars(args), 'store': os.path.join(tmp, 'macD'),
                                          'mac': 'ba:ae:6e:44:55:66',
                                          'rotate_identity': True}))
        b4 = rig(rm4, 'ba:ae:6e:77:88:99')
        chk('--rotate-identity is exempt: it drives the vif itself, per pass',
            rm4.align_iface_identity() and b4['calls'] == [], b4)

        rm5 = Relay(argparse.Namespace(**{**vars(args), 'store': os.path.join(tmp, 'macE')}))
        b5 = rig(rm5, None)
        chk('an unreadable interface address is a NOTE, not a false alarm',
            rm5.align_iface_identity() and b5['calls'] == [] and rm5.iface_mismatch is None)

        rm6 = Relay(argparse.Namespace(**{**vars(args), 'store': os.path.join(tmp, 'macF'),
                                          'mac': 'ba:ae:6e:44:55:66', 'rotate_every': '3600'}))
        b6 = rig(rm6, 'ba:ae:6e:77:88:99')
        chk('a TIMED-rotation relay still realigns its interface at startup',
            rm6.align_iface_identity() and b6['calls'] == ['ba:ae:6e:44:55:66'], b6)

        rgap = Relay(argparse.Namespace(**{**vars(args), 'store': os.path.join(tmp, 'gap'),
                                           'max_iface_failures': 2}))
        chk('a healthy relay does not ask to be restarted', rgap.iface_failures == 0)
        rgap.iface_failures = 2
        chk('and the restart threshold is what the argument says',
            rgap.iface_failures >= rgap.a.max_iface_failures)
        chk('the exchange gap is reported in status', 'exchange_gap_s' in rgap.status())

        sockp = os.path.join(tmp, 'ctl.sock')
        ctl = Control(sockp, r)
        ctl.start()
        time.sleep(0.3)
        try:
            chk('status answers over the socket', send_command(sockp, 'status')['ok'])
            chk('the control socket is private to its owner',
                stat.S_IMODE(os.stat(sockp).st_mode) == 0o600,
                oct(stat.S_IMODE(os.stat(sockp).st_mode)))
            me, other = os.getuid(), os.getuid() + 1
            pdir = tempfile.mkdtemp(prefix='linuxpass-perm-', dir='/tmp')
            os.chmod(pdir, 0o755)
            secret = os.path.join(pdir, 'secret')
            open(secret, 'w').close()
            os.chmod(secret, 0o600)
            chk('a caller may import a file it can read', peer_can_read(secret, me))
            chk('but not a file only someone else can read', not peer_can_read(secret, other))
            os.chmod(secret, 0o644)
            chk('a world-readable file is fine', peer_can_read(secret, other))
            os.chmod(pdir, 0o700)
            chk('unless a directory above it is closed', not peer_can_read(secret, other))
            os.chmod(pdir, 0o755)
            chk('a missing file is not readable', not peer_can_read(secret + 'x', other))
            os.chmod(secret, 0o600)
            refused = ctl.handle({'cmd': 'import', 'path': secret}, peer_uid=other)
            chk('import refuses a path the caller cannot read',
                not refused['ok'] and 'cannot read' in refused['error'], refused)
            shutil.rmtree(pdir, ignore_errors=True)
            chk('pause disables exchanges',
                send_command(sockp, 'pause')['enabled'] is False and r.enabled is False)
            chk('resume re-enables them',
                send_command(sockp, 'resume')['enabled'] is True and r.enabled is True)
            chk('toggle flips it', send_command(sockp, 'toggle')['enabled'] is False)
            send_command(sockp, 'toggle')
            chk('status reports the store contents',
                send_command(sockp, 'status')['status']['messages'] == len(r.store.messages()))
            chk('an unknown command is refused, not fatal',
                send_command(sockp, 'nonsense')['ok'] is False)
            chk('import can be driven over the socket',
                send_command(sockp, 'import', path=src)['ok'] if src is not None else True)
            chk('and status no longer advertises a forwarding mode',
                'forward_received' not in send_command(sockp, 'status')['status'])
            chk('status separates what we HOLD from what we can SERVE',
                {'servable', 'held_but_never_served'}
                <= set(send_command(sockp, 'status')['status']))
            stt = send_command(sockp, 'status')['status']
            chk('and the two account for everything in the store',
                stt['servable'] + stt['held_but_never_served'] >= 1
                and stt['servable'] <= stt['messages'],
                (stt['servable'], stt['held_but_never_served'], stt['messages']))
            st_ = send_command(sockp, 'store')
            chk('the whole store comes back in ONE round trip', st_['ok']
                and 'titles' in st_['store'], list(st_.get('store', {})))
            chk('and it reports the format\'s own title cap',
                st_['store']['max_titles'] == sp_store.MBOXLIST_MAX,
                st_['store']['max_titles'])
            t0 = st_['store']['titles'][0]
            chk('each title lists its messages with what the GUI needs to draw them',
                {'id', 'box', 'bytes', 'created', 'send_mode', 'origin', 'servable', 'hmac'}
                <= set(t0['messages'][0]), sorted(t0['messages'][0]))
            chk('a store view distinguishes servable from merely held',
                any(m['servable'] for tt in st_['store']['titles'] for m in tt['messages'])
                and any(not m['servable'] for tt in st_['store']['titles']
                        for m in tt['messages']) if len(st_['store']['titles']) > 1 else True)

            chk('the denylist view has both halves',
                {'blocked', 'cooldowns'} <= set(send_command(sockp, 'denylist')))
            chk('blocking over the socket needs a mac',
                send_command(sockp, 'block')['ok'] is False)
            send_command(sockp, 'block', mac='DE:AD:BE:EF:00:01', note='test')
            dl = send_command(sockp, 'denylist')
            chk('a blocked console appears on the denylist',
                any(b['mac'] == 'de:ad:be:ef:00:01' for b in dl['blocked']), dl['blocked'])
            chk('with its reason', dl['blocked'][0]['note'] == 'test')
            chk('and the relay refuses to serve it',
                r.peer_hook(None, 'DE:AD:BE:EF:00:01', [{'titleID': '00020800'}]) is None)
            send_command(sockp, 'unblock', mac='DE:AD:BE:EF:00:01')
            chk('unblocking clears it', not send_command(sockp, 'denylist')['blocked'])

            r.book.record('BE:EF:00:00:00:09')
            send_command(sockp, 'cooldown', mac='BE:EF:00:00:00:09', seconds=5)
            chk('the time remaining can be set from the socket',
                abs(send_command(sockp, 'cooldown', mac='BE:EF:00:00:00:09',
                                 seconds=5)['remaining_s'] - 5) < 1)
            chk('setting it to zero makes the peer due',
                send_command(sockp, 'cooldown', mac='BE:EF:00:00:00:09',
                             seconds=0)['remaining_s'] == 0)

            r.note_encounter({'peer': 'AA:BB:CC:00:00:07', 'result': 'exchanged',
                              'sent': [{'title': '00020800', 'bytes': 32712}], 'received': []})
            enc = send_command(sockp, 'encounters')['encounters']
            chk('an encounter is recorded as an event, with what moved',
                enc and enc[-1]['peer'] == 'AA:BB:CC:00:00:07'
                and enc[-1]['sent'][0]['title'] == '00020800', enc[-1] if enc else None)
            chk('and it carries a timestamp', isinstance(enc[-1].get('when'), (int, float)))
            chk('the log comes back as lines', isinstance(send_command(sockp, 'log')['log'], list))

            tid = st_['store']['titles'][-1]['title']
            mid = st_['store']['titles'][-1]['messages'][0]['id']
            bx = st_['store']['titles'][-1]['messages'][0]['box']
            chk('one message can be removed',
                send_command(sockp, 'message_remove', title=tid, id=mid, box=bx)['removed'])
            chk('removing it twice reports nothing to do',
                send_command(sockp, 'message_remove', title=tid, id=mid,
                             box=bx)['removed'] is False)
            n_before = len(send_command(sockp, 'store')['store']['titles'])
            chk('a whole title can be removed',
                send_command(sockp, 'title_remove', title=tid)['ok'])
            chk('and the store shrinks by one',
                len(send_command(sockp, 'store')['store']['titles']) == n_before - 1)
            chk('a malformed title is refused, not fatal',
                send_command(sockp, 'title_remove', title='zzzz')['ok'] is False)

            chk('stop asks the loop to finish',
                send_command(sockp, 'stop')['ok'] and r.running is False)
        finally:
            ctl.shutdown()
        chk('the socket is cleaned up on shutdown', not os.path.exists(sockp))

        shallow = control_socket_path(os.path.join(tmp, 'store'))
        chk('a normal store keeps its socket inside it',
            shallow == os.path.join(os.path.abspath(os.path.join(tmp, 'store')), CONTROL_SOCKET))
        deep = os.path.join(tmp, *(['verylongdirectoryname'] * 6), 'store')
        dp = control_socket_path(deep)
        chk('a store too deep for sun_path gets a short path instead',
            dp != os.path.join(deep, CONTROL_SOCKET) and len(dp.encode()) <= SOCK_PATH_MAX,
            '%d bytes' % len(dp.encode()))
        chk('and both ends derive the same one', control_socket_path(deep) == dp)
        chk('different deep stores do not collide',
            control_socket_path(deep + '2') != dp)
        os.makedirs(deep, exist_ok=True)
        r7 = Relay(argparse.Namespace(**{**vars(args), 'store': deep}))
        c7 = Control(control_socket_path(deep), r7)
        c7.start(); time.sleep(0.3)
        try:
            chk('a deep store\'s daemon really is reachable',
                send_command(control_socket_path(deep), 'status')['ok'])
            chk('and it did not record a bind failure', c7.failed is None, c7.failed)
        finally:
            c7.shutdown()
        c8 = Control('/nonexistent-directory-for-a-test/x.sock', r7)
        c8.start(); time.sleep(0.3)
        chk('an impossible socket path is reported on the relay log, not silently swallowed',
            c8.failed is not None, c8.failed)
        c8.shutdown()

        if src is not None:
            r3 = Relay(argparse.Namespace(**{**vars(args), 'store': os.path.join(tmp, 'store')}))

            class _FakeLink:
                src = b'\x00' * 6
                token = b'\x00' * 8
            svc = [{'titleID': '%08x' % t} for t in (0x0008C500, 0x00030600, 0x00020800)]
            got = r3.peer_hook(_FakeLink(), 'AA:BB:CC:DD:EE:01', svc)
            chk('the peer hook serves the titles the peer declared', got is not None)
            if got:
                services, objects = got
                mp = r3._pending_map
                n_msg = len(r3._pending_sent)
                chk('Tomodachi Life\'s two messages ride in ONE object',
                    len(mp) < n_msg and sum(len(v) for v in mp.values()) == n_msg,
                    '%d object(s) carry %d message(s)' % (len(mp), n_msg))
                chk('every mapped index really is an envelope in the object list',
                    all(objects[i][:2] == b'\x61\x61' for i in mp))
                chk('and every envelope in the object list is mapped',
                    {i for i, o in enumerate(objects) if o[:2] == b'\x61\x61'} == set(mp))
                first = min(mp)
                part = [m for i, ids in sorted(mp.items()) if i < first + 1 for m in ids]
                chk('a partial transfer credits only the messages that actually went',
                    len(part) == len(mp[first]) and len(part) < n_msg,
                    '%d of %d' % (len(part), n_msg))
                chk('and nothing is credited when no object was delivered',
                    [m for i, ids in sorted(mp.items()) if i < 0 for m in ids] == [])

        if src is not None:
            import sp_link
            rsim = Relay(argparse.Namespace(**{**vars(args), 'store': os.path.join(tmp, 'store')}))
            seen = {}

            def _hook(link, mac, services):
                seen['mac'] = mac
                seen['services'] = services
                r = rsim.peer_hook(link, mac, services)
                seen['result'] = r
                return r
            out = {}
            sp_link.simulate(verbose=0, peer_hook=_hook, out=out)
            L = out['link']
            sim_mac = ((corpus.vector('handshake') or {}).get('console_mac')
                       or '96:58:cb:11:22:33')
            chk('the console was identified through the real handshake',
                sp_link.T.macstr(L.peer) == sim_mac, L.peer)
            chk('its encrypted frame still decrypted with our payload attached',
                len(L.decrypted) >= 1, len(L.decrypted))
            chk('and the machine got as far as the recording allows',
                L.max_state >= L.SYNSENT, L.STATE_NAME[L.max_state])
            chk('the relay was asked what to serve, by the console\'s real MAC',
                seen.get('mac') == sim_mac, seen.get('mac'))
            chk('and it answered with (services, objects)',
                isinstance(seen.get('result'), tuple) and len(seen['result']) == 2)
            if isinstance(seen.get('result'), tuple):
                svc, objs = seen['result']
                chk('serving only the one title that console declared',
                    [t for t, _f, _tr in svc] == [0x00020800], svc)
                chk('and a complete object list, prefix included',
                    len(objs) >= 9 and objs[0][:2] == b'\x63\x63', len(objs))
                chk('with every message id accounted for in the delivery map',
                    sum(len(v) for v in rsim._pending_map.values()) == len(rsim._pending_sent))

            rdec = Relay(argparse.Namespace(**{**vars(args),
                                               'store': os.path.join(tmp, 'store')}))
            rdec.book.block(sim_mac, note='selftest')
            out2 = {}
            sp_link.simulate(verbose=0, peer_hook=rdec.peer_hook, out=out2)
            L2 = out2['link']
            chk('the link records WHY it was given nothing', L2.declined == 'blocked', L2.declined)
            chk('the reason appears in the per-run log',
                'denylist' in '\n'.join(L2.log_lines))
            chk('the relay still records it on its own side', rdec._declined == 'blocked')
            _tx, _ = sp_link.T.read_tx_counters('sim')
            L2.verdict(_tx, _tx, None)
            chk('and the verdict says the pass ended by our choice',
                'we offered nothing' in '\n'.join(L2.log_lines)
                and 'blocked' in '\n'.join(L2.log_lines))

            rcd = Relay(argparse.Namespace(**{**vars(args),
                                              'store': os.path.join(tmp, 'store')}))
            rcd.book.unblock(sim_mac)
            rcd.book.record(sim_mac)
            out3 = {}
            sp_link.simulate(verbose=0, peer_hook=rcd.peer_hook, out=out3)
            L3 = out3['link']
            chk('a cooldown decline reaches the link too', L3.declined == 'cooldown', L3.declined)
            chk('and names the cooldown in the run log',
                'cooldown' in '\n'.join(L3.log_lines))

            L1 = out['link']
            L1.verdict(_tx, _tx, None)
            chk('a served pass leaves the verdict clean',
                L1.declined is None
                and 'we offered nothing' not in '\n'.join(L1.log_lines))

        rnl = Relay(argparse.Namespace(**{**vars(args), 'store': os.path.join(tmp, 'store')}))
        rnl.book.block('DE:AD:BE:EF:00:02')
        chk('declining without a link does not raise',
            rnl.peer_hook(None, 'DE:AD:BE:EF:00:02', [{'titleID': '00020800'}]) is None)
        chk('and still records the reason on the relay', rnl._declined == 'blocked')

        class _NoLog:
            src = b'\x00' * 6
            token = b'\x00' * 8
        rnl2 = Relay(argparse.Namespace(**{**vars(args), 'store': os.path.join(tmp, 'store')}))
        rnl2.book.block('DE:AD:BE:EF:00:03')
        nl = _NoLog()
        chk('a link that cannot log is tolerated rather than crashing the hook',
            rnl2.peer_hook(nl, 'DE:AD:BE:EF:00:03', [{'titleID': '00020800'}]) is None)
        chk('and it is still marked on that link', getattr(nl, 'declined', None) == 'blocked')

        r4 = Relay(argparse.Namespace(**{**vars(args), 'store': os.path.join(tmp, 'keep'),
                                         'keep_runs': 3}))
        rd = os.path.join(tmp, 'keep', 'runs')
        os.makedirs(rd, exist_ok=True)
        for i in range(10):
            open(os.path.join(rd, 'relay_%d.log' % i), 'w').write('x')
            os.utime(os.path.join(rd, 'relay_%d.log' % i), (1000 + i, 1000 + i))
        r4.prune_runs()
        chk('per-pass logs are pruned to --keep-runs', len(os.listdir(rd)) == 3,
            sorted(os.listdir(rd)))
        chk('and the newest are the ones kept',
            sorted(os.listdir(rd)) == ['relay_7.log', 'relay_8.log', 'relay_9.log'],
            sorted(os.listdir(rd)))
        r5 = Relay(argparse.Namespace(**{**vars(args), 'store': os.path.join(tmp, 'keep'),
                                         'keep_runs': 0}))
        r5.prune_runs()
        chk('--keep-runs 0 keeps everything', len(os.listdir(rd)) == 3)

        old = os.environ.pop('NOTIFY_SOCKET', None)
        chk('sd_notify does nothing when not run under systemd', sd_notify('WATCHDOG=1') is False)
        os.environ['NOTIFY_SOCKET'] = os.path.join(tmp, 'nonexistent.sock')
        chk('and fails safe when the socket is not there', sd_notify('WATCHDOG=1') is False)
        nsock = os.path.join(tmp, 'notify.sock')
        ns = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        ns.bind(nsock)
        os.environ['NOTIFY_SOCKET'] = nsock
        chk('and delivers the heartbeat when it is', sd_notify('WATCHDOG=1') is True)
        ns.settimeout(1.0)
        chk('systemd would receive exactly WATCHDOG=1', ns.recv(64) == b'WATCHDOG=1')
        r6 = Relay(argparse.Namespace(**{**vars(args), 'store': os.path.join(tmp, 'keep')}))
        r6.last_tick = 0
        r6.tick()
        chk('the run loop\'s tick sends that heartbeat', ns.recv(64) == b'WATCHDOG=1')
        r6.tick()
        ns.settimeout(0.2)
        chk('but not more than once every 5 s', _timesout(lambda: ns.recv(64)))
        ns.close()
        os.environ.pop('NOTIFY_SOCKET', None)
        if old:
            os.environ['NOTIFY_SOCKET'] = old
        bad = _scan_code_for_machine_kill(os.path.abspath(__file__))
        chk('nothing in this daemon can reboot the machine', not bad, bad)

        whole = bytearray(32712)
        struct.pack_into('<I', whole, 4, 32712)
        chk('a message whose header matches its length is whole', message_is_whole(bytes(whole)))
        chk('and its declared length reads back', declared_length(bytes(whole)) == 32712,
            declared_length(bytes(whole)))
        chk('THE REAL CASUALTY: 24,664 B declaring 32,712 is rejected',
            not message_is_whole(bytes(whole)[:24664]))
        chk('a message longer than it declares is rejected too',
            not message_is_whole(bytes(whole) + b'\x00' * 4))
        chk('a runt too short to hold a header is rejected, not crashed',
            not message_is_whole(b'\x00' * 4) and declared_length(b'') == -1)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print('\n%d/%d checks passed' % (ok, tot))
    return 0 if ok == tot else 1


def main():
    ap = argparse.ArgumentParser(description='LinuxPass: StreetPass a Nintendo 3DS from Linux.')
    sub = ap.add_subparsers(dest='cmd')

    run = sub.add_parser('run', help='the daemon')
    run.add_argument('--store', default='relay_store')
    run.add_argument('--iface', default='mon0')
    run.add_argument('--channel', default='1,6,11')
    run.add_argument('--window', type=float, default=180.0,
                     help='seconds to listen per pass before starting a new one. A console that '
                          'fails an engagement backs off and may not try again for a minute or '
                          'more, so a short window tears the pass down mid-retry.')
    run.add_argument('--idle', type=float, default=2.0, help='pause between passes')
    run.add_argument('--cooldown', type=float, default=DEFAULT_COOLDOWN,
                     help='seconds before the same console is engaged again, keyed on the '
                          "PEER's MAC. This is OUR rate limit and it exists so we do not fill a "
                          'console inbox (~8-9 per title) with duplicates of our own messages. It '
                          "is NOT the console's MacFilter: that is a separate and much harder "
                          'limit at the far end, keyed on OUR MAC, which this program cannot '
                          'lift. An earlier version of this help said no such limit existed; that '
                          'was wrong -- the run it rested on was rotating identity, so every pass '
                          'presented a MAC the console had never seen.')
    run.add_argument('--mac', default=None, help='override the fixed identity')
    run.add_argument('--rotate-every', default='0', metavar='SECONDS',
                     help='present a new MAC every SECONDS (0 = never, the default; minimum %d). '
                          'The change happens at a pass boundary, so it can never land inside an '
                          'exchange, and it is persisted so a restart resumes the schedule instead '
                          'of falling back to the fixed MAC that consoles have already blocked. '
                          'This lifts the limit at the FAR end (the MacFilter). Ours is separate: '
                          'a period shorter than --cooldown buys nothing against a console we have '
                          'already met, because the peer book will still be holding it off.'
                          % MIN_ROTATE_SECONDS)
    run.add_argument('--rotate-identity', action='store_true',
                     help='present a NEW MAC for every exchange. This defeats BOTH our own '
                          "--cooldown and the peer console's MacFilter, which refuses any MAC it "
                          'has already completed an exchange with and was measured still refusing '
                          '18.1 h later (6 Sep 2026). On a fixed MAC the relay therefore gets one '
                          'exchange per console per manual filter clear. Off by default because '
                          'no real console rotates like this -- not because it does not work.')
    run.add_argument('--exchange-gap', type=float, default=0.0,
                     help='seconds to hold off after a COMPLETED exchange before engaging '
                          'anything at all. Unlike the per-peer cooldown this does not depend on '
                          'a MAC, which consoles rotate.')
    run.add_argument('--max-iface-failures', type=int, default=3,
                     help='consecutive passes with an unusable monitor interface before exiting '
                          'non-zero, so the systemd unit restarts and rebuilds it')
    run.add_argument('--keep-runs', type=int, default=50,
                     help='per-pass logs to keep in <store>/runs (0 = keep everything). A quiet '
                          '180 s pass still writes ~50 kB.')
    run.add_argument('--start-paused', action='store_true')
    run.add_argument('--yy-rate', type=float, default=11.0, metavar='MBPS',
                     help='802.11b rate for the encrypted payload frames (default 11, what two '
                          'real consoles use to each other). Pass 1 for the old behaviour.')
    run.add_argument('--manifest-repeat', type=int, default=1, metavar='N',
                     help='how many times to poke a console that answered our 0x81 with nothing. '
                          'ON BY DEFAULT, with --repeat-type 0xf2 -- see --no-silent-recovery')
    run.add_argument('--repeat-type', default='0xf2', metavar='HEX',
                     help='what --manifest-repeat sends (default 0xf2, the SCAN probe). 0x81 and '
                          '0x33 were both built and measured and do NOT work.')
    run.add_argument('--no-silent-recovery', dest='silent_recovery', action='store_false',
                     help='turn the 0xF2 silent-send recovery OFF. About one exchange in three '
                          'negotiates fully and then never opens a connection, delivering nothing '
                          'in either direction; the recovery costs a rescan of ~20-30 s on those '
                          'passes and cannot fire on a healthy one. Use this to reproduce the '
                          'unrecovered baseline.')
    run.add_argument('--pcap', action='store_true')
    run.add_argument('--verbose', '-v', type=int, default=1)
    run.add_argument('--settings-file', metavar='PATH',
                     help='where the GUI\'s adapter and rotation choices are saved. The unit '
                          'reads this file when it starts.')
    run.add_argument('--control-user', default=os.environ.get('SUDO_USER'), metavar='NAME',
                     help='the one non-root user allowed to use the control socket '
                          '(default: whoever ran sudo; empty means root only)')

    imp = sub.add_parser('import', help='ingest CEC data into the store')
    imp.add_argument('path', help='a save image, a mounted dump, or an emulator NAND directory')
    imp.add_argument('--store', default='relay_store')
    imp.add_argument('--from-log', action='store_true', help='an sp_link run log instead')
    imp.add_argument('--replace', action='store_true',
                     help='empty the outbox first, so this becomes the only data the relay '
                          'serves. Use it when swapping in another console\'s data.')

    st = sub.add_parser('status', help='print the store, or the running daemon if there is one')
    st.add_argument('--store', default='relay_store')

    ct = sub.add_parser('ctl', help='talk to a running daemon')
    ct.add_argument('command', choices=['status', 'pause', 'resume', 'toggle', 'stop', 'import',
                                        'forget', 'seed', 'store', 'encounters', 'denylist',
                                        'log', 'block', 'unblock', 'cooldown', 'title_remove',
                                        'message_remove', 'rotate', 'set_adapter'])
    ct.add_argument('--store', default='relay_store')
    ct.add_argument('--path', help='for `ctl import`: what to ingest')
    ct.add_argument('--replace', action='store_true',
                    help='for `ctl import`: clear the outbox; for `ctl seed`: replace the '
                         'existing Mii Plaza message')
    ct.add_argument('--mac', help='the peer for forget / block / unblock / cooldown')
    ct.add_argument('--note', default='', help='for `ctl block`: why')
    ct.add_argument('--seconds', type=float,
                    help='for `ctl cooldown`: time remaining. For `ctl rotate`: the rotation '
                         'period, 0 to turn rotation off')
    ct.add_argument('--now', action='store_true',
                    help='for `ctl rotate`: also take a new identity at the next pass boundary')
    ct.add_argument('--adapter', help='for `ctl set_adapter`: the interface name')
    ct.add_argument('--title', help='for title_remove / message_remove, 8 hex digits')
    ct.add_argument('--id', help='for `ctl message_remove`: the message id, 16 hex digits')
    ct.add_argument('--box', default='outbox', choices=['inbox', 'outbox'])
    ct.add_argument('--limit', type=int, help='for encounters / log')
    ct.add_argument('--mii-name'); ct.add_argument('--author-name'); ct.add_argument('--greeting')

    idp = sub.add_parser('identity', help='print the fixed identity for this store')
    idp.add_argument('--store', default='relay_store')

    sub.add_parser('selftest')
    a = ap.parse_args()

    if a.cmd == 'identity':
        ns = argparse.Namespace(store=a.store, cooldown=DEFAULT_COOLDOWN, mac=None,
                                rotate_identity=False, rotate_every='0',
                                start_paused=True, iface='none',
                                channel='1,6,11', window=1, verbose=0, idle=1, pcap=False,
                                exchange_gap=0.0, keep_runs=50, max_iface_failures=3)
        print(Relay(ns).identity)
        return 0

    if a.cmd in (None, 'selftest'):
        return _selftest()
    if a.cmd == 'import':
        s = sp_store.Store(a.store)
        if a.from_log:
            import_from_log(s, a.path)
        else:
            import_into(s, a.path, replace=a.replace)
        print(s.summary())
        return 0
    if a.cmd == 'status':
        sock = control_socket_path(a.store)
        if os.path.exists(sock):
            try:
                print(json.dumps(send_command(sock, 'status')['status'], indent=2))
                return 0
            except OSError:
                print('(no daemon answering; showing the store)')
        print(sp_store.Store(a.store).summary())
        return 0
    if a.cmd == 'ctl':
        kw = {}
        if a.command == 'import':
            if not a.path:
                print('ctl import needs --path'); return 2
            kw = {'path': os.path.abspath(a.path), 'replace': a.replace}
        elif a.command == 'forget':
            kw = {'mac': a.mac} if a.mac else {}
        elif a.command in ('block', 'unblock', 'cooldown'):
            if not a.mac:
                print('ctl %s needs --mac' % a.command); return 2
            kw = {'mac': a.mac}
            if a.command == 'block':
                kw['note'] = a.note
            if a.command == 'cooldown':
                if a.seconds is None:
                    print('ctl cooldown needs --seconds'); return 2
                kw['seconds'] = a.seconds
        elif a.command == 'title_remove':
            if not a.title:
                print('ctl title_remove needs --title'); return 2
            kw = {'title': a.title}
        elif a.command == 'message_remove':
            if not (a.title and a.id):
                print('ctl message_remove needs --title and --id'); return 2
            kw = {'title': a.title, 'id': a.id, 'box': a.box}
        elif a.command == 'rotate':
            if a.seconds is None and not a.now:
                print('ctl rotate needs --seconds and/or --now'); return 2
            if a.seconds is not None:
                kw['seconds'] = a.seconds
            if a.now:
                kw['now'] = True
        elif a.command == 'set_adapter':
            if not a.adapter:
                print('ctl set_adapter needs --adapter'); return 2
            kw = {'name': a.adapter}
        elif a.command in ('encounters', 'log') and a.limit:
            kw = {'limit': a.limit}
        elif a.command == 'seed':
            kw = {'replace': a.replace}
            for k in ('mii_name', 'author_name', 'greeting'):
                if getattr(a, k, None):
                    kw[k] = getattr(a, k)
        print(json.dumps(send_command(control_socket_path(a.store), a.command, **kw),
                         indent=2))
        return 0
    return Relay(a).run()


if __name__ == '__main__':
    sys.exit(main())
