#!/usr/bin/env python3
"""The relay's OWN identity: a Mii, a greeting and a profile card that belong to this box.

Until now the relay served a copy of some console's data, which works but is a mirror, not a
resident. This builds a Mii Plaza message from nothing -- no captured input -- whose Mii, name,
greeting, card and featured title are the relay's own, and files it in the store's outbox so it is
served like any other message the operator supplied.

**Everything is derived from the store path**, through the same SHA-256 that `sp_relay` uses for
the fixed MAC. So the identity is stable across restarts, reinstalls and rebuilds of the message,
and -- the part that matters -- the Mii's creator MAC is the MAC the relay actually transmits from.
A Mii whose creator MAC is some other device is a small lie that a curious person can read straight
out of the CFL block; there is no reason to tell it.

Authoring does NOT replace importing. A store can hold an authored Mii Plaza message and an
imported Mario Kart 7 ghost side by side, and `sp_relay` serves both -- they are both outbox
content the operator put there. Note that if you author a Plaza message and leave an imported one
in the outbox, BOTH are offered (two messages of one title, which a console accepts happily -- see
MULTI_TITLE.md). Use `--replace` if you meant to swap rather than add.

    sp_identity.py show   --store relay_store
    sp_identity.py seed   --store relay_store --mii-name Relay --greeting "Hello from Linux"
    sp_identity.py seed   --store relay_store --replace        # swap out whatever Plaza data
"""
import os, sys, json, struct, hashlib, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sp_build, sp_cec, sp_store, sp_mii

#: The same string `sp_relay.Relay.fixed_identity` hashes. One seed, one identity: if these ever
#: diverge, the Mii claims to have been made on a device the relay is not.
#:
#: DELIBERATELY NOT RENAMED with the rest of the project. This is a derivation constant, not a
#: name: it is hashed with the store path to produce the relay's MAC and its Mii id. Changing it
#: would silently hand every existing installation a new identity -- a new address on the air and
#: a different Mii in every plaza that has already met it. It is invisible to users, so it stays.
SEED_PREFIX = 'sp-relay:'
MII_NAME_MAX = 10          # 20 bytes of UTF-16LE at CFL+0x1A
GREETING_MAX = 16          # 0x20 bytes at body+OFF_GREETING


def seed_digest(store_path):
    return hashlib.sha256((SEED_PREFIX + os.path.abspath(store_path)).encode()).digest()


def derive(store_path):
    """-> the relay's stable identity, from its store path alone.

    `mac` is byte-for-byte what `sp_relay.Relay.fixed_identity()` produces; there is a selftest
    that fails if the two ever drift apart.
    """
    h = seed_digest(store_path)
    return {
        'store': os.path.abspath(store_path),
        'mac': 'ba:ae:6e:%02x:%02x:%02x' % (h[0], h[1], h[2]),
        # [P] sp_mii.random_mii_id: bit 5 of the first byte must be CLEAR or meet_ValidateMii
        # (0x159A8C) drops the whole message -- silently, after cecd has already lit the green LED.
        # High nibble 9 both clears it and matches all four real ids we have observed.
        'mii_id': (0x90 | (h[3] & 0x0F)) | (int.from_bytes(h[4:7], 'little') << 8),
        # cosmetic, but derived so two relays are visibly different people rather than clones
        'face_shape': h[7] % 12,
        'hat': h[8] % 76,
        'dream': h[9] % 20,
        'hobby': h[10] % 27,
        'gender': h[11] & 1,
    }


def build_message(store_path, mii_name='Relay', author_name='LinuxPass',
                  greeting='Hello from Linux', hits=0, population=0, pet=0,
                  title_short='LinuxPass', title_long='StreetPass from Linux',
                  title_publisher='LinuxPass', when=None, **extra):
    """-> a complete Mii Plaza wire message that is this relay's own.

    Raises rather than truncating: a name silently cut in half is a worse outcome than an error,
    because it only shows up as a wrong name on somebody else's console days later.
    """
    if len(mii_name) > MII_NAME_MAX:
        raise ValueError('a Mii name is at most %d characters, got %d (%r)'
                         % (MII_NAME_MAX, len(mii_name), mii_name))
    if len(author_name) > MII_NAME_MAX:
        raise ValueError('an author name is at most %d characters, got %d'
                         % (MII_NAME_MAX, len(author_name)))
    if len(greeting) > GREETING_MAX:
        raise ValueError('a greeting is at most %d characters, got %d (%r)'
                         % (GREETING_MAX, len(greeting), greeting))
    ident = derive(store_path)
    mii = sp_build.build_cfl(mii_name=mii_name, author_name=author_name,
                             mii_id=ident['mii_id'], creator_mac=ident['mac'],
                             face_shape=ident['face_shape'],
                             gender=ident['gender'])
    profile = sp_build.build_profile(streetpass_hits=hits, plaza_population=population,
                                     hat=ident['hat'], pet=pet,
                                     dream=ident['dream'], hobby=ident['hobby'])
    body = sp_build.build_body(mii, greeting=greeting, profile=profile,
                               title_short=title_short, title_long=title_long,
                               title_publisher=title_publisher, **extra)
    return sp_build.build_message(body, when=when)


def seed(store, store_path=None, replace=False, log=print, **kw):
    """Build this relay's Plaza message and file it in the outbox. -> the message's path."""
    store_path = store_path or store.root
    msg = build_message(store_path, **kw)
    container = msg[sp_build.ENVELOPE_LEN:] if msg[:2] == b'\x61\x61' else msg
    if replace:
        n = 0
        for t, b, c in store.messages(sp_build.PLAZA_TITLE, 'outbox'):
            n += bool(store.remove_message(t, b, c))
        log('  removed %d existing Mii Plaza message(s) from the outbox' % n)
    p = store.add_message(container, 'outbox', name='StreetPass Mii Plaza',
                          key=sp_build.plaza_hmac_key(),
                          origin='authored:%s' % os.path.basename(__file__))
    ident = derive(store_path)
    log('  filed this relay\'s own Mii Plaza message (%d B)' % len(container))
    log('    Mii %r by %r, id %08x, created on %s'
        % (kw.get('mii_name', 'Relay'), kw.get('author_name', 'LinuxPass'),
           ident['mii_id'], ident['mac']))
    return p


# ---------------------------------------------------------------------------------------------

def _selftest():
    import tempfile, shutil
    ok = tot = 0
    import lp_keys as _k
    if _k.selftest_keys():
        print('  (no console keys found -- running on generated throwaway keys)')

    def chk(n, c, g=''):
        nonlocal ok, tot
        tot += 1; ok += bool(c)
        print('  [%s] %s%s' % ('PASS' if c else 'FAIL', n, ('  %s' % (g,)) if g else ''))

    tmp = tempfile.mkdtemp()
    try:
        sp = os.path.join(tmp, 'relay_store')

        # ---- the identity is stable, and it agrees with the relay's own MAC ----------------
        a, b = derive(sp), derive(sp)
        chk('the identity is deterministic', a == b, a['mac'])
        chk('and a different store is a different identity',
            derive(os.path.join(tmp, 'other'))['mac'] != a['mac'])
        import sp_relay
        ns = argparse.Namespace(store=sp, cooldown=1.0, mac=None, rotate_identity=False,
                                start_paused=True, iface='none', channel='1', window=1,
                                verbose=0, idle=1, pcap=False, exchange_gap=0.0, keep_runs=50,
                                max_iface_failures=3)
        chk('the Mii\'s creator MAC IS the MAC the relay transmits from',
            sp_relay.Relay(ns).fixed_identity() == a['mac'], a['mac'])

        # ---- the Mii id must pass the plaza's own validator --------------------------------
        chk('bit 5 of the Mii id\'s first byte is clear, as meet_ValidateMii demands',
            not ((a['mii_id'] & 0xFF) >> 5) & 1, '%08x' % a['mii_id'])
        chk('and it has the high nibble every real id we have seen carries',
            (a['mii_id'] & 0xF0) == 0x90, '%08x' % a['mii_id'])
        ids = {derive(os.path.join(tmp, 's%d' % i))['mii_id'] for i in range(64)}
        chk('64 different stores give 64 different Miis, all valid',
            len(ids) == 64 and all(not ((i & 0xFF) >> 5) & 1 for i in ids))

        # ---- the message itself -------------------------------------------------------------
        m = build_message(sp, mii_name='Relay', greeting='Hello from Linux')
        chk('it is the same size as a real plaza message', len(m) == 32732, len(m))
        c = m[sp_build.ENVELOPE_LEN:]
        h = sp_cec.parse_header(c)
        chk('it declares the Mii Plaza title', h['cec_title_id'] == sp_build.PLAZA_TITLE)
        chk('its send mode is 0, as every real plaza message is', h['send_mode'] == 0,
            h['send_mode'])
        chk('its delivery mask has the StreetPass bit', h['field_34'] & 1, h['field_34'])
        parsed = sp_cec.parse_message(c)
        chk('it parses with no problems', not parsed['problems'], parsed['problems'])
        import hmac as _h
        body = c[h['header_size']:h['header_size'] + h['body_size']]
        chk('the HMAC trailer verifies under the plaza key',
            _h.new(sp_build.plaza_hmac_key(), body, hashlib.sha256).digest()
            == c[h['header_size'] + h['body_size']:h['total_size']])
        # The Mii rides in the body AES-CCM-wrapped (APT keyslot 0x31), so a byte scan finds
        # nothing -- unwrap it the way the plaza does and read the fields back out.
        cfl, mac_ok = sp_mii.read_plaza_mii(body)     # -> (CFLStoreData, AES-CCM tag ok)
        fields = sp_mii.parse_cfl(cfl)
        valid, why = sp_mii.validate_cfl(cfl)
        chk('the wrapped Mii\'s AES-CCM tag verifies', mac_ok)
        chk('and it passes meet_ValidateMii, the plaza\'s own gate', valid, why)
        chk('the relay\'s MAC really is in the Mii\'s creator field',
            cfl[0x10:0x16] == bytes(int(x, 16) for x in a['mac'].split(':')),
            cfl[0x10:0x16].hex())
        chk('the Mii carries the name and author we asked for',
            fields.get('mii_name') == 'Relay' and fields.get('author_name') == 'LinuxPass',
            (fields.get('mii_name'), fields.get('author_name')))
        chk('and the derived Mii id', struct.unpack_from('<I', cfl, 0x0C)[0] == a['mii_id'],
            '%08x' % struct.unpack_from('<I', cfl, 0x0C)[0])
        chk('the greeting is in the body where the plaza reads it',
            body[sp_build.OFF_GREETING:sp_build.OFF_GREETING + 32]
            .decode('utf-16-le').split('\x00')[0] == 'Hello from Linux',
            body[sp_build.OFF_GREETING:sp_build.OFF_GREETING + 32]
            .decode('utf-16-le', 'replace').split('\x00')[0])

        # ---- names and greetings are refused, not silently cut ------------------------------
        chk('an over-long Mii name is refused',
            _raises(lambda: build_message(sp, mii_name='ElevenChars')))
        chk('an over-long greeting is refused',
            _raises(lambda: build_message(sp, greeting='x' * (GREETING_MAX + 1))))
        chk('a Mii name the console rejects is refused too',
            _raises(lambda: build_message(sp, mii_name='a%b')))

        # ---- seeding a store ----------------------------------------------------------------
        st = sp_store.Store(sp)
        seed(st, sp, log=lambda m: None, mii_name='Relay')
        got = st.messages(sp_build.PLAZA_TITLE, 'outbox')
        chk('it lands in the OUTBOX, so it is served', len(got) == 1, len(got))
        chk('the store can verify it', st.verify(sp_build.PLAZA_TITLE, got[0][2]) is True)
        chk('and it is recorded as authored here, not received',
            st.origin(got[0][2], 'outbox')['source'].startswith('authored:'),
            st.origin(got[0][2], 'outbox'))
        chk('so the relay will serve it',
            len(sp_relay.select_for_peer(st, [sp_build.PLAZA_TITLE])) == 1)
        chk('and it is NOT counted as something a console gave us',
            not st.is_from_air(got[0][2], 'outbox'))

        # seeding twice without --replace adds a second, which a console accepts but is rarely
        # what anyone means
        seed(st, sp, log=lambda m: None, mii_name='Relay', greeting='second')
        chk('seeding again ADDS a message unless told to replace',
            len(st.messages(sp_build.PLAZA_TITLE, 'outbox')) == 2)
        seed(st, sp, replace=True, log=lambda m: None, mii_name='Relay')
        chk('--replace leaves exactly one',
            len(st.messages(sp_build.PLAZA_TITLE, 'outbox')) == 1)

        # ---- authored and imported content coexist ------------------------------------------
        import lp_corpus as corpus
        dump = corpus.path('console_nand_2') or corpus.path('console_nand') or ''
        if os.path.exists(dump):
            st2 = sp_store.Store(os.path.join(tmp, 'mixed'))
            sp_relay.import_into(st2, dump, log=lambda m: None)
            seed(st2, os.path.join(tmp, 'mixed'), replace=True, log=lambda m: None)
            serv = sp_relay.select_for_peer(st2, st2.titles())
            titles = {sp_cec.parse_header(x)['cec_title_id'] for x in serv}
            chk('an authored Mii and imported titles are served together',
                sp_build.PLAZA_TITLE in titles and len(titles) > 1,
                ['%08X' % t for t in sorted(titles)])
            plaza = [x for x in serv
                     if sp_cec.parse_header(x)['cec_title_id'] == sp_build.PLAZA_TITLE]
            chk('and the plaza message served is OURS, not the console\'s',
                len(plaza) == 1
                and st2.origin(plaza[0], 'outbox')['source'].startswith('authored:'),
                st2.origin(plaza[0], 'outbox'))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print('\n%d/%d checks passed' % (ok, tot))
    return 0 if ok == tot else 1


def _raises(fn):
    try:
        fn(); return False
    except ValueError:
        return True


def main():
    ap = argparse.ArgumentParser(description="The relay's own Mii Plaza identity.")
    sub = ap.add_subparsers(dest='cmd')
    for name in ('show', 'build', 'seed'):
        p = sub.add_parser(name)
        p.add_argument('--store', default='relay_store')
        if name != 'show':
            p.add_argument('--mii-name', default='Relay')
            p.add_argument('--author-name', default='LinuxPass')
            p.add_argument('--greeting', default='Hello from Linux')
            p.add_argument('--hits', type=int, default=0)
            p.add_argument('--population', type=int, default=0)
            p.add_argument('--pet', type=int, default=0)
        if name == 'build':
            p.add_argument('--out', default='relay_plaza.bin')
        if name == 'seed':
            p.add_argument('--replace', action='store_true',
                           help='remove any Mii Plaza message already in the outbox first')
    sub.add_parser('selftest')
    a = ap.parse_args()

    if a.cmd in (None, 'selftest'):
        return _selftest()

    if a.cmd == 'show':
        d = derive(a.store)
        d['mii_id'] = '%08x' % d['mii_id']
        print(json.dumps(d, indent=2))
        return 0

    kw = dict(mii_name=a.mii_name, author_name=a.author_name, greeting=a.greeting,
              hits=a.hits, population=a.population, pet=a.pet)
    if a.cmd == 'build':
        m = build_message(a.store, **kw)
        open(a.out, 'wb').write(m)
        print('wrote %s (%d B)' % (a.out, len(m)))
        return 0

    st = sp_store.Store(a.store)
    seed(st, a.store, replace=a.replace, **kw)
    print()
    print(st.summary())
    return 0


if __name__ == '__main__':
    sys.exit(main())
