#!/usr/bin/env python3
"""A GTK4 / libadwaita front end for LinuxPass.

Runs on the same machine as the daemon and talks to its unix control socket -- the same protocol
`sp_relay.py ctl` uses, so the GUI is a client, not a second implementation. Nothing here knows
anything about CEC, 802.11 or the store's layout; if a thing cannot be asked for over the socket,
it does not appear in this file.

    ./sp_gui.py                       # default store, $XDG_DATA_HOME/linuxpass/store
    ./sp_gui.py --store /path/to/store

Two rules this file keeps:

* **Never block the main loop.** Every socket call and every `systemctl` goes through `run_async`
  and comes back via `GLib.idle_add`. A 100 kB transfer can hold the daemon's attention for
  seconds, and a frozen window during an exchange would be the most visible bug in the program.
* **Never invent state.** If the daemon cannot be reached, the UI says so and offers Start; it does
  not show the last values it happened to have and let you believe they are current.
"""
import os, sys, json, time, threading, subprocess, argparse

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib, Gio, Gdk        # noqa: E402

# the daemon's modules live in the sibling package directory
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'linuxpass'))
import sp_relay                                            # noqa: E402

def default_store():
    """Where the store lives when nobody says otherwise: $XDG_DATA_HOME/linuxpass/store."""
    base = os.environ.get('XDG_DATA_HOME') or os.path.join(os.path.expanduser('~'), '.local', 'share')
    return os.path.join(base, 'linuxpass', 'store')


APP_ID = 'org.linuxpass.LinuxPass'
UNIT = 'linuxpass.service'
REFRESH_S = 2

#: The format holds 24 (MBoxList____ and the ee list both cap there). No console we have dumped
#: enables more than 12, so 12 is the number to warn at and 24 is the number to enforce.
SOFT_TITLE_CAP = 12

#: Written by the adapter dropdown, pulled in by the unit through `EnvironmentFile=-`. A plain
#: user-owned file precisely so the GUI needs no privilege it does not already have: the polkit
#: rule the installer writes covers `systemctl start/stop/restart linuxpass.service` and nothing
#: else, so a drop-in under /etc/systemd would need root the GUI has no way to ask for.
#:
#: PRECEDENCE, measured on this box 6 Sep 2026 with a throwaway unit rather than assumed:
#:   * an EnvironmentFile beats a unit `Environment=` line for the same key REGARDLESS of which
#:     appears first -- this is why /etc/default/linuxpass works at all;
#:   * a later EnvironmentFile beats an earlier one.
#: The unit therefore lists this file AFTER /etc/default/linuxpass, so the GUI's choice wins over
#: both the packaged default and the hand-edited one.
ENV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'relay.env')

#: ARPHRD_IEEE80211_RADIOTAP. A monitor vif is a wireless netdev like any other, so it has to be
#: excluded by type -- excluding the name `mon0` would miss a vif left behind under another name.
ARPHRD_RADIOTAP = '803'
#: How often the relay may present a new MAC. `Never` is the default and is honest hardware
#: behaviour; anything else is the relay pretending to be more than one console, which is the only
#: way a long-running relay stays reachable -- a console writes our MAC into its MacFilter when an
#: exchange completes and never speaks to it again (measured 5-7 Sep 2026: not after 24 h, a
#: reboot, a power-off, or a three-day jump of the console's own clock).
ROTATE_CHOICES = ((0, 'Never'), (3600, 'Every hour'), (4 * 3600, 'Every 4 hours'),
                  (8 * 3600, 'Every 8 hours'), (12 * 3600, 'Every 12 hours'),
                  (24 * 3600, 'Every day'))


def wireless_ifaces():
    """-> [(name, driver)] for every real wireless adapter, monitor vifs excluded, ath9k first.

    Interface names are NOT stable across reboots: this box has enumerated the same adapter as
    both wlp3s0 and wlp4s0, and because the unit named one of them literally, the service simply
    failed to start (6 Sep 2026). That is what this list exists to let the user correct.
    """
    out = []
    try:
        names = sorted(os.listdir('/sys/class/net'))
    except OSError:
        return out
    for n in names:
        d = os.path.join('/sys/class/net', n)
        if not os.path.isdir(os.path.join(d, 'wireless')):
            continue
        try:
            with open(os.path.join(d, 'type')) as f:
                if f.read().strip() == ARPHRD_RADIOTAP:
                    continue
        except OSError:
            pass
        try:
            drv = os.path.basename(os.path.realpath(os.path.join(d, 'device', 'driver')))
        except OSError:
            drv = ''
        out.append((n, '' if drv in ('driver', '') else drv))
    # ath9k is the only driver on this bench that can inject; an MT7902 sniffs but silently
    # transmits nothing, which looks exactly like a dead console. Offer the one that works first.
    out.sort(key=lambda t: (t[1] != 'ath9k', t[0]))
    return out


def read_env_file(path=None):
    """-> {KEY: value}. A missing file is not an error; the unit marks it optional too."""
    d = {}
    try:
        with open(path or ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, _, v = line.partition('=')
                d[k.strip()] = v.strip()
    except OSError:
        pass
    return d


def write_env_key(key, value, path=None):
    """Set (or, with value=None, drop) one KEY, keeping every other assignment. -> None or error.

    Only assignments survive a rewrite: the file is regenerated from the parsed keys, so any
    hand-added comment is lost. That is why the header says the file is written by this program.

    Written to a temp file and renamed, so a crash mid-write cannot leave the unit reading half
    an assignment -- systemd would refuse to start the service and the GUI is how you would fix
    that, which makes it exactly the wrong place to have a torn file.
    """
    path = path or ENV_FILE
    d = read_env_file(path)
    if value is None:
        d.pop(key, None)
    else:
        d[key] = value
    body = ["# Written by sp_gui.py. linuxpass.service pulls this in with `EnvironmentFile=-`,",
            "# listed after /etc/default/linuxpass, so what is set here wins over both that file",
            "# and the unit's own Environment= lines. Edit with the GUI, not by hand."]
    body += ['%s=%s' % (k, d[k]) for k in sorted(d)]
    try:
        tmp = path + '.tmp'
        with open(tmp, 'w') as f:
            f.write('\n'.join(body) + '\n')
        os.replace(tmp, path)
        return None
    except OSError as e:
        return str(e)



def run_async(fn, on_done=None):
    """Run `fn` off the UI thread; hand the result (or the exception) back on the UI thread."""
    def worker():
        try:
            r = fn()
        except Exception as e:                             # noqa: BLE001 - surfaced in the UI
            r = e
        if on_done is not None:
            GLib.idle_add(on_done, r)
    threading.Thread(target=worker, daemon=True).start()


def human_secs(s):
    s = int(max(0, s))
    if s < 60:
        return '%d s' % s
    if s < 3600:
        return '%d min' % (s // 60)
    if s < 86400:
        return '%d h %d min' % (s // 3600, (s % 3600) // 60)
    return '%d d %d h' % (s // 86400, (s % 86400) // 3600)


def human_bytes(n):
    return '%d B' % n if n < 1024 else ('%.1f kB' % (n / 1024.0))


class Daemon:
    """Everything the GUI can ask of the outside world. All calls are blocking; use run_async."""

    def __init__(self, store):
        self.store = os.path.abspath(store)
        # NOT os.path.join(store, 'relay.sock'): a deep store puts the socket elsewhere, and
        # both ends have to agree. sp_relay owns that rule.
        self.sock = sp_relay.control_socket_path(self.store)

    # -- the control socket ----------------------------------------------------------------
    def call(self, cmd, **kw):
        return sp_relay.send_command(self.sock, cmd, **kw)

    def try_call(self, cmd, **kw):
        """-> (reply, None) or (None, 'why not'). A daemon that is not running is not an error."""
        try:
            return self.call(cmd, **kw), None
        except (OSError, ValueError) as e:
            return None, str(e)

    # -- the service -----------------------------------------------------------------------
    @staticmethod
    def unit_state():
        try:
            r = subprocess.run(['systemctl', 'show', UNIT, '--no-pager',
                                '-p', 'ActiveState', '-p', 'SubState', '-p', 'NRestarts',
                                '-p', 'StatusText', '-p', 'ActiveEnterTimestamp',
                                '-p', 'UnitFileState'],
                               capture_output=True, timeout=10)
            d = {}
            for line in r.stdout.decode('utf-8', 'replace').splitlines():
                k, _, v = line.partition('=')
                d[k] = v
            return d
        except (OSError, subprocess.SubprocessError) as e:
            return {'error': str(e)}

    @staticmethod
    def systemctl(verb):
        """-> None on success, else the error text. Needs the polkit rule the installer writes."""
        try:
            r = subprocess.run(['systemctl', verb, UNIT], capture_output=True, timeout=45)
            if r.returncode == 0:
                return None
            err = (r.stderr or b'').decode('utf-8', 'replace').strip()
            if 'interactive authentication' in err:
                return ('Not permitted to %s %s.\n\nInstall the polkit rule that grants it:\n'
                        '    sudo ./install/install.sh install' % (verb, UNIT))
            return err or 'systemctl %s failed (%d)' % (verb, r.returncode)
        except (OSError, subprocess.SubprocessError) as e:
            return str(e)


class Page(Adw.Bin):
    """A tab. Subclasses fill `self.page` and implement refresh(); the app polls the visible one."""

    def __init__(self, app, title, icon):
        super().__init__()
        self.app = app
        self.title, self.icon = title, icon
        self.page = Adw.PreferencesPage()
        self.set_child(self.page)
        self._groups = []
        #: expander rows this page built, by a stable key, so a rebuild can restore what was open
        self._expanders = {}
        self._signature = None

    # -- redrawing without stamping on the user -------------------------------------------
    #
    # The app polls every couple of seconds. Rebuilding the widget tree each time destroys every
    # expanded row and replaces it with a fresh collapsed one, so anything you opened snapped shut
    # a second or two later. Two defences: skip the rebuild entirely when nothing being displayed
    # has changed, and when it has, put back whatever was open.

    def signature(self, data):
        """A hashable summary of what this page would DRAW. Equal signature, no redraw.

        Pages whose data contains a constantly-moving number normalise it to the string actually
        shown -- a countdown rendered as '11 h 29 min' changes once a minute, not twice a second.
        """
        return json.dumps(data, sort_keys=True, default=str)

    def unchanged(self, data):
        sig = self.signature(data)
        if sig == self._signature:
            return True
        self._signature = sig
        return False

    def remember_open(self):
        return {k for k, r in self._expanders.items() if r.get_expanded()}

    def restore_open(self, keys):
        for k in keys:
            r = self._expanders.get(k)
            if r is not None:
                r.set_expanded(True)

    def expander(self, key, **kw):
        """An ExpanderRow that survives a rebuild, identified by `key`."""
        r = Adw.ExpanderRow(**kw)
        self._expanders[key] = r
        return r

    def reset(self):
        for g in self._groups:
            self.page.remove(g)
        self._groups = []
        self._expanders = {}

    def group(self, title=None, description=None):
        g = Adw.PreferencesGroup()
        if title:
            g.set_title(title)
        if description:
            g.set_description(description)
        self.page.add(g)
        self._groups.append(g)
        return g

    def refresh(self):
        raise NotImplementedError

    def offline(self, why):
        self._signature = None          # so a reconnect always redraws
        self.reset()
        g = self.group('The relay is not answering')
        r = Adw.ActionRow(title='No daemon on the control socket',
                          subtitle='%s\n%s' % (self.app.daemon.sock, why))
        r.add_css_class('dim-label')
        g.add(r)


def row(title, subtitle=None, css=None):
    r = Adw.ActionRow(title=title)
    if subtitle:
        r.set_subtitle(subtitle)
    if css:
        r.add_css_class(css)
    return r


def first_icon(*names):
    """-> the first of `names` the icon theme actually has, else the last one.

    Icon names are not a stable API: `emblem-ok-symbolic` was in Adwaita for years and is gone in
    4.22, where it renders as a grey missing-image box rather than failing loudly. Checking is two
    lines and turns a silent visual bug into a graceful fallback.
    """
    try:
        theme = Gtk.IconTheme.get_for_display(Gdk.Display.get_default())
        for n in names:
            if theme.has_icon(n):
                return n
    except Exception:                                      # no display yet, or no theme
        pass
    return names[-1]


def icon_button(icon, tooltip, cb, css=None):
    b = Gtk.Button(icon_name=icon, valign=Gtk.Align.CENTER, tooltip_text=tooltip)
    b.add_css_class('flat')
    if css:
        b.add_css_class(css)
    b.connect('clicked', lambda *_a: cb())
    return b


# =============================================================================================

class HomePage(Page):
    def __init__(self, app):
        super().__init__(app, 'Home', 'go-home-symbolic')
        self.busy = False

    def refresh(self):
        run_async(lambda: (Daemon.unit_state(), self.app.daemon.try_call('status')), self._draw)

    def _service_group(self, unit):
        active = unit.get('ActiveState') == 'active'
        sub = unit.get('SubState', '?')
        g = self.group('Service')
        state = unit.get('ActiveState', '?')
        r = row('linuxpass.service',
                state if sub in ('', '?', state) else '%s (%s)' % (state, sub))
        dot = Gtk.Image(icon_name='media-playback-start-symbolic' if active
                        else 'media-playback-stop-symbolic')
        dot.add_css_class('success' if active else 'error')
        r.add_prefix(dot)
        box = Gtk.Box(spacing=6, valign=Gtk.Align.CENTER)
        for label, verb in (('Start', 'start'), ('Stop', 'stop'), ('Restart', 'restart')):
            b = Gtk.Button(label=label)
            b.set_sensitive(not self.busy and (active if verb != 'start' else not active)
                            or (verb == 'restart' and active))
            b.connect('clicked', self._service_action, verb)
            if verb == 'stop':
                b.add_css_class('destructive-action')
            box.append(b)
        r.add_suffix(box)
        g.add(r)
        g.add(self._adapter_row(active))
        if unit.get('UnitFileState'):
            g.add(row('Starts at boot', unit['UnitFileState']))
        if unit.get('NRestarts', '0') not in ('0', ''):
            g.add(row('Automatic restarts', '%s since it was last started by hand — the watchdog '
                                            'restarts the service, never the machine'
                      % unit['NRestarts']))
        return active

    def _adapter_row(self, active):
        """Choose which radio the daemon claims.

        Settable only while the service is stopped: the monitor vif is built by ExecStartPre, so
        a change made mid-run would not take effect until a restart, and a control that silently
        does nothing is worse than one that is visibly unavailable.
        """
        ifaces = wireless_ifaces()
        chosen = read_env_file().get('SP_IFACE', '')
        names = [n for n, _ in ifaces]
        labels = ['%s  (%s)' % (n, d) if d else n for n, d in ifaces]
        # An adapter named in the env file but absent right now must still be listed, or simply
        # opening this window would silently reassign the daemon to a different radio.
        if chosen and chosen not in names:
            names.insert(0, chosen)
            labels.insert(0, '%s  (not present)' % chosen)
        if not names:
            return row('Adapter', 'no wireless device found')
        r = row('Adapter', 'stop the service to change this' if active
                else 'used the next time the service starts')
        dd = Gtk.DropDown.new_from_strings(labels)
        dd.set_valign(Gtk.Align.CENTER)
        dd.set_selected(names.index(chosen) if chosen in names else 0)
        dd.set_sensitive(not active and not self.busy)
        dd.connect('notify::selected', self._adapter_changed, names)
        r.add_suffix(dd)
        return r

    def _adapter_changed(self, dd, _pspec, names):
        i = dd.get_selected()
        if i >= len(names):          # GTK_INVALID_LIST_POSITION is G_MAXUINT, so this covers it
            return
        err = write_env_key('SP_IFACE', names[i])
        if err:
            self.app.error('Could not save the adapter choice', err)

    def _service_action(self, _btn, verb):
        self.busy = True
        self.refresh()

        def done(err):
            self.busy = False
            if err:
                self.app.error('Could not %s the service' % verb, err)
            self.refresh()
        run_async(lambda: Daemon.systemctl(verb), done)

    def signature(self, data):
        unit, (st, why) = data
        s = dict(st['status']) if st else {'offline': why}
        # displayed as '3 min', so it changes once a minute, not every two seconds
        if 'uptime_s' in s:
            s['uptime_s'] = human_secs(s['uptime_s'])
        # Same treatment, and here it matters more than tidiness: these tick every poll, and a
        # redraw rebuilds the rotation dropdown. Left raw, the list would be torn down under the
        # user's cursor every two seconds.
        for k in ('identity_age_s', 'next_rotation_s'):
            if s.get(k) is not None:
                s[k] = human_secs(s[k])
        s['_peers'] = sorted(s.pop('peers', {}))
        return json.dumps([unit, s, self.busy], sort_keys=True, default=str)

    def _draw(self, result):
        if self.unchanged(result):
            return
        unit, (st, why) = result
        self.reset()
        active = self._service_group(unit)

        if st is None:
            g = self.group('Exchanges')
            g.add(row('The daemon is not answering on its control socket',
                      why if active else 'Start the service above.'))
            return
        s = st['status']

        g = self.group('Exchanges', 'The service can be running with exchanges held off. '
                                    'This switch is instant and needs no privileges.')
        sw = Gtk.Switch(active=s['enabled'], valign=Gtk.Align.CENTER)
        sw.connect('state-set', self._toggle)
        r = row('Exchange with consoles that pass',
                'listening' if s['enabled'] else 'paused — probes still go out, nothing is served')
        r.add_suffix(sw)
        r.set_activatable_widget(sw)
        g.add(r)

        g = self.group('Identity')
        g.add(row('MAC presented on air', s['identity']))
        g.add(row('Identity mode', self._identity_mode(s)))
        g.add(self._rotation_row(s))
        g.add(row('Store', s['store']))

        g = self.group('Data')
        g.add(row('Messages this relay will serve', '%d' % s['servable']))
        g.add(row('Held', '%d' % s['held_but_never_served']))

        g = self.group('Statistics')
        g.add(row('Exchanges since start', '%d over %d listening pass(es)'
                  % (s['exchanges'], s['passes'])))
        g.add(row('Uptime', human_secs(s['uptime_s'])))
        g.add(row('Last console', s['last_peer'] or '—'))
        g.add(row('Peers on a cooldown', '%d' % len(s['peers'])))
        if s['last_error']:
            g.add(row('Last error', s['last_error'], css='error'))

    @staticmethod
    def _identity_mode(s):
        if s.get('rotate_identity'):
            return 'a new MAC every pass — no real console can do this'
        every = int(s.get('rotate_every_s') or 0)
        if not every:
            return 'fixed, derived from the store path'
        held = human_secs(s.get('identity_age_s') or 0)
        return 'on a timer — this one has been in use for %s (%d change(s) so far)' \
               % (held, s.get('rotations') or 0)

    def _rotation_row(self, s):
        """How often the relay takes a new MAC.

        Applied live over the control socket AND written to relay.env, so the setting both takes
        effect now and survives a restart -- the same value in both places, so there is no
        precedence question to get wrong. The daemon only ever changes identity at a pass
        boundary, so nothing here can interrupt an exchange in progress.
        """
        cur = int(s.get('rotate_every_s') or 0)
        vals = [v for v, _ in ROTATE_CHOICES]
        labels = [l for _, l in ROTATE_CHOICES]
        # A period set by hand in /etc/default/linuxpass has to appear, or opening this window
        # would silently round it to one of ours.
        if cur and cur not in vals:
            vals.insert(1, cur)
            labels.insert(1, 'Every %s' % human_secs(cur))
        if s.get('rotate_identity'):
            sub = '--rotate-identity is on, which overrides this'
        elif not cur:
            sub = 'one exchange per console, ever — it blocks this MAC once it is done'
        else:
            nxt = s.get('next_rotation_s')
            # A change is applied at a pass boundary, never mid-exchange, so "now" means "when
            # this listening window ends" -- say that rather than showing a stuck 0 s.
            sub = ('at the end of this listening pass' if nxt == 0
                   else 'next change in %s' % human_secs(nxt)) if nxt is not None else 'on'
            # Rotating faster than our OWN per-peer cooldown looks like it should give more
            # exchanges and does not: the far end's MacFilter is lifted, the peer book is not.
            cd = s.get('cooldown_s') or 0
            if cd and cur < cd:
                sub += ' — but our own %s cooldown still holds off a console we have met' \
                       % human_secs(cd)
        r = row('Change the MAC', sub)
        dd = Gtk.DropDown.new_from_strings(labels)
        dd.set_valign(Gtk.Align.CENTER)
        dd.set_selected(vals.index(cur) if cur in vals else 0)
        dd.set_sensitive(not self.busy and not s.get('rotate_identity'))
        dd.connect('notify::selected', self._rotation_changed, vals)
        r.add_suffix(dd)
        return r

    def _rotation_changed(self, dd, _pspec, vals):
        i = dd.get_selected()
        if i >= len(vals):           # GTK_INVALID_LIST_POSITION is G_MAXUINT
            return
        n = vals[i]
        err = write_env_key('SP_ROTATE', str(n))
        if err:
            self.app.error('Could not save the rotation setting', err)
            return
        self.app.act('rotate', then=('The MAC will now stay fixed' if not n
                                     else 'The MAC will change every %s' % human_secs(n)),
                     seconds=n)

    def _toggle(self, sw, want):
        run_async(lambda: self.app.daemon.call('resume' if want else 'pause'),
                  lambda _r: self.refresh())
        return False


# =============================================================================================

class EncountersPage(Page):
    def __init__(self, app):
        super().__init__(app, 'Encounters', 'network-wireless-symbolic')

    def refresh(self):
        run_async(lambda: self.app.daemon.try_call('encounters', limit=200), self._draw)

    def _draw(self, res):
        rep, why = res
        if rep is None:
            return self.offline(why)
        if self.unchanged(rep):
            return
        was_open = self.remember_open()
        self.reset()
        enc = list(reversed(rep['encounters']))
        g = self.group('Encounters', '%d recorded, newest first. Every console that exchanged.' % len(enc))
        if not enc:
            g.add(row('Nothing yet',
                      'A console has to be in sleep mode, in range, and past its own StreetPass '
                      'rate limit before it will engage.'))
            return
        for e in enc:
            when = time.strftime('%d %b %H:%M:%S', time.localtime(e.get('when', 0)))
            res_txt = e.get('result', '?')
            sent, got = e.get('sent') or [], e.get('received') or []
            if res_txt == 'exchanged':
                sub = '%s   —   sent %d (%s), received %d (%s)' % (
                    when, len(sent), human_bytes(sum(x.get('bytes', 0) for x in sent)),
                    len(got), human_bytes(sum(x.get('bytes', 0) for x in got)))
            else:
                sub = '%s   —   %s' % (when, res_txt)
            ex = self.expander('%s/%s' % (e.get('when'), e.get('peer')),
                               title=e.get('peer', '?'), subtitle=sub)
            ic = Gtk.Image(icon_name={
                'exchanged': first_icon('object-select-symbolic', 'emblem-ok-symbolic'),
                'blocked': 'action-unavailable-symbolic'}.get(res_txt, 'dialog-warning-symbolic'))
            ic.add_css_class({'exchanged': 'success', 'blocked': 'error'}
                             .get(res_txt, 'warning'))
            ex.add_prefix(ic)
            for label, items in (('Sent', sent), ('Received', got)):
                for it in items:
                    ex.add_row(row('%s  %s' % (label, it.get('title', '?')),
                                   human_bytes(it.get('bytes', 0))))
            if not sent and not got:
                ex.add_row(row(res_txt, 'nothing was transferred'))
            g.add(ex)
        self.restore_open(was_open)


# =============================================================================================

class StorePage(Page):
    """Shared drawing for the Outbox and Inbox tabs; they differ only in box and in what you may
    do to what they show."""

    BOX = 'outbox'

    def refresh(self):
        run_async(lambda: self.app.daemon.try_call('store'), self._draw)

    def _messages(self, t):
        return [m for m in t['messages'] if m['box'] == self.BOX]

    def _draw(self, res):
        rep, why = res
        if rep is None:
            return self.offline(why)
        if self.unchanged(rep):
            return
        was_open = self.remember_open()
        self.reset()
        st = rep['store']
        titles = [t for t in st['titles'] if self._messages(t)]
        self.header(st, titles)
        for t in titles:
            ms = self._messages(t)
            ex = self.expander(t['title'],
                               title='%s   %s' % (t['title'], t['name'] or 'unknown title'),
                               subtitle='%d message(s)%s' % (
                                   len(ms), '' if t['has_key'] else '   ·   no HMAC key'))
            self.decorate_title(ex, t)
            for m in ms:
                bits = ['%s' % human_bytes(m['bytes']), 'created %s' % m['created'],
                        'send mode %d' % m['send_mode'], 'HMAC %s' % m['hmac']]
                mr = Adw.ActionRow(title=m['origin'] or 'origin not recorded',
                                   subtitle='   ·   '.join(bits))
                mr.set_title_lines(1)
                if m['hmac'] == 'FAILED':
                    mr.add_css_class('error')
                self.decorate_message(mr, t, m)
                ex.add_row(mr)
            g = self._groups[-1]
            g.add(ex)
        self.restore_open(was_open)

    def header(self, st, titles):
        raise NotImplementedError

    def decorate_title(self, ex, t):
        pass

    def decorate_message(self, mr, t, m):
        pass


class OutboxPage(StorePage):
    BOX = 'outbox'

    def __init__(self, app):
        super().__init__(app, 'Outbox', 'document-send-symbolic')

    def header(self, st, titles):
        # `titles` is what this tab SHOWS (titles with outbox content); st['titles'] is everything
        # the store registers, including titles that only ever received. Reporting the second
        # number under a list of the first is how you get "12 titles" above four rows.
        shown, registered, cap = len(titles), len(st['titles']), st['max_titles']
        note = ('%d title(s) served, %d registered in the store, %d is the format\'s limit.'
                % (shown, registered, cap))
        if registered > SOFT_TITLE_CAP:
            note += (' No console we have dumped enables more than %d.' % SOFT_TITLE_CAP)
        g = self.group('Served to consoles', 'CEC data served to consoles. ' + note)
        box = Gtk.Box(spacing=6, halign=Gtk.Align.END, valign=Gtk.Align.CENTER, margin_bottom=6)
        for label, cb in (('Author Mii identity…', self.app.dialog_identity),
                          ('Import CEC data…', self.app.dialog_import)):
            b = Gtk.Button(label=label)
            b.connect('clicked', lambda _b, f=cb: f())
            box.append(b)
        g.set_header_suffix(box)
        if not titles:
            g.add(row('Nothing to serve',
                      'Give the relay some data: author its Mii Plaza identity, or import a '
                      'console dump or an Azahar/Citra NAND.'))

    def decorate_title(self, ex, t):
        ex.add_suffix(icon_button('user-trash-symbolic',
                                  'Remove this title, its messages, its name and its HMAC key',
                                  lambda tt=t: self.app.confirm_remove_title(tt),
                                  css='destructive-action'))

    def decorate_message(self, mr, t, m):
        if not m['servable']:
            mr.add_suffix(Gtk.Label(label='not served', css_classes=['dim-label'],
                                    valign=Gtk.Align.CENTER))
        mr.add_suffix(icon_button('user-trash-symbolic', 'Delete this message',
                                  lambda: self.app.remove_message(t['title'], m['id'], 'outbox')))


class InboxPage(StorePage):
    BOX = 'inbox'

    def __init__(self, app):
        super().__init__(app, 'Inbox', 'document-save-symbolic')

    def header(self, st, titles):
        g = self.group('Received from consoles',
                       'CEC data which has been recieved by consoles with successful exchanges.')
        if not titles:
            g.add(row('Nothing received yet', 'Messages land here after an exchange.'))

    def decorate_message(self, mr, t, m):
        mr.add_suffix(icon_button('user-trash-symbolic', 'Delete this received message',
                                  lambda: self.app.remove_message(t['title'], m['id'], 'inbox')))


# =============================================================================================

class DenylistPage(Page):
    def __init__(self, app):
        super().__init__(app, 'Denylist', 'action-unavailable-symbolic')

    def refresh(self):
        run_async(lambda: self.app.daemon.try_call('denylist'), self._draw)

    def signature(self, data):
        rep, why = data
        if rep is None:
            return 'offline:%s' % why
        d = {'blocked': rep['blocked'],
             'cooldowns': [{**c, 'remaining_s': human_secs(c['remaining_s'])}
                           for c in rep['cooldowns']]}
        return json.dumps(d, sort_keys=True, default=str)

    def _draw(self, res):
        if self.unchanged(res):
            return
        rep, why = res
        if rep is None:
            return self.offline(why)
        self.reset()

        g = self.group('Blocked consoles',
                       'Never exchanged with. Unlike a cooldown this is a '
                       'refusal, not a delay.')
        b = Gtk.Button(label='Block a console…', halign=Gtk.Align.END, margin_bottom=6)
        b.connect('clicked', lambda *_a: self.app.dialog_block())
        g.set_header_suffix(b)
        if not rep['blocked']:
            g.add(row('Nothing blocked', 'Consoles are free to exchange with.'))
        for e in rep['blocked']:
            r = row(e['mac'], e.get('note') or 'blocked %s'
                    % time.strftime('%d %b %H:%M', time.localtime(e.get('when', 0))))
            r.add_suffix(icon_button('list-remove-symbolic', 'Unblock',
                                     lambda m=e['mac']: self.app.act('unblock', mac=m)))
            g.add(r)

        g = self.group('Cooldowns',
                       'After an exchange a console is left alone for a while. Note this is keyed '
                       'on its MAC, which a 3DS rotates, the limit that really holds is the '
                       'console\'s own, keyed on ours.')
        if not rep['cooldowns']:
            g.add(row('No consoles met yet', ''))
        for e in rep['cooldowns']:
            rem = e['remaining_s']
            r = row(e['mac'],
                    ('due now' if rem <= 0 else 'due in %s' % human_secs(rem))
                    + '   ·   %d exchange(s)' % e['exchanges']
                    + ('   ·   %d failed attempt(s)' % e['attempts'] if e['attempts'] else ''))
            box = Gtk.Box(spacing=6, valign=Gtk.Align.CENTER)
            if rem > 0:
                bb = Gtk.Button(label='Clear')
                bb.connect('clicked',
                           lambda _b, m=e['mac']: self.app.act('cooldown', mac=m, seconds=0))
                box.append(bb)
            bb = Gtk.Button(label='Set…')
            bb.connect('clicked', lambda _b, m=e['mac'], v=rem: self.app.dialog_cooldown(m, v))
            box.append(bb)
            box.append(icon_button('action-unavailable-symbolic', 'Block this console',
                                   lambda m=e['mac']: self.app.act('block', mac=m,
                                                                   note='blocked from the GUI')))
            r.add_suffix(box)
            g.add(r)


# =============================================================================================

class LogPage(Page):
    def __init__(self, app):
        super().__init__(app, 'Log', 'utilities-terminal-symbolic')
        self.follow = True
        self.view = Gtk.TextView(editable=False, monospace=True, cursor_visible=False,
                                 wrap_mode=Gtk.WrapMode.WORD_CHAR,
                                 top_margin=8, bottom_margin=8, left_margin=8, right_margin=8)
        sw = Gtk.ScrolledWindow(vexpand=True, hexpand=True, child=self.view)
        sw.add_css_class('card')
        tb = Gtk.Box(spacing=6, margin_start=12, margin_end=12, margin_top=6, margin_bottom=6)
        sw_follow = Gtk.Switch(active=True, valign=Gtk.Align.CENTER)
        sw_follow.connect('state-set', self._set_follow)
        tb.append(Gtk.Label(label='Follow', valign=Gtk.Align.CENTER))
        tb.append(sw_follow)
        spacer = Gtk.Box(hexpand=True)
        tb.append(spacer)
        b = Gtk.Button(label='Refresh now')
        b.connect('clicked', lambda *_a: self.refresh())
        tb.append(b)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, margin_start=12, margin_end=12,
                      margin_top=12, margin_bottom=12, spacing=6)
        box.append(tb)
        box.append(sw)
        self.set_child(box)
        self.scroller = sw

    def _set_follow(self, _sw, v):
        self.follow = v
        return False

    def refresh(self):
        run_async(lambda: self.app.daemon.try_call('log', limit=400), self._draw)

    def _draw(self, res):
        rep, why = res
        buf = self.view.get_buffer()
        if rep is None:
            buf.set_text('The relay is not answering on %s\n\n%s'
                         % (self.app.daemon.sock, why))
            return
        text = '\n'.join(rep['log'])
        if buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False) == text:
            return
        buf.set_text(text)
        if self.follow:
            GLib.idle_add(self._to_end)

    def _to_end(self):
        adj = self.scroller.get_vadjustment()
        adj.set_value(adj.get_upper() - adj.get_page_size())
        return False


# =============================================================================================

class RelayWindow(Adw.ApplicationWindow):
    def __init__(self, app, **kw):
        super().__init__(application=app, title='LinuxPass',
                         default_width=980, default_height=760, **kw)
        self.app = app
        self.stack = Adw.ViewStack()
        for page in app.pages:
            self.stack.add_titled_with_icon(page, page.title.lower(), page.title, page.icon)
        switcher = Adw.ViewSwitcher(stack=self.stack,
                                    policy=Adw.ViewSwitcherPolicy.WIDE)
        header = Adw.HeaderBar(title_widget=switcher)
        self.banner = Adw.Banner(revealed=False)
        self.toasts = Adw.ToastOverlay()
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        inner.append(self.banner)
        inner.append(self.stack)
        self.stack.set_vexpand(True)
        self.toasts.set_child(inner)
        tv = Adw.ToolbarView(content=self.toasts)
        tv.add_top_bar(header)
        bar = Adw.ViewSwitcherBar(stack=self.stack)
        tv.add_bottom_bar(bar)
        bar.set_reveal(False)
        self.set_content(tv)
        self.stack.connect('notify::visible-child', lambda *_a: app.refresh_now())


class RelayApp(Adw.Application):
    def __init__(self, store):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.NON_UNIQUE)
        self.daemon = Daemon(store)
        self.pages = []
        self.win = None

    def do_startup(self):
        Adw.Application.do_startup(self)
        self.pages = [HomePage(self), EncountersPage(self), OutboxPage(self),
                      InboxPage(self), DenylistPage(self), LogPage(self)]

    def do_activate(self):
        if self.win is None:
            self.win = RelayWindow(self)
            GLib.timeout_add_seconds(REFRESH_S, self._tick)
            self.refresh_now()
        self.win.present()

    # -- refresh -----------------------------------------------------------------------------
    def _tick(self):
        self.refresh_now()
        return True

    def refresh_now(self):
        if self.win is None:
            return
        cur = self.win.stack.get_visible_child()
        if isinstance(cur, Page):
            cur.refresh()

    # -- feedback ----------------------------------------------------------------------------
    def toast(self, text):
        if self.win:
            self.win.toasts.add_toast(Adw.Toast(title=text, timeout=4))

    def error(self, heading, body):
        d = Adw.AlertDialog(heading=heading, body=body)
        d.add_response('ok', 'OK')
        d.present(self.win)

    def act(self, cmd, then=None, **kw):
        """Fire a control command, report the outcome, refresh."""
        def done(rep):
            if isinstance(rep, Exception):
                self.error('The relay did not accept that', str(rep))
            elif not rep.get('ok', False):
                self.error('The relay refused', rep.get('error', 'no reason given'))
            else:
                self.toast(then or ('%s done' % cmd))
            self.refresh_now()
        run_async(lambda: self.daemon.call(cmd, **kw), done)

    # -- dialogs -----------------------------------------------------------------------------
    def remove_message(self, title, mid, box):
        d = Adw.AlertDialog(heading='Delete this message?',
                            body='%s from the %s of %s.\n\nThis cannot be undone.'
                                 % (mid, box, title))
        d.add_response('cancel', 'Cancel')
        d.add_response('del', 'Delete')
        d.set_response_appearance('del', Adw.ResponseAppearance.DESTRUCTIVE)
        d.connect('response', lambda _d, r: r == 'del' and self.act(
            'message_remove', then='Message deleted', title=title, id=mid, box=box))
        d.present(self.win)

    def confirm_remove_title(self, t):
        d = Adw.AlertDialog(
            heading='Remove %s?' % (t['name'] or t['title']),
            body='This deletes its %d message(s), its display name and its HMAC key.\n\n'
                 'The key came from a console dump and there is no other copy here — you would '
                 'have to import that dump again to get it back.' % len(t['messages']))
        d.add_response('cancel', 'Cancel')
        d.add_response('del', 'Remove title')
        d.set_response_appearance('del', Adw.ResponseAppearance.DESTRUCTIVE)
        d.connect('response', lambda _d, r: r == 'del' and self.act(
            'title_remove', then='Title removed', title=t['title']))
        d.present(self.win)

    def dialog_block(self):
        e = Gtk.Entry(placeholder_text='aa:bb:cc:dd:ee:ff')
        n = Gtk.Entry(placeholder_text='why (optional)')
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.append(e)
        box.append(n)
        d = Adw.AlertDialog(heading='Block a console',
                            body='It will never be served, whatever else is true.')
        d.set_extra_child(box)
        d.add_response('cancel', 'Cancel')
        d.add_response('ok', 'Block')
        d.set_response_appearance('ok', Adw.ResponseAppearance.DESTRUCTIVE)

        def resp(_d, r):
            if r == 'ok' and e.get_text().strip():
                self.act('block', then='Blocked', mac=e.get_text().strip(),
                         note=n.get_text().strip())
        d.connect('response', resp)
        d.present(self.win)

    def dialog_cooldown(self, mac, current):
        adj = Gtk.Adjustment(value=max(0, current) / 60.0, lower=0, upper=48 * 60,
                             step_increment=5, page_increment=60)
        sp = Gtk.SpinButton(adjustment=adj, digits=0)
        d = Adw.AlertDialog(heading='Time remaining for %s' % mac,
                            body='Minutes until this relay will engage it again. Zero means now.')
        d.set_extra_child(sp)
        d.add_response('cancel', 'Cancel')
        d.add_response('ok', 'Set')
        d.connect('response', lambda _d, r: r == 'ok' and self.act(
            'cooldown', then='Cooldown updated', mac=mac, seconds=sp.get_value() * 60.0))
        d.present(self.win)

    def dialog_identity(self):
        import sp_identity
        ident = sp_identity.derive(self.daemon.store)
        rows, fields = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8), {}
        for key, label, default in (('mii_name', 'Mii name (max 10)', 'Relay'),
                                    ('author_name', 'Author (max 10)', 'LinuxPass'),
                                    ('greeting', 'Greeting (max 16)', 'Hello from Linux')):
            e = Gtk.Entry(text=default, placeholder_text=label)
            fields[key] = e
            rows.append(Gtk.Label(label=label, xalign=0, css_classes=['dim-label']))
            rows.append(e)
        adv = Gtk.Expander(label='Advanced')
        ab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin_top=6)
        for key, label, up in (('hits', 'StreetPass hits on the card', 999999),
                               ('population', 'Plaza population', 3000),
                               ('pet', 'Pet (0 none, 1 dog, 2 cat)', 2)):
            sp = Gtk.SpinButton(adjustment=Gtk.Adjustment(value=0, lower=0, upper=up,
                                                          step_increment=1, page_increment=10),
                                digits=0)
            fields[key] = sp
            ab.append(Gtk.Label(label=label, xalign=0, css_classes=['dim-label']))
            ab.append(sp)
        ab.append(Gtk.Label(
            xalign=0, wrap=True, css_classes=['dim-label'],
            label='Derived from the store path and not editable: MAC %s, Mii id %08x, face %d, '
                  'hat %d, dream %d, hobby %d. The Mii\'s creator MAC is the MAC this relay '
                  'transmits from — they are the same value on purpose.'
                  % (ident['mac'], ident['mii_id'], ident['face_shape'], ident['hat'],
                     ident['dream'], ident['hobby'])))
        adv.set_child(ab)
        rows.append(adv)

        d = Adw.AlertDialog(
            heading='Author this relay\'s Mii Plaza identity',
            body='Builds a Mii Plaza message from nothing — no captured data — and replaces the '
                 'one in the outbox.')
        d.set_extra_child(rows)
        d.add_response('cancel', 'Cancel')
        d.add_response('ok', 'Write it')
        d.set_response_appearance('ok', Adw.ResponseAppearance.SUGGESTED)

        def resp(_d, r):
            if r != 'ok':
                return
            kw = {'replace': True}
            for k, w in fields.items():
                kw[k] = int(w.get_value()) if isinstance(w, Gtk.SpinButton) else w.get_text()
            self.act('seed', then='Identity written to the outbox', **kw)
        d.connect('response', resp)
        d.present(self.win)

    def dialog_import(self):
        chooser = Gtk.FileDialog(title='Import CEC data')
        rep = Adw.AlertDialog(
            heading='Import CEC data',
            body='A console save image, a mounted dump directory, or an Azahar/Citra NAND.\n\n'
                 'Replace empties the outbox first, so this becomes the only data served. '
                 'Without it, an import adds to what is already there.')
        rep.add_response('cancel', 'Cancel')
        rep.add_response('add', 'Add to outbox')
        rep.add_response('replace', 'Replace outbox')
        rep.set_response_appearance('replace', Adw.ResponseAppearance.DESTRUCTIVE)

        def chosen(mode):
            def on_file(dlg, res):
                try:
                    f = dlg.open_finish(res)
                except GLib.Error:
                    return
                self.act('import', then='Imported', path=f.get_path(),
                         replace=(mode == 'replace'))
            chooser.open(self.win, None, on_file)

        rep.connect('response', lambda _d, r: r in ('add', 'replace') and chosen(r))
        rep.present(self.win)


def main():
    ap = argparse.ArgumentParser(description='GTK front end for LinuxPass.')
    ap.add_argument('--store', default=default_store())
    a = ap.parse_args()
    Adw.init()
    app = RelayApp(a.store)
    return app.run([])


if __name__ == '__main__':
    sys.exit(main())
