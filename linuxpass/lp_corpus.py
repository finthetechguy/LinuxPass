#!/usr/bin/env python3
"""
The optional test corpus: real captures and console dumps, which are NOT shipped.

Several self-tests are regressions against real hardware -- a captured console frame that
must be reproduced byte-for-byte, a real CEC message that must parse. That data is a
recording of specific consoles: it carries their IDs, their session MACs and their Mii
names, so it cannot go in a public repository.

The tests that need it therefore ask for it by a *logical* name and report `[SKIP]` when it
is absent. Everything that can be proven with synthetic data still runs, so a clone with no
corpus at all has a self-test suite that passes.

To run the full suite, point LinuxPass at your own corpus:

    $LINUXPASS_CORPUS         a directory, or
    ~/.config/linuxpass/corpus/, or
    ./tests/corpus/           (git-ignored)

A corpus directory may contain `manifest.json` mapping logical names to filenames:

    {"plaza_message":  "cecmsg_aabbcc_to_ddeeff_5.bin",
     "console_nand":   "partitionA.bin"}

Without a manifest the logical name is tried as a filename directly. `vectors.json` in the
same directory supplies the numeric regression vectors (console IDs, MACs, expected keys);
see docs/wiki/Running-the-self-tests.md for its shape.
"""
import json
import os

ENV = 'LINUXPASS_CORPUS'
MANIFEST = 'manifest.json'
VECTORS = 'vectors.json'

_MANIFEST_CACHE = {}
_VECTOR_CACHE = {}


def _config_dir():
    base = os.environ.get('XDG_CONFIG_HOME') or os.path.join(os.path.expanduser('~'), '.config')
    return os.path.join(base, 'linuxpass', 'corpus')


def dirs():
    """Every directory searched for corpus data, in order."""
    out = []
    env = os.environ.get(ENV)
    if env:
        out.extend(p for p in env.split(os.pathsep) if p)
    out.append(_config_dir())
    out.append('/etc/linuxpass/corpus')
    here = os.path.dirname(os.path.abspath(__file__))
    out.append(os.path.join(os.path.dirname(here), 'tests', 'corpus'))
    out.append(os.path.join(os.getcwd(), 'tests', 'corpus'))
    out.append(os.getcwd())
    seen, uniq = set(), []
    for p in out:
        rp = os.path.abspath(p)
        if rp not in seen:
            seen.add(rp)
            uniq.append(rp)
    return uniq


def _manifest(d):
    if d in _MANIFEST_CACHE:
        return _MANIFEST_CACHE[d]
    p = os.path.join(d, MANIFEST)
    out = {}
    if os.path.isfile(p):
        try:
            with open(p) as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                out = {k: v for k, v in loaded.items() if isinstance(v, str)}
        except (ValueError, OSError):
            out = {}
    _MANIFEST_CACHE[d] = out
    return out


def path(name):
    """Absolute path for a logical corpus name, or None if no corpus supplies it."""
    for d in dirs():
        if not os.path.isdir(d):
            continue
        mapped = _manifest(d).get(name, name)
        cand = mapped if os.path.isabs(mapped) else os.path.join(d, mapped)
        if os.path.isfile(cand):
            return cand
    return None


def dir():
    """The first existing corpus directory, or None.

    Blocks that need a whole tree rather than one named file (a directory of harvested
    outbox messages, say) resolve it through here and skip when it is None.
    """
    for d in dirs():
        if os.path.isdir(d) and (os.path.isfile(os.path.join(d, MANIFEST))
                                 or os.path.isfile(os.path.join(d, VECTORS))):
            return d
    return None


def glob(pattern):
    """Sorted matches for a glob relative to the corpus directory. [] when there is none."""
    import glob as _glob
    d = dir()
    if d is None:
        return []
    return sorted(_glob.glob(os.path.join(d, pattern)))


def load(name):
    """Contents of a logical corpus entry, or None if absent."""
    p = path(name)
    if p is None:
        return None
    with open(p, 'rb') as fh:
        return fh.read()


def have(*names):
    """True only if every named entry is available."""
    return all(path(n) is not None for n in names)


def vectors():
    """The numeric regression vectors, or {} when no corpus supplies them."""
    for d in dirs():
        p = os.path.join(d, VECTORS)
        if os.path.isfile(p):
            if p in _VECTOR_CACHE:
                return _VECTOR_CACHE[p]
            try:
                with open(p) as fh:
                    v = json.load(fh)
            except (ValueError, OSError):
                v = {}
            if not isinstance(v, dict):
                v = {}
            _VECTOR_CACHE[p] = v
            return v
    return {}


def vector(name):
    """One vector group, or None. Hex strings are left as strings for the caller to decode."""
    return vectors().get(name)


def why_skipped():
    """One line explaining an absent corpus, for a self-test to print once."""
    return ('no test corpus found (set $%s, or put one in %s) -- hardware regression checks '
            'skipped' % (ENV, _config_dir()))


if __name__ == '__main__':
    print('corpus search path:')
    for d in dirs():
        print('  %s%s' % (d, '' if os.path.isdir(d) else '   (absent)'))
    v = vectors()
    print('\nvectors.json: %s' % (', '.join(sorted(v)) if v else 'not found'))
