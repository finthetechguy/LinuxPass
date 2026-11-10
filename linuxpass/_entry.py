#!/usr/bin/env python3
"""Console entry points for the installed package."""
import os
import sys


def relay(argv=None):
    import sp_relay
    return sp_relay.main()


def gui(argv=None):
    # Inside the package once installed, beside it in a checkout.
    here = os.path.dirname(os.path.abspath(__file__))
    for d in (os.path.join(here, 'gui'), os.path.join(os.path.dirname(here), 'gui')):
        if os.path.isfile(os.path.join(d, 'sp_gui.py')):
            sys.path.insert(0, d)
            break
    try:
        import sp_gui
    except (ImportError, ValueError) as e:
        print('The GUI needs PyGObject, GTK 4 and libadwaita from your distribution (%s).' % e,
              file=sys.stderr)
        return 1
    return sp_gui.main()


if __name__ == '__main__':
    sys.exit(relay())
