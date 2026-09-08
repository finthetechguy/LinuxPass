#!/usr/bin/env python3
"""Console entry points, so `pip install .` gives you `linuxpass` and `linuxpass-gui`.

The modules import each other flat (`import sp_link`, not `from linuxpass import sp_link`),
so importing this package puts its own directory on `sys.path` first -- see __init__.py.
"""
import os
import sys


def relay(argv=None):
    import sp_relay
    return sp_relay.main()


def gui(argv=None):
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, os.path.join(here, 'gui'))
    import sp_gui
    return sp_gui.main()


if __name__ == '__main__':
    sys.exit(relay())
