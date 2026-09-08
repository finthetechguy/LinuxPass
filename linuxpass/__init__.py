"""LinuxPass -- StreetPass a Nintendo 3DS from Linux.

The modules in this package keep the flat ``sp_*`` names they were developed under and import
each other directly (``import sp_link``, not ``from linuxpass import sp_link``). Importing the
package puts its own directory on ``sys.path`` so those imports resolve wherever it is
installed. See docs/SCRIPTS.md for why the names were left alone.
"""
import os
import sys

__version__ = '0.1.0'

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
