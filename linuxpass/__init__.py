"""LinuxPass: StreetPass a Nintendo 3DS from Linux."""
import os
import sys

__version__ = '0.1.0'

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
