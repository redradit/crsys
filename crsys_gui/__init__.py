"""CRSYS graphical interface (CustomTkinter).

Launch with::

    python -m crsys_gui              # default keyring in ~/.crsys
    python -m crsys_gui -k FOLDER    # keyring in a specific folder
"""

from .app import CrsysApp, main
from .keyring import DEFAULT_DIR, Identity, Keyring

__all__ = ["CrsysApp", "DEFAULT_DIR", "Identity", "Keyring", "main"]
