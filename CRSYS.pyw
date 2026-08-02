"""Launch the CRSYS interface by double-click (the .pyw extension hides the console)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crsys_gui.app import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
