import argparse
import sys

import _gui
"""Production import
from . import _gui
from . import exceptions
from . import db_utils
"""

__all__ = [
    'exceptions', 'db_utils'
]
__version__ = "1.0"


if __name__ == '__main__':
    app = _gui.MainApplication()
    app.mainloop()

