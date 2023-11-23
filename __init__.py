import argparse
import sys

import _gui

__all__ = [
    'exceptions', 'db_utils'
]
__version__ = "1.0"


if __name__ == '__main__':
    app = _gui.MainApplication()
    app.mainloop()

