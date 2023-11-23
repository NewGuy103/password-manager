import argparse
import sys

import _gui
"""Production import
from . import _gui

"""


__all__ = [
    'exceptions', 'db_utils'
]
__version__ = "1.0"


class _ParseCLIArgs:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description=f'PasswordManager v{__version__}. Use --gui for the GUI.'
        )

        self.args = None
        self._make_args()

    def _make_args(self):
        self.parser.add_argument(
            '-g', '--gui',
            help="Run the CLI of PasswordManager.",
            action='store_true'
        )

    def parse_args(self):
        self.args = self.parser.parse_args()

        if self.args.gui:
            app = _gui.MainApplication()
            app.mainloop()

            sys.exit(0)


if __name__ == '__main__':
    cli = _ParseCLIArgs()
    cli.parse_args()