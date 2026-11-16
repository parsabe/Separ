"""Separ CLI launcher."""

import sys

from refmon.cli import *  # noqa: F403
from refmon.cli import main

if __name__ == "__main__":
    sys.exit(main())
