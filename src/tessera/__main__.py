"""Allow ``python -m tessera``."""

from __future__ import annotations

import sys

from tessera.cli import main

if __name__ == "__main__":
    sys.exit(main())
