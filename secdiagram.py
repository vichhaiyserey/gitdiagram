#!/usr/bin/env python3
"""secdiagram entrypoint: python secdiagram.py --dir PATH/TO/GIT/DIR"""

from __future__ import annotations

from secdiagram_core.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
