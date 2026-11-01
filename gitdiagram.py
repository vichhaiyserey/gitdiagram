#!/usr/bin/env python3
"""gitdiagram entrypoint: python gitdiagram.py --dir PATH/TO/GIT/DIR"""

from __future__ import annotations

from gitdiagram_core.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
