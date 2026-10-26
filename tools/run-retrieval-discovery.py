#!/usr/bin/env python3
"""Measure bounded synthetic evidence discovery without model-quality claims."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
    from retrieval_discovery import main as discovery_main

    return discovery_main()


if __name__ == "__main__":
    raise SystemExit(main())
