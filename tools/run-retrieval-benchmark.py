#!/usr/bin/env python3
"""Run the bounded development-only synthetic retrieval benchmark."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    # The harness deliberately lives with test fixtures, outside the package.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
    from retrieval_benchmark import main as benchmark_main

    return benchmark_main()


if __name__ == "__main__":
    raise SystemExit(main())
