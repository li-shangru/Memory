#!/usr/bin/env python3
"""Run this checkout's developer factory from any current directory."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))

from agent_factory import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(["--repo", str(ROOT), *sys.argv[1:]]))
