"""Directory-execution bootstrap for the staged Memory intake companion."""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    package_parent = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(package_parent))

from staged_memory_intake.cli import main

raise SystemExit(main())
