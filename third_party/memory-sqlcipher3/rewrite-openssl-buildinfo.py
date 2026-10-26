"""Remove one disposable build path from OpenSSL's compiled build metadata."""

from __future__ import annotations

import sys
from pathlib import Path

OLD = b'$cflags = "compiler: $cflags";\n'
NEW = (
    b"# Memory records the exact compiler and flags in its committed provenance.\n"
    b"# Do not embed the disposable source-build path carried by prefix-map flags.\n"
    b'$cflags = "compiler: see Memory companion provenance";\n'
)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: rewrite-openssl-buildinfo.py MKBUILDINF.PL")
    path = Path(sys.argv[1])
    source = path.read_bytes()
    if source.count(OLD) != 1:
        raise SystemExit("expected exactly one OpenSSL compiler-description assignment")
    path.write_bytes(source.replace(OLD, NEW))


if __name__ == "__main__":
    main()
