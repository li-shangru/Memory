#!/bin/sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# uv run prepends the checkout environment to PATH. Capture the caller's actual
# everyday command first so verification cannot accidentally certify that shadow.
MEMORY_DELIVERY_SHELL_CLI=$(command -v memory || true)
export MEMORY_DELIVERY_SHELL_CLI
cd "$repo_root"
exec uv run --locked python tools/delivery.py "$@"
