#!/bin/sh
# The fast gate: everything that does not need a browser.
#
# Use this while working. It is not the gate that decides a change is done --
# `./tools/check.sh` is, and it additionally runs the real-browser owner
# journeys, which are the only thing that exercises rendered copy, focus, and
# the drag and drop path. Owner-visible wording changes are not verified here.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

if [ "$#" -ne 0 ]; then
    echo "usage: ./tools/fast-check.sh" >&2
    exit 2
fi

uv run pytest -m 'not browser and not slow'
uv run ruff check src tests tools
uv run ruff format --check src tests tools
uv run mypy src tests tools
