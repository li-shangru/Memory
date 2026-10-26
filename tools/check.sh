#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

if [ "${1-}" = "--loc" ]; then
    if [ "$#" -ne 1 ]; then
        echo "usage: ./tools/check.sh [--loc | --source-only]" >&2
        exit 2
    fi
    authored_loc=$(
        find src/memory tests tools -type f \
            \( -name '*.py' -o -name '*.sh' -o -name '*.sql' \) \
            -exec wc -l {} + |
            awk '$2 != "total" { total += $1 } END { print total + 0 }'
    )
    echo "Authored LOC (source + tests): $authored_loc"
    exit 0
fi

source_only=0
if [ "$#" -eq 1 ] && [ "$1" = "--source-only" ]; then
    source_only=1
elif [ "$#" -ne 0 ]; then
    echo "usage: ./tools/check.sh [--loc | --source-only]" >&2
    exit 2
fi

uv lock --check
# The real-browser owner journeys are part of this gate, so install their
# pinned Chromium before collecting tests.
./tools/setup-browser-tests.sh
uv run pytest
uv run ruff check src tests tools
uv run ruff format --check src tests tools
uv run mypy src tests tools

if [ "$source_only" -eq 1 ]; then
    echo "Source gate passed; local delivery is not verified by --source-only."
else
    ./tools/deliver.sh check
fi
