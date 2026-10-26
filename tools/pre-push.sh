#!/bin/sh
set -eu

# A push publishes work, and the fast gate is the smallest check that proves
# the tree being published. Git hands every pre-push hook the ref lines on
# stdin; consume them fully so a partial read never breaks the push protocol,
# and skip the gate when nothing is actually being pushed.
refs=$(cat)
[ -n "$refs" ] || exit 0

repo_root=$(git rev-parse --show-toplevel)
exec "$repo_root/tools/fast-check.sh"
