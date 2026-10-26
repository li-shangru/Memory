#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
hooks_dir=$(git -C "$repo_root" rev-parse --git-path hooks)
case "$hooks_dir" in
    /*) ;;
    *) hooks_dir="$repo_root/$hooks_dir" ;;
esac

mkdir -p "$hooks_dir"
install -m 0755 "$repo_root/tools/precommit.sh" "$hooks_dir/pre-commit"
install -m 0755 "$repo_root/tools/pre-push.sh" "$hooks_dir/pre-push"
echo "Installed pre-commit and pre-push hooks."
