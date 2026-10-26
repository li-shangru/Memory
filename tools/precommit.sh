#!/bin/sh
set -eu

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

staged_paths=$(git diff --cached --name-only --diff-filter=ACMR)
[ -n "$staged_paths" ] || exit 0

format_root=
cleanup() {
    if [ -n "$format_root" ]; then
        rm -rf "$format_root"
    fi
}
trap cleanup EXIT HUP INT TERM

fence_patterns=$(
    awk '
        /^# Never commit / { inside = 1; next }
        inside && seen && NF == 0 { exit }
        inside && /^#/ { next }
        inside && NF { seen = 1; print }
    ' .gitignore
)
credential_pattern='(api[[:space:]_-]*key|token|secret)[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9_./+=-]{16,}'
private_key_marker='-----'"BEGIN"

matches_fence() {
    candidate=$1
    pattern=$2
    case "$pattern" in
        */)
            directory=${pattern%/}
            case "/$candidate/" in
                *"/$directory/"*) return 0 ;;
            esac
            ;;
        *)
            case "$candidate" in
                $pattern | */$pattern) return 0 ;;
            esac
            ;;
    esac
    return 1
}

while IFS= read -r path; do
    while IFS= read -r pattern; do
        if matches_fence "$path" "$pattern"; then
            echo "pre-commit blocked: forbidden path $path; keep runtime data and downloads out of the repo." >&2
            exit 1
        fi
    done <<EOF
$fence_patterns
EOF

    staged_size=$(git cat-file -s ":$path")
    if [ "$staged_size" -gt 1048576 ]; then
        echo "pre-commit blocked: $path is larger than 1 MB; keep large files out of the repo." >&2
        exit 1
    fi

    if git show ":$path" | LC_ALL=C grep -a -F -q -- "$private_key_marker"; then
        echo "pre-commit blocked: private key or certificate header in $path; remove it before committing." >&2
        exit 1
    fi

    # This complete public statement generates random bytes at runtime. Omit
    # only that exact line from this check; appended text and all other lines
    # remain eligible, and private-key/entropy checks still scan the full file.
    runtime_random_assignment='^[[:space:]]*self[.]_secret = secrets[.]token_bytes[(]SECRET_BYTES[)]$'
    if git show ":$path" |
        LC_ALL=C grep -a -E -v -- "$runtime_random_assignment" |
        LC_ALL=C grep -a -E -i -q -- "$credential_pattern"; then
        echo "pre-commit blocked: possible secret in $path; remove it before committing." >&2
        exit 1
    fi

    entropy_candidates=$(
        git show ":$path" |
            LC_ALL=C grep -a -E -o -- '[A-Za-z0-9_+/=-]{40,}' || true
    )
    for candidate in $entropy_candidates; do
        # These fixed public dependency URLs and SDK executable are not credentials.
        # Match whole tokens; extra bytes and other tokens still go through checks.
        case "$candidate" in
            /Library/Developer/CommandLineTools/usr/bin/python3) continue ;;
            com/li-shangru/Memory/releases/tag/vendored-wheels-1) continue ;;
            com/li-shangru/Memory/releases/download/vendored-wheels-1/) continue ;;
        esac
        case "$candidate" in *[A-Z]*) ;; *) continue ;; esac
        case "$candidate" in *[a-z]*) ;; *) continue ;; esac
        case "$candidate" in *[0-9]*) ;; *) continue ;; esac
        echo "pre-commit blocked: high-entropy token in $path; remove it before committing." >&2
        exit 1
    done

    case "$path" in
        *.py)
            if [ -z "$format_root" ]; then
                format_root=$(mktemp -d "${TMPDIR:-/tmp}/memory-precommit.XXXXXX")
            fi
            mkdir -p "$format_root/$(dirname "$path")"
            git show ":$path" >"$format_root/$path"
            ;;
    esac
done <<EOF
$staged_paths
EOF

if [ -n "$format_root" ]; then
    ruff="$repo_root/.venv/bin/ruff"
    if [ ! -x "$ruff" ]; then
        echo "pre-commit blocked: Ruff is missing; run uv sync before committing." >&2
        exit 1
    fi
    if ! "$ruff" format --check --config "$repo_root/pyproject.toml" "$format_root" >/dev/null; then
        echo "pre-commit blocked: staged Python fails ruff format; format it before committing." >&2
        exit 1
    fi
fi
