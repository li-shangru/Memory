#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
driver="$repo_root/tools/smoke-ui-driver.py"
temp_base=${TMPDIR:-/tmp}
temp_base=${temp_base%/}
temp_base=$(CDPATH= cd -- "$temp_base" && pwd -P)
uv_command=${MEMORY_SMOKE_UV_COMMAND:-uv}
security_command=${MEMORY_SMOKE_SECURITY_COMMAND:-/usr/bin/security}
unset PYTHONPATH PYTHONHOME VIRTUAL_ENV UV_PROJECT UV_PROJECT_ENVIRONMENT UV_WORKING_DIR
venv_dir=$(mktemp -d "$temp_base/memory-ui-venv.XXXXXX")
store_home=$(mktemp -d "$temp_base/memory-ui-home.XXXXXX")
work_dir=$(mktemp -d "$temp_base/memory-ui-work.XXXXXX")
venv_dir=$(CDPATH= cd -- "$venv_dir" && pwd -P)
store_home=$(CDPATH= cd -- "$store_home" && pwd -P)
work_dir=$(CDPATH= cd -- "$work_dir" && pwd -P)

validate_temp_directory() {
    candidate=$1
    prefix=$2
    [ -d "$candidate" ] || return 1
    case "$candidate" in
        "$temp_base/$prefix".*) return 0 ;;
        *) return 1 ;;
    esac
}

remove_temp_directory() {
    candidate=$1
    prefix=$2
    label=$3
    if validate_temp_directory "$candidate" "$prefix"; then
        if ! rm -rf -- "$candidate"; then
            echo "ui smoke cleanup could not remove its $label" >&2
            return 1
        fi
        return 0
    fi
    echo "ui smoke cleanup refused an unexpected $label path" >&2
    return 1
}

if ! validate_temp_directory "$venv_dir" memory-ui-venv; then
    echo "ui smoke refused an unexpected virtualenv path" >&2
    exit 1
fi
if ! validate_temp_directory "$store_home" memory-ui-home; then
    echo "ui smoke refused an unexpected Store-home path" >&2
    exit 1
fi
if ! validate_temp_directory "$work_dir" memory-ui-work; then
    echo "ui smoke refused an unexpected working path" >&2
    exit 1
fi
case "$work_dir" in
    "$repo_root"|"$repo_root"/*)
        echo "ui smoke refused a working directory inside the repository" >&2
        exit 1
        ;;
esac
[ -f "$driver" ] || {
    echo "ui smoke requires its launch driver" >&2
    exit 1
}

cleanup() {
    status=$?
    set +e
    cleanup_status=0
    retain_store=0
    identity="$store_home/runtime.json"
    if [ -x "$venv_dir/bin/python" ] && [ -f "$identity" ] && [ ! -L "$identity" ]; then
        store_id=$(
            "$venv_dir/bin/python" -I -c '
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    payload = json.load(source)
if not isinstance(payload, dict) or set(payload) != {
    "inbox_path",
    "product",
    "runtime_mode",
    "schema_lineage",
    "schema_version",
    "store_id",
}:
    raise SystemExit(1)
store_id = payload.get("store_id")
if (
    payload.get("product") != "memory"
    or payload.get("runtime_mode") != "personal"
    or payload.get("schema_lineage") != "memory-store-v1"
    or type(payload.get("schema_version")) is not int
    or payload.get("schema_version") != 1
):
    raise SystemExit(1)
if not isinstance(store_id, str) or re.fullmatch(r"[0-9a-f]{32}", store_id) is None:
    raise SystemExit(1)
print(store_id)
' "$identity" 2>/dev/null
        )
        identity_status=$?
        if [ "$identity_status" -ne 0 ] || [ -z "$store_id" ]; then
            echo "ui smoke cleanup refused an invalid Store identity" >&2
            cleanup_status=1
            retain_store=1
        elif [ ! -x "$security_command" ]; then
            echo "ui smoke cleanup could not execute the Keychain command" >&2
            cleanup_status=1
            retain_store=1
        else
            "$security_command" delete-generic-password \
                -s memory -a "$store_id" >/dev/null 2>&1
            delete_status=$?
            if [ "$delete_status" -ne 0 ]; then
                echo "ui smoke cleanup could not delete the synthetic key" >&2
                cleanup_status=1
                retain_store=1
            else
                "$security_command" find-generic-password \
                    -s memory -a "$store_id" >/dev/null 2>&1
                find_status=$?
                if [ "$find_status" -ne 44 ]; then
                    echo "ui smoke cleanup could not verify key absence" >&2
                    cleanup_status=1
                    retain_store=1
                fi
            fi
        fi
    elif [ "$status" -eq 0 ] || [ -e "$identity" ] || [ -L "$identity" ]; then
        echo "ui smoke cleanup has no valid Store identity" >&2
        cleanup_status=1
        retain_store=1
    fi
    remove_temp_directory "$venv_dir" memory-ui-venv virtualenv ||
        cleanup_status=1
    remove_temp_directory "$work_dir" memory-ui-work \
        "working directory" || cleanup_status=1
    if [ "$retain_store" -eq 0 ]; then
        remove_temp_directory "$store_home" memory-ui-home \
            "Store home" || cleanup_status=1
    else
        echo "ui smoke retained synthetic Store home for recovery: $store_home" >&2
    fi
    if [ "$status" -eq 0 ] && [ "$cleanup_status" -ne 0 ]; then
        status=$cleanup_status
    fi
    trap - EXIT
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

cd "$repo_root"
"$uv_command" venv --python 3.14 "$venv_dir"
wheelhouse="$venv_dir/wheelhouse"
mkdir -m 700 "$wheelhouse"
if [ -n "${MEMORY_SMOKE_WHEEL-}" ]; then
    actual_wheel_digest=$(shasum -a 256 "$MEMORY_SMOKE_WHEEL" | awk '{print $1}')
    [ "$actual_wheel_digest" = "${MEMORY_SMOKE_WHEEL_SHA256-}" ] || {
        echo "ui smoke refused an unverified supplied wheel" >&2
        exit 1
    }
    cp "$MEMORY_SMOKE_WHEEL" "$wheelhouse/"
else
    "$uv_command" build --wheel --out-dir "$wheelhouse"
fi
set -- "$wheelhouse"/*.whl
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    echo "ui smoke requires exactly one Store wheel" >&2
    exit 1
fi
wheel=$1
if [ -n "${MEMORY_SMOKE_WHEEL-}" ]; then
    copied_wheel_digest=$(shasum -a 256 "$wheel" | awk '{print $1}')
    [ "$copied_wheel_digest" = "${MEMORY_SMOKE_WHEEL_SHA256-}" ] || {
        echo "ui smoke refused a changed supplied wheel" >&2
        exit 1
    }
fi
companion_source=${MEMORY_SMOKE_COMPANION:-"$repo_root/third_party/wheels/memory_sqlcipher3-0.6.2+sqlcipher4.17.0.memory1-cp314-cp314-macosx_26_0_arm64.whl"}
companion_digest=${MEMORY_SMOKE_COMPANION_SHA256:-3436966d149f0e498f69aa78612bc8be2b9c8340fa44c5fb3f4cc50c5ddf2106}
[ -f "$companion_source" ] && [ ! -L "$companion_source" ] || {
    echo "ui smoke requires the exact SQLCipher companion wheel" >&2
    exit 1
}
companion="$venv_dir/memory_sqlcipher3-0.6.2+sqlcipher4.17.0.memory1-cp314-cp314-macosx_26_0_arm64.whl"
cp "$companion_source" "$companion"
actual_companion_digest=$(shasum -a 256 "$companion" | awk '{print $1}')
[ "$actual_companion_digest" = "$companion_digest" ] || {
    echo "ui smoke refused an unverified supplied companion" >&2
    exit 1
}
if [ -n "${MEMORY_SMOKE_CONSTRAINTS-}" ]; then
    "$uv_command" pip install --python "$venv_dir/bin/python" \
        --constraint "$MEMORY_SMOKE_CONSTRAINTS" "$companion" "$wheel"
else
    "$uv_command" pip install --python "$venv_dir/bin/python" "$companion" "$wheel"
fi
"$uv_command" pip check --python "$venv_dir/bin/python"

installed_python="$venv_dir/bin/python"
installed_memory="$venv_dir/bin/memory"
[ -x "$installed_python" ] || {
    echo "ui smoke could not execute the installed interpreter" >&2
    exit 1
}
[ -f "$installed_memory" ] && [ ! -L "$installed_memory" ] && [ -x "$installed_memory" ] || {
    echo "ui smoke could not execute the installed Store command" >&2
    exit 1
}

cd "$work_dir"
asset_report=$(
    "$installed_python" -I -c '
import pathlib
import sys

import memory
import memory.ui as ui
import memory.ui.app as app

package_root = pathlib.Path(memory.__file__).resolve().parent
ui_root = pathlib.Path(ui.__file__).resolve().parent
templates = sorted(path.name for path in (ui_root / "templates").rglob("*.html"))
static = sorted(path.name for path in (ui_root / "static").glob("*"))
if len(templates) < 18 or len(static) < 3:
    raise SystemExit(1)
if app._PACKAGE_ROOT.resolve() != ui_root:
    raise SystemExit(1)
if not (ui_root / "templates" / "base.html").is_file():
    raise SystemExit(1)
if not (ui_root / "static" / "app.css").is_file():
    raise SystemExit(1)
print(package_root)
print(ui_root)
print(len(templates))
print(len(static))
'
) || {
    echo "ui smoke could not resolve installed owner UI assets" >&2
    exit 1
}
module_root=$(printf '%s\n' "$asset_report" | sed -n 1p)
ui_root=$(printf '%s\n' "$asset_report" | sed -n 2p)
template_count=$(printf '%s\n' "$asset_report" | sed -n 3p)
static_count=$(printf '%s\n' "$asset_report" | sed -n 4p)
case "$module_root" in
    "$venv_dir"/*) ;;
    *)
        echo "ui smoke imported the Store package outside its virtualenv" >&2
        exit 1
        ;;
esac
case "$ui_root" in
    "$venv_dir"/*/site-packages/memory/ui) ;;
    *)
        echo "ui smoke resolved owner UI assets outside its virtualenv" >&2
        exit 1
        ;;
esac
echo "Installed owner UI templates: $template_count"
echo "Installed owner UI assets: $static_count"

"$installed_memory" init --home "$store_home" >/dev/null
"$installed_python" -I "$driver" --memory "$installed_memory" --home "$store_home"

echo "ui smoke passed"
