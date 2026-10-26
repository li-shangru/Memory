#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temp_base=${TMPDIR:-/tmp}
temp_base=${temp_base%/}
temp_base=$(CDPATH= cd -- "$temp_base" && pwd -P)
uv_command=${MEMORY_SMOKE_UV_COMMAND:-uv}
security_command=${MEMORY_SMOKE_SECURITY_COMMAND:-/usr/bin/security}
memory_override=${MEMORY_SMOKE_CLI_COMMAND-}
unset PYTHONPATH PYTHONHOME VIRTUAL_ENV UV_PROJECT UV_PROJECT_ENVIRONMENT UV_WORKING_DIR
venv_dir=$(mktemp -d "$temp_base/memory-wheel-venv.XXXXXX")
store_home=$(mktemp -d "$temp_base/memory-wheel-home.XXXXXX")
venv_dir=$(CDPATH= cd -- "$venv_dir" && pwd -P)
store_home=$(CDPATH= cd -- "$store_home" && pwd -P)

validate_temp_directory() {
    candidate=$1
    prefix=$2
    [ -d "$candidate" ] || return 1
    case "$candidate" in
        "$temp_base/$prefix".*) return 0 ;;
        *) return 1 ;;
    esac
}

if ! validate_temp_directory "$venv_dir" memory-wheel-venv; then
    echo "wheel smoke refused an unexpected virtualenv path" >&2
    exit 1
fi
if ! validate_temp_directory "$store_home" memory-wheel-home; then
    echo "wheel smoke refused an unexpected Store-home path" >&2
    exit 1
fi

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
            echo "wheel smoke cleanup refused an invalid Store identity" >&2
            cleanup_status=1
            retain_store=1
        elif [ ! -x "$security_command" ]; then
            echo "wheel smoke cleanup could not execute the Keychain command" >&2
            cleanup_status=1
            retain_store=1
        else
            "$security_command" delete-generic-password \
                -s memory -a "$store_id" >/dev/null 2>&1
            delete_status=$?
            if [ "$delete_status" -ne 0 ]; then
                echo "wheel smoke cleanup could not delete the synthetic key" >&2
                cleanup_status=1
                retain_store=1
            else
                "$security_command" find-generic-password \
                    -s memory -a "$store_id" >/dev/null 2>&1
                find_status=$?
                if [ "$find_status" -ne 44 ]; then
                    echo "wheel smoke cleanup could not verify key absence" >&2
                    cleanup_status=1
                    retain_store=1
                fi
            fi
        fi
    elif [ "$status" -eq 0 ] || [ -e "$identity" ] || [ -L "$identity" ]; then
        echo "wheel smoke cleanup has no valid Store identity" >&2
        cleanup_status=1
        retain_store=1
    fi
    if validate_temp_directory "$venv_dir" memory-wheel-venv; then
        if ! rm -rf -- "$venv_dir"; then
            echo "wheel smoke cleanup could not remove its virtualenv" >&2
            cleanup_status=1
        fi
    else
        echo "wheel smoke cleanup refused an unexpected virtualenv path" >&2
        cleanup_status=1
    fi
    if [ "$retain_store" -eq 0 ]; then
        if validate_temp_directory "$store_home" memory-wheel-home; then
            if ! rm -rf -- "$store_home"; then
                echo "wheel smoke cleanup could not remove its Store home" >&2
                cleanup_status=1
            fi
        else
            echo "wheel smoke cleanup refused an unexpected Store-home path" >&2
            cleanup_status=1
        fi
    else
        echo "wheel smoke retained synthetic Store home for recovery: $store_home" >&2
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
        echo "wheel smoke refused an unverified supplied wheel" >&2
        exit 1
    }
    cp "$MEMORY_SMOKE_WHEEL" "$wheelhouse/"
else
    "$uv_command" build --wheel --out-dir "$wheelhouse"
fi
set -- "$wheelhouse"/*.whl
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    echo "wheel smoke requires exactly one Store wheel" >&2
    exit 1
fi
wheel=$1
if [ -n "${MEMORY_SMOKE_WHEEL-}" ]; then
    copied_wheel_digest=$(shasum -a 256 "$wheel" | awk '{print $1}')
    [ "$copied_wheel_digest" = "${MEMORY_SMOKE_WHEEL_SHA256-}" ] || {
        echo "wheel smoke refused a changed supplied wheel" >&2
        exit 1
    }
fi
companion_source=${MEMORY_SMOKE_COMPANION:-"$repo_root/third_party/wheels/memory_sqlcipher3-0.6.2+sqlcipher4.17.0.memory1-cp314-cp314-macosx_26_0_arm64.whl"}
companion_digest=${MEMORY_SMOKE_COMPANION_SHA256:-3436966d149f0e498f69aa78612bc8be2b9c8340fa44c5fb3f4cc50c5ddf2106}
[ -f "$companion_source" ] && [ ! -L "$companion_source" ] || {
    echo "wheel smoke requires the exact SQLCipher companion wheel" >&2
    exit 1
}
companion="$venv_dir/memory_sqlcipher3-0.6.2+sqlcipher4.17.0.memory1-cp314-cp314-macosx_26_0_arm64.whl"
cp "$companion_source" "$companion"
actual_companion_digest=$(shasum -a 256 "$companion" | awk '{print $1}')
[ "$actual_companion_digest" = "$companion_digest" ] || {
    echo "wheel smoke refused an unverified supplied companion" >&2
    exit 1
}
"$venv_dir/bin/python" -I - "$wheel" <<'PY'
import email.parser
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as archive:
    metadata_name = next(
        name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
    )
    message = email.parser.BytesParser().parsebytes(archive.read(metadata_name))
assert "memory-sqlcipher3==0.6.2+sqlcipher4.17.0.memory1" in message.get_all(
    "Requires-Dist", []
)
PY

if [ -n "${MEMORY_SMOKE_CONSTRAINTS-}" ]; then
    "$uv_command" pip install --python "$venv_dir/bin/python" \
        --constraint "$MEMORY_SMOKE_CONSTRAINTS" "$companion" "$wheel"
else
    "$uv_command" pip install --python "$venv_dir/bin/python" "$companion" "$wheel"
fi
"$uv_command" pip check --python "$venv_dir/bin/python"
module_path=$(
    "$venv_dir/bin/python" -I -c '
import pathlib
import memory

print(pathlib.Path(memory.__file__).resolve())
'
)
case "$module_path" in
    "$venv_dir"/*) ;;
    *)
        echo "wheel smoke imported the Store package outside its virtualenv" >&2
        exit 1
        ;;
esac
echo "Wheel module: $module_path"

skill_path=$(
    "$venv_dir/bin/python" -I -c '
from importlib.resources import files

resource = files("memory").joinpath("skill", "SKILL.md")
resource.read_bytes()
print(resource)
'
)
case "$skill_path" in
    "$venv_dir"/*/site-packages/memory/skill/SKILL.md) ;;
    *)
        echo "wheel smoke discovered the Store Skill outside its virtualenv" >&2
        exit 1
        ;;
esac
skill_contract_digest=$(
    "$venv_dir/bin/python" -I -c '
import hashlib
from importlib.resources import files

raw = files("memory").joinpath("skill", "SKILL.md").read_bytes()
normalized = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
digest = hashlib.sha256(normalized).hexdigest()
if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
    raise SystemExit(1)
print(digest)
'
)
echo "Wheel skill: $skill_path"
echo "Wheel skill digest: $skill_contract_digest"

if [ -n "$memory_override" ]; then
    cli_command=$memory_override
else
    cli_command="$venv_dir/bin/memory"
fi
[ -x "$cli_command" ] || {
    echo "wheel smoke could not execute the installed Store command" >&2
    exit 1
}

cd "$store_home"
"$cli_command" init --home "$store_home"
paths_json=$("$cli_command" paths --home "$store_home" --json)
"$venv_dir/bin/python" -c '
import json
import pathlib
import sys

payload = json.loads(sys.argv[1])
home = pathlib.Path(sys.argv[2])
assert payload["home"] == str(home)
assert payload["database"] == str(home / "store.sqlite3")
assert payload["inbox"] == str(home / "inbox")
assert payload["inbox_claims"] == str(home / "inbox-claims")
assert payload["identity"] == str(home / "runtime.json")
' "$paths_json" "$store_home"

if [ -z "$memory_override" ]; then
    native_extension=$(
        "$venv_dir/bin/python" -I -c \
            'import sqlcipher3._sqlite3 as native; print(native.__file__)'
    )
    native_links=$(otool -L "$native_extension")
    printf '%s\n' "$native_links" | grep -F "/usr/lib/libSystem.B.dylib" >/dev/null
    [ "$(printf '%s\n' "$native_links" | sed '1d' | wc -l | tr -d ' ')" = "1" ] || {
        echo "wheel smoke found an external SQLCipher dependency" >&2
        exit 1
    }
    "$venv_dir/bin/python" -I - "$store_home" <<'PY'
import importlib.metadata
import sys
from pathlib import Path

from memory.database import open_database
from memory.keys import load_master_key
from memory.runtime import load_runtime_identity, resolve_runtime

paths = resolve_runtime(Path(sys.argv[1]))
identity = load_runtime_identity(paths)
key = load_master_key(identity)
connection = open_database(paths, key, read_only=True)
try:
    bound = paths.database.stat()
    assert connection.file_identity() == (bound.st_dev, bound.st_ino)
    status_row = connection.execute("PRAGMA cipher_status").fetchone()
    cipher_row = connection.execute("PRAGMA cipher_version").fetchone()
    sqlite_row = connection.execute("SELECT sqlite_version()").fetchone()
    provider_row = connection.execute("PRAGMA cipher_provider").fetchone()
    compile_options = {
        str(row[0]) for row in connection.execute("PRAGMA compile_options")
    }
finally:
    connection.close()
required_options = {
    "HAS_CODEC", "ENABLE_FTS3", "ENABLE_FTS3_PARENTHESIS", "ENABLE_FTS4",
    "ENABLE_FTS5", "ENABLE_RTREE", "ENABLE_STAT4", "ENABLE_UPDATE_DELETE_LIMIT",
    "SOUNDEX", "USE_URI", "TEMP_STORE=2", "THREADSAFE=1",
    "MAX_VARIABLE_NUMBER=250000", "DEFAULT_PAGE_SIZE=4096",
    "DEFAULT_CACHE_SIZE=-8000", "ENABLE_COLUMN_METADATA",
    "ENABLE_MATH_FUNCTIONS", "ENABLE_PERCENTILE",
    "EXTRA_INIT=sqlcipher_extra_init",
    "EXTRA_SHUTDOWN=sqlcipher_extra_shutdown",
}
assert importlib.metadata.version("memory-sqlcipher3") == "0.6.2+sqlcipher4.17.0.memory1"
assert status_row is not None and str(status_row[0]) == "1"
assert cipher_row == ("4.17.0 community",)
assert sqlite_row == ("3.53.3",)
assert provider_row == ("openssl",)
assert required_options <= compile_options, required_options - compile_options
print(f"Wheel SQLCipher engine: {cipher_row[0]}")
print(f"Wheel SQLite engine: {sqlite_row[0]}")
print(f"Wheel SQLCipher provider: {provider_row[0]}")
PY

    "$venv_dir/bin/python" -I - "$cli_command" "$store_home" <<'PY'
import sys

import anyio
from mcp import Client
from mcp.client.stdio import StdioServerParameters, stdio_client

EXPECTED_TOOLS = [
    "store.status",
    "source.list",
    "source.search",
    "source.read",
    "inbox.scan",
    "inbox.list",
    "inbox.read",
    "memory.search",
    "memory.get",
    "memory.facets",
    "change_set.create",
    "change_set.get",
    "change_set.edit",
    "change_set.approve_and_apply",
]


class StdioTransport:
    def __init__(self) -> None:
        self._manager = stdio_client(
            StdioServerParameters(
                command=sys.argv[1],
                args=["mcp", "--home", sys.argv[2]],
            )
        )

    async def __aenter__(self):
        return await self._manager.__aenter__()

    async def __aexit__(self, exc_type, exc_value, traceback):
        return await self._manager.__aexit__(exc_type, exc_value, traceback)


async def probe(mode: str) -> str:
    async with Client(StdioTransport(), mode=mode) as client:
        listing = await client.list_tools()
        status = await client.call_tool("store.status", {})
        protocol_version = client.protocol_version
        assert client.server_info.name == "Memory"
    assert [tool.name for tool in listing.tools] == EXPECTED_TOOLS
    assert status.is_error is not True
    assert status.structured_content is not None
    assert status.structured_content["schema"] == "memory.mcp.v1"
    assert status.structured_content["instruction_trust"] == "inert"
    return protocol_version


modern_protocol = anyio.run(probe, "auto")
legacy_protocol = anyio.run(probe, "legacy")
assert modern_protocol == "2026-07-28"
assert legacy_protocol == "2025-11-25"
print(f"Wheel MCP modern stdio protocol: {modern_protocol}")
print(f"Wheel MCP legacy stdio protocol: {legacy_protocol}")
PY

    "$uv_command" run --isolated --python 3.14 \
        --with 'mcp==1.29.0' -- python -I - "$cli_command" "$store_home" <<'PY'
import sys

import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

EXPECTED_TOOLS = [
    "store.status",
    "source.list",
    "source.search",
    "source.read",
    "inbox.scan",
    "inbox.list",
    "inbox.read",
    "memory.search",
    "memory.get",
    "memory.facets",
    "change_set.create",
    "change_set.get",
    "change_set.edit",
    "change_set.approve_and_apply",
]


async def probe() -> str:
    parameters = StdioServerParameters(
        command=sys.argv[1],
        args=["mcp", "--home", sys.argv[2]],
    )
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            initialized = await session.initialize()
            listing = await session.list_tools()
            status = await session.call_tool("store.status", {})
    assert initialized.serverInfo.name == "Memory"
    assert [tool.name for tool in listing.tools] == EXPECTED_TOOLS
    assert status.isError is not True
    assert status.structuredContent is not None
    assert status.structuredContent["schema"] == "memory.mcp.v1"
    assert status.structuredContent["instruction_trust"] == "inert"
    return initialized.protocolVersion


protocol = anyio.run(probe)
assert protocol == "2025-11-25"
print(f"Wheel MCP 1.29 client protocol: {protocol}")
PY
fi

echo "wheel smoke passed"
