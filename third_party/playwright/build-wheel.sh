#!/bin/sh
set -eu

recipe_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH= cd -- "$recipe_root/../.." && pwd -P)
output_dir="$repo_root/third_party/wheels"
output_name="playwright-1.62.0+memory.1-py3-none-macosx_26_0_arm64.whl"
output="$output_dir/$output_name"
uv_command=${MEMORY_PLAYWRIGHT_BUILD_UV:-uv}
upstream_url="https://files.pythonhosted.org/packages/af/1a/0bfbe9904350961f4dbb713f04342e40d548c5fc26c8157bd13617c81492/playwright-1.62.0-py3-none-macosx_11_0_arm64.whl"
upstream_sha="db755ab27db21a04186f1fe8169888e42356086e439b1059b923ef417f0b6034"
code_tree_sha="82149c494b20c20937efb9f5bdcb7a3367aeb701346b3b944a72dd2b012bafca"
license_sha="7fab1461b41970ff376f1c9303a637076bfaaeb71cd12dd3a1c44aaf59a1a2b9"
declared_macos_floor="26.0"
expected_node_minos="13.5"

[ "$(uname -s)" = "Darwin" ] || { echo "build requires macOS" >&2; exit 1; }
[ "$(uname -m)" = "arm64" ] || { echo "build requires arm64" >&2; exit 1; }
[ "$("$uv_command" --version)" = "uv 0.12.5 (210d1f678 2026-08-14 aarch64-apple-darwin)" ] || {
    echo "build requires uv 0.12.5" >&2
    exit 1
}
"$uv_command" run --isolated --no-project --python 3.14 -- python -I -c \
    'import sys; assert sys.version_info[:3] == (3, 14, 7)'

temp_base=${TMPDIR:-/tmp}
temp_base=${temp_base%/}
build_root=$(mktemp -d "$temp_base/memory-playwright-build.XXXXXX")
case "$build_root" in
    "$temp_base"/memory-playwright-build.*) ;;
    *) echo "refused unexpected build root" >&2; exit 1 ;;
esac
cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    case "$build_root" in
        "$temp_base"/memory-playwright-build.*) rm -rf -- "$build_root" ;;
        *) status=1 ;;
    esac
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

upstream="$build_root/upstream.whl"
candidate="$build_root/$output_name"
curl --fail --location --silent --show-error "$upstream_url" --output "$upstream"
actual=$(shasum -a 256 "$upstream" | awk '{print $1}')
[ "$actual" = "$upstream_sha" ] || { echo "upstream wheel hash mismatch" >&2; exit 1; }

"$uv_command" run --isolated --no-project --python 3.14 -- python -I - \
    "$upstream" "$candidate" "$code_tree_sha" <<'PY'
import base64
import csv
import hashlib
import io
import pathlib
import sys
import zipfile

source = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
expected_code_tree = sys.argv[3]
old_dist_info = "playwright-1.62.0.dist-info/"
new_dist_info = "playwright-1.62.0+memory.1.dist-info/"


def renamed(name: str) -> str:
    if name.startswith(old_dist_info):
        return new_dist_info + name.removeprefix(old_dist_info)
    return name


def digest_field(data: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "sha256=" + encoded.decode("ascii")


with zipfile.ZipFile(source) as archive:
    infos = archive.infolist()
    assert len(infos) == 221
    assert len({info.filename for info in infos}) == len(infos)
    code_digest = hashlib.sha256()
    code_names = sorted(
        info.filename
        for info in infos
        if ".dist-info/" not in info.filename and not info.is_dir()
    )
    assert len(code_names) == 181
    for name in code_names:
        code_digest.update(name.encode())
        code_digest.update(b"\0")
        code_digest.update(hashlib.sha256(archive.read(name)).digest())
    assert code_digest.hexdigest() == expected_code_tree

    transformed: dict[str, bytes] = {}
    for info in infos:
        if info.is_dir():
            continue
        name = renamed(info.filename)
        if name == new_dist_info + "RECORD":
            continue
        data = archive.read(info.filename)
        if name == new_dist_info + "METADATA":
            assert data.count(b"Version: 1.62.0\n") == 1
            assert data.count(b"Requires-Dist: pyee<14,>=13\n") == 1
            data = data.replace(
                b"Version: 1.62.0\n", b"Version: 1.62.0+memory.1\n"
            ).replace(
                b"Requires-Dist: pyee<14,>=13\n",
                b"Requires-Dist: pyee<15,>=14\n",
            )
        elif name == new_dist_info + "WHEEL":
            assert data.count(b"Tag: py3-none-any\n") == 1
            data = data.replace(
                b"Tag: py3-none-any\n",
                b"Tag: py3-none-macosx_26_0_arm64\n",
            )
        transformed[name] = data

    record_stream = io.StringIO(newline="")
    writer = csv.writer(record_stream, lineterminator="\n")
    for name in sorted(transformed):
        data = transformed[name]
        writer.writerow((name, digest_field(data), len(data)))
    record_name = new_dist_info + "RECORD"
    writer.writerow((record_name, "", ""))
    transformed[record_name] = record_stream.getvalue().encode("utf-8")

    source_info = {renamed(info.filename): info for info in infos}
    with zipfile.ZipFile(output, "w", allowZip64=True) as destination:
        for name in sorted(transformed):
            original = source_info[name]
            target = zipfile.ZipInfo(name, date_time=original.date_time)
            target.compress_type = original.compress_type
            target.comment = original.comment
            target.extra = original.extra
            target.internal_attr = original.internal_attr
            target.external_attr = original.external_attr
            target.create_system = original.create_system
            target.create_version = original.create_version
            target.extract_version = original.extract_version
            target.flag_bits = original.flag_bits
            destination.writestr(target, transformed[name], compresslevel=9)
PY

"$uv_command" run --isolated --no-project --python 3.14 -- python -I - \
    "$upstream" "$candidate" "$license_sha" "$recipe_root/LICENSE" \
    "$declared_macos_floor" "$expected_node_minos" <<'PY'
import hashlib
import pathlib
import re
import subprocess
import sys
import zipfile

upstream = pathlib.Path(sys.argv[1])
candidate = pathlib.Path(sys.argv[2])
expected_license = sys.argv[3]
committed_license = pathlib.Path(sys.argv[4])
declared_floor = tuple(int(part) for part in sys.argv[5].split("."))
expected_node_minos = sys.argv[6]
with zipfile.ZipFile(upstream) as old, zipfile.ZipFile(candidate) as new:
    old_members = {
        name: old.read(name)
        for name in old.namelist()
        if not name.endswith("/") and ".dist-info/" not in name
    }
    new_members = {
        name: new.read(name)
        for name in new.namelist()
        if not name.endswith("/") and ".dist-info/" not in name
    }
    assert new_members == old_members
    old_info = {info.filename: info for info in old.infolist()}
    new_info = {info.filename: info for info in new.infolist()}
    for name in old_members:
        assert new_info[name].create_system == old_info[name].create_system
        assert new_info[name].external_attr == old_info[name].external_attr
        assert new_info[name].internal_attr == old_info[name].internal_attr
    assert new_info["playwright/driver/node"].external_attr >> 16 == 0o100755
    assert {
        "playwright/driver/LICENSE",
        "playwright/driver/package/LICENSE",
        "playwright/driver/package/NOTICE",
        "playwright/driver/package/ThirdPartyNotices.txt",
    } <= new_members.keys()
    license_bytes = new.read(
        "playwright-1.62.0+memory.1.dist-info/licenses/LICENSE"
    )
    assert hashlib.sha256(license_bytes).hexdigest() == expected_license
    assert license_bytes == committed_license.read_bytes()
    node_path = candidate.parent / "node-probe"
    node_path.write_bytes(new.read("playwright/driver/node"))

load_commands = subprocess.run(
    ["otool", "-l", str(node_path)],
    check=True,
    capture_output=True,
    text=True,
).stdout
node_minos = re.findall(r"^\s*minos ([0-9.]+)$", load_commands, re.MULTILINE)
assert node_minos == [expected_node_minos]
assert tuple(int(part) for part in node_minos[0].split(".")) <= declared_floor
PY

verify_venv="$build_root/verify"
"$uv_command" venv --python 3.14 "$verify_venv"
"$uv_command" pip install --python "$verify_venv/bin/python" \
    "pyee==14.0.0" "greenlet>=3.1.1,<4"
"$uv_command" pip install --python "$verify_venv/bin/python" \
    --no-index --no-deps "$candidate"
"$uv_command" pip check --python "$verify_venv/bin/python"
"$verify_venv/bin/python" -I -c \
    'import importlib.metadata, playwright; assert importlib.metadata.version("playwright") == "1.62.0+memory.1"; assert importlib.metadata.version("pyee") == "14.0.0"; assert playwright.__file__'
[ "$("$verify_venv/bin/playwright" --version)" = "Version 1.62.0" ] || {
    echo "Playwright CLI identity drifted" >&2
    exit 1
}

mkdir -p "$output_dir"
rm -f -- "$output"
cp "$candidate" "$output"
digest=$(shasum -a 256 "$output" | awk '{print $1}')
printf '%s  third_party/wheels/%s\n' "$digest" "$output_name" > "$recipe_root/wheel-hash.txt"
printf 'built %s\n' "$output"
printf 'sha256 %s\n' "$digest"
