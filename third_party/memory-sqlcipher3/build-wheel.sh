#!/bin/sh
set -eu

recipe_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH= cd -- "$recipe_root/../.." && pwd -P)
output_dir="$repo_root/third_party/wheels"
output_name="memory_sqlcipher3-0.6.2+sqlcipher4.17.0.memory1-cp314-cp314-macosx_26_0_arm64.whl"
output="$output_dir/$output_name"
uv_command=${MEMORY_SQLCIPHER_BUILD_UV:-uv}

sqlcipher3_url="https://files.pythonhosted.org/packages/ae/c1/414003d77549c444bafd636149ab3ace6f4e2cb4666c9955d54ad62096cb/sqlcipher3-0.6.2.tar.gz"
sqlcipher3_sha="a2b675289ba8889f389625a21f3a01f1ff159a551b5b88fba8fd92da0e02380a"
sqlcipher_url="https://github.com/sqlcipher/sqlcipher/archive/refs/tags/v4.17.0.tar.gz"
sqlcipher_sha="79c0e164b9c059e7487bf8f29272f601cca5f3312cc267461f81e349962a5058"
openssl_url="https://github.com/openssl/openssl/releases/download/openssl-4.0.1/openssl-4.0.1.tar.gz"
openssl_sha="2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09"

runtime_root="/usr/local/lib/memory-sqlcipher3/0.6.2-sqlcipher4.17.0.memory1"
export MACOSX_DEPLOYMENT_TARGET=26.0
export SOURCE_DATE_EPOCH=1783520526
export ZERO_AR_DATE=1

[ "$(uname -s)" = "Darwin" ] || { echo "build requires macOS" >&2; exit 1; }
[ "$(uname -m)" = "arm64" ] || { echo "build requires arm64" >&2; exit 1; }
[ "$(sw_vers -productVersion)" = "27.0" ] || { echo "build requires macOS 27.0" >&2; exit 1; }
[ "$(sw_vers -buildVersion)" = "26A428" ] || { echo "build requires macOS build 26A428" >&2; exit 1; }
[ "$("$uv_command" --version)" = "uv 0.12.17 (635500036 2026-09-18 aarch64-apple-darwin)" ] || {
    echo "build requires uv 0.12.17" >&2
    exit 1
}
[ "$(xcodebuild -version)" = "$(printf 'Xcode 27.0\nBuild version 27A266a')" ] || {
    echo "build requires Xcode 27.0 build 27A266a" >&2
    exit 1
}
clang --version | grep -F "Apple clang version 21.0.0 (clang-2100.3.34.2)" >/dev/null
"$uv_command" run --isolated --no-project --python 3.14 -- python -I -c \
    'import platform, sys; assert sys.version_info[:3] == (3, 14, 7); assert platform.machine() == "arm64"'

build_root=$(mktemp -d "${TMPDIR:-/tmp}/memory-sqlcipher-source.XXXXXX")
case "$build_root" in
    "${TMPDIR:-/tmp}"/memory-sqlcipher-source.*) ;;
    *) echo "refused unexpected build root" >&2; exit 1 ;;
esac
canonical_build_root=$(CDPATH= cd -- "$build_root" && pwd -P)
path_map_flags="-ffile-prefix-map=$build_root=/usr/src/memory-sqlcipher3"
if [ "$canonical_build_root" != "$build_root" ]; then
    path_map_flags="$path_map_flags -ffile-prefix-map=$canonical_build_root=/usr/src/memory-sqlcipher3"
fi
cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    case "$build_root" in
        "${TMPDIR:-/tmp}"/memory-sqlcipher-source.*) rm -rf -- "$build_root" ;;
        *) status=1 ;;
    esac
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

downloads="$build_root/downloads"
stage="$build_root/stage"
mkdir -p "$downloads" "$stage"

fetch() {
    url=$1
    expected=$2
    destination=$3
    curl --fail --location --silent --show-error "$url" --output "$destination"
    actual=$(shasum -a 256 "$destination" | awk '{print $1}')
    [ "$actual" = "$expected" ] || {
        echo "source hash mismatch: $destination" >&2
        exit 1
    }
}

fetch "$sqlcipher3_url" "$sqlcipher3_sha" "$downloads/sqlcipher3.tar.gz"
fetch "$sqlcipher_url" "$sqlcipher_sha" "$downloads/sqlcipher.tar.gz"
fetch "$openssl_url" "$openssl_sha" "$downloads/openssl.tar.gz"

tar -xzf "$downloads/openssl.tar.gz" -C "$build_root"
openssl_source="$build_root/openssl-4.0.1"
openssl_prefix="$stage$runtime_root/openssl"
"$uv_command" run --isolated --no-project --python 3.14 -- \
    python -I "$recipe_root/rewrite-openssl-buildinfo.py" \
    "$openssl_source/util/mkbuildinf.pl"
(
    cd "$openssl_source"
    ./Configure darwin64-arm64-cc no-shared no-tests no-module \
        --prefix="$runtime_root/openssl" \
        --openssldir="$runtime_root/openssl/ssl" \
        -mmacosx-version-min=26.0 -O2 -g0 \
        $path_map_flags
    make -j8
    make DESTDIR="$stage" install_sw
)

tar -xzf "$downloads/sqlcipher.tar.gz" -C "$build_root"
sqlcipher_source="$build_root/sqlcipher-4.17.0"
sqlcipher_prefix="$stage$runtime_root/sqlcipher"
(
    cd "$recipe_root"
    shasum -a 256 -c source-patch-hashes.txt
)
(
    cd "$sqlcipher_source"
    patch -p1 -F 0 -t < "$recipe_root/patches/sqlcipher-file-identity.patch"
)
compile_flags="-O2 -g0 -mmacosx-version-min=26.0"
compile_flags="$compile_flags $path_map_flags"
compile_flags="$compile_flags -DSQLITE_HAS_CODEC=1"
compile_flags="$compile_flags -DSQLITE_ENABLE_COLUMN_METADATA=1"
compile_flags="$compile_flags -DSQLITE_ENABLE_FTS3=1"
compile_flags="$compile_flags -DSQLITE_ENABLE_FTS3_PARENTHESIS=1"
compile_flags="$compile_flags -DSQLITE_ENABLE_FTS4=1"
compile_flags="$compile_flags -DSQLITE_ENABLE_FTS5=1"
compile_flags="$compile_flags -DSQLITE_ENABLE_MATH_FUNCTIONS=1"
compile_flags="$compile_flags -DSQLITE_ENABLE_PERCENTILE=1"
compile_flags="$compile_flags -DSQLITE_ENABLE_RTREE=1"
compile_flags="$compile_flags -DSQLITE_ENABLE_STAT4=1"
compile_flags="$compile_flags -DSQLITE_ENABLE_UPDATE_DELETE_LIMIT=1"
compile_flags="$compile_flags -DSQLITE_SOUNDEX=1"
compile_flags="$compile_flags -DSQLITE_USE_URI=1"
compile_flags="$compile_flags -DSQLITE_TEMP_STORE=2"
compile_flags="$compile_flags -DSQLITE_THREADSAFE=1"
compile_flags="$compile_flags -DSQLITE_EXTRA_INIT=sqlcipher_extra_init"
compile_flags="$compile_flags -DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown"
compile_flags="$compile_flags -DHAVE_STDINT_H=1"
compile_flags="$compile_flags -DSQLITE_MAX_VARIABLE_NUMBER=250000"
compile_flags="$compile_flags -DSQLITE_DEFAULT_PAGE_SIZE=4096"
compile_flags="$compile_flags -DSQLITE_DEFAULT_CACHE_SIZE=-8000"
(
    cd "$sqlcipher_source"
    CPPFLAGS="-I$openssl_prefix/include" \
    LDFLAGS="-L$openssl_prefix/lib -lcrypto -mmacosx-version-min=26.0" \
    CFLAGS="$compile_flags" \
    ./configure \
        --disable-tcl \
        --disable-shared \
        --enable-static \
        --dll-basename=libsqlcipher \
        --enable-load-extension \
        --fts3 --fts4 --fts5 --update-limit --rtree --column-metadata \
        --with-tempstore=yes \
        --prefix="$runtime_root/sqlcipher" \
        --includedir="$runtime_root/sqlcipher/include/sqlcipher"
    make -j8
    make DESTDIR="$stage" install
)

tar -xzf "$downloads/sqlcipher3.tar.gz" -C "$build_root"
wrapper="$build_root/sqlcipher3-0.6.2"
(
    cd "$wrapper"
    patch -p1 -F 0 -t < "$recipe_root/patches/sqlcipher3-file-identity.patch"
)
cp "$sqlcipher_prefix/include/sqlcipher/sqlite3.h" "$wrapper/vendor/sqlite3.h"
cp "$recipe_root/downstream-setup.py" "$wrapper/setup.py"
cp "$recipe_root/downstream-pyproject.toml" "$wrapper/pyproject.toml"
cp "$openssl_source/LICENSE.txt" "$wrapper/LICENSE.OpenSSL.txt"
cp "$sqlcipher_source/LICENSE.txt" "$wrapper/LICENSE.SQLCipher-BSD.txt"
cp "$sqlcipher_source/LICENSE.md" "$wrapper/LICENSE.SQLCipher-Community.md"
cp "$sqlcipher_source/SQLITE_LICENSE.md" "$wrapper/LICENSE.SQLite-Public-Domain.md"

builder="$build_root/builder"
"$uv_command" venv --python 3.14 "$builder"
"$uv_command" pip install --python "$builder/bin/python" \
    "build==1.5.0" "setuptools==84.0.0" "wheel==0.48.0"
(
    cd "$wrapper"
    export MEMORY_SQLCIPHER_PREFIX="$sqlcipher_prefix"
    export MEMORY_OPENSSL_PREFIX="$openssl_prefix"
    export CFLAGS="$compile_flags"
    "$builder/bin/python" -I -m build --wheel --no-isolation
)

set -- "$wrapper/dist"/*.whl
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "build produced an unexpected wheel set" >&2; exit 1; }
wheel=$1
[ "$(basename "$wheel")" = "$output_name" ] || { echo "wheel tag drifted" >&2; exit 1; }

unpacked="$build_root/unpacked"
repacked="$build_root/repacked"
mkdir -p "$unpacked" "$repacked"
"$builder/bin/wheel" unpack --dest "$unpacked" "$wheel"
set -- "$unpacked"/memory_sqlcipher3-0.6.2+sqlcipher4.17.0.memory1
[ "$#" -eq 1 ] && [ -d "$1" ] || { echo "wheel unpack drifted" >&2; exit 1; }
unpacked_root=$1
set -- "$unpacked_root"/sqlcipher3/_sqlite3*.so
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "native extension missing" >&2; exit 1; }
strip -x "$1"
"$builder/bin/wheel" pack --dest-dir "$repacked" "$unpacked_root"
wheel="$repacked/$output_name"

verify_venv="$build_root/verify"
"$uv_command" venv --python 3.14 --clear "$verify_venv"
"$uv_command" pip install --python "$verify_venv/bin/python" "$wheel"
extension=$(
    "$verify_venv/bin/python" -I -c \
        'import sqlcipher3._sqlite3 as native; print(native.__file__)'
)
otool_output=$(otool -L "$extension")
printf '%s\n' "$otool_output" | grep -F "/usr/lib/libSystem.B.dylib" >/dev/null
[ "$(printf '%s\n' "$otool_output" | sed '1d' | wc -l | tr -d ' ')" = "1" ] || {
    echo "native extension has an unexpected dynamic dependency" >&2
    exit 1
}
forbidden_paths=$(strings "$extension" | grep -E '/tmp/|/private/|/Users/|/opt/homebrew|Cellar' || true)
if [ -n "$forbidden_paths" ]; then
    printf '%s\n' "$forbidden_paths" >&2
    echo "native extension embeds a disposable or mutable build path" >&2
    exit 1
fi

"$verify_venv/bin/python" -I - "$build_root/synthetic.sqlite3" <<'PY'
import importlib.metadata
import pathlib
import sys

from sqlcipher3 import dbapi2 as sqlcipher

required = {
    "HAS_CODEC", "ENABLE_FTS3", "ENABLE_FTS3_PARENTHESIS", "ENABLE_FTS4",
    "ENABLE_FTS5", "ENABLE_RTREE", "ENABLE_STAT4", "ENABLE_UPDATE_DELETE_LIMIT",
    "SOUNDEX", "USE_URI", "TEMP_STORE=2", "THREADSAFE=1",
    "MAX_VARIABLE_NUMBER=250000", "DEFAULT_PAGE_SIZE=4096",
    "DEFAULT_CACHE_SIZE=-8000", "ENABLE_COLUMN_METADATA",
    "ENABLE_MATH_FUNCTIONS", "ENABLE_PERCENTILE",
    "EXTRA_INIT=sqlcipher_extra_init", "EXTRA_SHUTDOWN=sqlcipher_extra_shutdown",
}
assert importlib.metadata.version("memory-sqlcipher3") == "0.6.2+sqlcipher4.17.0.memory1"
path = pathlib.Path(sys.argv[1])
connection = sqlcipher.connect(path)
connection.execute("PRAGMA key='synthetic-build-key'")
assert tuple(map(str, connection.execute("PRAGMA cipher_status").fetchone())) == ("1",)
assert connection.execute("PRAGMA cipher_version").fetchone() == ("4.17.0 community",)
assert connection.execute("SELECT sqlite_version()").fetchone() == ("3.53.3",)
assert connection.execute("PRAGMA cipher_provider").fetchone() == ("openssl",)
options = {str(row[0]) for row in connection.execute("PRAGMA compile_options")}
assert required <= options, required - options
connection.execute("CREATE TABLE synthetic_record(value TEXT) STRICT")
connection.execute("INSERT INTO synthetic_record VALUES ('synthetic-roundtrip')")
connection.commit()
connection.close()
raw = path.read_bytes()
assert not raw.startswith(b"SQLite format 3\x00")
assert b"synthetic-roundtrip" not in raw
connection = sqlcipher.connect(path)
connection.execute("PRAGMA key='synthetic-build-key'")
assert connection.execute("SELECT value FROM synthetic_record").fetchone() == ("synthetic-roundtrip",)
connection.close()
wrong = sqlcipher.connect(path)
wrong.execute("PRAGMA key='synthetic-wrong-key'")
try:
    wrong.execute("SELECT value FROM synthetic_record").fetchone()
except sqlcipher.DatabaseError:
    pass
else:
    raise AssertionError("wrong key opened encrypted database")
finally:
    wrong.close()
PY

"$verify_venv/bin/python" -I "$recipe_root/verify-file-identity.py"

mkdir -p "$output_dir"
if [ -e "$output" ]; then
    cmp -s "$wheel" "$output" || {
        echo "refused to replace an existing artifact with different bytes" >&2
        exit 1
    }
else
    cp "$wheel" "$output"
fi
digest=$(shasum -a 256 "$output" | awk '{print $1}')
# Retain the hashes of previous immutable release assets.
awk -v digest="$digest" -v path="third_party/wheels/$output_name" \
    '$2 != path { print } END { print digest "  " path }' \
    "$recipe_root/wheel-hash.txt" > "$recipe_root/wheel-hash.txt.tmp"
mv "$recipe_root/wheel-hash.txt.tmp" "$recipe_root/wheel-hash.txt"
openssl_archive_digest=$(shasum -a 256 "$openssl_prefix/lib/libcrypto.a" | awk '{print $1}')
sqlcipher_archive_digest=$(shasum -a 256 "$sqlcipher_prefix/lib/libsqlite3.a" | awk '{print $1}')
extension_digest=$(shasum -a 256 "$extension" | awk '{print $1}')
{
    printf '%s  libcrypto.a (OpenSSL 4.0.1 source build)\n' "$openssl_archive_digest"
    printf '%s  libsqlite3.a (SQLCipher 4.17.0 with memory1 identity patch)\n' "$sqlcipher_archive_digest"
    printf '%s  sqlcipher3/_sqlite3.cpython-314-darwin.so\n' "$extension_digest"
} > "$recipe_root/native-hashes.txt"
printf 'built %s\n' "$output"
printf 'sha256 %s\n' "$digest"
printf 'native sha256 libcrypto.a %s\n' "$openssl_archive_digest"
printf 'native sha256 libsqlite3.a %s\n' "$sqlcipher_archive_digest"
