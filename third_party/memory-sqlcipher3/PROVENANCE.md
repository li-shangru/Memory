# Provenance

Both downstream companion wheels are versioned assets on the
[vendored-wheels-1 Release](https://github.com/li-shangru/Memory/releases/tag/vendored-wheels-1),
outside the Git tree and published branch/tag history. From the repository root, run
`python3 third_party/fetch-wheels.py` before building or testing; it verifies
both entries in `wheel-hash.txt` and populates the ignored `third_party/wheels/`
cache. Source recipes, patches, this provenance, licenses, and manifests stay in Git.

Artifact identity:

- distribution: `memory-sqlcipher3`
- version: `0.6.2+sqlcipher4.17.0.memory1`
- import package: `sqlcipher3`
- tag: `cp314-cp314-macosx_26_0_arm64`
- runtime: SQLCipher 4.17.0 / SQLite 3.53.3 / OpenSSL 4.0.1

Pinned sources:

| Source | URL | SHA-256 |
| --- | --- | --- |
| sqlcipher3 0.6.2 | `https://files.pythonhosted.org/packages/ae/c1/414003d77549c444bafd636149ab3ace6f4e2cb4666c9955d54ad62096cb/sqlcipher3-0.6.2.tar.gz` | `a2b675289ba8889f389625a21f3a01f1ff159a551b5b88fba8fd92da0e02380a` |
| SQLCipher 4.17.0 | `https://github.com/sqlcipher/sqlcipher/archive/refs/tags/v4.17.0.tar.gz` | `79c0e164b9c059e7487bf8f29272f601cca5f3312cc267461f81e349962a5058` |
| OpenSSL 4.0.1 | `https://github.com/openssl/openssl/releases/download/openssl-4.0.1/openssl-4.0.1.tar.gz` | `2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09` |

Pinned build environment:

- macOS 27.0, build 26A428, Apple arm64
- Xcode 27.0, build 27A266a
- Apple clang 21.0.0 (`clang-2100.3.34.2`)
- CPython 3.14.7
- uv 0.12.17 (`635500036 2026-09-18 aarch64-apple-darwin`)
- build 1.5.0, setuptools 84.0.0, wheel 0.48.0
- deployment target 26.0

Deterministic `memory1` outputs (two consecutive clean recipe runs):

| Output | SHA-256 |
| --- | --- |
| companion wheel | `3436966d149f0e498f69aa78612bc8be2b9c8340fa44c5fb3f4cc50c5ddf2106` |
| `libcrypto.a` | `22671fb69c5cff130664d2ce594451411aa7ee86a90697b9b9c2c3f6861724ef` |
| `libsqlite3.a` | `a1b27ceed551e78ac47e442e8efd9208c42f2cc94fa2fa02a809cfe5069beb02` |
| `sqlcipher3/_sqlite3.cpython-314-darwin.so` | `516c034b2768458ae97c910d2545e42131119b47f0ef80cd009d58b36c0cf53f` |

Previous immutable artifact `0.6.2+sqlcipher4.17.0` remains available on that Release.
Its two-build evidence used macOS 26.6.1 build 25G76, Xcode 26.6 build 17F113,
Apple clang 21.0.0 (`clang-2100.1.1.101`), CPython 3.14.7, uv 0.12.5, and the
same pinned Python build tools and deployment target. Its unchanged hashes are:

| Output | SHA-256 |
| --- | --- |
| companion wheel | `ad7e1fcd20de2d7cf94da8fb5a56962f77a941bd46326e9501daf6a0e6011f11` |
| `libcrypto.a` | `c24211131d8ece9182502f82a3addfde1f6a49cd65e015f22edd6524a762fbd4` |
| `libsqlite3.a` | `e3dd4f9a874c0c7257c17cad3b0f3055db1ad2e1c0c7265dbdd04ade1e5241c3` |

`build-wheel.sh` is the executable record of configure flags. SQLCipher is
built from source with the previous wrapper's FTS, RTREE, STAT4, URI, cache,
and variable-limit capabilities preserved, plus current 4.17 column metadata,
math, percentile, and extra init/shutdown support. OpenSSL and SQLCipher use a
stable configured prefix with `DESTDIR` staging; the final extension embeds no
personal, temporary, Homebrew, or Cellar path and `otool -L` reports only
`/usr/lib/libSystem.B.dylib`.

The one downstream OpenSSL source rewrite replaces its runtime
compiler-description string with a pointer to this provenance. The strict
rewrite fails unless the exact expected upstream assignment occurs once;
OpenSSL otherwise embeds the full compiler command, including the necessarily
disposable source path used by the path-remapping flags. The actual compiler
identity, flags, source hash, native archive hash, and environment remain
recorded here and in the executable recipe.

The final artifact digest is recorded in `wheel-hash.txt`; deterministic static
archive digests are recorded in `native-hashes.txt`. The recipe additionally
proves distribution identity, exact engine/provider versions, compile options,
encrypted read/write, absent plaintext marker/header, and wrong-key refusal.


## Downstream main-file identity extension

`patches/sqlcipher-file-identity.patch` adds private file-control opcode
`SQLITE_FCNTL_MEMORY_FILE_IDENTITY` (`0x4d454d01`) and its two-uint64 result
structure to the generated SQLCipher header. Its implementation lives inside the
owning Unix VFS and calls `osFstat(pFile->h, ...)`, the VFS's native fstat syscall,
to return only the regular main file's device and inode. Failure returns
`SQLITE_IOERR_FSTAT` or `SQLITE_NOTFOUND`; no pathname is resolved and no file
descriptor is opened, closed or exposed by the operation.

`patches/sqlcipher3-file-identity.patch` adds the zero-argument Python method
`Connection.file_identity()`. Existing initialized/closed/thread checks run first.
The method holds the GIL and tries the database's recursive mutex without waiting,
then uses the public `sqlite3_file_control(db, "main", opcode, &result)` API. This
prevents a callback on a concurrent shared connection from deadlocking while it
needs the GIL. A busy mutex or unsupported/failed file control raises a
content-free `OperationalError`; success returns two Python integers. It performs
no SQL and works before a key is supplied. The recipe replaces the wrapper's
explicitly included vendored header with the exact generated patched SQLCipher
header, matching the linked static archive.

The upstream source archives, SQLCipher/SQLite/OpenSSL engine versions and crypto
parameters are unchanged. Both downstream source patches are hash-bound in
`source-patch-hashes.txt` and applied without fuzz. They are maintained Memory
extensions, not upstream API claims. `verify-file-identity.py` is a native smoke independent
of the Memory package using fresh synthetic files and no Keychain access.
