# memory-sqlcipher3 companion

This directory owns Memory's downstream binary boundary for SQLCipher. The
distribution is named `memory-sqlcipher3` while preserving the upstream
`sqlcipher3` import package. It is not an official Zetetic binary or support
offering.

The artifact is deliberately narrow: CPython 3.14, Apple arm64, and macOS
26.0 or newer. The build downloads only three pinned stable source archives,
verifies their SHA-256 digests, builds OpenSSL and SQLCipher statically with an
intentional compatible SQLite option profile, applies two reviewed downstream
identity patches, and builds the wrapper against that exact generated SQLCipher
header without its stale vendored amalgamation. It verifies the result before
writing a new versioned wheel. Existing artifacts are never replaced by different
bytes.

Companion revision `0.6.2+sqlcipher4.17.0.memory1` adds
`Connection.file_identity() -> tuple[int, int]`. It returns the device and inode
of the main database descriptor owned by SQLCipher's Unix VFS, before any key,
PRAGMA or schema access. It does not reopen a pathname or expose a descriptor.
The method accepts no arguments and works for ordinary, read-only and immutable
on-disk connections. A closed or wrong-thread connection raises the wrapper's
existing `ProgrammingError`; an unavailable main file or busy database mutex
raises `OperationalError`. It does not authenticate database contents or assert
that a pathname still refers to the same inode; the caller compares the returned
identity against its independently authorized file identity.

Run from a clean checkout on the exact environment in `PROVENANCE.md`:

```sh
./third_party/memory-sqlcipher3/build-wheel.sh
shasum -a 256 -c third_party/memory-sqlcipher3/wheel-hash.txt
```

Run the recipe twice and compare both `wheel-hash.txt` and `native-hashes.txt`
before accepting a new release artifact. `source-patch-hashes.txt` binds the exact
downstream patch bytes. The native smoke runs in a disposable directory, including
restored-path replacement, pre-key read-only/immutable access, error behavior,
busy-mutex refusal and preservation of existing SQLite reader locks.

The release unit is a two-wheel wheelhouse: the built Memory wheel and the
committed companion in `third_party/wheels`. A lone Memory wheel cannot locate
an unhosted relative dependency. Source resolution is pinned by
`[tool.uv.sources]`; exact-wheel installation must provide the companion path
or wheelhouse explicitly.

The `licenses/` files are normalized, source-derived convenience copies for
repository review. The build recipe copies the license files directly from the
hash-pinned source archives into the delivered companion wheel, where their
bytes remain exact to those inputs.
