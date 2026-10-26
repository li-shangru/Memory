# Companion wheel distribution

Wheel binaries are assets of the
[vendored-wheels-1 GitHub Release](https://github.com/li-shangru/Memory/releases/tag/vendored-wheels-1),
outside the Git tree and published branch/tag history. Source recipes, patches, provenance, licenses,
and SHA-256 manifests stay in this directory.

After cloning, run from the repository root:

```sh
python3 third_party/fetch-wheels.py
uv sync --locked
uv build --wheel
./tools/check.sh --source-only
```

An unpacked complete source archive supports the same fetch, sync, and build
commands. Run source qualification from a Git clone: the suite also checks Git
tracking and repository boundaries, which require `.git` metadata.

Python 3.14 and uv are required; the wheels support macOS 26+ on Apple arm64.
Fetching uses only Python's standard library and needs no project environment.
It downloads all three assets into the ignored `third_party/wheels/` cache:

- the current SQLCipher companion used by Memory;
- the previous immutable SQLCipher companion retained for reproducibility;
- the Playwright companion used for browser testing.

The command verifies every entry in `memory-sqlcipher3/wheel-hash.txt` and
`playwright/wheel-hash.txt`. Valid cached files need no network access. Invalid
cached files are downloaded again; network errors or mismatched hashes fail the
command and remove temporary downloads. A wheel replaces its cached destination
only after verification. Rerun the same command after a failed transfer.

To verify cached files independently:

```sh
shasum -a 256 -c third_party/memory-sqlcipher3/wheel-hash.txt
shasum -a 256 -c third_party/playwright/wheel-hash.txt
```

For reproducible source builds, follow the exact environments and recipes in
[SQLCipher](memory-sqlcipher3/README.md) and [Playwright](playwright/README.md).
Existing Release assets and their pinned hashes are immutable identities. Publish
changed bytes under a new artifact version and a new Release tag, then update
the fetch URL, manifests, dependency pins, and affected provenance together.
