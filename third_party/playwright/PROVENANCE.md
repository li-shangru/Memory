# Provenance

The downstream wheel is a versioned asset on the
[vendored-wheels-1 Release](https://github.com/li-shangru/Memory/releases/tag/vendored-wheels-1).
It is absent from the Git tree and published branch/tag history. From the repository root, run
`python3 third_party/fetch-wheels.py` before building or testing; the command
verifies `wheel-hash.txt` and populates the ignored `third_party/wheels/` cache.
Recipes, this provenance, licenses, and hash manifests remain in Git.

- downstream distribution: `playwright==1.62.0+memory.1`
- downstream artifact: `playwright-1.62.0+memory.1-py3-none-macosx_26_0_arm64.whl`
- upstream artifact: `playwright-1.62.0-py3-none-macosx_11_0_arm64.whl`
- upstream URL: `https://files.pythonhosted.org/packages/af/1a/0bfbe9904350961f4dbb713f04342e40d548c5fc26c8157bd13617c81492/playwright-1.62.0-py3-none-macosx_11_0_arm64.whl`
- upstream SHA-256: `db755ab27db21a04186f1fe8169888e42356086e439b1059b923ef417f0b6034`
- upstream signed tag/source commit: `3b7c24c3e67dc84f7b0eddd0c5fd2ca685705021`
- upstream tag archive SHA-256: `30cc72a0c00a22c3d287539233d3d6abd579becbfe7d02aef80bd3e75c951455`
- license: Apache-2.0, exact upstream wheel bytes in `LICENSE`
- deterministic downstream SHA-256 (two consecutive recipe runs):
  `ab2da760f37867fa775bf565f2fa3d8c59f2d414bf4dc553879f9053c6c1824a`

PyPI publishes no Playwright 1.62.0 sdist. The executable recipe starts from
the exact official macOS arm64 wheel and makes only these metadata changes:

1. version `1.62.0` becomes `1.62.0+memory.1`;
2. `pyee>=13,<14` becomes `pyee>=14,<15`;
3. the internal WHEEL tag becomes `py3-none-macosx_26_0_arm64`, matching
   Memory's explicit macOS 26 arm64 release floor;
4. the dist-info directory is renamed and RECORD regenerated.

The recipe verifies a stable aggregate hash for all 181 non-dist-info files,
compares every one byte-for-byte to the upstream artifact, preserves Unix
executable modes, the official entry points, LICENSE, NOTICE, and
ThirdPartyNotices, installs with pyee 14.0.0, runs `uv pip check`, and invokes
the installed CLI. It also reads the bundled Node executable's
`LC_BUILD_VERSION`, pins its upstream minimum to 13.5, and rejects a minimum
above the declared macOS 26.0 floor. Memory's full browser journeys provide
the launch and rendered-product proof.

The deterministic packer is CPython 3.14.7's standard-library `zipfile`, not
the `wheel` package. It sorts members, preserves upstream timestamps and mode
metadata, and uses a fixed compression level. That deliberately produces a
different container digest than the independent wheel-0.47 reference
(`0af4f9c8...`) while the asserted allowed payload bytes are identical. The
recipe pins current stable uv 0.12.5 and exact CPython 3.14.7, which owns the
archive implementation.
