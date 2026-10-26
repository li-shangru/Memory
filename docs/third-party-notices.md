# Third-party components

The root [MIT license](../LICENSE) applies to original Memory code and
documentation. Third-party code and binaries keep their own copyright notices
and licenses; the project license does not relicense them.

## Committed SQLCipher companion

The runtime uses `memory-sqlcipher3` 0.6.2+sqlcipher4.17.0.memory1, a downstream
build of the sqlcipher3 Python wrapper, SQLCipher, and OpenSSL. It is not an
official Zetetic binary or support offering.

- [Build recipe and interface](../third_party/memory-sqlcipher3/README.md)
- Pinned source URLs, hashes, and build environment: `PROVENANCE.md` in the
  [companion directory](../third_party/memory-sqlcipher3/).
- [Source-derived license texts](../third_party/memory-sqlcipher3/licenses/)

The wheel itself includes source-derived license files. The earlier companion
wheel is retained for synthetic compatibility tests, with its own unchanged
notices. Neither wheel is covered solely by Memory's MIT license.

## Committed Playwright companion

Development uses Playwright 1.62.0+memory.1, a metadata-only adaptation of the
upstream arm64 wheel. Its code, Node driver, and bundled notices are preserved.
It is not a product runtime dependency.

- [Recipe and scope](../third_party/playwright/README.md)
- [Apache 2.0 license](../third_party/playwright/LICENSE)
- [Wheel digest](../third_party/playwright/wheel-hash.txt)

The bundled Node executable contains build paths beneath the upstream `admin`
account's `build/ws` directory. These belong to the upstream artifact, not a
Memory user. The exception is bound to member `playwright/driver/node` SHA-256
`f480e325ee0ca9cb9eef00b5ca6057a2a104807a1b073f1bc373a55c67facff5`
and wheel SHA-256
`ab2da760f37867fa775bf565f2fa3d8c59f2d414bf4dc553879f9053c6c1824a`.
The wheel is preserved byte-for-byte; see its build recipe's code-tree
hash rather than treating these strings as a local installation inventory.

## Other dependencies

`pyproject.toml` declares runtime and development dependencies; `uv.lock` pins
their source artifacts. uv downloads them separately. Their installed package
metadata and notices govern reuse and redistribution. Retain those notices
when distributing a combined environment or additional binaries.
