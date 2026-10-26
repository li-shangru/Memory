# Playwright dependency companion

Memory owns this metadata-only downstream wheel because stable Playwright
1.62.0 still caps pyee below stable pyee 14.0.0. The distribution keeps the
official `playwright` name, import package, code, driver, and CLI; its local
version changes only package metadata needed to allow `pyee>=14,<15` and to
describe the bundled arm64 Node binary honestly.

For normal setup, run `python3 third_party/fetch-wheels.py` from the repository
root. It downloads this companion from the versioned
[Release](https://github.com/li-shangru/Memory/releases/tag/vendored-wheels-1)
and verifies `wheel-hash.txt`; binaries are kept in an ignored local cache.

To reproduce the artifact, run the recipe twice and compare `wheel-hash.txt`
before publishing any new versioned Release asset:

```sh
./third_party/playwright/build-wheel.sh
shasum -a 256 -c third_party/playwright/wheel-hash.txt
```

This is a development and browser-test dependency. It is not shipped in the
Memory product wheel or installed product dependency graph.
