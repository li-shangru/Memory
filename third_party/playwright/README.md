# Playwright dependency companion

Memory owns this metadata-only downstream wheel because stable Playwright
1.62.0 still caps pyee below stable pyee 14.0.0. The distribution keeps the
official `playwright` name, import package, code, driver, and CLI; its local
version changes only package metadata needed to allow `pyee>=14,<15` and to
describe the bundled arm64 Node binary honestly.

Run the recipe twice and compare `wheel-hash.txt` before replacing the committed
artifact:

```sh
./third_party/playwright/build-wheel.sh
shasum -a 256 -c third_party/playwright/wheel-hash.txt
```

This is a development and browser-test dependency. It is not shipped in the
Memory product wheel or installed product dependency graph.
