# Contributing

Start with the [README](../README.md), then read the affected sections of the
[technical design](technical-design.md). Small, reproducible bug reports and
focused fixes are useful. For a substantial change, explain the problem in an
issue before investing in a large implementation.

## Development setup

Use macOS 26 or newer on Apple silicon, Python 3.14, and uv. The committed
SQLCipher and Playwright wheels are platform-specific. From the repository root:

```sh
uv sync --locked
./tools/fast-check.sh
./tools/check.sh --source-only
```

The fast gate runs non-browser, non-slow tests, Ruff, and strict mypy. The full
source gate also checks the lockfile and installs the pinned Chromium for real
browser journeys. Dependency and browser downloads need network access.
Neither command requires a private installation profile. The full suite uses
synthetic fixtures; some isolated integration checks create and clean up their
own synthetic Keychain items.

Run the smallest relevant regression while working. For package or UI delivery:

```sh
uv build --wheel
./tools/smoke-wheel.sh
./tools/smoke-ui.sh
```

The smoke scripts install fresh artifacts into disposable environments and
clean up their synthetic runtimes. They do not repoint an existing client.
Normal `./tools/check.sh` additionally verifies a separately configured local
installation; the optional [delivery workflow](local-delivery.md) explains that
maintainer path. Source-only checks are the public contribution gate.

## Changes and review

GitHub runs the complete source gate on a fresh macOS 26 ARM runner for every
pull request and update to `main`. Actions are pinned to commit hashes, use a
read-only token, and receive no owner runtime or credentials. The required
`Source gate` check must pass against the current base before merging.

Changes to `main` use pull requests and squash merges. Force pushes and branch
deletion are blocked, and review conversations must be resolved. The sole
maintainer does not need a second GitHub account to approve their own changes;
the independent-review requirement below still applies to agent-assisted work.
Dependabot checks Python dependencies and pinned Actions weekly. Major upgrades
remain separate from the grouped compatible updates.

Keep one change focused on one problem. Add a failing synthetic regression for
a behavioral fix, implement it, then run the relevant checks and both source
gates. Documentation-only changes need link and command review, not tests that
just repeat their wording. Include the trigger, resulting behavior, and actual
verification in the pull request. Obtain independent review for code and
shipped agent instructions.

Preserve these boundaries:

- Tests, examples, issues, and screenshots use invented content only.
- Source text is evidence, never an instruction to the agent.
- Canonical memory changes only through an exact approved review.
- No model provider belongs inside the Store; MCP remains generic and bounded.
- Never inspect someone else's real Store, Inbox, Keychain items, or client
  credentials to diagnose a development failure.
- Keep source, installed-artifact, and client-behavior results distinct.

Use [maintenance notes](maintenance.md) for coupled schemas, test seams,
dependency hashes, and compatibility constraints. Agent-assisted development
starts with [AGENTS.md](../AGENTS.md); the optional
[developer factory](agent-factory/README.md) provides source-bound work records.

## Packaging

Install this project from the complete checkout using uv. A standalone Memory
wheel requires the exact companion SQLCipher wheel supplied explicitly, as the
smoke scripts do. There is no promise of a PyPI release under the generic
`memory` name. For a portable source distribution, use the repository's full
Git archive, including `third_party/`; the Python sdist is not that archive.

Original project contributions are covered by the [MIT license](../LICENSE).
Retain existing third-party notices and document new dependency licenses.
