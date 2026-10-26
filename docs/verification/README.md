# Verification

Different checks support different claims. See the
[current source receipt](../acceptance/v1.13.0-acceptance.md) for the public
distribution's recorded checks.

| Claim | Procedure |
| --- | --- |
| Synthetic source behavior, including browser journeys | `./tools/fast-check.sh` and `./tools/check.sh --source-only` |
| Fresh wheel and MCP protocol behavior | `./tools/smoke-wheel.sh` |
| Fresh wheel's local UI launches and stops | `./tools/smoke-ui.sh` |
| A selected everyday installation matches source | Optional [local delivery](../local-delivery.md) |
| A real client's retrieval and review behavior | [Installed-client smoke](../client-setup.md#installed-client-smoke) |
| Repeated model-answer behavior | [Synthetic client ceremonies](../smoke-ceremony.md) |

The automated suite includes simulated owner-presence adapters. Passing it does
not prove that a human completed a system prompt, that an existing client loaded
a new version, or that model answers meet a quality benchmark. Those need separate
observations. All development verification uses new synthetic content and isolated
runtimes; do not use personal Stores as test fixtures.

Use [client smoke notes](../acceptance/client-smoke.md) and
[owner UI notes](../acceptance/v1-acceptance.md) as blank recording templates.
Copy them to a private location outside the checkout before use, and leave the
tracked templates unexecuted. Keep all completed trial records outside Git.
Source fixtures describe authored test
cases and expected contracts; they are not observations of client answers or
evidence that a model passed a campaign. The current source excludes inherited
client trial records and personal installation results. This statement describes
the current tree, not earlier commits, release assets, or downloaded copies.
