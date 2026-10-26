# Security and privacy

Memory keeps retained content in a local SQLCipher-encrypted Store. Its master
key is held in macOS Keychain. This describes the design boundary, not a claim
of independent security certification.

## What you authorize

- A connected MCP client can read retained sources and approved memory at all
  sensitivity levels. Captured sources can be read before their proposed
  memories are approved. Connect only trusted clients.
- The default write flow requires approval of an exact review revision through
  macOS owner presence. The optional `--trust-elicitation` configuration changes
  that trust boundary; leave it off unless you understand and trust the client's
  approval surface.
- The Store does not call a model service. Your connected client may transmit
  retrieved content to its provider according to that client's configuration.
- Sensitivity tags describe content. They do not isolate clients or prevent a
  trusted client from reading restricted material.

## Retention and backups

Inbox capture takes custody and removes the captured Inbox file. Use copies.
Sources and correction history are append-only. There is no individual hard
forget, redaction, or source-deletion feature; start a new Store to omit content.

Keep the Store on a local, private directory. Do not put its database in a
synced folder. A copied database alone is not a recoverable backup: the matching
macOS Keychain item is also required. There is no bundled backup/restore or
cross-machine migration tool. See the [owner guide](owner-guide.md#19-backing-up-the-store-and-moving-it-to-another-mac).

An owner-authenticated JSON export contains plaintext sources and records from
all sensitivity levels. Protect the exported file separately. It is not an
encrypted backup or an importable restore format. See [export scope](export-format.md).

## Threat boundary

The UI binds to loopback, uses short-lived session state, and authenticates
approval through macOS. These controls do not protect against malware already
running as your macOS account or a compromised browser profile. An assistant
can still reason incorrectly or fail to retrieve relevant evidence. Inspect
important conclusions against the originals.

Runtime, approval, and UI contracts are specified in the
[technical design](technical-design.md). Tests use disposable synthetic content;
they do not establish immunity from security defects or model prompt injection.

## Reporting a problem

The dependency declarations include security floors for the MCP SDK and its
HTTPX2, PyJWT, and OpenTelemetry dependencies. The lockfile fixes the tested
versions. Dependabot monitors both Python dependencies and GitHub Actions;
dependency changes must pass the source gate before merging. A green test run
does not substitute for reviewing an advisory or establishing its applicability.

For ordinary bugs, open a repository issue with:

- `memory --version`, macOS version, and processor architecture;
- a minimal reproduction using newly invented notes;
- expected and observed behavior, including bounded error codes.

Do not attach Store databases, Keychain material, personal notes, full exports,
authentication links, client configuration containing credentials, or raw
conversation transcripts. Review screenshots for sensitive content first.

For a suspected vulnerability, use GitHub's private **Report a vulnerability**
option if it is enabled. If no private channel is available, open a content-free
issue asking for a private reporting channel; withhold exploit details and
personal data until one is provided.
