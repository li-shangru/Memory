# Relocate the notes root

Treat relocation as owner-requested maintenance. Stop the owner UI and every
connected Memory client; run `status` and require configuration with no active
transaction.

Require an absent destination, then run `relocate` with the exact absolute
destination root.
This durable no-copy root/Inbox transition carries `.obsidian` opaquely and
must return `relocated`, `recovered`, or `current`.

If `status` reports `notes_root_changed`, stop. Only after the owner explicitly
confirms the configured path as intended authority and Memory resolves its exact
`04_Inbox` child, choose:

- Keep it: run
  `relocate --to <same exact absolute path> --adopt-current-authority`.
  It validates layout and Memory binding, atomically adopts current root and
  Inbox identities, moves nothing, never runs Memory Inbox relocation, and
  must return `current`.
- Move elsewhere: require a different absent destination and add the flag
  to the ordinary relocation command. The helper adopts the confirmed
  authority before the durable move.

After success, rerun `status` before reading `02_Staged`; restart clients. If
interrupted, rerun the exact same `relocate` command and destination. A pending
relocation blocks every other helper command.
Never rename the configured root in Finder, use a raw filesystem move,
create a symlink, edit either private configuration, inspect a workflow
child, invent owner confirmation, or use the flag for an unexpected path
or layout.
