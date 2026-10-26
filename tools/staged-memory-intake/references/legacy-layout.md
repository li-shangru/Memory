# Migrate legacy folder names

If `status` reports `layout_migration_required`, stop the owner UI and every
connected Memory client. Run `migrate-layout` with no path argument. It changes
only exact legacy Pending, Staged, Prepared, and Inbox labels to `01_Pending`,
`02_Staged`, `03_Prepared`, and `04_Inbox`, rebinds Memory, and preserves every
directory identity. Require `migrated`, `recovered`, or `current`; restart
clients.

If interrupted, rerun the same `migrate-layout` command. A
`layout_migration_pending` result blocks every other helper command. Never
rename these folders in Finder or use a raw filesystem rename. Never create
aliases or symlinks. Never edit either private configuration. Never inspect or
enumerate a workflow child during migration. Stop on collision, mixed layout,
changed identity, or unsafe permission.
