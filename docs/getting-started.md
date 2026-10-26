# Your first memory

This walkthrough uses fictional notes so you can understand the workflow before
importing personal material. It assumes you have installed the command from
the repository as described in the [README](../README.md#get-started).

## 1. Create a separate demo Store

Choose a new local directory outside the checkout and outside synced folders.
Use a real directory path; initialization refuses symlinked ancestors. This
example keeps the demo separate from the default personal Store:

```sh
MEMORY_DEMO_HOME="$HOME/MemoryDemo"
memory init --home "$MEMORY_DEMO_HOME"
memory ui --home "$MEMORY_DEMO_HOME"
```

Keep that terminal open. In a second terminal, set `MEMORY_DEMO_HOME` to the
same path. The command creates an encrypted Store and a new macOS Keychain
item. If the directory already contains unrelated files, choose a new name.

## 2. Connect your agent to the demo

```sh
MEMORY_DEMO_HOME="$HOME/MemoryDemo"
memory mcp config --home "$MEMORY_DEMO_HOME" --format json
# Or use --format toml for a TOML client.
```

Follow [client setup](client-setup.md#connect-a-client-for-everyday-use) to add
the entry and, where supported, the `using-memory` Skill. Preserve the generated
`--home` argument. If a client already has a Memory connection, use a separate
client profile/workspace rather than replacing that connection for a demo.
Restart the client and check that its connection is available.

## 3. Add one fictional note

In the local UI, choose **Inbox** and upload a text file containing:

```text
SYNTHETIC DEMONSTRATION — these are invented facts.
For the demo project, Mira chose a weekly written update because the team
works across time zones. Mira wants to revisit this choice on 2030-06-15.
```

Keep another copy outside the Inbox. Scanning moves captured files into the
Store and removes them from the Inbox; deleting a proposed memory later will
not remove the captured original.

Ask your connected agent:

> Process the Memory Inbox and draft one review for this batch. Keep the
> reason for the decision and the revisit date, with their source evidence.

The model may propose different wording or more than one item. Check its
meaning against your note. A sealed source is already retained and readable;
approval governs whether the interpretation becomes canonical memory.

## 4. Review and approve

Open **Pending Reviews** in the local UI. Inspect each proposed item and its
source. Edit or reject incorrect proposals. Approve only the final revision
you want to retain; the default flow requires macOS owner authentication.
All approved changes in that review apply together, or none do.

Typing an approval into chat does not satisfy the default authentication
requirement. If you cancel the system prompt, the dependent action stops.

## 5. Ask a new question

In a new conversation with the same connection, ask:

> Why did Mira choose written updates for the demo project, and when should
> that choice be revisited? Cite the retained source.

Compare the answer with the source in the UI. You should be able to inspect
the approved memory, its evidence, and the original text. Exact model wording
is not guaranteed; retrieval and reasoning remain the agent's responsibility.

## 6. Correct a detail

Open the memory in the UI and capture a correction note with a new fictional
date. The UI seals a separate correction batch. Give that batch to your agent
for a new review, then inspect and approve it. The successor becomes current;
the old revision and original source remain in history.

## Stop or continue

Press Ctrl-C in the UI terminal to stop the server. This does not delete the
Store or its key. Remove the demo connection from your client if you no longer
need it. Keep the demo Store separate from any personal Store.

There is no automatic demo teardown or individual hard-delete command. Before
using personal content, read the [retention and backup limits](security.md).
Uninstalling the command with `uv tool uninstall memory` does not erase a Store.
