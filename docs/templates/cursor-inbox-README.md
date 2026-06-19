# Cursor external inbox

Drop a short task here to wake the Cursor agent without opening a chat.

## How to trigger

Create a file with extension `.md`, `.txt`, or `.msg`:

```text
.cursor-inbox/check-deploy.md
```

Example content:

```markdown
# Task
Run `git status` in Foreman and summarize uncommitted changes.
```

The agent (or the inbox poll loop) picks it up, acts, then moves the file to `processed/`.

## Other triggers

| Method | Who | Notes |
|--------|-----|-------|
| **This folder** | You, scripts, CI | Works with local `/loop` and Cursor Automations on this repo |
| **Foreman mailbox** | Codex, Claude, operator via `request_harness_review(targetHarnessId: "cursor", …)` | Needs Foreman tray running; local poll uses `--probe` |
| **Cursor Automation webhook** | Any HTTP client | See `Foreman/docs/cursor-external-wake.md` |

## Processed archive

Handled files go to `.cursor-inbox/processed/` (create if missing). Delete old ones anytime.
