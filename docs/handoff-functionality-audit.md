# Functionality-audit hand-off (Codex-owned files)

## ⚠️ CRITICAL live regression — Harnesses tab bricks the dashboard (uncommitted wake feature)
The uncommitted wake-request work in `HarnessesWindow.xaml.cs` runs its probe on the **UI thread**:
`Loaded` and a 5s `DispatcherTimer.Tick` both call `Refresh()` → `RefreshLiveState()` →
`_getWakeRequests?.Invoke()`, which blocks on the elevated sidecar. Result: switching to the Harnesses
tab **hangs and renders nothing**, `_items` never populates, and because `HasUnsavedChanges()` then
compares an empty row set against persisted `DisabledHarnesses`/`CustomHarnessExes`, every tab switch
fires a false **"You have unsaved changes on the Harnesses tab"** dialog — trapping the user.
**Fix:** run the wake probe OFF the UI thread (`Task.Run` + marshal back via Dispatcher) with a short
timeout, populate `_items` from settings FIRST (independent of wake data), and only overlay wake state
when/if it arrives; treat probe failure as "Wake n/a", never a block. Until then the main-tree build is
unusable — a clean build is running from a `HEAD` worktree as a stopgap (`W:\TOOLS\Foreman-head`).

## ⚠️ HEAD does not build standalone — committed code references an untracked file
`src/Foreman.McpServer/ForemanMcpTools.cs` (committed, `get_audit_route`) references
`AuditRouteResolver`, but `src/Foreman.Core/Alerts/AuditRouteResolver.cs` is **untracked** — so a fresh
checkout of HEAD fails to compile (`CS0246 AuditRouteResolver`). Commit `AuditRouteResolver.cs` (and its
untracked test `tests/Foreman.Core.Tests/Alerts/AuditRouteResolverTests.cs`) so HEAD builds on its own.

---


A functionality/polish audit (2026-06-17) confirmed 25 findings. The 17 in clean files are fixed
(commits `e45b26b`, `7723066`, `e06f809`, `b558fe2`, plus the snake_case tool-name fix `2726421`).
The items below live in **Codex's uncommitted working tree**, so they were left for that branch to
fold in rather than risk clobbering in-progress work. File:line are from the audit; re-confirm before
editing.

## Same-class snake_case tool-name leftovers (the bug fixed in `2726421`)
Two harness-facing sites still name MCP tools in PascalCase (the server registers snake_case, so a
harness that follows them calls a nonexistent tool):
- `src/Foreman.App/App.xaml.cs` ~L592 / L606 — escalation + audit prompt text: `ReplyToAskHarnessRequest(...)` → `reply_to_ask_harness_request(...)`.
- `src/Foreman.App/Windows/AlertDetailWindow.xaml.cs` L145, L283, L329, L330 — operator-facing "the harness can reply with `ReplyToAskHarnessRequest` / `ListAskHarnessRequests`" → snake_case.

## High — dead settings (UI knob that does nothing)
- **`HookJamThresholdMinutes`** (`ForemanSettings.cs:13`, dup `HarnessProfile.cs:81`, README `Configuration` row, SettingsWindow load/validate/save): no detector reads it — `HangDetector` only uses `HangThresholdMinutes` and has no concept of a hook. The whole upstream is dead too: `ClaudeSettingsReader.TryRead` is never called and `HookCommands` is never consumed. **Recommend: remove** the knob + README row + both fields (and the `<see cref>` in the `HangThresholdMinutes` xmldoc), unless you want to build process→hook-child attribution (`IsHookChild` on `ProcessRecord`, populated in the tree tracker, then branch in `HangDetector.Check`). `ProcessLimitsConfig.HangThresholdMinutes` (`HarnessProfile.cs:78`) is likewise unread — dead per-profile knob.
- **`AlertSuppressWindowMinutes`** (`ForemanSettings.cs:29`, SettingsWindow load/validate/save): read nowhere. Superseded by `HangRealertCooldownMinutes` (per-process hang re-alert cooldown) + `AlertCadenceGovernor` (burst coalescing). **Recommend: remove** the knob + field. (Audit note: it is NOT in `SettingsSeal`, so no seal change needed.)

## Medium
- **OS-event-log default-on vs precondition** (`App.xaml.cs:300`, `IOsEventLogSink.cs:27`): `OsEventLog.Enabled` defaults true, but the 'Foreman Agent Safety' event source is only registered by the elevated ETW sidecar / Guardian — both default off. So on a default install the blackbox handoff silently no-ops. **Recommend:** register the source at install / a one-time elevated step (decoupled from the network/decoy sidecar), or default `Enabled=false` and auto-enable once the source is present. Surface `UnavailableReason` (already populated) in `/health` or a doctor view. Avoid an unsolicited UAC prompt on normal launch.

## Low
- **`LlmTriage.MaxEventsPerReview`** (`ForemanSettings.cs:284`) is echoed to agents by `list_audit_preferences` (`ForemanMcpTools.cs:616`) as a cap but is never enforced (no audit path gathers an events window). Stop advertising it, or enforce it where the scheduled-audit dispatch builds its prompt.
- **`SendTestAlert`** (`TrayController.cs:512-513`) recommends "double-click the log row" — the row opens on a single click. Change to "click the log row". (Matches the LogWindow footer fix already landed.)
- **Foreman.Platform / Foreman.Platform.Linux** seam compiles but no shipping project references it (only each other + their test project). Wire `Foreman.Monitor` to consume it via `IProcessSnapshotProvider`/`IProcessEventSource`/`IProcessIoReader` (runtime-select the Linux impls on non-Windows), or exclude both from the release artifact until consumed. NOTE: this is NOT the OS-event-log "cross-platform seam" (task #65) — that one is a separate, live Core seam (`IOsEventLogSink`/`OsEventLogForwarder`/`WindowsEventLogSink`).

## task #56 — Scheduled cross-harness model audit is built but never runs
`ScheduledAuditPolicy.DueAudits` + `ScheduledAuditSettings` (`ForemanSettings.ScheduledAudit`) are
complete and unit-tested, but nothing ticks them: no timer, no dispatch, no Settings UI, so toggling
`ScheduledAudit.Enabled` in settings.json does nothing. The runtime wiring belongs in `App.xaml.cs`
(Codex-owned), hence the hand-off. **Shape:** add one `PeriodicTimer` loop (model on
`RunAskHarnessReaperAsync`); each tick early-return if `!Enabled`, else build a `HarnessAuditState` per
monitored harness (last-audit time, events-since, recent-activity) from data the runtime already tracks,
call `ScheduledAuditPolicy.DueAudits(now, settings.ScheduledAudit, states, pickAuditor)`, and dispatch
each due audit through the **existing** reactive Ask-Harness/adversarial-audit path (don't invent a new
one). Verify the real auditor-selector API before coding (the audit assumed `LlmTriage.SelectAuditor`).
Route through the existing mute/presence-lock/cadence guardrails. Then surface the toggle in Settings.
