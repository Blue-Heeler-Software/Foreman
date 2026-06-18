# Handoff: responsiveness audit + restart/integrity follow-ups (2026-06-19)

Captured because the high-value items are **blocked by the Bitdefender quarantine pin** on
`Foreman.Monitor`'s build-output path (clear it — folder exclusion + delete the quarantine entry / reboot —
to rebuild `Foreman.Monitor` and `Foreman.App`). McpServer/Core changes build + test independently of the pin.

## A. Responsiveness audit (read-only audit; no code changed)

1. **Stale monitored-process volume is the biggest drag.** Live Foreman reported ~8,692 monitored processes vs
   ~386 actually on the box — the tree accumulates terminated processes without pruning. Hot path:
   `ProcessTreeTracker.GetAll()` → `ForemanState.ProcessCount`, dashboard snapshots, process-monitor refreshes,
   `IoPoller`. **Fix = a reconciliation/prune pass** (periodically compare tracked PID+start-time to the OS live
   set; evict records that no longer exist; keep terminated/orphan evidence in the event log, not the hot
   snapshot). **Lives in `Foreman.Monitor` — AV-pin-blocked.** Short-term mitigation: a fresh Foreman restart
   clears the oversized in-memory tree (rebuilds from live WMI); it re-accumulates until the prune lands.
2. **Dashboard opens every heavy tab at once** — `TrayController.cs:493` constructs ProcessMonitor/Harnesses/
   BehaviorMetrics/Log windows (and their timers) on dashboard open. **Lazy-create tabs; start timers only when
   visible.** App-side.
3. **UI timers do expensive work on the dispatcher** — DashboardWindow:215, ProcessMonitorWindow:38,
   HarnessDetailWindow:61, BehaviorMetricsWindow:48 rebuild live views (sort, per-harness lookups, full
   ItemsSource replace) on dispatcher timers. App-side.
4. **Resource sampling on the UI thread** — `ResourceSampler.cs:28` (GPU counter enum at :98 is worst). Move to a
   background `UiTelemetryCache`; WPF renders the latest completed sample. App-side.
5. **EventBus subscribers run synchronously** — `EventBus.cs:42` invokes sinks on the publisher thread; JSONL
   append (App.xaml.cs:176), hash-chain (EventLogStore.cs:122), Windows Event Log (WindowsEventLogSink.cs:55) add
   latency during alert bursts. **Bounded background audit writer, preserving ordering + hash-chain integrity +
   failure alerts.** `EventBus` is in Core (buildable) BUT the change is delicate (ordering/integrity) and spans
   App — do it with the rest of the pass so it can be integration-tested, not piecemeal.

**Plan when unblocked:** `LiveSnapshotCache` (one background producer builds AllProcesses/ByHarness/
RunningHarnessIds/usage every 1-2s; UI reads immutable snapshots) + process reconciliation/prune + lazy tabs +
background telemetry (slow/skip GPU reads over a latency budget) + debounced UI refresh (one pending dispatcher
refresh, coalesced ~250-500ms) + async ordered audit writer + async Log-tab hydration. None weakens detection.

## B. "restart to link" is misleading (the recurring restart frustration)

Verified: tokens are valid (Cursor's MAC matches the live secret; secret unchanged since 9 June; no auth errors).
A harness only flips to "linked" when it makes an authenticated MCP call; these clients connect lazily (on first
tool use), so a configured harness shows "restart to link" forever until it actually invokes a `foreman_*` tool —
**restarting doesn't help.** Fix (App): reword to e.g. *"configured — links on first Foreman tool call"*, and/or
count the MCP `initialize` handshake as "seen". App-side.

## C. Event-log integrity HIGH (BrokenLink line 434) — benign

Line 434 is a 2026-06-11 info event in a 1,578-line log that survived weeks + many dev rebuilds; the break is old
(reported every startup since ~June 11), not fresh tampering — surrounding entries are benign, no edit pattern.
Most likely build/format drift across rebuilds or a past log rotation. **Remedy:** rotate/re-seal the event log
to get a clean baseline so future integrity alerts are trustworthy (archive the old `events.log.jsonl`, start a
fresh chain). Don't suppress the check.

## D. MCP tool-scan probe leaks unobserved exceptions (crash.log noise)

`McpToolProbe.ProbeAsync` (McpToolProbe.cs:38) → `McpClient.CreateAsync` spins a background receive loop; when a
remote MCP server returns 401/405 the loop faults and the exception is unobserved → caught by App's
`TaskScheduler.UnobservedTaskException` handler (logged to crash.log + a spurious High OS-event-log entry).
Handled/non-fatal but noisy. **Fix candidates:** a cheap pre-flight reachability check before creating the full
MCP client (skip 401/auth-required endpoints), or attribute+downgrade probe-originated unobserved exceptions.
Needs a live run to verify (the scan monitor runs in the App) → do post-pin.

## F. Operator-approval channel ("%harness% wants to X — Yes/No")

Generalised "harness proposes a privileged action → operator approves → Foreman executes" channel. A harness
must NEVER restart the watchdog (or kill a sibling) directly — it REQUESTS, the operator decides, and the
request is logged (watchdog-targeting = notable, usually benign).

- MCP (buildable): `request_operator_action(action, reason)`, `action ∈ {restart-foreman, restart-harness:<id>,
  reconnect-extension, …}`. CanMutate-gated; reason redacted+capped; rate-limited/coalesced (spam = signal +
  annoyance); logs a Medium MonitoringNoticeEvent.
- App (post-reboot): a non-modal Yes/No toast "%harness% wants to %action% — <reason>" that MUST respect
  game-mode (no focus steal). Only the operator's Yes executes. Self-restart = spawn a fresh instance that waits
  on the single-instance mutex then exits (interacts with watchdog-of-watchdog — do carefully).
- **Reuse for the deferred cross-tree kill approval** (request_process_kill currently returns
  "operator_approval_required" + a Medium notice with no execute path — this channel is that execute path).
- NB: this is a primitive, not a fix for "Foreman got into a bad state" — the real drivers (A. process-tree
  leak, B. misleading "restart to link") are the actual reasons restarts feel necessary.

## E. Auto-start points at `W:` (MEDIUM alert)

Foreman's HKCU Run entry targets the dev build on the non-system `W:` drive; if `W:` mounts late at sign-in,
auto-start fails. Real fix = install a Release build to `C:` and repoint auto-start there (packaging task), not a
registry tweak (the exe currently only exists on `W:`).

---

**Done already (not blocked):** `request_harness_review` outbound handoff tool (operator-only, Ask-Harness;
commit on main). The integrity + restart diagnoses above are read-only findings.
