# Handoff: responsiveness audit + restart/integrity follow-ups (2026-06-19)

Captured because the high-value items are **blocked by the Bitdefender quarantine pin** on
`Foreman.Monitor`'s build-output path (clear it — folder exclusion + delete the quarantine entry / reboot —
to rebuild `Foreman.Monitor` and `Foreman.App`). McpServer/Core changes build + test independently of the pin.

## A. Responsiveness audit (read-only audit; no code changed)

1. **Stale monitored-process volume is the biggest drag.** ~~Live Foreman reported ~8,692 monitored processes vs
   ~386 actually on the box.~~ **DONE 2026-06-19 (commits `30de561` + `9ec94a5`):** `ProcessTreeTracker.Prune` /
   `PruneDeadProcesses` evict records whose PID is absent from the live OS set; the IoPoller runs it each tick
   with a two-pass grace so the WMI deletion event (and its orphan/nonzero-exit accounting) wins the race, plus
   degraded-state logging. Adversarially reviewed (false-eviction + concurrency clean). RESIDUAL FOLLOW-UP — ORPHAN recovery DONE 2026-06-19 (commit `3f4f449`): the reconciler now returns a
   `PruneOutcome` (Evicted + Orphans); for each evicted parent it marks + surfaces still-live children as
   orphaned, and the IoPoller emits `OrphanDetectedEvent` with the WMI path's local-model-host suppression
   (no double-emit — the two-pass grace means WMI-handled parents are gone before eviction). STILL OPEN:
   harness-nonzero-EXIT detection on a dropped delete event is not recovered (the exit code is gone with the
   missed WMI event, so it cannot be reconstructed) — accept as a known limit of a dropped-event world.
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

**Messaging rule (applies to ALL Foreman restart/reboot copy):** never say a bare "restart" or "reboot" — name
the scope: **harness restart** (the agent), **Foreman restart** (the watchdog exe), or **PC reboot** (machine).
Operator instruction. This covers this hint, toasts, and the `request_operator_action` actions
(`restart-foreman` / `restart-harness:<id>`). The three are routinely conflated and that has wasted real effort.

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
- **Restart-harness (restart-harness:<id>)**: KILL already exists (`ProcessTreeTracker.KillHarness`, operator,
  KillGuard-protected). RESTART = kill + relaunch from the captured ExecutablePath + CommandLine + cwd. HONEST
  CAVEAT: relaunch is lossy for INTERACTIVE agents — re-spawning gives a fresh detached process, NOT the original
  terminal/IDE session (conversation/workspace state is gone, won't reattach to the user's terminal). So surface
  it as "Restart (fresh session)" with that warning, enabled only when a usable launch recipe exists; good for
  daemon/launch-by-command agents (LM Studio, headless runners), leaky for terminal/GUI sessions. Operator can
  hit it directly on a harness card; a harness can request it for a SIBLING via this channel (operator-gated —
  sibling restart is a sabotage vector). NB: does NOT fix "restart to link" (B) — agent still links on first tool
  call; this is for clearing stuck/hung agents + changes that truly need a relaunch.
- NB: this is a primitive, not a fix for "Foreman got into a bad state" — the real drivers (A. process-tree
  leak, B. misleading "restart to link") are the actual reasons restarts feel necessary.

## E. Auto-start points at `W:` (MEDIUM alert)

Foreman's HKCU Run entry targets the dev build on the non-system `W:` drive; if `W:` mounts late at sign-in,
auto-start fails. Real fix = install a Release build to `C:` and repoint auto-start there (packaging task), not a
registry tweak (the exe currently only exists on `W:`).

DECIDED 2026-06-19 (operator): fold this into the signed-Release packaging (alongside the pending SignPath work),
NOT a dev-build workaround. Two dev-build workarounds were considered and rejected for now: (a) a per-user
scheduled task that retries until `W:` mounts (fixes late-mount only, changes the auto-start mechanism), and (b)
staging a copy to `C:\…\Programs` + auto-refresh (most robust but drops a SECOND copy of the AV-flagged
`Foreman.Monitor.dll` on `C:`, expanding the Bitdefender surface we just fought). The clean fix is: release.yml
publishes a single-file signed build → an installer drops it under `C:` (e.g. `%LocalAppData%\Programs\ForemanAgentSafety`)
→ `StartupManager.SetEnabled` registers that stable path. `StartupManager.GetDriveWarning` already surfaces the
risk in the meantime.

---

**Done already (not blocked):** `request_harness_review` outbound handoff tool (Ask-Harness mailbox;
operator calls can set reviewer context, harness calls are wrapped as attributed untrusted mail). The
integrity + restart diagnoses above are read-only findings.

## H. BUG: MCP auth secret desyncs on restart -> ALL tokens 401 (observed 2026-06-19)

Symptom: after a Foreman restart, every harness card shows "restart to link" at once and all MCP calls 401 —
including the raw operator token. Verified root cause: the running server's auth secret did not match the
on-disk `mcp.token`. Proof: the configured `fmh1.claude-code` token's MAC matches `HMAC(current mcp.token,
"claude-code")`, and the file is readable (owner FullControl, clean 43 chars), yet both it and the raw
operator token return 401 (a 401 is `Authenticate()` failing — LoopbackPolicy/peer-binding return 403). So the
live process is on a different secret than the file.

Mechanism: `McpAuthToken.LoadOrCreate` (McpAuthToken.cs:46) silently mints a throwaway random in-memory secret
when it cannot read `mcp.token` (the read is wrapped in `catch { }`), and `WriteSetupFile`/persist are
best-effort `catch {}` too (corroborated here: `mcp-setup.txt` was NOT refreshed on the 3:29 start). A
transient read failure at startup — e.g. AV churning the data-dir ACLs, a momentary lock — therefore orphans
EVERY saved harness token AND the operator token, with no log line. Auth then can't even fall back to the disk
secret if the lock persists into request time.

UPDATE 2026-06-19 (CORRECTION — restarts do NOT fix it): two further `Foreman restart`s (PID 48508 -> 28472,
both normal explorer launches, same user, NOT containerized — verified) reproduced the 401 identically. Foreman's
own token middleware returns the 401 (body `{"error":"A valid Foreman MCP token is required..."}`, the
McpServerHost.cs:141 Deny), so it is genuinely the token check failing on the correct on-disk secret. The live
process is ALSO not writing its data dir (`events.log`/`mcp-setup.txt` stale, older than the process) though it
logs fine to the Windows Event Log. So the Foreman PROCESS cannot read or write `%LocalAppData%\Foreman` while a
trusted process (PowerShell, explorer) can — it boots on a throwaway secret AND the disk-fallback read also fails.
The event log shows ROLLBACK + hash-chain-break alerts: the operator's Bitdefender quarantine-restore reverted
Foreman's data files to an earlier state. STRONGLY INDICATED cause: Bitdefender folder/ransomware protection is
blocking the unsigned dev `Foreman.exe` from its own AppData (BD blocks are NOT surfaced to the Windows Event
Log, which is why no AV-block event appears). Not 100% confirmed without the BD console.

Recovery (NOT another Foreman restart — proven futile): (1) try-before-reboot — add `Foreman.exe` AND
`%LocalAppData%\Foreman` to Bitdefender's exclusions / trusted apps / ransomware-protection allow-list, then one
Foreman restart, then curl-verify the operator token returns non-401. (2) Definitive — PC reboot (clears the AV
pin + AV file-access state + stale handles, gives a clean auto-start), then rebuild current source, then relaunch.
Re-seal the event log after (item C) since the rollback poisoned the chain baseline.

Real fix (App/McpServer rebuild): make `LoadOrCreate` fail loud instead of silently minting a throwaway when the
file EXISTS but is unreadable — retry with backoff, and if it still can't read an existing token file, log a High
event and refuse to serve `/mcp` (return a clear 503 "token unreadable") rather than booting on a secret that
guarantees every client 401s. Never mint-fresh over an existing-but-locked file. Consider a fixed/explicit data
dir off the redirected/AV-sensitive path.

RESOLVED 2026-06-19: CONFIRMED root cause was Bitdefender's real-time/behavioral shield blocking the Foreman
PROCESS from reading/writing `%LocalAppData%\Foreman` at startup (no quarantine; antivirus file/path exclusions
did NOT cover it). Proof: with BD fully off + a fresh restart, the dir wrote again and tokens validated (401 ->
400). Final fix that stuck: PC reboot (cleared BD's accumulated behavioral state + the Monitor.dll build pin) +
BD exclusions applied on restart + a full rebuild -> launching the fresh build with BD back ON now reads/writes
the dir and validates tokens. Durable cure remains SignPath code-signing so BD trusts the binary instead of
heuristically flagging it (the unsigned dev build trips its AV-killer heuristics). The `LoadOrCreate` fail-loud
hardening above is still worth doing so a future read-miss is visible, not silent.

## G. Deferred: Codex cross-review handoff (operator chose "wait for reboot", 2026-06-19)

The plan was to have Codex review how its own audit suggestions were implemented. It never landed and
could not have: the running Foreman is a stale pre-pin build that does NOT expose `request_harness_review`
(or any broker/LiveWeave tool), AND Codex has no live MCP session (`list_connected_mcp_clients` shows only
Claude Code). Operator chose to defer rather than relay the prompt manually.

**Fire only when BOTH preconditions hold:** (1) Foreman has been rebuilt+relaunched so
`request_harness_review` is in the live tool list, and (2) Codex has a live MCP session to Foreman
(confirm via `list_connected_mcp_clients`) — otherwise the ask just queues unseen. Codex is currently on
DJC, so it must be reconnected to Foreman first.

**Review target + ready prompt** (`request_harness_review`, targetHarness `codex`):

> Codex: you previously ran a Foreman audit and produced a numbered list of suggestions. Two were
> implemented and I want you to verify them:
> - Suggestion #1 -> commit `d713713` "fix(release): publish the hardened guardian into the installer payload"
> - Suggestion #4 -> commit `f300be9` "fix(app): clear real build warnings (nullable deref + unawaited dispatch)"
>
> Review each commit against your original suggestion. For each report: (a) does the change fully and
> correctly address what you raised, (b) is anything missed or only partially done, (c) any regression or
> new risk introduced. Be specific and cite file:line. Reply via `reply_to_ask_harness_request`.

## J. Pre-existing anti-rollback hardening (surfaced by the rotate review, 2026-06-19)

The presence-gated rotate + re-seal (commits `373943d` + `376b5ce`) is sound; its adversarial review flagged two
PRE-EXISTING SEC B8 gaps it does NOT introduce or widen, worth their own hardening later:
1. ~~**Unauthenticated OS-log anchor.**~~ **DONE — anchor-MAC, commit `65359d1` (2026-06-19).** Anchors now carry a
   MAC under the chain head-seal key (`LogAnchor.Seal`); `AnchorPolicy.Evaluate` trusts only an authentically-sealed
   anchor when sealing is on (NullHeadSigner path unchanged → zero change for casual users). Forged/unsigned anchors
   are rejected; a present-but-invalid seal raises a distinct forgery alarm. The MAC input is domain-separated
   (`foreman-anchor-v1:<head>`) so a `.head`/archived-`.head` seal can't be lifted into an anchor, and the forgery
   alarm is not suppressed by a key-change that coincides with a settings-tamper flag (both fixes from the adversarial
   review). RESIDUALS still open (need a sealed **monotonic epoch** to close, the "bind a monotonic epoch" idea below):
   (a) **replay** of a genuinely-old VALID anchor re-written as newest after rolling back to its state; (b) the
   **migration / key-less windows** where unsigned anchors (first sealing launch, or a session where the private key
   was unavailable) are skipped, so a rollback whose surviving witnesses are all unsigned reads as NoPrior. A sealed
   epoch (ranked by the reader, max-epoch-valid-wins) closes both without the trim false-positive that max-count has.
2. **Witness-read is count/scan-bounded, not order-explicit.** `WindowsEventLogSink.ReadOwnRecent(256)` also stops
   after ~20k raw shared-log entries; a flooded Application log can push Foreman's latest anchor out of the read
   slice. It degrades SAFELY (→ NoPriorAnchor, never a false rollback), so it's robustness not a break. Hardening:
   read by descending TimeGenerated / `EventLogReadingDirection.Backwards`, budgeting the cap to Foreman entries.
