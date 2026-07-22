# P0 Fix Brief — Round-2 Audit (for the next fix pass)

Source: `docs/audit-2026-07-22-round2-fix-verification.md`. Target these five P0 items only. Line numbers are from
commit `89633d1`; confirm by symbol name against current code before editing (the tree may have moved).

## The one rule that matters most

Round 1's fix pass closed each finding **on the path the audit named and the path the new test exercised**, then
left a sibling bypass open. A green test on the original path is what *retired* the finding while the exploit still
worked. So for every item below:

> **Write the regression test to exercise the BYPASS, not the original path.** The test must FAIL on today's code
> (`89633d1`) and pass only when the real hole is closed. If you cannot write a test that fails today, you have not
> found the hole the audit is describing — re-read the "bypass" line before touching code.

Do not mark an item done because the previously-added test still passes. Each item names the specific new test.

---

## P0-1 — C1: deleting `settings.json.seal` disarms the entire tamper-revert

**Defect.** `SettingsStore.Load` (`src/Foreman.Core/Settings/SettingsStore.cs:66-93`) reverts only inside
`else if (LastSealVerdict == Tampered)`. A missing seal file makes `ReadSeal` return null → `Verify` yields
`Unsealed` → control falls through to `return settings;` at `:93`, adopting the attacker-edited file verbatim with
no revert and no alert. The `.lastgood`/`.lastgood.seal` recovery snapshot is read only in the `Tampered` branch
(`:76`), never when the primary seal is simply absent — even though "`.lastgood` + `.lastgood.seal` present but
`settings.json.seal` absent" is an unambiguous deletion signature. No consumer reacts to `Unsealed`
(`App.xaml.cs:1039` handles `Tampered`, `:1050` handles `Unverified`, nothing handles `Unsealed`).

**Fix.** When the primary seal is missing/empty BUT a verifiable `.lastgood` + `.lastgood.seal` pair exists, treat
it as `Tampered` (revert to the recovered snapshot, quarantine, alert). Persist a durable "this install has been
sealed at least once" bit OUTSIDE `settings.json` (guardian-side, or an OS-event-log marker) so the no-seal path
cannot be re-entered on demand by an attacker who deletes both the seal and the recovery pair.

**Bypass test (must fail today).** Seed a valid sealed `settings.json` + `.lastgood(.seal)`, then edit `settings.json`
to weaken posture and DELETE `settings.json.seal`. Assert `Load` returns the recovered last-good settings (not the
edited file) and reports a loud (Tampered-class) verdict. A test that only edits `settings.json` while leaving the
seal in place does NOT cover this.

---

## P0-2 — C2: Guardian install-time trust anchor is still attacker-controlled on unsigned builds

**Defect.** `GuardianInstallReference` proves "canonical layout" using only the attacker-supplied launcher: leaf-name
check `Foreman.exe` (`src/Foreman.Guardian/GuardianInstallReference.cs:39`) and a `guardian\Foreman.Guardian.exe`
sibling derived from that same attacker path (`:51-58`). `GuardianIntegrity.Decide` returns `Trusted=true` when
`referenceSigner` is null, `trustedDevelopmentLayout` is the hardcoded literal `true`
(`src/Foreman.Guardian/GuardianInstaller.cs:47`), and `subjectSigner` is null — i.e. always, on shipping unsigned
builds. `GuardianInstaller.cs:54/77` then persists the attacker path + hash as the sole authorized SYSTEM-pipe
caller. The install root is per-user writable (`installer/foreman.iss:24-25`, `PrivilegesRequired=lowest`), so there
is no non-user-writable location to be canonical against. Working chain: stage `%LOCALAPPDATA%\x\Foreman.exe` +
`x\guardian\`, then `ShellExecute("runas", "x\guardian\Foreman.Guardian.exe", "--install ...")` — one self-consented
UAC prompt of a shape Foreman routinely asks users to accept.

**Fix.** Record the install root under **HKLM** during the elevated install; require the resolved launcher to match
that recorded root (a location a medium-IL attacker cannot write). Bind the launcher to the invoking process by PID
rather than a re-suppliable path/name. Make the unsigned-development branch a loud, explicit
`--allow-unsigned-development` opt-in so a shipped-but-unsigned build FAILS CLOSED by default instead of silently
trusting. Also back up/restore `client-policy.json` inside the install rollback (`GuardianInstaller.cs:77` writes it
before the point of no return and the catch never restores it — a FAILED attacker install still replaces the pin).

**Note two false "it's fixed" claims to correct while here:**
- The remediation note near `docs/audit-2026-07-21-full-functional-qol-redteam.md:173` asserting unsigned is only
  reachable via the live-launcher/layout route — it is not; correct or delete it.
- The `src/Foreman.Core/Settings/SettingsSeal.cs` doc comment claiming a "SACL write-audit on settings.json" and an
  OS-event-log anchor protect against a same-user editor — neither exists (the only SACL is on decoy files).

**Bypass test (must fail today).** `GuardianIntegrity.VerifyForInstall` / `Decide` with an unsigned reference at an
arbitrary path NOT matching the HKLM-recorded root must return `Trusted=false` unless the explicit dev opt-in is set.
The existing regression test asserts on `GuardianInstallReference.LayoutMatches`, a helper production never calls
(`GuardianIntegrityTests.cs:29-37`) — replace it with a test through the real `VerifyForInstall` production path.

---

## P0-3 — C3: attacker-minted Critical severity inverts the eviction policy; genuine High is dropped on arrival

**Defect.** `report_suspicious_command` publishes `match.Severity` verbatim (`src/Foreman.McpServer/ForemanMcpTools.cs:372`),
and rules `del-001..del-006` in `src/Foreman.Core/patterns/dangerous-commands.json` are `"severity":"critical"` for
text that is only pattern-matched, never executed. `BoundedEventHistory.Add` (`src/Foreman.Core/Events/BoundedEventHistory.cs:25-34`)
and `ForemanState.OnEvent` (`src/Foreman.McpServer/ForemanState.cs:112-127`) choose the eviction victim as the global
minimum of `(Acknowledged, Severity, Timestamp)` over a list that INCLUDES the just-added item. Once ~1000
attacker-minted unacknowledged Criticals are resident, an arriving genuine **High** (severity 3) is the global minimum
and is evicted immediately — it never reaches the dashboard feed, `get_events`, or the ackable store. Most of Foreman's
own self-protection alarms are High, not Critical (settings tamper, sidecar impersonation, log integrity, MCP down,
tool-scan). This is strictly worse than the pre-fix FIFO, which retained that High for 1000 more events.

**Fix (pick one, or combine).** Partition MCP-sourced `CommandAlertEvent`s into a reserved sub-quota (e.g. a small
fixed ring, ~64 slots) that can only evict its OWN partition; and/or add a provenance tier ahead of severity
(host-detected outranks agent-self-reported); and/or clamp MCP-minted pre-flight alerts to Medium in the store while
keeping true severity in the returned verdict + durable log. Add an eviction floor so an arriving unacknowledged
High/Critical is never chosen as its own eviction victim. Also give the equal-severity tie-break a provenance term so
an agent-minted Critical never evicts a host-minted Critical of any age.

**Bypass test (must fail today).** Fill the store to capacity with agent-provenance `Critical` events, then publish
ONE host-detected `High`; assert the High is present afterward (in `BoundedEventHistory` AND `ForemanState`). Second
assertion: an arriving unacknowledged Critical must not be its own eviction victim. The round-1 tests flooded only at
Info/Medium — never at the Critical severity the attacker actually controls — which is why the fix reads green.

---

## P0-4 — Regression: sidecar supervisor wedges into a permanent silent blackout

**Defect.** `SidecarSupervisor.Tick` (`src/Foreman.Core/Health/SidecarSupervisor.cs:81-86`) early-returns and zeroes
`_downTicks` whenever `_launchInProgress()` is true, BEFORE the relaunch/notify logic. `_launchInProgress` is set in
`ElevatedSidecarController.Start()` (`:90`) and cleared only on `Stop()` (`:104`), the nonce handshake (`:142`), or
`RunAsync`'s `finally` (`:165`). `RunAsync` blocks at `await server.WaitForConnectionAsync(ct)` (`:122`) with NO
timeout. So if the sidecar launches (UAC accepted) but dies/hangs before writing its nonce (ETW init crash, AV kill,
self-check failure), `WaitForConnectionAsync` never returns, `finally` never runs, `_launchInProgress` stays true
forever, and `Tick`'s early-return suppresses its own recovery: `expectedUp && !connected`, no relaunch, no High
notice, Setup Health silently shows down. The pre-fix code handled exactly this (grace tick → relaunch x2 → "keeps
stopping" High).

**Fix.** Stamp a launch timestamp and expire `_launchInProgress` after a bounded interval, OR add a connection
timeout to `WaitForConnectionAsync`, so a launched-but-never-connecting sidecar re-enters the normal relaunch/notify
path. The supervisor must never suppress its own recovery indefinitely. (While here: `SidecarSupervisor.cs:109-110`
increments the relaunch budget AFTER `_relaunch()`, so a throwing relaunch retries forever — increment before
invoking.)

**Bypass test (must fail today).** Drive the supervisor with `expectedUp=true`, `connected=false`,
`launchInProgress=true` held past the expiry deadline; assert it eventually relaunches and emits the down High notice
rather than staying silent forever.

---

## P0-5 — Regression: a documented `mcp.token` rotation reverts all settings to defaults

**Defect.** The fix made `Tampered` destructive (`src/Foreman.Core/Settings/SettingsStore.cs:74-91`). In the default
(no-guardian) install the seal secret IS the `mcp.token` value (`src/Foreman.App/App.xaml.cs:161-162`). Deleting
`mcp.token` to rotate is documented/supported (`src/Foreman.Core/Security/McpAuthToken.cs:263`). After rotation,
`Verify` uses the new secret against the old-secret seal → `Tampered`; `TryReadRecovery` reads `.lastgood`, also
old-secret-sealed → also fails → returns null → `QuarantineTampered` renames `settings.json`(+`.seal`) to `*.tampered`
and `Load` returns `new ForemanSettings()`. The next `Save` re-seals the defaults, so every sealed field (presence
lock, decoy auditing, ADB enrollment/binary, CU config, harness trust, mutes, OS event log, Game Mode) reverts — and
reverting to defaults can WEAKEN posture (Game Mode defaults on). Contents are recoverable from the `*.tampered` file
but the live posture is lost.

**Fix.** Do not treat a seal-secret mismatch as tampering when the install secret was just rotated.
`McpAuthToken.RecentlyRegenerated()` already exists — on a `Tampered` verdict, if the secret was recently rotated (or
the recovery snapshot exists and fails ONLY the seal, not a content check), adopt-and-re-seal the existing settings
instead of quarantine+revert. At minimum, require explicit operator confirmation before replacing `settings.json` with
defaults, and key the recovery snapshot with a rotation-stable secret.

**Bypass test (must fail today).** With a valid old-secret-sealed `settings.json`, rotate the token so
`RecentlyRegenerated()` is true, then `Load`; assert it adopts-and-re-seals the EXISTING settings (fields preserved),
not quarantine + defaults.

---

## Definition of done for this pass

1. All five bypass tests above exist and FAILED before your change / PASS after.
2. The two false remediation claims (P0-2) are corrected.
3. `dotnet build Foreman.slnx -c Debug` is clean and all six test suites pass.
4. For each item, a one-line note in the commit body stating which sibling path is now covered that the round-1 fix
   missed — so the reviewer can confirm the hole, not just the named path, is closed.

P1/P2 items (head-key pin projection, CuBroker Held-item cap + Guardian auto-relaunch, vault in-memory protection,
decoy `%ProgramData%` tree hardening + auditpol-by-GUID, LiveWeave `TimedOut` prune, Android `Claim()` re-gate, UI
human-factors) are tracked in the round-2 report Section 8 and are out of scope for this P0 pass.

---

## Implementation hand-back for round 3

- **P0-1 sibling covered:** deleting the primary seal now enters the tamper/recovery path when a verified recovery
  pair or durable OS-event witness proves this is not a first run; deleting all three same-directory files no longer
  silently recreates first-run state when that witness exists.
- **P0-2 sibling covered:** a live PID plus attacker-controlled sibling layout no longer authorises an arbitrary
  unsigned root; production evaluates the HKLM-recorded root and unsigned Release installs fail closed unless an
  explicit development opt-in is present. Failed installs restore both the previous policy bytes and root anchor.
- **P0-3 sibling covered:** MCP-originated Critical events have a reserved quota and are first eviction candidates,
  so they cannot evict an arriving host High/Critical in either in-memory store; host High/Critical arrivals are not
  eligible to evict themselves.
- **P0-4 sibling covered:** a launch that never completes the nonce handshake times out, and a stuck
  `launchInProgress` state expires in the supervisor; relaunch budget is charged before the callback and a throwing
  callback cannot retry forever. The non-cancellable `Process.Start(runas)` section is single-flight, so expiry cannot
  stack a second UAC prompt over one that is still open.
- **P0-5 sibling covered:** a recent token rotation may re-seal only when the current settings bytes exactly match
  the independently stored last-known-good bytes; a current-only edit still follows the tamper/revert path.

The earlier “handoff” did not create a Foreman handoff request: it wrote this file and described it as ready to point
at Codex. Live Foreman history contains no Codex request for this brief (only an unrelated, answered emergency-audit
request), so there was nothing for Codex to receive or poll. A real handoff must call `request_harness_review`; writing
a repository file alone is preparation, not delivery.
