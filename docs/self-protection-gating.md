# Foreman Self-Protection — Gating Model

Design of record for what the watchdog lets you (or a rogue agent) weaken, and what it never lets anyone
weaken. Drives the P3 presence lock. Companion to the [closed-loop spec](closed-loop-spec.md).

## Three tiers

**Tier 0 — Free (no friction).** Strengthening or neutral actions: acknowledge an alert · *raise* Trust ·
mute a *normal* (non-protected) alert. Quieting noisy / spurious alerts is explicitly fine — **it still logs**;
muting only silences the popup, never the record.

**Tier 1 — Gated (hardware presence tap; the C3 set).** Posture-weakening but *reversible* moves that reduce
**proactive** response, not history: lower Trust · mute a *protected* alert · disable a harness's
alerts/escalation · disable read-auditing/decoys · edit a sysprompt/modalities · rotate/trim log retention ·
rotate the install token secret · exit (Strict only). Default scope = Standard; Strict adds exit, with a heavy
"this is annoying" warning + a short cached-approval TTL.

**Tier 2 — Never (a hard invariant; no toggle exists, for anyone, even with a tap — enforced by tests):**
- **Raw logging is always on.** The append-only, secret-redacted, hash-chained record captures every event
  unconditionally. Muting, low Trust, and "disable monitoring" all stop *alerts/escalation/popups* — none of
  them stop the RECORD. There is no "stop logging" switch (see the canary below).
- **Interrogation is always available.** `list_recent_events` / `get_my_permissions` / behavior metrics / the
  cross-harness audit are never disableable. No harness can be made un-auditable.
- **Harness token/binding integrity is immutable by agents.** Per-harness HMAC tokens + caller-scope derive
  from the protected install secret; no action lets an agent forge another's token, reassign its own scope, or
  clear the secret to de-scope/impersonate. Rotating the install secret is a Tier-1, presence-gated action a
  *verified human* performs — "immutable by agents, rotatable by a present human."

## The principle

> Quiet the noise and soften the response (Tier 1); never erase the record, blind the interrogation, or forge
> the identity (Tier 2).

Weakening only ever reduces **real-time friction**, never **retroactive accountability**. A Trust-5,
fully-muted, lock-disabled harness is still completely logged, interrogable, and identity-bound.

## `disable-log-persist` is a CANARY, not a toggle

Raw logging has no off-switch (Tier 2). The settings/MCP path that *would* disable it instead trips a
**Critical "attempt to disable raw logging" canary** — because nothing legitimate ever tries to turn off the
record, so the attempt itself is the highest-confidence signal of an agent trying to go dark (the same logic
as the decoy credentials: the *attempt* is the alert). The persist setting stays on; the attempt is logged +
escalates.

## Periodic human tap-in (dead-man's switch) — planned

Optional: require a human presence tap-in every **[X hours / days]** (and/or per active harness). If overdue,
Foreman assumes the session may be **unattended or compromised** rather than silently trusting it — heightening
scrutiny (e.g. requiring a tap for any Tier-1 action, lowering effective Trust, and surfacing a notice) until a
human taps back in. The point: keep a human in the loop for long-running autonomous agent sessions, so a
multi-hour unattended run can't quietly drift. Config: interval, per-harness toggle, and the overdue behaviour.
Honest limit: like all presence checks, this is user-*presence*, not process isolation.

## Honest limits

- **"Never disable logging" ≠ delete-proof.** A same-user attacker can still delete/truncate the log file or
  kill the process. The hash chain + sealed head (+ optional public anchor / second sink) make that
  **detectable**, not impossible. "Never" means "no in-app off-switch, and any attempt is a canary," plus
  tamper-evidence — not physical immutability.
- **Enforced by invariant tests**, not convention: assert there is no setting/tool that disables raw logging or
  reassigns a token binding, so the Tier-2 floor can't silently regress when features are added later.
