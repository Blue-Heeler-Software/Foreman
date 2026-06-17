# Foreman Temporal Truth Model

Foreman does not treat wall-clock time as ground truth. Local wall UTC is useful for human correlation, but a same-user agent or a compromised host can move the clock.

## Current local truth

Every persisted event gets append-time metadata from `EventLogStore`:

- `Sequence`: strictly increasing local append order. This is the ordering truth.
- `TemporalSessionId`: unique Foreman process/session id for the clock source.
- `RecordedAtUtc`: local wall UTC at append time. This is a label, not proof.
- `MonotonicTicks` and `MonotonicFrequency`: local monotonic time for duration checks within one session.
- `TemporalAnomalies`: clock behavior warnings, currently wall-clock rollback, monotonic regression, and wall-vs-monotonic divergence.

The hash chain commits to these fields. Casual edits, drops, reorders, or recomputed records with non-increasing sequence or same-session monotonic regression fail verification.

## Later trusted-time hooks

`HeadSeal` now carries a `TemporalCheckpoint` and optional `TimeAnchor`. The default `NullTimeAnchor` is no-op, but the interface is ready for:

- TPM-backed head sealing.
- A remote or public timestamp/transparency anchor over `(headHash, count, temporal checkpoint)`.

Those later anchors can prove a checkpoint existed no later than an external timestamp. Until one is configured, Foreman provides local ordering and anomaly evidence, not external trusted time.

## Rule of use

- Use `Sequence` for event order.
- Use monotonic ticks for local durations within one `TemporalSessionId`.
- Use `RecordedAtUtc` for display and cross-log correlation only.
- Treat `TemporalAnomalies` as evidence that wall-clock based conclusions need review.
