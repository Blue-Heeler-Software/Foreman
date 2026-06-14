namespace Foreman.Core.Alerts;

/// <summary>Config for context-scaling the hang/idle timeout (see <see cref="IdleThresholdPolicy"/>).</summary>
public sealed class IdleThresholdScalingSettings
{
    /// <summary>
    /// Scale the hang/idle timeout up when the operator is away and/or the harness is at rest. This only ever
    /// LENGTHENS the timeout (every factor is clamped to &gt;= 1), so enabling it can only quiet expected-idle
    /// noise — it can never create a new alert or shorten the window below the base. Off = flat base threshold.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Ceiling on the operator-away factor. The effective threshold grows toward base × this as the human's
    /// last-input idle time stretches past the base threshold (someone gone two hours → idle agents are very
    /// expected). 1.0 = ignore operator presence.
    /// </summary>
    public double MaxOperatorAwayFactor { get; set; } = 3.0;

    /// <summary>
    /// Factor applied when the harness shows no recent task activity (parked, waiting for the next prompt rather
    /// than running work). 1.0 = ignore task-activity. Kept below the operator factor on purpose: "nobody home"
    /// is the stronger quieting signal than "nothing running".
    /// </summary>
    public double AtRestFactor { get; set; } = 1.5;

    /// <summary>Window (minutes) of recent harness-subtree I/O that counts the harness as actively running a task.</summary>
    public int ActivityWindowMinutes { get; set; } = 5;

    /// <summary>Hard cap on the combined multiplier (operator-away × at-rest).</summary>
    public double MaxMultiplier { get; set; } = 4.0;

    /// <summary>
    /// Absolute ceiling (minutes) on the effective threshold, so even in the quietest quadrant a genuinely stalled
    /// process ALWAYS alerts eventually (into the log/digest). 0 = no absolute ceiling (multiplier cap still applies).
    /// </summary>
    public int AbsoluteMaxThresholdMinutes { get; set; } = 180;
}

/// <summary>Whether a harness is currently running work, or parked at rest. Unknown is treated as Active (conservative).</summary>
public enum HarnessActivity { Active, AtRest, Unknown }

/// <summary>The scaled threshold plus the multiplier and a human-readable reason (surfaced in the hang event).</summary>
public readonly record struct IdleThresholdResult(int EffectiveMinutes, double Multiplier, string Reason);

/// <summary>
/// Scales the hang/idle timeout by context so a fixed 30-minute "no I/O" rule stops mislabelling expected-idle
/// processes as hung. The two signals (the user's ask):
///   • operator presence — minutes since the human last touched keyboard/mouse (system last-input time);
///   • harness task-activity — whether the harness's process subtree is running work or parked at rest.
///
/// Design guarantee — MONOTONIC RELAXATION. Every factor is clamped to &gt;= 1, so the effective threshold is
/// ALWAYS &gt;= the base. Turning this on can only LENGTHEN the window (quiet expected idle); it can never tighten
/// it, never create an alert that wouldn't fire today, and — because hang is an operational signal, never part of
/// the always-escalate security set — never suppress a security detection. Both a multiplier cap and an absolute
/// minutes ceiling bound the relaxation so a real stall always alerts eventually.
///
/// The matrix it produces (base = the configured HangThresholdMinutes):
///   operator present + harness active  → base            (today's behaviour; a watched task that stalled)
///   operator present + harness at rest → base × atRest   (parked while watched — the human knows it's idle)
///   operator away    + harness active  → base × away     (unattended task; can't act now → see it in the digest)
///   operator away    + harness at rest → base × away × atRest (the fully-expected idle state — quietest)
/// </summary>
public static class IdleThresholdPolicy
{
    public static IdleThresholdResult Effective(
        int baseThresholdMinutes,
        int operatorIdleMinutes,
        HarnessActivity harnessActivity,
        IdleThresholdScalingSettings settings)
    {
        if (!settings.Enabled || baseThresholdMinutes <= 0)
            return new IdleThresholdResult(baseThresholdMinutes, 1.0, $"base {baseThresholdMinutes}m");

        // Operator-away factor: 1.0 while the human has been active within the base window; ramps toward
        // MaxOperatorAwayFactor as their idle time grows past the base threshold. Clamped >= 1.
        var awayFactor = 1.0;
        if (operatorIdleMinutes > baseThresholdMinutes)
        {
            var ratio = (double)operatorIdleMinutes / baseThresholdMinutes;
            awayFactor = Math.Clamp(ratio, 1.0, Math.Max(1.0, settings.MaxOperatorAwayFactor));
        }

        // At-rest factor: a harness with no recent task activity is in its expected parked state. Unknown is
        // treated as Active (don't relax on missing data).
        var restFactor = harnessActivity == HarnessActivity.AtRest
            ? Math.Max(1.0, settings.AtRestFactor)
            : 1.0;

        var multiplier = Math.Clamp(awayFactor * restFactor, 1.0, Math.Max(1.0, settings.MaxMultiplier));

        var raw = (int)Math.Round(baseThresholdMinutes * multiplier, MidpointRounding.AwayFromZero);
        var capped = settings.AbsoluteMaxThresholdMinutes > 0
            ? Math.Min(raw, settings.AbsoluteMaxThresholdMinutes)
            : raw;
        var effective = Math.Max(baseThresholdMinutes, capped);   // never below base, even if the ceiling < base

        var reason = multiplier <= 1.0
            ? $"base {baseThresholdMinutes}m"
            : $"{baseThresholdMinutes}m ×{multiplier:0.0} → {effective}m (operator idle {operatorIdleMinutes}m " +
              $"×{awayFactor:0.0}, {(harnessActivity == HarnessActivity.AtRest ? $"at rest ×{restFactor:0.0}" : "active")})";

        return new IdleThresholdResult(effective, multiplier, reason);
    }
}
