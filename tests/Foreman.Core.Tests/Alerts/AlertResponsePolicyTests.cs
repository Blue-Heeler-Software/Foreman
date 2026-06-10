using Foreman.Core.Alerts;
using Foreman.Core.Behavior;
using Foreman.Core.Models;
using Foreman.Core.Settings;

namespace Foreman.Core.Tests.Alerts;

public sealed class AlertResponsePolicyTests
{
    private static readonly DateTimeOffset T = DateTimeOffset.UnixEpoch;

    private static EscalationEvent Esc(EscalationLevel level) =>
        new(T, level, EscalationLevel.Watch, "codex", "Codex CLI", "reason", 5, 3, 2, ["net"], "net-001", "pipe");

    // ── Guardrail: only the non-destructive set is configurable ───────────────
    [Fact]
    public void Sanitize_ClampsToAllowed()
    {
        // 8 is an out-of-set bit (e.g. a hypothetical Kill) — must be stripped.
        var configured = EscalationAction.AskHarness | (EscalationAction)8;
        Assert.Equal(EscalationAction.AskHarness, AlertResponsePolicy.Sanitize(configured));
    }

    [Fact]
    public void Allowed_HasNoDestructiveActions()
    {
        // The whole point: the allowed set is exactly the three safe actions, nothing else.
        Assert.Equal(
            EscalationAction.AskHarness | EscalationAction.AdversarialAudit | EscalationAction.RequestSelfCleanup,
            AlertResponsePolicy.Allowed);
    }

    // ── ForLevel mapping + defaults ───────────────────────────────────────────
    [Fact]
    public void ForLevel_MapsTiers_AndWatchIsNone()
    {
        var s = new AlertResponseSettings();
        Assert.Equal(EscalationAction.None, AlertResponsePolicy.ForLevel(s, EscalationLevel.Watch));
        Assert.Equal(EscalationAction.AskHarness, AlertResponsePolicy.ForLevel(s, EscalationLevel.Alarm));
        Assert.True(AlertResponsePolicy.ForLevel(s, EscalationLevel.Emergency).HasFlag(EscalationAction.AdversarialAudit));
    }

    // ── Effective: audit gated to audit-worthy events ─────────────────────────
    [Fact]
    public void Effective_AllowsAudit_OnAlarmEscalation()
    {
        var a = AlertResponsePolicy.Effective(EscalationAction.AdversarialAudit, Esc(EscalationLevel.Alarm));
        Assert.True(a.HasFlag(EscalationAction.AdversarialAudit));   // Alarm+ qualifies for audit
    }

    [Fact]
    public void Effective_StripsAudit_OnAlertEscalation()
    {
        // An Alert-tier escalation doesn't qualify for cross-LLM audit (AuditPolicy) — so audit is
        // dropped even if the operator enabled it for that tier; AskHarness still fires.
        var a = AlertResponsePolicy.Effective(
            EscalationAction.AskHarness | EscalationAction.AdversarialAudit, Esc(EscalationLevel.Alert));
        Assert.False(a.HasFlag(EscalationAction.AdversarialAudit));
        Assert.True(a.HasFlag(EscalationAction.AskHarness));
    }

    [Fact]
    public void Effective_StripsAudit_ForHousekeepingEvent()
    {
        // A hang that escalated is housekeeping — never peer-audited even if audit is configured.
        var hang = new HangDetectedEvent(T, "src", "hung", 1, "bash", 60, 30, null, null, null, null, null);
        var a = AlertResponsePolicy.Effective(EscalationAction.AdversarialAudit | EscalationAction.RequestSelfCleanup, hang);
        Assert.False(a.HasFlag(EscalationAction.AdversarialAudit));
        Assert.True(a.HasFlag(EscalationAction.RequestSelfCleanup));   // cleanup still allowed
    }
}

public sealed class SelectAuditorTests
{
    private static LlmTriageSettings Triage(bool preventSelf = true) => new()
    {
        Enabled = true,
        PreventSelfAudit = preventSelf,
        AuditorPreferences =
        [
            new() { AuditorId = "codex", TargetHarnessIds = ["claude-code"], MinimumSeverities = ["High", "Critical"], Priority = 100 },
            new() { AuditorId = "opencode", TargetHarnessIds = ["claude-code", "codex"], MinimumSeverities = ["Medium"], Priority = 50 },
        ],
    };

    [Fact]
    public void PicksHighestPriorityMatchingAuditor()
        => Assert.Equal("codex", Triage().SelectAuditor("claude-code", ForemanSeverity.High)?.AuditorId);

    [Fact]
    public void RespectsMinimumSeverity()
        // claude-code at Medium: codex (min High) is out, opencode (min Medium) matches.
        => Assert.Equal("opencode", Triage().SelectAuditor("claude-code", ForemanSeverity.Medium)?.AuditorId);

    [Fact]
    public void ExcludesSelfWhenPreventSelfAuditOn()
        // codex being audited: opencode targets codex; codex itself must not audit itself.
        => Assert.Equal("opencode", Triage().SelectAuditor("codex", ForemanSeverity.Critical)?.AuditorId);

    [Fact]
    public void NoMatch_ReturnsNull()
        => Assert.Null(Triage().SelectAuditor("gemini-cli", ForemanSeverity.Critical));

    [Fact]
    public void DisabledTriage_ReturnsNull()
    {
        var t = Triage();
        t.Enabled = false;
        Assert.Null(t.SelectAuditor("claude-code", ForemanSeverity.High));
    }
}
