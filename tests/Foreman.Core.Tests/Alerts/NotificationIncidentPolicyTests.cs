using Foreman.Core.Alerts;
using Foreman.Core.Behavior;
using Foreman.Core.Models;

namespace Foreman.Core.Tests.Alerts;

public sealed class NotificationIncidentPolicyTests
{
    private static readonly DateTimeOffset T = DateTimeOffset.UnixEpoch;

    [Fact]
    public void CriticalEvents_AreNotClassified()
    {
        var evt = Command(ForemanSeverity.Critical, "cred-004");
        Assert.Null(NotificationIncidentPolicy.Classify(evt));
    }

    [Fact]
    public void EscalationTransitions_AreNotClassified()
    {
        var evt = new EscalationEvent(T, EscalationLevel.Alarm, EscalationLevel.Alert,
            "codex", "Codex", "threshold", 5, 3, 2, ["credential", "network"], "win-001", "PowerShell encoded command");

        Assert.Null(NotificationIncidentPolicy.Classify(evt));
    }

    [Fact]
    public void CommandAlerts_GroupByRule()
    {
        var incident = NotificationIncidentPolicy.Classify(Command(ForemanSeverity.High, "win-001"));

        Assert.NotNull(incident);
        Assert.Equal("command/win-001", incident!.ClassKey);
        Assert.Contains("win-001", incident.Label);
    }

    [Fact]
    public void StaleTokenNotice_GroupsByClaimedHarness()
    {
        var evt = new MonitoringNoticeEvent(T, ForemanSeverity.Medium, "Foreman.McpAuth",
            "Foreman can't validate 'browser-extension's saved token. Open Connect Agent and reconnect it.");

        var incident = NotificationIncidentPolicy.Classify(evt);

        Assert.NotNull(incident);
        Assert.Equal("mcp-auth/stale-token/browser-extension", incident!.ClassKey);
        Assert.Contains("browser-extension", incident.Label);
    }

    [Fact]
    public void Orphans_GroupByHarnessWhenKnown()
    {
        var evt = new OrphanDetectedEvent(T, "Foreman.Monitor", "orphan", 123, "pwsh.exe",
            100, "codex.exe", 10, HarnessType: "codex", HarnessName: "Codex");

        var incident = NotificationIncidentPolicy.Classify(evt);

        Assert.NotNull(incident);
        Assert.Equal("orphan/codex", incident!.ClassKey);
        Assert.Contains("Codex", incident.Label);
    }

    private static CommandAlertEvent Command(ForemanSeverity sev, string ruleId) =>
        new(T, sev, "Foreman.Monitor", "message", "powershell -EncodedCommand ...",
            ruleId, "PowerShell encoded command", "desc", "guide", 42);
}
