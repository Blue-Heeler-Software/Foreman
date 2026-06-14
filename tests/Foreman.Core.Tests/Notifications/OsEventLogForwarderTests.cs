using Foreman.Core.Behavior;
using Foreman.Core.Models;
using Foreman.Core.Notifications;
using Foreman.Core.Security;

namespace Foreman.Core.Tests.Notifications;

public sealed class OsEventLogForwarderTests
{
    private sealed class FakeSink : IOsEventLogSink
    {
        public bool Available = true;
        public readonly List<(int Id, OsEventCategory Cat, ForemanSeverity Sev, string Msg)> Writes = new();
        public bool IsAvailable => Available;
        public string? UnavailableReason => Available ? null : "test-unavailable";
        public void Write(int eventId, OsEventCategory category, ForemanSeverity severity, string message)
            => Writes.Add((eventId, category, severity, message));
    }

    private static readonly DateTimeOffset T = DateTimeOffset.UnixEpoch;

    private static CommandAlertEvent Cmd(string ruleId, string message = "alert", string cmdLine = "do thing") =>
        new(T, ForemanSeverity.High, "Foreman.Monitor", message, cmdLine, ruleId, "rule", "desc", "guidance", 1234);

    private static EscalationEvent Esc(EscalationLevel level) =>
        new(T, level, EscalationLevel.Watch, "codex", "Codex CLI", "reason", 12, 6, 3,
            ["cred", "priv", "net"], "cred-013", "trigger");

    [Fact]   // a security command alert is mirrored with the CommandAlert id, Security category
    public void CommandAlert_IsMirrored()
    {
        var sink = new FakeSink();
        new OsEventLogForwarder(sink).OnEvent(Cmd("cred-001"));
        var w = Assert.Single(sink.Writes);
        Assert.Equal(OsEventIds.CommandAlert, w.Id);
        Assert.Equal(OsEventCategory.Security, w.Cat);
    }

    [Fact]   // the decoy honeytoken rule gets its own high-signal event id
    public void DecoyRule_GetsDecoyTripwireId()
    {
        var sink = new FakeSink();
        new OsEventLogForwarder(sink).OnEvent(Cmd("cred-040"));
        Assert.Equal(OsEventIds.DecoyTripwire, Assert.Single(sink.Writes).Id);
    }

    [Theory]   // escalations map by level; below Alarm they don't qualify at all
    [InlineData(EscalationLevel.Alarm, OsEventIds.EscalationAlarm, true)]
    [InlineData(EscalationLevel.Emergency, OsEventIds.EscalationEmergency, true)]
    public void Escalation_MapsByLevel(EscalationLevel level, int expectedId, bool mirrored)
    {
        var sink = new FakeSink();
        new OsEventLogForwarder(sink).OnEvent(Esc(level));
        if (mirrored) Assert.Equal(expectedId, Assert.Single(sink.Writes).Id);
        else Assert.Empty(sink.Writes);
    }

    [Fact]   // an Alert-tier escalation is below the Alarm bar → not handed off
    public void Escalation_BelowAlarm_NotMirrored()
    {
        var sink = new FakeSink();
        new OsEventLogForwarder(sink).OnEvent(Esc(EscalationLevel.Alert));
        Assert.Empty(sink.Writes);
    }

    [Fact]
    public void PermissionViolation_IsMirrored()
    {
        var sink = new FakeSink();
        new OsEventLogForwarder(sink).OnEvent(
            new PermissionViolationEvent(T, "Foreman.Profiles", "blocked", 1, "claude-code-default", "CommandBlocked", "detail"));
        Assert.Equal(OsEventIds.PermissionViolation, Assert.Single(sink.Writes).Id);
    }

    [Fact]   // operational noise + info chatter must NEVER reach the OS log (kept to JSONL + UI)
    public void OperationalAndInfo_NotMirrored()
    {
        var sink = new FakeSink();
        var fwd = new OsEventLogForwarder(sink);
        fwd.OnEvent(new HangDetectedEvent(T, "Foreman.Monitor", "hang", 1, "bash.exe", 60, 60, null, null, null, null, null));
        fwd.OnEvent(new OrphanDetectedEvent(T, "Foreman.Monitor", "orphan", 1, "bash.exe", 2, "node.exe", 60));
        fwd.OnEvent(new NonzeroExitEvent(T, "Foreman.Monitor", "exit", 1, "git.exe", 1, null));
        fwd.OnEvent(new InfoEvent(T, "Foreman", "monitoring started"));
        Assert.Empty(sink.Writes);
    }

    [Fact]   // secrets are masked before anything reaches the OS log (egress boundary)
    public void Secrets_AreRedactedBeforeWrite()
    {
        const string token = "ghp_0123456789012345678901234567890123";
        var sink = new FakeSink();
        new OsEventLogForwarder(sink).OnEvent(Cmd("cred-020", message: $"leaked {token}", cmdLine: $"echo {token}"));
        var w = Assert.Single(sink.Writes);
        Assert.DoesNotContain(token, w.Msg);
        Assert.Contains(SecretRedactor.Mask, w.Msg);
    }

    [Theory]   // High monitoring notices surface as Health, split by source (WMI degraded vs MCP)
    [InlineData("Foreman.Monitor", OsEventIds.MonitoringDegraded)]
    [InlineData("Foreman.Mcp", OsEventIds.McpServerStateChanged)]
    public void MonitoringNotice_MapsToHealth(string source, int expectedId)
    {
        var sink = new FakeSink();
        new OsEventLogForwarder(sink).OnEvent(
            new MonitoringNoticeEvent(T, ForemanSeverity.High, source, "degraded"));
        var w = Assert.Single(sink.Writes);
        Assert.Equal(expectedId, w.Id);
        Assert.Equal(OsEventCategory.Health, w.Cat);
    }

    [Fact]   // a below-High monitoring notice doesn't clear the audit bar → not mirrored
    public void MonitoringNotice_BelowHigh_NotMirrored()
    {
        var sink = new FakeSink();
        new OsEventLogForwarder(sink).OnEvent(
            new MonitoringNoticeEvent(T, ForemanSeverity.Medium, "Foreman.Monitor", "minor"));
        Assert.Empty(sink.Writes);
    }

    [Fact]   // disabled → nothing is written
    public void Disabled_WritesNothing()
    {
        var sink = new FakeSink();
        new OsEventLogForwarder(sink, () => false).OnEvent(Cmd("cred-001"));
        Assert.Empty(sink.Writes);
    }

    [Fact]   // an unavailable sink (source not registered) is skipped, never forced
    public void UnavailableSink_IsSkipped()
    {
        var sink = new FakeSink { Available = false };
        new OsEventLogForwarder(sink).OnEvent(Cmd("cred-001"));
        Assert.Empty(sink.Writes);
    }
}
