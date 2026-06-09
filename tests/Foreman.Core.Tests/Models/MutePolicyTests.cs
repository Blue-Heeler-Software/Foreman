using Foreman.Core.Models;

namespace Foreman.Core.Tests.Models;

public sealed class MutePolicyTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UnixEpoch;
    private static readonly string[] Emergency = ["cred-005", "net-001"];

    private static CommandAlertEvent Cmd(ForemanSeverity sev, string ruleId) =>
        new(Now, sev, "MCP.Test", "msg", "cmd", ruleId, "name", "desc", "guidance", 0);

    private static HangDetectedEvent Hang() =>
        new(Now, "Foreman.Monitor", "bash hung", 1234, "bash", 60, 30, null, null, null, null, null);

    // ── Protection ────────────────────────────────────────────────────────────
    [Fact] public void Critical_IsProtected()
        => Assert.True(MutePolicy.IsProtected(Cmd(ForemanSeverity.Critical, "del-001"), Emergency));

    [Fact] public void EmergencyRule_IsProtected_EvenAtMedium()
        => Assert.True(MutePolicy.IsProtected(Cmd(ForemanSeverity.Medium, "cred-005"), Emergency));

    [Fact] public void CredCategory_IsProtected()
        => Assert.True(MutePolicy.IsProtected(Cmd(ForemanSeverity.Medium, "cred-013"), Emergency));

    [Fact] public void Hang_IsNotProtected()
        => Assert.False(MutePolicy.IsProtected(Hang(), Emergency));

    // ── Create-mute guardrail ───────────────────────────────────────────────────
    [Fact]
    public void Protected_RefusesPermanentMute()
        => Assert.Null(MutePolicy.CreateMute(Cmd(ForemanSeverity.Critical, "del-001"), duration: null, Emergency, Now));

    [Fact]
    public void Protected_RefusesOverCapSnooze()
        => Assert.Null(MutePolicy.CreateMute(Cmd(ForemanSeverity.Critical, "del-001"), TimeSpan.FromMinutes(120), Emergency, Now));

    [Fact]
    public void Protected_AllowsShortSnooze()
    {
        var m = MutePolicy.CreateMute(Cmd(ForemanSeverity.Critical, "del-001"), TimeSpan.FromMinutes(30), Emergency, Now);
        Assert.NotNull(m);
        Assert.Equal(Now + TimeSpan.FromMinutes(30), m!.Until);
        Assert.Equal("rule", m.Scope);
        Assert.Equal("del-001", m.Value);
    }

    [Fact]
    public void NonProtected_AllowsPermanentMute()
    {
        var m = MutePolicy.CreateMute(Hang(), duration: null, Emergency, Now);
        Assert.NotNull(m);
        Assert.Null(m!.Until);                       // permanent allowed for a hang
        Assert.Equal("source", m.Scope);             // no ruleId → scope by source
        Assert.Equal("Foreman.Monitor", m.Value);
    }

    // ── Suppression matching ────────────────────────────────────────────────────
    [Fact]
    public void IsSuppressed_MatchesActiveRuleMute()
    {
        var mutes = new[] { new MuteEntry { Scope = "rule", Value = "net-002", Until = Now + TimeSpan.FromHours(1) } };
        Assert.True(MutePolicy.IsSuppressed(Cmd(ForemanSeverity.High, "net-002"), mutes, Now));
    }

    [Fact]
    public void IsSuppressed_IgnoresExpiredMute()
    {
        var mutes = new[] { new MuteEntry { Scope = "rule", Value = "net-002", Until = Now - TimeSpan.FromMinutes(1) } };
        Assert.False(MutePolicy.IsSuppressed(Cmd(ForemanSeverity.High, "net-002"), mutes, Now));
    }

    [Fact]
    public void IsSuppressed_SourceScope_MutesHang()
    {
        var mutes = new[] { new MuteEntry { Scope = "source", Value = "Foreman.Monitor", Until = null } };
        Assert.True(MutePolicy.IsSuppressed(Hang(), mutes, Now));
    }

    [Fact]
    public void IsSuppressed_NoMatch_NotSuppressed()
    {
        var mutes = new[] { new MuteEntry { Scope = "rule", Value = "net-002" } };
        Assert.False(MutePolicy.IsSuppressed(Cmd(ForemanSeverity.High, "cred-001"), mutes, Now));
    }
}
