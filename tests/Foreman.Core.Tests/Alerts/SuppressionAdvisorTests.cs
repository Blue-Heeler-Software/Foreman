using Foreman.Core.Alerts;

namespace Foreman.Core.Tests.Alerts;

public sealed class SuppressionAdvisorTests
{
    private static AdaptiveAlertSettings Settings(int after = 3) => new() { Enabled = true, SuggestAfterAcks = after };
    private static readonly DateTimeOffset T = DateTimeOffset.UnixEpoch;

    [Theory]   // SECURITY / behavioural classes are NEVER eligible to be quieted, no matter how often dismissed
    [InlineData("win-001")]
    [InlineData("cred-decoy-read")]
    [InlineData("command")]
    [InlineData("escalation")]
    [InlineData("decoy")]
    public void SecurityClasses_NeverSuggest(string type)
    {
        var s = Settings(after: 2);
        SuppressionSuggestion? last = null;
        for (var i = 0; i < 10; i++) last = SuppressionAdvisor.RecordOperatorAck(s, "claude-code", type, T);
        Assert.Null(last);
        Assert.Empty(s.Patterns);   // ineligible classes aren't even tracked
    }

    [Fact]   // an operational class repeatedly dismissed → a one-time quieting suggestion
    public void HangClass_SuggestsAtThreshold_RaiseHangThreshold()
    {
        var s = Settings(after: 3);
        Assert.Null(SuppressionAdvisor.RecordOperatorAck(s, "djc-mcp", "hang", T));   // 1
        Assert.Null(SuppressionAdvisor.RecordOperatorAck(s, "djc-mcp", "hang", T));   // 2
        var sug = SuppressionAdvisor.RecordOperatorAck(s, "djc-mcp", "hang", T);      // 3 → suggest
        Assert.NotNull(sug);
        Assert.Equal(SuppressionSuggestionKind.RaiseHangThreshold, sug!.Kind);
        Assert.Equal("djc-mcp", sug.HarnessId);
        Assert.Equal(3, sug.AckCount);
    }

    [Theory]   // non-hang operational classes suggest a class mute instead of a threshold bump
    [InlineData("orphan")]
    [InlineData("idle")]
    [InlineData("nonzero-exit")]
    public void NonHangOperational_SuggestsMuteClass(string type)
    {
        var s = Settings(after: 2);
        SuppressionAdvisor.RecordOperatorAck(s, "codex", type, T);
        var sug = SuppressionAdvisor.RecordOperatorAck(s, "codex", type, T);
        Assert.Equal(SuppressionSuggestionKind.MuteClass, sug!.Kind);
    }

    [Fact]   // surfaced ONCE — further dismissals don't re-nag (the advisor must not become noise itself)
    public void Suggestion_FiresOnlyOnce()
    {
        var s = Settings(after: 2);
        SuppressionAdvisor.RecordOperatorAck(s, "djc-mcp", "hang", T);
        Assert.NotNull(SuppressionAdvisor.RecordOperatorAck(s, "djc-mcp", "hang", T));   // first cross → suggest
        Assert.Null(SuppressionAdvisor.RecordOperatorAck(s, "djc-mcp", "hang", T));      // still counts, no re-nag
        Assert.Null(SuppressionAdvisor.RecordOperatorAck(s, "djc-mcp", "hang", T));
        Assert.Equal(4, s.Patterns["djc-mcp|hang"].AckCount);
    }

    [Fact]
    public void BelowThreshold_NoSuggestion()
    {
        var s = Settings(after: 5);
        for (var i = 0; i < 4; i++) Assert.Null(SuppressionAdvisor.RecordOperatorAck(s, "djc-mcp", "hang", T));
    }

    [Fact]   // disabled → no tracking, no suggestion
    public void Disabled_DoesNothing()
    {
        var s = new AdaptiveAlertSettings { Enabled = false, SuggestAfterAcks = 1 };
        Assert.Null(SuppressionAdvisor.RecordOperatorAck(s, "djc-mcp", "hang", T));
        Assert.Empty(s.Patterns);
    }

    [Fact]
    public void MissingHarness_AttributedToUnattributed()
    {
        var s = Settings(after: 1);
        var sug = SuppressionAdvisor.RecordOperatorAck(s, "", "hang", T);
        Assert.Equal("(unattributed)", sug!.HarnessId);
    }
}
