using Foreman.Core.Mcp;

namespace Foreman.Core.Tests.Mcp;

public sealed class PeerIdentityPolicyTests
{
    [Theory]   // the connecting process resolves to the claimed harness → token + transport agree
    [InlineData("claude-code", "claude-code")]
    [InlineData("claude-code", "CLAUDE-CODE")]        // canonical id compared case-insensitively
    [InlineData("custom:foo.exe", "custom:foo.exe")]
    public void SameHarness_Matches(string claimed, string attributed) =>
        Assert.Equal(PeerBindingVerdict.Match, PeerIdentityPolicy.Evaluate(claimed, attributed));

    [Theory]   // THE attack: a different known harness presented this token → stolen/replayed
    [InlineData("claude-code", "codex")]
    [InlineData("codex", "custom:evil.exe")]
    public void DifferentHarness_IsMismatch(string claimed, string attributed) =>
        Assert.Equal(PeerBindingVerdict.Mismatch, PeerIdentityPolicy.Evaluate(claimed, attributed));

    [Theory]   // peer not attributable (PID-lookup miss, classification race, unclassified) → FAIL OPEN
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void UnattributablePeer_IsUnattributed(string? attributed) =>
        Assert.Equal(PeerBindingVerdict.Unattributed, PeerIdentityPolicy.Evaluate("claude-code", attributed));

    [Theory]   // operator token carries no harness claim → out of scope, not a mismatch
    [InlineData(null)]
    [InlineData("")]
    public void NoClaim_IsUnattributed(string? claimed) =>
        Assert.Equal(PeerBindingVerdict.Unattributed, PeerIdentityPolicy.Evaluate(claimed, "claude-code"));
}
