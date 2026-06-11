using Foreman.Core.Security;

namespace Foreman.Core.Tests.Security;

public sealed class PresenceLockPolicyTests
{
    private static PresenceLockSettings Off() => new() { Enabled = false };
    private static PresenceLockSettings Standard() => new() { Enabled = true, Scope = LockScope.Standard };
    private static PresenceLockSettings Strict() => new() { Enabled = true, Scope = LockScope.Strict };

    [Theory]
    [InlineData(WeakeningAction.LowerTrust)]
    [InlineData(WeakeningAction.MuteProtectedAlert)]
    [InlineData(WeakeningAction.DisableMonitoring)]
    [InlineData(WeakeningAction.DisableReadAuditing)]
    [InlineData(WeakeningAction.DisableLogPersist)]
    [InlineData(WeakeningAction.ClearOrRotateLog)]
    [InlineData(WeakeningAction.EditHarnessSysprompt)]
    [InlineData(WeakeningAction.ExitForeman)]
    public void LockOff_GatesNothing(WeakeningAction action)
        => Assert.False(PresenceLockPolicy.RequiresPresence(action, Off()));

    [Theory]
    [InlineData(WeakeningAction.LowerTrust)]
    [InlineData(WeakeningAction.MuteProtectedAlert)]
    [InlineData(WeakeningAction.DisableMonitoring)]
    [InlineData(WeakeningAction.DisableReadAuditing)]
    [InlineData(WeakeningAction.DisableLogPersist)]
    [InlineData(WeakeningAction.ClearOrRotateLog)]
    [InlineData(WeakeningAction.EditHarnessSysprompt)]
    public void Standard_GatesTheWeakeningSet(WeakeningAction action)
        => Assert.True(PresenceLockPolicy.RequiresPresence(action, Standard()));

    [Fact]
    public void Standard_DoesNotGateExit()
        => Assert.False(PresenceLockPolicy.RequiresPresence(WeakeningAction.ExitForeman, Standard()));

    [Fact]
    public void Strict_GatesExitToo()
        => Assert.True(PresenceLockPolicy.RequiresPresence(WeakeningAction.ExitForeman, Strict()));

    [Fact]
    public void Strict_StillGatesTheStandardSet()
        => Assert.True(PresenceLockPolicy.RequiresPresence(WeakeningAction.ClearOrRotateLog, Strict()));

    [Fact]
    public void Defaults_AreOff_AndStandard()
    {
        var s = new PresenceLockSettings();
        Assert.False(s.Enabled);
        Assert.Equal(LockScope.Standard, s.Scope);
    }
}
