using Foreman.Core.Security;

namespace Foreman.Core.Tests.Security;

/// <summary>Dead-man's switch (#62): fires once when the operator is absent past the window while agents run, and re-arms on return.</summary>
public sealed class DeadMansSwitchPolicyTests
{
    private static DeadMansSwitchSettings On(int absence = 240) => new() { Enabled = true, AbsenceMinutes = absence };

    [Fact]
    public void Disabled_NeverFires()
        => Assert.False(DeadMansSwitchPolicy.ShouldFire(9999, 5, alreadyFired: false, new DeadMansSwitchSettings()));

    [Fact]
    public void Absent_WithActiveAgents_Fires()
        => Assert.True(DeadMansSwitchPolicy.ShouldFire(241, 2, alreadyFired: false, On()));

    [Fact]
    public void NoActiveAgents_DoesNotFire() // unattended only matters while agents run
        => Assert.False(DeadMansSwitchPolicy.ShouldFire(999, 0, alreadyFired: false, On()));

    [Fact]
    public void BelowThreshold_DoesNotFire()
        => Assert.False(DeadMansSwitchPolicy.ShouldFire(239, 2, alreadyFired: false, On()));

    [Fact]
    public void AlreadyFired_DoesNotReFire() // one notice per absence episode
        => Assert.False(DeadMansSwitchPolicy.ShouldFire(500, 2, alreadyFired: true, On()));

    [Theory]
    [InlineData(0, true)]      // operator active → re-arm
    [InlineData(239, true)]    // still below threshold → re-arm
    [InlineData(240, false)]   // at/over threshold → stay armed (don't reset)
    [InlineData(999, false)]
    public void ShouldRearm_TracksReturn(int absence, bool expected)
        => Assert.Equal(expected, DeadMansSwitchPolicy.ShouldRearm(absence, On()));
}
