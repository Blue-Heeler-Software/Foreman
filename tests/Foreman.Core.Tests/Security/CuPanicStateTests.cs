using Foreman.Core.Security;

namespace Foreman.Core.Tests.Security;

public sealed class CuPanicStateTests
{
    [Fact]
    public void StartsActive_NotHalted() => Assert.False(new CuPanicState().IsHalted);

    [Fact]
    public void Halt_SetsHalted_AndIsIdempotent()
    {
        var s = new CuPanicState();
        Assert.True(s.Halt());     // first halt changes state
        Assert.True(s.IsHalted);
        Assert.False(s.Halt());    // second is a no-op
        Assert.True(s.IsHalted);
    }

    [Fact]
    public void Resume_Clears_AndIsIdempotent()
    {
        var s = new CuPanicState();
        s.Halt();
        Assert.True(s.Resume());   // clears
        Assert.False(s.IsHalted);
        Assert.False(s.Resume());  // no-op
    }

    [Fact]
    public void Changed_FiresOnEachTransition_NotOnNoOp()
    {
        var s = new CuPanicState();
        var seen = new List<bool>();
        s.Changed += halted => seen.Add(halted);
        s.Halt();    // -> true
        s.Halt();    // no-op (no event)
        s.Resume();  // -> false
        s.Resume();  // no-op
        Assert.Equal(new[] { true, false }, seen);
    }

    [Fact]
    public void Changed_ThrowingSubscriber_DoesNotWedgeThePanicPath()
    {
        var s = new CuPanicState();
        s.Changed += _ => throw new InvalidOperationException("boom");
        Assert.True(s.Halt());     // the flag must still flip despite a bad subscriber
        Assert.True(s.IsHalted);
    }
}

/// <summary>Resuming computer use after a panic stop is a weakening action: gated by presence when the lock is on.</summary>
public sealed class ResumeComputerUseGatingTests
{
    [Fact]
    public void ResumeComputerUse_GatedWhenLockOn()
        => Assert.True(PresenceLockPolicy.RequiresPresence(
            WeakeningAction.ResumeComputerUse,
            new PresenceLockSettings { Enabled = true, Scope = LockScope.Standard }));

    [Fact]
    public void ResumeComputerUse_NotGatedWhenLockOff()
        => Assert.False(PresenceLockPolicy.RequiresPresence(
            WeakeningAction.ResumeComputerUse,
            new PresenceLockSettings { Enabled = false }));
}
