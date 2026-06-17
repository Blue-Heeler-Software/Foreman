using Foreman.Core.Events;
using Foreman.Core.Notifications;

namespace Foreman.Core.Tests.Events;

/// <summary>
/// B9 watchdog-of-the-watchdog: reconstruct how the prior Foreman instance ended from the OS event log. A hard
/// kill (TerminateProcess) leaves a dangling Started with no terminal marker — that's the signal a clean stop or
/// crash would not produce, so it must classify as Killed and survive (re-logged) into the next life.
/// </summary>
public sealed class LifecycleForensicsTests
{
    private static OsEventRecord R(int id) => new(id, "x");

    [Fact]
    public void NoRecords_IsUnknown()
        => Assert.Equal(PriorShutdown.Unknown, LifecycleForensics.ClassifyFrom(Array.Empty<OsEventRecord>()));

    [Fact]
    public void TrailingStoppedClean_IsClean()
        => Assert.Equal(PriorShutdown.Clean, LifecycleForensics.ClassifyFrom(new[]
        {
            R(OsEventIds.StoppedClean), R(OsEventIds.Started), // newest first
        }));

    [Fact]
    public void DanglingStarted_IsKilled() // ran, never recorded a terminal event = TerminateProcess
        => Assert.Equal(PriorShutdown.Killed, LifecycleForensics.ClassifyFrom(new[]
        {
            R(OsEventIds.Started),
            R(OsEventIds.StoppedClean), // the run BEFORE this one ended clean — irrelevant; we take the most recent
        }));

    [Fact]
    public void HandledCrashThenGone_IsKilled() // survived a dispatcher exception, then vanished without a terminal marker
        => Assert.Equal(PriorShutdown.Killed, LifecycleForensics.ClassifyFrom(new[]
        {
            R(OsEventIds.CrashHandled), R(OsEventIds.Started),
        }));

    [Fact]
    public void FatalCrash_IsCrashed() // already alerted at crash time — not a silent kill
        => Assert.Equal(PriorShutdown.Crashed, LifecycleForensics.ClassifyFrom(new[]
        {
            R(OsEventIds.CrashFatal), R(OsEventIds.Started),
        }));

    [Fact]
    public void AnchorAndSecurityNoise_AreNotRunMarkers() // the rollback anchor + security events must not be mistaken for a stop
    {
        var records = new[]
        {
            R(OsEventIds.LogChainAnchor),   // most recent, but NOT a run-marker
            R(OsEventIds.CommandAlert),     // security noise after the kill window — also not a run-marker
            R(OsEventIds.Started),          // the real last run-marker → dangling → Killed
        };
        Assert.Equal(OsEventIds.Started, LifecycleForensics.LastRunMarker(records));
        Assert.Equal(PriorShutdown.Killed, LifecycleForensics.ClassifyFrom(records));
    }
}
