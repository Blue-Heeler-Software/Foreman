using System.Runtime.Versioning;

namespace Foreman.App;

/// <summary>
/// Off-UI-thread wrapper around <see cref="ResourceSampler"/>. A background <see cref="PeriodicTimer"/> loop
/// samples the caller's pid set on a steady cadence and publishes the latest <see cref="ResourceSampler.Metrics"/>
/// snapshot; the UI just reads <see cref="Latest"/> — never touching the slow path (the per-process handle reads
/// and, worst of all, the GPU performance-counter enumeration) on the dispatcher.
///
/// CPU and I/O are rates computed from deltas between samples, so the steady background interval is exactly the
/// cadence <see cref="ResourceSampler"/> needs — and a single loop means no overlapping, non-thread-safe Sample()
/// calls. The snapshot is an immutable dictionary swapped in atomically, so a UI read is always consistent.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class UiTelemetryCache : IDisposable
{
    private readonly ResourceSampler _sampler = new();
    private readonly Func<IReadOnlyCollection<int>> _pids;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;
    private volatile IReadOnlyDictionary<int, ResourceSampler.Metrics> _latest =
        new Dictionary<int, ResourceSampler.Metrics>();

    public UiTelemetryCache(Func<IReadOnlyCollection<int>> pids, TimeSpan? interval = null)
    {
        _pids = pids;
        // Task.Run the WHOLE loop onto the thread pool. RunAsync's first Sample() runs SYNCHRONOUSLY (it's before
        // the first await), so calling RunAsync directly here would run that sample — including the slow and, on
        // some NVIDIA systems, indefinitely-HANGING GPU performance-counter read — on the CALLER's thread, which
        // is the WPF UI thread (this cache is built in window constructors). That wedged the whole dispatcher when
        // the dashboard/Process-Monitor opened. Task.Run guarantees sampling never touches the UI thread.
        _loop = Task.Run(() => RunAsync(interval ?? TimeSpan.FromSeconds(2), _cts.Token));
    }

    /// <summary>The most recent completed sample. Empty until the first background pass finishes (≈immediately).</summary>
    public IReadOnlyDictionary<int, ResourceSampler.Metrics> Latest => _latest;

    /// <summary>Metrics for one pid, or null if it wasn't in the latest sample (gone / not yet sampled).</summary>
    public ResourceSampler.Metrics? For(int pid) => _latest.TryGetValue(pid, out var m) ? m : null;

    private async Task RunAsync(TimeSpan interval, CancellationToken ct)
    {
        using var timer = new PeriodicTimer(interval);
        // Sample once immediately so the first UI read isn't empty, then on the steady cadence.
        do
        {
            try { _latest = _sampler.Sample(_pids()); }
            catch { /* best-effort telemetry — a bad pass must never kill the loop */ }
        }
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false));
    }

    public void Dispose()
    {
        _cts.Cancel();
        // BOUNDED wait — Dispose runs on the UI thread (window close), and the loop may be parked in an
        // uncancellable native GPU counter read. Never block the dispatcher waiting for it; let that thread die on
        // its own. A short join is enough for the common (idle) case.
        try { _loop.Wait(TimeSpan.FromSeconds(2)); }
        catch { /* cancelled / already finished / faulted */ }
        _cts.Dispose();
        _sampler.Dispose();
    }
}
