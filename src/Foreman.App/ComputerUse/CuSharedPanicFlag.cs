using System.IO.MemoryMappedFiles;
using System.Runtime.Versioning;
using System.Threading;
using Foreman.Core.ComputerUse;

namespace Foreman.App.ComputerUse;

/// <summary>
/// App-side writer of the shared panic + bound-window signal (spec INV-2 / INV-3). Backed by a named memory-mapped
/// file the sidecar reads before every input (Slice 4) and a named auto-reset event that wakes it the instant a
/// halt is set, so a panic interrupts even a mid-stream injection without waiting for the next poll.
///
/// Layout (little-endian): [0]=panic byte, [8]=bound HWND (long), [16]=epoch (long). The epoch is written LAST so a
/// reader that observes a new epoch knows the other fields are already committed (a seqlock-style discipline) and a
/// stale read is detectable. Same-user processes can open this by name; the read-only-to-sidecar guarantee (a
/// read-only duplicated handle) is completed in Slice 4 - in Slice 3 the App is the only party that touches it.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class CuSharedPanicFlag : ICuPanicSignal, IDisposable
{
    private const int Capacity = 64;
    private const long OffPanic = 0, OffHwnd = 8, OffEpoch = 16;

    private readonly object _lock = new();
    private readonly MemoryMappedFile _mmf;
    private readonly MemoryMappedViewAccessor _view;
    private readonly EventWaitHandle _wake;
    private long _epoch;

    /// <summary>Names the sidecar uses to open the same objects (passed on its command line in Slice 4).</summary>
    public string MapName { get; }
    public string EventName { get; }

    public CuSharedPanicFlag()
    {
        var id = Guid.NewGuid().ToString("N");
        MapName = "foreman-cu-panic-" + id;
        EventName = "foreman-cu-wake-" + id;
        _mmf = MemoryMappedFile.CreateNew(MapName, Capacity);
        _view = _mmf.CreateViewAccessor(0, Capacity, MemoryMappedFileAccess.ReadWrite);
        _wake = new EventWaitHandle(false, EventResetMode.AutoReset, EventName);
        _view.Write(OffPanic, (byte)0);
        _view.Write(OffHwnd, 0L);
        _view.Write(OffEpoch, 0L);
    }

    public bool IsHalted { get { lock (_lock) return _view.ReadByte(OffPanic) != 0; } }
    public long BoundHwnd { get { lock (_lock) return _view.ReadInt64(OffHwnd); } }
    public long Epoch { get { lock (_lock) return _view.ReadInt64(OffEpoch); } }

    public void SetHalted(bool halted)
    {
        lock (_lock)
        {
            _view.Write(OffPanic, (byte)(halted ? 1 : 0));
            _view.Write(OffEpoch, ++_epoch);   // epoch last
            _view.Flush();
        }
        if (halted) { try { _wake.Set(); } catch { } }   // wake the sidecar out of any wait immediately
    }

    public void SetBound(long hwnd)
    {
        lock (_lock)
        {
            _view.Write(OffHwnd, hwnd);
            _view.Write(OffEpoch, ++_epoch);   // epoch last
            _view.Flush();
        }
    }

    public void Dispose()
    {
        try { _view.Dispose(); } catch { }
        try { _mmf.Dispose(); } catch { }
        try { _wake.Dispose(); } catch { }
    }
}
