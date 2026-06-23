using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Foreman.Core.ComputerUse;

namespace Foreman.App.ComputerUse;

/// <summary>
/// App-side writer of the shared panic + bound-window signal (spec INV-2 / INV-3) that the desktop sidecar reads
/// before every input. The map is created UNNAMED, so no same-user process can <c>OpenExisting</c> it; the sidecar
/// gets read access only via a READ-ONLY duplicated handle (<see cref="DuplicateReadOnlyHandleInto"/>) pushed over the
/// authenticated control pipe after the handshake. The App is therefore the ONLY writer of panic/boundHwnd/epoch -
/// the read's #1 carry-forward (a same-user named DACL alone cannot make this guarantee; create-handle RW vs a
/// duplicated read-only handle does).
///
/// Layout (little-endian): [0]=panic byte, [8]=bound HWND (long), [16]=epoch (long). The epoch is written LAST so a
/// reader that re-reads it can detect a torn read (seqlock). The App mirrors <c>CuPanicState.Changed</c> into this.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class CuSharedPanicFlag : ICuPanicSignal, IDisposable
{
    private const int Capacity = 64;
    private const long OffPanic = 0, OffHwnd = 8, OffEpoch = 16;

    private readonly object _lock = new();
    private readonly MemoryMappedFile _mmf;
    private readonly MemoryMappedViewAccessor _view;   // the App's read-write creation view (the only writer)
    private long _epoch;
    private byte _expectedPanic;                        // canary baseline = what the App last wrote

    public int MapCapacity => Capacity;

    public CuSharedPanicFlag()
    {
        // Unnamed (mapName: null) => not reachable by name; only a duplicated handle grants access.
        _mmf = MemoryMappedFile.CreateNew(null, Capacity, MemoryMappedFileAccess.ReadWrite);
        _view = _mmf.CreateViewAccessor(0, Capacity, MemoryMappedFileAccess.ReadWrite);
        _view.Write(OffPanic, (byte)0);
        _view.Write(OffHwnd, 0L);
        _view.Write(OffEpoch, 0L);
        _view.Flush();
    }

    public bool IsHalted { get { lock (_lock) return _view.ReadByte(OffPanic) != 0; } }
    public long BoundHwnd { get { lock (_lock) return _view.ReadInt64(OffHwnd); } }
    public long Epoch { get { lock (_lock) return _view.ReadInt64(OffEpoch); } }

    public void SetHalted(bool halted)
    {
        lock (_lock)
        {
            var b = (byte)(halted ? 1 : 0);
            _view.Write(OffPanic, b);
            _expectedPanic = b;
            _view.Write(OffEpoch, ++_epoch);   // epoch LAST (seqlock)
            _view.Flush();
        }
    }

    public void SetBound(long hwnd)
    {
        lock (_lock)
        {
            _view.Write(OffHwnd, hwnd);
            _view.Write(OffEpoch, ++_epoch);   // epoch LAST
            _view.Flush();
        }
    }

    /// <summary>
    /// Duplicate a READ-ONLY handle of the (unnamed) map into <paramref name="targetProcess"/> (the sidecar) and
    /// return the handle value as it exists in THAT process - to be sent over the authenticated pipe. The sidecar
    /// maps it with FILE_MAP_READ; it can never obtain write access (the duplicated handle carries only
    /// SECTION_MAP_READ), and no other process can reach the map at all (it is unnamed). Returns 0 on failure.
    /// </summary>
    public long DuplicateReadOnlyHandleInto(IntPtr targetProcess)
    {
        var self = GetCurrentProcess();
        var source = _mmf.SafeMemoryMappedFileHandle.DangerousGetHandle();
        if (!DuplicateHandle(self, source, targetProcess, out var dup, SECTION_MAP_READ, bInheritHandle: false, dwOptions: 0))
            return 0;
        return dup.ToInt64();
    }

    /// <summary>Tamper canary: the map is unnamed + the only other handle is read-only, so the panic byte must always
    /// equal what the App last wrote. Any divergence means an unexpected writer reached the mapping (or memory
    /// corruption) - the caller treats it as Critical (halt + kill the sidecar). Returns true on tamper.</summary>
    public bool DetectTamper()
    {
        lock (_lock) return _view.ReadByte(OffPanic) != _expectedPanic;
    }

    public void Dispose()
    {
        try { _view.Dispose(); } catch { }
        try { _mmf.Dispose(); } catch { }
    }

    private const uint SECTION_MAP_READ = 0x0004;   // == FILE_MAP_READ

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(
        IntPtr hSourceProcess, IntPtr hSourceHandle, IntPtr hTargetProcess,
        out IntPtr lpTargetHandle, uint dwDesiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);
}
