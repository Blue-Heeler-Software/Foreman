using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading;
using Foreman.Core.ComputerUse;

namespace Foreman.App.ComputerUse;

/// <summary>
/// App-side writer of the shared panic + bound-window signal (spec INV-2 / INV-3) that the desktop sidecar reads
/// before every input. The map is created UNNAMED, so no process can <c>OpenExisting</c> it by name; the sidecar gets
/// read access only via a READ-ONLY duplicated handle (<see cref="DuplicateReadOnlyHandleInto"/>) pushed over the
/// authenticated control pipe after the handshake - a handle that physically cannot be escalated to write. So the
/// sidecar cannot forge the halt or move the bound window, and no process can reach the map by name.
///
/// HONEST LIMIT (review finding): this makes the App the only *intended* writer, not an absolute one. A same-user
/// process that gets PROCESS_VM_WRITE or PROCESS_DUP_HANDLE on the App can write its mapped pages (or pull the App's
/// read-write handle) directly - but that is the general "an attacker who can write Foreman's own process memory owns
/// Foreman" residual (identical to patching <c>CuPanicState</c> in-process), out of the bounded medium-IL threat model
/// and not fixable by a memory map. INV-3's HARD floor is therefore the App-side TerminateProcess(sidecar) + BlockInput
/// (Slice 4b), which does NOT depend on this byte; this map is the fast in-sidecar abort, not the floor.
///
/// Layout (little-endian): [0]=panic byte, [8]=bound HWND (long), [16]=epoch (long). Each writer commits the field(s)
/// then a release barrier then the epoch LAST, so a reader's seqlock (epoch read-fields-read, retry on mismatch) gets
/// a tear-free snapshot. The canary records the App's expected panic/hwnd/epoch and flags ANY divergence. The App
/// mirrors <c>CuPanicState.Changed</c> into this.
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
    private byte _expectedPanic;     // canary baselines = exactly what the App last wrote to each field
    private long _expectedHwnd;
    private long _expectedEpoch;

    public int MapCapacity => Capacity;

    public CuSharedPanicFlag()
    {
        // Unnamed (mapName: null) => not reachable by name; only a duplicated handle grants access.
        _mmf = MemoryMappedFile.CreateNew(null, Capacity, MemoryMappedFileAccess.ReadWrite);
        _view = _mmf.CreateViewAccessor(0, Capacity, MemoryMappedFileAccess.ReadWrite);
        _view.Write(OffPanic, (byte)0);
        _view.Write(OffHwnd, 0L);
        _view.Write(OffEpoch, 0L);   // Flush is unnecessary for a memory-backed map (shared pages are coherent)
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
            Thread.MemoryBarrier();             // release: the field commits before the epoch that publishes it
            _view.Write(OffEpoch, ++_epoch);    // epoch LAST (seqlock)
            _expectedPanic = b; _expectedEpoch = _epoch;
        }
    }

    public void SetBound(long hwnd)
    {
        lock (_lock)
        {
            _view.Write(OffHwnd, hwnd);
            Thread.MemoryBarrier();             // release: the field commits before the epoch that publishes it
            _view.Write(OffEpoch, ++_epoch);    // epoch LAST
            _expectedHwnd = hwnd; _expectedEpoch = _epoch;
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

    /// <summary>Tamper canary across ALL three trust-bearing fields (panic, boundHwnd, epoch): each must equal exactly
    /// what the App last wrote. The real write-protection is the unnamed map + read-only sidecar handle; this canary is
    /// the secondary net that catches the in-process-write residual (PROCESS_VM_WRITE/handle-dup on the App) and memory
    /// corruption. The caller treats true as Critical (kill the sidecar). Returns true on any divergence.</summary>
    public bool DetectTamper()
    {
        lock (_lock)
            return _view.ReadByte(OffPanic) != _expectedPanic
                || _view.ReadInt64(OffHwnd) != _expectedHwnd
                || _view.ReadInt64(OffEpoch) != _expectedEpoch;
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
