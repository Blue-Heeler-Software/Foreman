using Foreman.Core.Models;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace Foreman.Monitor;

/// <summary>
/// Thread-safe store of all tracked processes. Keyed by (pid, startTimeMs) to survive PID reuse.
/// </summary>
public sealed class ProcessTreeTracker
{
    private readonly ConcurrentDictionary<string, ProcessRecord> _records = new();
    // secondary lookup: pid → key (last winner wins on reuse)
    private readonly ConcurrentDictionary<int, string> _pidIndex = new();

    public IEnumerable<ProcessRecord> GetAll() => _records.Values;

    public ProcessRecord? GetByPid(int pid)
    {
        if (_pidIndex.TryGetValue(pid, out var key) && _records.TryGetValue(key, out var rec))
            return rec;
        return null;
    }

    public void OnProcessCreated(ProcessRecord record)
    {
        _records[record.Key] = record;
        _pidIndex[record.Pid] = record.Key;
    }

    /// <summary>
    /// Called when a process exits. Returns all live children that are now orphaned.
    /// </summary>
    public IReadOnlyList<ProcessRecord> OnProcessDeleted(
        int pid,
        DateTimeOffset? startTime,
        out ProcessRecord? deleted)
    {
        deleted = null;

        string? key = null;
        if (startTime is not null)
        {
            var stableKey = $"{pid}:{startTime.Value.ToUnixTimeMilliseconds()}";
            if (_records.ContainsKey(stableKey))
                key = stableKey;
        }

        if (key is null && !_pidIndex.TryGetValue(pid, out key)) return [];

        _records.TryRemove(key, out deleted);
        if (_pidIndex.TryGetValue(pid, out var indexedKey) && indexedKey == key)
            _pidIndex.TryRemove(pid, out _);

        // find children whose parent was this pid and are still alive
        var orphans = _records.Values
            .Where(r => r.ParentPid == pid && r.State != ProcessState.Terminated)
            .ToList();
        foreach (var orphan in orphans)
            orphan.State = ProcessState.Orphaned;
        return orphans;
    }

    /// <summary>
    /// Reconciliation pass: evicts tracked records whose process is no longer live, so the tree can't
    /// accumulate stale entries when a WMI termination event is dropped under load (the classic
    /// "thousands of monitored processes vs hundreds real" drift). A record is removed ONLY when its PID
    /// is absent from <paramref name="livePids"/> — a PID missing from the full OS process list is
    /// definitively gone — so a live process is never evicted on uncertainty. Records younger than
    /// <paramref name="minAge"/> are kept, since they may simply post-date a snapshot taken a moment
    /// before they were created. Returns the evicted records so the caller can log the reconciliation.
    ///
    /// Pure and deterministic for testing; <see cref="PruneDeadProcesses"/> supplies the live set.
    /// NOTE: a reused PID keeps BOTH its records alive here (the live PID protects them); that rarer case
    /// is handled by <see cref="OnProcessCreated"/> re-pointing the index, not by this janitor.
    /// </summary>
    public IReadOnlyList<ProcessRecord> Prune(IReadOnlySet<int> livePids, DateTimeOffset now, TimeSpan minAge)
    {
        List<ProcessRecord>? evicted = null;
        foreach (var rec in _records.Values)   // ConcurrentDictionary snapshot enumeration is safe under concurrent writes
        {
            if (livePids.Contains(rec.Pid)) continue;     // still alive
            if (now - rec.StartTime < minAge) continue;   // too young — may post-date the live snapshot
            if (_records.TryRemove(rec.Key, out var removed))
            {
                // Only drop the pid→key index if it still points at the record we removed (a PID reused
                // after the snapshot would have re-pointed the index at the newer record — leave that).
                if (_pidIndex.TryGetValue(rec.Pid, out var idxKey) && idxKey == rec.Key)
                    _pidIndex.TryRemove(rec.Pid, out _);
                (evicted ??= []).Add(removed);
            }
        }
        return evicted ?? (IReadOnlyList<ProcessRecord>)[];
    }

    /// <summary>
    /// Gathers the live OS PID set and prunes dead records against it. Best-effort: a process that exits
    /// mid-enumeration simply isn't in the set (and is pruned on the next pass).
    /// </summary>
    public IReadOnlyList<ProcessRecord> PruneDeadProcesses(TimeSpan minAge)
    {
        var live = new HashSet<int>();
        foreach (var p in Process.GetProcesses())
        {
            live.Add(p.Id);
            p.Dispose();
        }
        return Prune(live, DateTimeOffset.UtcNow, minAge);
    }

    public bool IsTrackedHarness(int pid)
    {
        var rec = GetByPid(pid);
        return rec?.IsHarness ?? false;
    }

    /// <summary>
    /// Walks the parent chain from <paramref name="pid"/> (inclusive) and returns the first
    /// record matching <paramref name="match"/>, or null.
    ///
    /// Safe against PID reuse, missing parents, and cycles: the walk stops as soon as a
    /// parent is no longer tracked, and a visited-set prevents infinite loops. Failing to
    /// find a match returns null, so callers fail *toward silence* (no false attribution).
    /// </summary>
    private ProcessRecord? WalkAncestors(int pid, Func<ProcessRecord, bool> match)
    {
        var seen = new HashSet<int>();
        var current = GetByPid(pid);
        while (current is not null && seen.Add(current.Pid))
        {
            if (match(current)) return current;
            // A genuine harness subtree never descends THROUGH a Windows OS host (svchost, services, sihost,
            // …) — a real harness child hits its harness match first. So an OS host appearing as an ANCESTOR
            // means this parent edge is stale / a reused PID / an unreliable WMI ParentProcessId: stop here
            // rather than mis-attributing an unrelated OS process to a harness (which then floods hang notices).
            if (IsSystemHost(current.Name)) break;
            if (current.ParentPid == 0 || current.ParentPid == current.Pid) break;
            current = GetByPid(current.ParentPid);
        }
        return null;
    }

    // Windows OS hosts that never sit INSIDE a harness's process subtree. Hitting one while walking ANCESTORS
    // marks the chain above it untrustworthy (PID reuse / stale ppid), so the walk stops and attributes nothing.
    private static readonly HashSet<string> SystemHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "services.exe", "wininit.exe", "winlogon.exe", "lsass.exe", "csrss.exe", "smss.exe",
        "explorer.exe", "sihost.exe", "taskhostw.exe", "dwm.exe", "fontdrvhost.exe", "ctfmon.exe",
        "RuntimeBroker.exe", "MoUsoCoreWorker.exe", "usocoreworker.exe", "dllhost.exe", "WmiPrvSE.exe",
        "System", "Registry", "MemCompression",
    };

    private static bool IsSystemHost(string? name) => name is not null && SystemHosts.Contains(name);

    /// <summary>
    /// Nearest ancestor (including the process itself) that is an actively-monitored harness
    /// (IsHarness == true). Used to scope hang detection to harness trees.
    /// </summary>
    public ProcessRecord? FindHarnessAncestor(int pid) => WalkAncestors(pid, static r => r.IsHarness);

    /// <summary>
    /// Nearest ancestor (including the process itself) that carries a HarnessType — even a
    /// disabled one. Used to *attribute* a child process to the harness it belongs to: a
    /// PowerShell hook or a shell spawned by claude-code matches no harness rule itself, but
    /// its parent chain leads back to the harness node process.
    /// </summary>
    public ProcessRecord? FindHarnessTypeAncestor(int pid) => WalkAncestors(pid, static r => r.HarnessType is not null);

    /// <summary>
    /// Nearest ancestor (including the process itself) with a matched permission profile.
    /// </summary>
    public ProcessRecord? FindProfileAncestor(int pid) => WalkAncestors(pid, static r => r.ProfileName is not null);

    /// <summary>
    /// Nearest ancestor (including the process itself) whose command line is a package install
    /// (npm/pnpm/yarn/bun install, node-gyp, pip/uv install, python setup.py). Used to escalate a
    /// credential/network rule that fires INSIDE an install subtree — the Miasma / Phantom-Gyp
    /// install-time detonation, where such a read is almost never legitimate.
    /// </summary>
    public ProcessRecord? FindInstallAncestor(int pid) =>
        WalkAncestors(pid, static r => Foreman.Core.Security.InstallSubtree.IsPackageInstall(r.CommandLine));

    public void UpdateIoCounters(int pid, ulong readOps, ulong writeOps)
    {
        if (!_pidIndex.TryGetValue(pid, out var key)) return;
        if (!_records.TryGetValue(key, out var rec)) return;

        if (readOps != rec.LastReadOps || writeOps != rec.LastWriteOps)
        {
            rec.LastReadOps = readOps;
            rec.LastWriteOps = writeOps;
            rec.LastIoChangeTime = DateTimeOffset.UtcNow;
            rec.State = ProcessState.Active;
        }
    }

    public void SetState(int pid, ProcessState state)
    {
        if (!_pidIndex.TryGetValue(pid, out var key)) return;
        if (_records.TryGetValue(key, out var rec))
            rec.State = state;
    }

    /// <summary>
    /// Returns all currently tracked processes whose HarnessType matches
    /// (case-insensitive). Used by BehaviorMetricsWindow / EscalationAlarmWindow.
    /// </summary>
    public IEnumerable<ProcessRecord> GetByHarnessType(string harnessType) =>
        _records.Values.Where(r =>
            string.Equals(r.HarnessType, harnessType, StringComparison.OrdinalIgnoreCase));

    public IEnumerable<ProcessRecord> GetTreeByHarnessType(string harnessType) =>
        _records.Values.Where(r =>
            string.Equals(r.HarnessType, harnessType, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(FindHarnessTypeAncestor(r.Pid)?.HarnessType, harnessType, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Terminates every tracked process in the matching harness tree. Driven by the LIVE tree
    /// (not a stale alert), so each record is current by construction. Skips Foreman itself and
    /// the low system PIDs. Silently ignores processes that have already exited.
    /// </summary>
    public void KillHarness(string harnessType)
    {
        foreach (var rec in GetTreeByHarnessType(harnessType).ToList())
        {
            if (KillGuard.IsProtected(rec.Pid, rec.Name)) continue;   // never the OS, the shell, AV, or Foreman's own
            try
            {
                using var proc = Process.GetProcessById(rec.Pid);
                proc.Kill(entireProcessTree: rec.IsHarness);
                SetState(rec.Pid, ProcessState.Terminated);
            }
            catch { /* already exited or access denied */ }
        }
    }

    /// <summary>
    /// Terminates the process identified by <paramref name="pid"/> AND <paramref name="expectedStartTime"/>
    /// (the WMI CreationDate captured on the originating alert), plus its descendant tree.
    ///
    /// Identity is proven by comparing the alert's captured start time against the CURRENTLY-tracked
    /// record for that PID — both are the same WMI source, so equal means "same process" and a recycled
    /// PID (which has a different CreationDate, or is no longer tracked) is refused. This is what makes a
    /// stale alert safe: it cannot kill an unrelated process that later inherited the PID.
    ///
    /// Returns false when the target can't be verified, isn't tracked, has exited, or access is denied.
    /// </summary>
    public bool KillProcess(int pid, DateTimeOffset? expectedStartTime)
    {
        if (KillGuard.IsProtectedPid(pid)) return false;
        if (expectedStartTime is not { } expected) return false;   // no identity pin → never kill a bare PID

        var rec = GetByPid(pid);
        if (rec is null) return false;                             // not tracked (exited or never seen)
        if (KillGuard.IsProtected(pid, rec.Name)) return false;    // protected by name (Foreman/guardian/sidecar/OS/AV)
        if (Math.Abs((rec.StartTime - expected).TotalSeconds) > 1) return false;  // PID reused since the alert

        try
        {
            using var proc = Process.GetProcessById(pid);
            proc.Kill(entireProcessTree: true);
            SetState(pid, ProcessState.Terminated);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
