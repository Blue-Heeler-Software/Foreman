using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Xml.Linq;
using Foreman.Core.Ipc;
using Foreman.Core.Security;

namespace Foreman.EtwSidecar;

/// <summary>
/// Elevated decoy read-auditing. Places a SACL audit ACE (audit successful ReadData by Everyone) on each
/// decoy credential file, enables the Windows "Audit File System" subcategory if it isn't already on, and
/// tails the Security log for Event 4663 (object access). Any read of a tracked decoy by a process other
/// than Foreman becomes a <see cref="DecoyReadMessage"/> the sidecar streams to the app.
///
/// All of this needs admin (the sidecar is the only elevated component). Cleanup is exact: it removes only the
/// audit ACEs it owns — the ones it added this run, plus any identical Everyone/ReadData/Success ACE it adopted
/// from a prior run that crashed before cleanup (its own signature on its own decoy) — and reverts the audit
/// subcategory ONLY if it was the one to enable it, so a policy the user already had is never touched. A broader
/// pre-existing rule is never adopted or stripped. Everything is wrapped so a failure degrades to "no decoy
/// auditing" rather than throwing.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class DecoyAudit : IDisposable
{
    private readonly string[] _decoyPaths;
    private readonly int[] _excludedPids;
    private readonly ConcurrentQueue<DecoyReadMessage> _hits = new();
    private readonly List<string> _sacled = [];
    private EventLogWatcher? _watcher;
    private bool _weEnabledAuditPol;

    public DecoyAudit(IEnumerable<string> decoyPaths, IEnumerable<int> excludedPids)
    {
        _decoyPaths = decoyPaths.Where(p => !string.IsNullOrWhiteSpace(p)).ToArray();
        _excludedPids = excludedPids.ToArray();
    }

    public bool Start()
    {
        if (_decoyPaths.Length == 0) return false;
        try
        {
            EnablePrivilege("SeSecurityPrivilege");
            foreach (var p in _decoyPaths)
                if (EnsureAuditAce(p)) _sacled.Add(p);
            // _sacled now holds every path we are actually auditing — ones we newly SACL'd AND ones that already
            // carried our exact ACE from a prior run that crashed before Cleanup. If it is empty, every decoy is
            // missing or unwritable, so there is nothing to watch. (The old gate keyed off only NEWLY-added ACEs,
            // so a full set of crash-orphaned ACEs left the watcher un-started while the app still showed
            // "connected" — a silently dead tripwire.)
            if (_sacled.Count == 0) return false;
            _weEnabledAuditPol = EnableFileSystemAuditingIfNeeded();
            StartWatcher();
            return true;
        }
        catch { Cleanup(); return false; }
    }

    /// <summary>Pulls any decoy reads observed since the last call (the pipe-writer loop drains this).</summary>
    public IReadOnlyList<DecoyReadMessage> Drain()
    {
        var list = new List<DecoyReadMessage>();
        while (_hits.TryDequeue(out var m)) list.Add(m);
        return list;
    }

    private void StartWatcher()
    {
        var query = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=4663)]]");
        _watcher = new EventLogWatcher(query);
        _watcher.EventRecordWritten += OnEvent;
        _watcher.Enabled = true;
    }

    private void OnEvent(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord is null) return;
        try
        {
            var (objectName, pid, image) = ParseAccessEvent(e.EventRecord.ToXml());
            if (pid == 0) return;
            if (!DecoyAuditPolicy.IsDecoyRead(objectName, pid, image, _decoyPaths, _excludedPids)) return;
            _hits.Enqueue(new DecoyReadMessage
            {
                TimestampUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Path = objectName ?? string.Empty,
                Pid = pid,
                Image = image ?? string.Empty,
            });
        }
        catch { /* one bad event — ignore */ }
        finally { try { e.EventRecord.Dispose(); } catch { } }
    }

    // 4663 EventData carries ObjectName, ProcessId (hex), ProcessName (accessing image).
    private static (string? objectName, int pid, string? image) ParseAccessEvent(string xml)
    {
        var doc = XDocument.Parse(xml);
        XNamespace ns = doc.Root!.Name.Namespace;
        string? obj = null, image = null;
        var pid = 0;
        foreach (var d in doc.Descendants(ns + "Data"))
        {
            switch ((string?)d.Attribute("Name"))
            {
                case "ObjectName":  obj = d.Value; break;
                case "ProcessName": image = d.Value; break;
                case "ProcessId":   pid = ParsePid(d.Value); break;
            }
        }
        return (obj, pid, image);
    }

    private static int ParsePid(string v)
    {
        v = v.Trim();
        try
        {
            return v.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                ? (int)Convert.ToInt64(v[2..], 16)
                : (int.TryParse(v, out var p) ? p : 0);
        }
        catch { return 0; }
    }

    // Ensures our exact Everyone/ReadData/Success audit ACE is present on a decoy path. Returns true when that
    // ACE is present as a result — whether we just added it, OR an identical one already existed. We ADOPT the
    // pre-existing case because that ACE is our own signature on a decoy WE plant and audit: it can only be a
    // leftover from a prior run that crashed before Cleanup. Adopting it means (a) we count the path as audited
    // so the watcher actually starts, and (b) a clean teardown reclaims and removes it (RemoveAuditRuleSpecific
    // targets ONLY the exact ReadData/Success ACE, so a BROADER pre-existing rule like Everyone/FullControl is
    // still never stripped). Returns false only when the file is missing or the SACL write failed — i.e. the
    // path is NOT being audited and must not keep the watcher alive on its own.
    private static bool EnsureAuditAce(string path)
    {
        try
        {
            if (!File.Exists(path)) return false;
            var fi = new FileInfo(path);
            var sec = fi.GetAccessControl(AccessControlSections.Audit);
            var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

            foreach (FileSystemAuditRule r in sec.GetAuditRules(true, true, typeof(SecurityIdentifier)))
                if (Equals(r.IdentityReference, everyone)
                    && r.FileSystemRights == FileSystemRights.ReadData
                    && r.AuditFlags == AuditFlags.Success)
                    return true;   // our exact ACE already present (crash-orphaned) — adopt: watch it, remove on teardown

            sec.AddAuditRule(new FileSystemAuditRule(everyone, FileSystemRights.ReadData, AuditFlags.Success));
            fi.SetAccessControl(sec);
            return true;
        }
        catch { return false; }
    }

    // Removes ONLY the exact Everyone/ReadData/Success ACE we added (RemoveAuditRuleSpecific, not ...All —
    // ...All would also strip a broader pre-existing rule like Everyone/FullControl/Success). Called only for
    // paths in _sacled, i.e. where TrySetAuditAce actually added the rule.
    private static void TryRemoveAuditAce(string path)
    {
        try
        {
            if (!File.Exists(path)) return;
            var fi = new FileInfo(path);
            var sec = fi.GetAccessControl(AccessControlSections.Audit);
            sec.RemoveAuditRuleSpecific(new FileSystemAuditRule(
                new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                FileSystemRights.ReadData, AuditFlags.Success));
            fi.SetAccessControl(sec);
        }
        catch { }
    }

    // Returns true only if WE flipped it on (so we revert exactly what we changed).
    private static bool EnableFileSystemAuditingIfNeeded()
    {
        try
        {
            if (RunAuditpol("/get /subcategory:\"File System\"").Contains("Success", StringComparison.OrdinalIgnoreCase))
                return false;
            RunAuditpol("/set /subcategory:\"File System\" /success:enable");
            return true;
        }
        catch { return false; }
    }

    private static string RunAuditpol(string args)
    {
        var psi = new ProcessStartInfo("auditpol", args)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var p = Process.Start(psi)!;
        var o = p.StandardOutput.ReadToEnd();
        p.WaitForExit(5000);
        return o;
    }

    private void Cleanup()
    {
        try { if (_watcher is not null) { _watcher.Enabled = false; _watcher.Dispose(); _watcher = null; } } catch { }
        foreach (var p in _sacled) TryRemoveAuditAce(p);
        _sacled.Clear();
        if (_weEnabledAuditPol)
        {
            try { RunAuditpol("/set /subcategory:\"File System\" /success:disable"); } catch { }
            _weEnabledAuditPol = false;
        }
    }

    public void Dispose() => Cleanup();

    // ── enable SeSecurityPrivilege in this (elevated) token, required to write a SACL ──────────────────
    [StructLayout(LayoutKind.Sequential)] private struct LUID { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] private struct TOKEN_PRIVILEGES { public uint Count; public LUID Luid; public uint Attributes; }

    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool LookupPrivilegeValue(string? system, string name, out LUID luid);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES newState, uint len, IntPtr prev, IntPtr retLen);

    private const uint TOKEN_ADJUST_PRIVILEGES = 0x20, TOKEN_QUERY = 0x8, SE_PRIVILEGE_ENABLED = 0x2;

    private static void EnablePrivilege(string name)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var tok)) return;
        try
        {
            if (!LookupPrivilegeValue(null, name, out var luid)) return;
            var tp = new TOKEN_PRIVILEGES { Count = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
            AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        }
        finally { CloseHandle(tok); }
    }
}
