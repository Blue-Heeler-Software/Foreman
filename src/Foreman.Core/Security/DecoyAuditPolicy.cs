namespace Foreman.Core.Security;

/// <summary>
/// Pure decision logic for the elevated SACL read-auditing layer: given a Windows Security-log file-access
/// event (Event 4663 — object name + accessing PID), decide whether it is a genuine read of a tracked decoy
/// credential worth a Critical alert. Shared by the elevated sidecar (which filters the noisy 4663 stream
/// down to decoy hits before sending anything over the pipe) and the app, and unit-tested here so the
/// sidecar's filter is verified without needing elevation.
///
/// The key correctness point: Foreman itself reads the decoy files during sentinel re-validation
/// (<see cref="DecoyCredentialManager.Revalidate"/>) and on plant/remove — so the app's own PID (and the
/// sidecar's) MUST be excluded, or Foreman would alarm on its own housekeeping.
/// </summary>
public static class DecoyAuditPolicy
{
    /// <summary>
    /// True when a 4663 read of <paramref name="objectName"/> by <paramref name="subjectPid"/> is a real
    /// decoy read: the path equals one of <paramref name="decoyPaths"/> and the reader is not an excluded
    /// PID (Foreman app + sidecar).
    /// </summary>
    public static bool IsDecoyRead(
        string? objectName,
        int subjectPid,
        IReadOnlyCollection<string> decoyPaths,
        IReadOnlyCollection<int> excludedPids)
    {
        if (string.IsNullOrWhiteSpace(objectName)) return false;
        if (excludedPids.Contains(subjectPid)) return false;

        var target = Normalize(objectName);
        foreach (var d in decoyPaths)
            if (Normalize(d).Equals(target, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    /// <summary>Normalises a Windows path for comparison: strips a \\?\ long-path prefix, unifies separators.</summary>
    public static string Normalize(string path)
    {
        var p = path.Trim();
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p[4..];
        return p.Replace('/', '\\').TrimEnd('\\');
    }
}
