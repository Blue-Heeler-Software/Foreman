namespace Foreman.Core.Settings;

/// <summary>
/// Pure logic for the "start Foreman when the user signs in" registration —
/// building, parsing, and repairing the HKCU Run value. The registry itself is
/// the single source of truth for whether the feature is on (no settings field),
/// so the JSON settings and the OS can never disagree. The actual registry I/O
/// lives in Foreman.App (StartupManager); this type stays platform-free so the
/// decisions are unit-testable.
/// </summary>
public static class StartupRegistration
{
    /// <summary>Value name under HKCU\Software\Microsoft\Windows\CurrentVersion\Run.</summary>
    public const string RunValueName = "Foreman";

    /// <summary>Relative registry path of the per-user Run key.</summary>
    public const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";

    /// <summary>Builds the Run value for an exe path. Always quoted — paths contain spaces.</summary>
    public static string BuildCommand(string exePath) => $"\"{exePath}\"";

    /// <summary>
    /// Extracts the exe path from an existing Run value: quoted token if quoted,
    /// up to and including ".exe" otherwise, whole value as a last resort.
    /// Returns null for empty or malformed (unterminated quote) values.
    /// </summary>
    public static string? ParseExePath(string? runValue)
    {
        if (string.IsNullOrWhiteSpace(runValue)) return null;
        var v = runValue.Trim();

        if (v.StartsWith('"'))
        {
            var end = v.IndexOf('"', 1);
            return end > 1 ? v[1..end] : null;
        }

        var exe = v.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return exe >= 0 ? v[..(exe + 4)] : v;
    }

    /// <summary>
    /// True when the registered entry should be rewritten to point at the running exe.
    /// Heals a moved/renamed install (registered exe no longer exists) and malformed
    /// values, but never hijacks a registration whose target is still present — so a
    /// Debug build run from bin\ won't steal the entry from a published install.
    /// No-ops when the feature is off (no value).
    /// </summary>
    public static bool NeedsRepair(string? existingValue, string currentExePath, Func<string, bool> fileExists)
    {
        if (string.IsNullOrWhiteSpace(existingValue)) return false;   // feature off — nothing to repair

        var registered = ParseExePath(existingValue);
        if (registered is null) return true;                          // malformed — rewrite

        if (string.Equals(registered, currentExePath, StringComparison.OrdinalIgnoreCase))
            return false;                                             // already us

        return !fileExists(registered);                               // heal only if the target is gone
    }
}
