using Foreman.Core.Settings;
using Microsoft.Win32;
using System.IO;
using System.Linq;

namespace Foreman.App;

/// <summary>
/// Thin registry wrapper for the "start with Windows" feature. Per-user HKCU Run
/// entry — no elevation needed. All decision logic lives in
/// <see cref="StartupRegistration"/> (Core, unit-tested); this type only does the I/O.
/// </summary>
public static class StartupManager
{
    /// <summary>True if a Run entry for Foreman Agent Safety exists (the registry is the source of truth).</summary>
    public static bool IsEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(StartupRegistration.RunKeyPath);
            if (key is null) return false;
            return key.GetValue(StartupRegistration.RunValueName) is string
                || StartupRegistration.LegacyRunValueNames.Any(n => key.GetValue(n) is string);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Registers/unregisters the currently running exe. Throws on registry failure so the UI can report it.</summary>
    public static void SetEnabled(bool on)
    {
        using var key = Registry.CurrentUser.CreateSubKey(StartupRegistration.RunKeyPath, writable: true)
            ?? throw new InvalidOperationException("Cannot open the HKCU Run key.");

        if (on)
        {
            var exe = Environment.ProcessPath
                ?? throw new InvalidOperationException("Cannot resolve Foreman Agent Safety's executable path.");
            key.SetValue(StartupRegistration.RunValueName, StartupRegistration.BuildCommand(exe));
        }
        else
        {
            key.DeleteValue(StartupRegistration.RunValueName, throwOnMissingValue: false);
        }
        // Always drop every legacy alias (incl. the no-space "ForemanAgentSafety") so neither enabling nor
        // disabling can leave a stranded duplicate Run entry behind.
        foreach (var name in StartupRegistration.LegacyRunValueNames)
            key.DeleteValue(name, throwOnMissingValue: false);
    }

    /// <summary>
    /// If start-with-Windows is on, returns a warning when the registered exe lives on a drive that may be
    /// absent at sign-in (removable / network / a secondary-fixed disk like W: that can be disconnected or
    /// mount late) — the classic "it silently didn't start at boot" cause. Null when off, safe, or unknown.
    /// Reads the live registry value + the target drive's OS type; best-effort.
    /// </summary>
    public static string? GetDriveWarning()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(StartupRegistration.RunKeyPath);
            var value = (key?.GetValue(StartupRegistration.RunValueName) as string)
                     ?? StartupRegistration.LegacyRunValueNames.Select(n => key?.GetValue(n) as string).FirstOrDefault(v => v is not null);
            var exe = StartupRegistration.ParseExePath(value);
            if (exe is null) return null;   // feature off / malformed

            var root = Path.GetPathRoot(exe);
            var driveType = DriveType.Unknown;
            try { if (!string.IsNullOrEmpty(root)) driveType = new DriveInfo(root).DriveType; }
            catch { /* drive absent right now — ClassifyDriveRisk still flags it via the root != system-drive check */ }

            var systemRoot = Path.GetPathRoot(Environment.SystemDirectory);   // e.g. "C:\"
            var risk = StartupRegistration.ClassifyDriveRisk(exe, systemRoot, driveType);
            return StartupRegistration.DescribeDriveRisk(risk, exe);
        }
        catch { return null; }
    }

    /// <summary>
    /// Called once at app launch: if the feature is on but the registered exe has moved
    /// or the value is malformed, re-point it at the running exe. Best-effort — startup
    /// must never fail over a registry hiccup.
    /// </summary>
    public static void RepairIfNeeded()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(StartupRegistration.RunKeyPath, writable: true);
            if (key is null) return;

            var currentValue = key.GetValue(StartupRegistration.RunValueName) as string;
            // First present legacy alias ("Foreman", "ForemanAgentSafety", …) from any older build.
            var legacyValue = StartupRegistration.LegacyRunValueNames
                .Select(n => key.GetValue(n) as string)
                .FirstOrDefault(v => v is not null);
            if (currentValue is null && legacyValue is null) return;   // feature off — nothing to do

            var value = currentValue ?? legacyValue!;
            var current = Environment.ProcessPath;
            if (current is null) return;

            if (StartupRegistration.NeedsRepair(value, current, File.Exists))
                key.SetValue(StartupRegistration.RunValueName, StartupRegistration.BuildCommand(current));
            else if (currentValue is null)
                key.SetValue(StartupRegistration.RunValueName, value);   // migrate a legacy-only entry to the canonical name

            // Always remove EVERY legacy alias so a stale duplicate (e.g. the no-space name) can't double-launch at logon.
            foreach (var name in StartupRegistration.LegacyRunValueNames)
                key.DeleteValue(name, throwOnMissingValue: false);
        }
        catch { /* best-effort */ }
    }
}
