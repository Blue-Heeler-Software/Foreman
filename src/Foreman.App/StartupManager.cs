using Foreman.Core.Settings;
using Microsoft.Win32;
using System.IO;

namespace Foreman.App;

/// <summary>
/// Thin registry wrapper for the "start with Windows" feature. Per-user HKCU Run
/// entry — no elevation needed. All decision logic lives in
/// <see cref="StartupRegistration"/> (Core, unit-tested); this type only does the I/O.
/// </summary>
public static class StartupManager
{
    /// <summary>True if a Run entry for Foreman exists (the registry is the source of truth).</summary>
    public static bool IsEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(StartupRegistration.RunKeyPath);
            return key?.GetValue(StartupRegistration.RunValueName) is string;
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
                ?? throw new InvalidOperationException("Cannot resolve Foreman's executable path.");
            key.SetValue(StartupRegistration.RunValueName, StartupRegistration.BuildCommand(exe));
        }
        else
        {
            key.DeleteValue(StartupRegistration.RunValueName, throwOnMissingValue: false);
        }
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
            if (key?.GetValue(StartupRegistration.RunValueName) is not string value) return;

            var current = Environment.ProcessPath;
            if (current is null) return;

            if (StartupRegistration.NeedsRepair(value, current, File.Exists))
                key.SetValue(StartupRegistration.RunValueName, StartupRegistration.BuildCommand(current));
        }
        catch { /* best-effort */ }
    }
}
