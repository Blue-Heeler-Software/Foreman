using System.IO;
using Microsoft.Win32;

namespace Foreman.App;

/// <summary>
/// Discovers whether the opt-in guardian service is installed (circle-back Phase A). A cheap HKLM read — present
/// ⇒ the app routes sealing through the guardian; absent ⇒ it keeps the per-user local path (the casual default).
/// Reading the Services key needs no elevation; any failure reads as "not installed" so discovery never throws.
/// </summary>
internal static class GuardianDiscovery
{
    public const string ServiceName = "Foreman.Guardian";
    public static string InstalledExePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        "Foreman", "guardian", "Foreman.Guardian.exe");

    public static bool IsGuardianInstalled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{ServiceName}");
            return key is not null;
        }
        catch
        {
            return false;
        }
    }
}
