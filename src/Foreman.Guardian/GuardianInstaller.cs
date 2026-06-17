using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Foreman.Core.Notifications;

namespace Foreman.Guardian;

/// <summary>
/// Installs / uninstalls the guardian as a LocalSystem Windows service (circle-back Phase A, the privilege
/// boundary). Runs ELEVATED (the app launches it with runas). Steps, in order, idempotent + rolled back on failure:
///   1. LPE guard — verify this binary is the genuine same-publisher Foreman before it can become SYSTEM.
///   2. Copy the guardian payload to %ProgramFiles%\Foreman\guardian (NOT user-writable).
///   3. ACL it: SYSTEM + Administrators full, Users read+execute (no write) — the agent can't tamper the binary.
///   4. Create + ACL %ProgramData%\Foreman\guardian as SYSTEM/Admins only (no interactive user) for SYSTEM state.
///   5. CreateService LocalSystem, auto-start (Win32 — no sc.exe quoting pitfalls).
///   6. Register the OS event-log source.
///   7. Start it.
/// Uninstall is presence-gated by the caller; here it just stops → deletes the service → removes the dirs.
///
/// The path/gate logic is pure + testable; the privileged execution (CreateService, ACLs, ProgramFiles writes)
/// can only be validated by an actual elevated run.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class GuardianInstaller
{
    public const string ServiceName = "Foreman.Guardian";
    public const string DisplayName = "Foreman Agent Safety Guardian";

    public static string ProgramFilesDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Foreman", "guardian");
    public static string ProgramDataDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Foreman", "guardian");
    public static string InstalledExePath => Path.Combine(ProgramFilesDir, "Foreman.Guardian.exe");

    public static int Install(string? foremanPath, Action<string> log)
    {
        // 1. LPE guard — refuse to register a binary that isn't the genuine, same-publisher Foreman as SYSTEM.
        var (trusted, reason) = GuardianIntegrity.VerifyForInstall(foremanPath);
        if (!trusted) { log($"install REFUSED (integrity): {reason}"); return 2; }
        log($"integrity ok: {reason}");

        var srcDir = Path.GetDirectoryName(Environment.ProcessPath)!;
        try
        {
            CopyTree(srcDir, ProgramFilesDir, log);          // 2
            HardenDir(ProgramFilesDir, allowUsersReadExecute: true);   // 3
            HardenDir(ProgramDataDir, allowUsersReadExecute: false);   // 4 (SYSTEM/Admins only)

            CreateService(InstalledExePath, log);            // 5
            TryRegisterEventSource(log);                     // 6
            StartService(log);                               // 7

            log("guardian installed and started.");
            return 0;
        }
        catch (Exception ex)
        {
            log($"install FAILED: {ex.Message} — rolling back.");
            Rollback(log);
            return 4;
        }
    }

    public static int Uninstall(Action<string> log)
    {
        try
        {
            StopAndDeleteService(log);
            TryDeleteDir(ProgramFilesDir, log);
            TryDeleteDir(ProgramDataDir, log);
            log("guardian uninstalled.");
            return 0;
        }
        catch (Exception ex)
        {
            log($"uninstall error: {ex.Message}");
            return 4;
        }
    }

    private static void Rollback(Action<string> log)
    {
        try { StopAndDeleteService(log); } catch { }
        TryDeleteDir(ProgramFilesDir, log);
        TryDeleteDir(ProgramDataDir, log);
    }

    // ── filesystem ───────────────────────────────────────────────────────────────────────────────────
    private static void CopyTree(string src, string dst, Action<string> log)
    {
        Directory.CreateDirectory(dst);
        foreach (var dir in Directory.GetDirectories(src, "*", SearchOption.AllDirectories))
            Directory.CreateDirectory(dir.Replace(src, dst));
        foreach (var file in Directory.GetFiles(src, "*", SearchOption.AllDirectories))
            File.Copy(file, file.Replace(src, dst), overwrite: true);
        log($"copied guardian payload → {dst}");
    }

    private static void HardenDir(string dir, bool allowUsersReadExecute)
    {
        Directory.CreateDirectory(dir);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);   // drop inherited (user) ACEs
        sec.SetOwner(admins);
        sec.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        if (allowUsersReadExecute)
            sec.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));

        new DirectoryInfo(dir).SetAccessControl(sec);
    }

    private static void TryDeleteDir(string dir, Action<string> log)
    {
        try { if (Directory.Exists(dir)) { Directory.Delete(dir, recursive: true); log($"removed {dir}"); } }
        catch (Exception ex) { log($"could not remove {dir}: {ex.Message}"); }
    }

    private static void TryRegisterEventSource(Action<string> log)
    {
        try
        {
            if (!System.Diagnostics.EventLog.SourceExists(OsEventLogNames.SourceName))
            {
                System.Diagnostics.EventLog.CreateEventSource(
                    new System.Diagnostics.EventSourceCreationData(OsEventLogNames.SourceName, OsEventLogNames.LogName));
                log("registered OS event-log source.");
            }
        }
        catch (Exception ex) { log($"event-source registration skipped: {ex.Message}"); }
    }

    // ── Win32 service control (advapi32) ──────────────────────────────────────────────────────────────
    private const uint SC_MANAGER_ALL_ACCESS = 0xF003F, SERVICE_ALL_ACCESS = 0xF01FF;
    private const uint SERVICE_WIN32_OWN_PROCESS = 0x10, SERVICE_AUTO_START = 0x2, SERVICE_ERROR_NORMAL = 0x1;
    private const uint SERVICE_CONTROL_STOP = 0x1;

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS { public uint a, b, c, d, e, f, g; }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? machine, string? db, uint access);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateService(IntPtr scm, string name, string display, uint access, uint type,
        uint start, uint error, string binPath, string? group, IntPtr tagId, string? deps, string? user, string? pwd);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenService(IntPtr scm, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool StartService(IntPtr svc, uint argc, string[]? argv);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ControlService(IntPtr svc, uint control, ref SERVICE_STATUS status);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DeleteService(IntPtr svc);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr h);

    private const int ERROR_SERVICE_EXISTS = 1073;

    private static void CreateService(string exePath, Action<string> log)
    {
        var scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed");
        try
        {
            // binPath stored verbatim by SCM (no shell) — quote the exe (Program Files has a space) + the verb.
            var binPath = $"\"{exePath}\" --service";
            var svc = CreateService(scm, ServiceName, DisplayName, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, binPath, null, IntPtr.Zero, null, null /*=LocalSystem*/, null);
            if (svc == IntPtr.Zero)
            {
                var err = Marshal.GetLastWin32Error();
                if (err == ERROR_SERVICE_EXISTS) { log("service already exists — reusing."); return; }
                throw new Win32Exception(err, "CreateService failed");
            }
            CloseServiceHandle(svc);
            log("service created (LocalSystem, auto-start).");
        }
        finally { CloseServiceHandle(scm); }
    }

    private static void StartService(Action<string> log)
    {
        var scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed");
        try
        {
            var svc = OpenService(scm, ServiceName, SERVICE_ALL_ACCESS);
            if (svc == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenService failed");
            try
            {
                if (!StartService(svc, 0, null))
                {
                    var err = Marshal.GetLastWin32Error();
                    if (err != 1056) log($"start returned {err} (1056 = already running).");  // ERROR_SERVICE_ALREADY_RUNNING
                    else log("service already running.");
                }
                else log("service started.");
            }
            finally { CloseServiceHandle(svc); }
        }
        finally { CloseServiceHandle(scm); }
    }

    private static void StopAndDeleteService(Action<string> log)
    {
        var scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed");
        try
        {
            var svc = OpenService(scm, ServiceName, SERVICE_ALL_ACCESS);
            if (svc == IntPtr.Zero) { log("service not present."); return; }
            try
            {
                var status = new SERVICE_STATUS();
                ControlService(svc, SERVICE_CONTROL_STOP, ref status);   // best-effort stop
                System.Threading.Thread.Sleep(500);
                if (!DeleteService(svc)) log($"DeleteService returned {Marshal.GetLastWin32Error()}.");
                else log("service deleted.");
            }
            finally { CloseServiceHandle(svc); }
        }
        finally { CloseServiceHandle(scm); }
    }
}
