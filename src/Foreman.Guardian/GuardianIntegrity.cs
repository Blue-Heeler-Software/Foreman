using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;

namespace Foreman.Guardian;

/// <summary>
/// Authenticode gate for the guardian, mirroring the App's <c>SidecarIntegrity</c> (B5). Two uses:
///  - CLIENT AUTH (runtime): the guardian signs the event-log head ONLY for a caller whose binary carries the
///    same Authenticode signer as the guardian itself — so a same-user agent can't connect to the pipe and ask
///    the guardian to sign a forged chain head (which would defeat the entire prevention tier).
///  - INSTALL SELF-VERIFY (LPE guard): before registering itself as a LocalSystem service, the elevated guardian
///    confirms its OWN binary carries the same signer as the installed Foreman.exe — so an agent that overwrote
///    the user-writable staged guardian binary can't get its code registered as SYSTEM.
///
/// Auto-adapts to dev vs release exactly like the sidecar: when the reference binary is UNSIGNED (dev build) no
/// trust anchor exists, so it allows; the LPE/forgery targets the signed, branded release, where it enforces.
///
/// Deliberately duplicated from SidecarIntegrity (App is WPF the guardian must not reference; Core is
/// cross-platform so Windows-only WinVerifyTrust can't live there). CONSOLIDATE into a shared Windows platform
/// assembly when Codex's Foreman.Platform refactor lands.
/// </summary>
[SupportedOSPlatform("windows")]
public static class GuardianIntegrity
{
    /// <summary>Pure trust decision from two VERIFIED signer thumbprints (null = unsigned/invalid).</summary>
    public static (bool Trusted, string Reason) Decide(string? referenceSigner, string? subjectSigner)
    {
        if (referenceSigner is null)
            return (true, "reference binary is unsigned (dev build) — signature not enforced.");
        if (subjectSigner is null)
            return (false, "the subject binary is unsigned or its Authenticode signature is invalid, but the reference is signed.");
        if (!string.Equals(referenceSigner, subjectSigner, StringComparison.OrdinalIgnoreCase))
            return (false, "the subject binary is signed by a different publisher than the reference.");
        return (true, "Authenticode signer matches the reference publisher.");
    }

    /// <summary>Client auth: is <paramref name="clientPath"/> signed by the SAME publisher as this guardian? Never throws.</summary>
    public static (bool Trusted, string Reason) VerifyClient(string? clientPath) =>
        SafeVerify(reference: Environment.ProcessPath, subject: clientPath);

    /// <summary>Install self-verify: is THIS guardian binary signed by the same publisher as Foreman.exe? Never throws.</summary>
    public static (bool Trusted, string Reason) VerifyForInstall(string? foremanPath) =>
        SafeVerify(reference: foremanPath, subject: Environment.ProcessPath);

    private static (bool, string) SafeVerify(string? reference, string? subject)
    {
        try
        {
            return Decide(VerifiedSignerThumbprint(reference), VerifiedSignerThumbprint(subject));
        }
        catch
        {
            // Fault → fail CLOSED only when the reference is signed; otherwise (dev) allow.
            var refSigned = SafeVerifiedSigner(reference) is not null;
            return refSigned
                ? (false, "integrity check failed unexpectedly while the reference is signed.")
                : (true, "integrity check inconclusive; reference is unsigned (dev).");
        }
    }

    private static string? SafeVerifiedSigner(string? p) { try { return VerifiedSignerThumbprint(p); } catch { return null; } }

    /// <summary>Authenticode signer thumbprint IF the file's embedded signature is valid (chains to a trusted root); else null.</summary>
    private static string? VerifiedSignerThumbprint(string? path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
        if (!IsAuthenticodeValid(path)) return null;
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return cert.Thumbprint;
        }
        catch { return null; }
    }

    // ── WinVerifyTrust interop (mirrors SidecarIntegrity) ──────────────────────────────────────────────
    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private const uint WTD_UI_NONE = 2, WTD_REVOKE_NONE = 0, WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1, WTD_STATEACTION_CLOSE = 2, WTD_SAFER_FLAG = 0x100;

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

    private static bool IsAuthenticodeValid(string path)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = path,
        };
        var pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        var data = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = WTD_CHOICE_FILE,
            dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = WTD_SAFER_FLAG,
        };
        var pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, fDeleteOld: false);
            data.pFile = pFile;
            Marshal.StructureToPtr(data, pData, fDeleteOld: false);

            var result = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

            data.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(data, pData, fDeleteOld: false);
            WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

            return result == 0;
        }
        finally
        {
            Marshal.FreeHGlobal(pData);
            Marshal.FreeHGlobal(pFile);
        }
    }
}
