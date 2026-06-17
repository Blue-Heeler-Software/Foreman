using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Foreman.Guardian;

/// <summary>
/// Holds the settings-seal secret behind the SYSTEM boundary (circle-back Phase A, step 7). Stored under
/// %ProgramData%\Foreman\guardian (ACL'd by the installer to SYSTEM + Administrators only — no interactive user),
/// generated on first use. Because the medium-IL agent can't read it, it can't recompute the settings seal to
/// forge a weakened posture — the same protection the head-seal key gets, applied to the settings seal.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class GuardianSecret
{
    private readonly string _path;
    private string? _cached;

    public GuardianSecret(string? dir = null)
        => _path = Path.Combine(dir ?? GuardianInstaller.ProgramDataDir, "settings.secret");

    /// <summary>Returns the secret, creating + persisting one (32 random bytes, base64) on first use.</summary>
    public string Get()
    {
        if (_cached is not null) return _cached;
        try
        {
            if (File.Exists(_path))
            {
                var existing = File.ReadAllText(_path).Trim();
                if (existing.Length >= 32) return _cached = existing;
            }
        }
        catch { /* unreadable — mint a fresh one */ }

        var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.WriteAllText(_path, secret);
        }
        catch { /* can't persist — still usable this run */ }
        return _cached = secret;
    }
}
