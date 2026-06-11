using System.Text;

namespace Foreman.Core.Security;

/// <summary>
/// Decoy ("canary" / honeytoken) credential files. The June-2026 Miasma worm harvests ~130 credential
/// paths; planting believable-but-fake files at the ones you DON'T already use turns the harvester's own
/// enumeration into a near-zero-false-positive tripwire — nothing legitimate ever reads a file you planted
/// as bait.
///
/// Three detection layers stack on these decoys:
///   1. Sentinel-in-command (here, no elevation): each decoy embeds a recognizable sentinel token; if that
///      value ever flows through a monitored command line (echo / upload / base64 staging), rule cred-040
///      fires Critical — the harvester read the bait and is handling it.
///   2. SACL read-auditing (elevated sidecar, separate): a Windows audit ACE on each decoy emits Security
///      Event 4663 on any read, including the payload's direct fopen that no command line shows.
///   3. AWS canarytoken (optional, out-of-band): one decoy can carry a real canarytokens.org AWS key that
///      beacons when the stolen key is USED against AWS.
///
/// Placement is GAPS-ONLY: a decoy is written only where no real file exists, so a working ~/.aws/credentials
/// or ~/.npmrc is never shadowed. Removal only deletes files that still carry the Foreman sentinel, so a real
/// file the user later created in a decoy slot is never destroyed.
/// </summary>
public sealed class DecoyCredentialSettings
{
    /// <summary>Off by default — planting files in the user profile is opt-in.</summary>
    public bool Enabled { get; set; } = false;

    /// <summary>Also enable the elevated SACL read-auditing layer (Security Event 4663). Needs the sidecar.</summary>
    public bool EnableReadAuditing { get; set; } = false;

    /// <summary>Embed a real canarytokens.org / CloudTrail-watched AWS key in the aws-credentials decoy so a USED key beacons.</summary>
    public bool IncludeAwsCanaryToken { get; set; } = false;

    /// <summary>The canarytoken AWS access-key id (user pastes one from canarytokens.org). Not a secret to Foreman — it's bait.</summary>
    public string? AwsCanaryAccessKeyId { get; set; }

    /// <summary>The canarytoken AWS secret. Bait, not a real secret.</summary>
    public string? AwsCanarySecretAccessKey { get; set; }

    /// <summary>Absolute paths Foreman has actually planted, so removal touches only its own decoys.</summary>
    public List<string> PlantedPaths { get; set; } = [];
}

public enum DecoyKind
{
    AwsCredentials,
    SshPrivateKey,
    Npmrc,
    GitCredentials,
    KubeConfig,
    PypiRc,
    NetRc,
    DockerConfig,
}

/// <summary>One candidate decoy location, relative to the user's home directory.</summary>
public sealed record DecoySpec(string RelativePath, DecoyKind Kind);

/// <summary>The outcome of planning placements: what to plant vs. what was skipped because a real file exists.</summary>
public sealed record DecoyPlacement(string FullPath, DecoyKind Kind, string Content);

/// <summary>Abstracts the file system so placement/removal is unit-testable without touching disk.</summary>
public interface IDecoyFileSystem
{
    string HomeDirectory { get; }
    bool Exists(string fullPath);
    string ReadAllText(string fullPath);
    void WriteAllText(string fullPath, string content);
    void Delete(string fullPath);
}

/// <summary>
/// Pure policy for decoy placement + believable content generation. No I/O, no elevation — fully testable.
/// </summary>
public static class DecoyCredentialPolicy
{
    /// <summary>
    /// Stable, recognizable sentinel embedded in every Foreman decoy (uses leetspeak zeroes so it never
    /// collides with a real AKIA-key/ghp-token). Detection rule cred-040 matches these; removal verifies a
    /// file still contains <see cref="SentinelMarker"/> before deleting it.
    /// </summary>
    public const string SentinelMarker = "FOREMAN-DECOY-CANARY";
    public const string SentinelAwsKey = "AKIAF0REMANDEC0YAAAA";
    public const string SentinelGitHubToken = "ghp_F0REMANDEC0Y00000000000000000000000000";

    /// <summary>Credential paths the Miasma sweep enumerates — the candidate decoy slots (gaps-only at plant time).</summary>
    public static IReadOnlyList<DecoySpec> Candidates { get; } =
    [
        new(".aws/credentials",      DecoyKind.AwsCredentials),
        new(".ssh/id_rsa",           DecoyKind.SshPrivateKey),
        new(".npmrc",                DecoyKind.Npmrc),
        new(".git-credentials",      DecoyKind.GitCredentials),
        new(".kube/config",          DecoyKind.KubeConfig),
        new(".pypirc",               DecoyKind.PypiRc),
        new(".netrc",                DecoyKind.NetRc),
        new(".docker/config.json",   DecoyKind.DockerConfig),
    ];

    /// <summary>
    /// Plans which decoys to plant: a candidate is included only when no real file occupies its slot
    /// (gaps-only). <paramref name="exists"/> is injected so this is pure/testable.
    /// </summary>
    public static IReadOnlyList<DecoyPlacement> PlanPlacements(
        string homeDirectory, Func<string, bool> exists, DecoyCredentialSettings settings)
    {
        var placements = new List<DecoyPlacement>();
        foreach (var spec in Candidates)
        {
            var full = JoinHome(homeDirectory, spec.RelativePath);
            if (exists(full)) continue;   // gaps-only: never shadow a real credential file
            placements.Add(new DecoyPlacement(full, spec.Kind, GenerateContent(spec.Kind, settings)));
        }
        return placements;
    }

    /// <summary>Believable, syntactically-valid, NON-functional content for a decoy of the given kind.</summary>
    public static string GenerateContent(DecoyKind kind, DecoyCredentialSettings settings)
    {
        var awsKey = settings is { IncludeAwsCanaryToken: true, AwsCanaryAccessKeyId.Length: > 0 }
            ? settings.AwsCanaryAccessKeyId!
            : SentinelAwsKey;
        var awsSecret = settings is { IncludeAwsCanaryToken: true, AwsCanarySecretAccessKey.Length: > 0 }
            ? settings.AwsCanarySecretAccessKey!
            : SentinelMarker + "/wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLE";

        return kind switch
        {
            // The trailing comment guarantees the sentinel is present even when a real canary key is used
            // for the values, so Remove() can always verify this is Foreman's decoy before deleting it.
            DecoyKind.AwsCredentials =>
                $"[default]\naws_access_key_id = {awsKey}\naws_secret_access_key = {awsSecret}\n# {SentinelMarker}\n",

            DecoyKind.SshPrivateKey =>
                "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
                "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQy\n" +
                "NTUxOQAAACDA000000000000000000000000000000000000000000000000000000000==\n" +
                "-----END OPENSSH PRIVATE KEY-----\n" +
                $"# {SentinelMarker} (decoy; do not use)\n",

            DecoyKind.Npmrc =>
                $"//registry.npmjs.org/:_authToken={SentinelMarker}-npm-0000000000000000\n",

            DecoyKind.GitCredentials =>
                $"https://x-access-token:{SentinelGitHubToken}@github.com\n",

            DecoyKind.KubeConfig =>
                "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://10.0.0.1:6443\n  name: prod\n" +
                "users:\n- name: admin\n  user:\n" +
                $"    token: {SentinelMarker}-kube-0000000000000000000000\n",

            DecoyKind.PypiRc =>
                $"[pypi]\nusername = __token__\npassword = pypi-{SentinelMarker}0000000000000000000000\n",

            DecoyKind.NetRc =>
                $"machine github.com\n  login x-access-token\n  password {SentinelGitHubToken}\n",

            DecoyKind.DockerConfig =>
                "{\n  \"auths\": {\n    \"https://index.docker.io/v1/\": {\n      \"auth\": \"" +
                Convert.ToBase64String(Encoding.ASCII.GetBytes("decoy:" + SentinelMarker)) +
                "\"\n    }\n  },\n  \"_\": \"" + SentinelMarker + "\"\n}\n",

            _ => SentinelMarker + "\n",
        };
    }

    /// <summary>True if the given text is one of Foreman's decoys (carries the sentinel) — gate removal on this.</summary>
    public static bool IsDecoyContent(string? text) =>
        text is not null &&
        (text.Contains(SentinelMarker, StringComparison.Ordinal) ||
         text.Contains(SentinelAwsKey, StringComparison.Ordinal) ||
         text.Contains(SentinelGitHubToken, StringComparison.Ordinal));

    /// <summary>Absolute path of a candidate decoy under the given home directory.</summary>
    public static string FullPath(string home, DecoySpec spec) => JoinHome(home, spec.RelativePath);

    private static string JoinHome(string home, string relative) =>
        Path.Combine(home, relative.Replace('/', Path.DirectorySeparatorChar));
}

/// <summary>Result of a plant operation, for the operator log + the settings record of what to clean up.</summary>
public sealed record DecoyPlantResult(IReadOnlyList<string> Planted, IReadOnlyList<string> SkippedExisting);

/// <summary>
/// Plants and removes decoys using an injected file system. Plant is gaps-only; Remove deletes only files
/// that still carry the Foreman sentinel (so a real file later created in a decoy slot is never destroyed).
/// </summary>
public sealed class DecoyCredentialManager(IDecoyFileSystem fs)
{
    public DecoyPlantResult Plant(DecoyCredentialSettings settings)
    {
        var planted = new List<string>();
        var skipped = new List<string>();
        // Iterate candidates directly so a real file in a decoy slot is reported as skipped (gaps-only).
        foreach (var spec in DecoyCredentialPolicy.Candidates)
        {
            var full = DecoyCredentialPolicy.FullPath(fs.HomeDirectory, spec);
            if (fs.Exists(full)) { skipped.Add(full); continue; }   // never shadow a real credential file
            fs.WriteAllText(full, DecoyCredentialPolicy.GenerateContent(spec.Kind, settings));
            planted.Add(full);
        }
        return new DecoyPlantResult(planted, skipped);
    }

    /// <summary>Removes the recorded decoys — but only files that still contain the Foreman sentinel.</summary>
    public IReadOnlyList<string> Remove(IEnumerable<string> plantedPaths)
    {
        var removed = new List<string>();
        foreach (var path in plantedPaths)
        {
            if (!fs.Exists(path)) continue;
            string text;
            try { text = fs.ReadAllText(path); } catch { continue; }
            if (!DecoyCredentialPolicy.IsDecoyContent(text)) continue;   // not our decoy anymore — leave it
            fs.Delete(path);
            removed.Add(path);
        }
        return removed;
    }
}
