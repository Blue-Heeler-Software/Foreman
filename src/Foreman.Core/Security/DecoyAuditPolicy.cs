namespace Foreman.Core.Security;

/// <summary>
/// Pure decision logic for the elevated SACL read-auditing layer: given a Windows Security-log file-access
/// event (Event 4663 — object name + accessing PID + accessing image), decide whether it is a genuine read of
/// a tracked decoy credential worth a Critical alert. Shared by the elevated sidecar (which filters the noisy
/// 4663 stream down to decoy hits before sending anything over the pipe) and the app, and unit-tested here so
/// the sidecar's filter is verified without needing elevation.
///
/// Two correctness points:
///   1. Foreman itself reads the decoy files during sentinel re-validation
///      (<see cref="DecoyCredentialManager.Revalidate"/>) and on plant/remove — so the app's own PID (and the
///      sidecar's) MUST be excluded, or Foreman would alarm on its own housekeeping.
///   2. A CANONICAL decoy sits at a path real tools also read (git's HTTPS helper reads ~/.netrc and
///      ~/.git-credentials on every push, npm/node read ~/.npmrc, ssh reads ~/.ssh/id_rsa). Reading such a
///      decoy from that path's OWN legitimate tool is normal and is suppressed via <see cref="ExpectedReaders"/>;
///      any OTHER reader (a harvester, powershell, python, or a tool reading a path it doesn't own) still fires.
///      BAIT decoys have no legitimate reader, so they classify to null and any read fires image-agnostically.
/// </summary>
public static class DecoyAuditPolicy
{
    /// <summary>
    /// True when a 4663 read of <paramref name="objectName"/> by <paramref name="subjectPid"/>
    /// (<paramref name="readerImage"/> is the accessing executable) is a real decoy read: the path equals one
    /// of <paramref name="decoyPaths"/>, the reader is not an excluded PID (Foreman app + sidecar), and — for a
    /// canonical decoy — the reader is not that path's expected legitimate tool.
    /// </summary>
    public static bool IsDecoyRead(
        string? objectName,
        int subjectPid,
        string? readerImage,
        IReadOnlyCollection<string> decoyPaths,
        IReadOnlyCollection<int> excludedPids)
    {
        if (string.IsNullOrWhiteSpace(objectName)) return false;
        if (excludedPids.Contains(subjectPid)) return false;

        var target = Normalize(objectName);
        var matched = false;
        foreach (var d in decoyPaths)
            if (Normalize(d).Equals(target, StringComparison.OrdinalIgnoreCase)) { matched = true; break; }
        if (!matched) return false;

        // The Windows Search indexer (SearchProtocolHost / SearchIndexer / SearchFilterHost) reads file CONTENT
        // in indexed locations — the user profile included — on every index pass, so it reads a home-root BAIT
        // decoy (secrets.env, vault.txt, …) as routine OS housekeeping, not harvesting. Suppress it, matched
        // PATH-ANCHORED under \Windows\System32\ (not by basename) so a renamed harvester dropped elsewhere
        // can't borrow the exemption — placing a binary in System32 already requires admin. This is the belt to
        // the FILE_ATTRIBUTE_NOT_CONTENT_INDEXED braces set on planted decoys (which stops the indexer at source).
        if (IsBenignSystemIndexer(readerImage)) return false;

        // Suppress a CANONICAL decoy read by that path's own legitimate tool (e.g. git-remote-https reading
        // ~/.netrc on every push). Bait paths classify to null → no allowlist → any read fires.
        var kind = ClassifyCanonical(target);
        if (kind is { } k
            && ExpectedReaders.TryGetValue(k, out var allowed)
            && readerImage is not null
            && allowed.Contains(ImageBasename(readerImage)))
            return false;

        return true;
    }

    /// <summary>
    /// The <see cref="DecoyKind"/> of the CANONICAL decoy at this (already-normalized) path, or null when the
    /// path is a bait decoy or unrecognized — either way meaning "no expected-reader suppression; any read
    /// fires". Matched by relative-path tail so it works without knowing the home directory.
    /// </summary>
    private static DecoyKind? ClassifyCanonical(string normalizedPath)
    {
        foreach (var spec in DecoyCredentialPolicy.Candidates)
        {
            if (spec.Role != DecoyRole.Canonical) continue;
            var relTail = "\\" + spec.RelativePath.Replace('/', '\\');
            if (normalizedPath.EndsWith(relTail, StringComparison.OrdinalIgnoreCase))
                return spec.Kind;
        }
        return null;
    }

    /// <summary>
    /// Per-path legitimate readers. Reading a canonical decoy from one of these images is normal tool
    /// behaviour and is suppressed; everything else fires — shells (powershell/cmd/bash), editors, python on
    /// .pypirc, git on an SSH key, and any binary reading a path it doesn't own. Deliberately tight: broad or
    /// cross-tool readers are NOT listed, so a harvester can't hide behind them. Matched on the bare image
    /// name as emitted in 4663 (includes the .exe extension).
    /// </summary>
    private static readonly Dictionary<DecoyKind, HashSet<string>> ExpectedReaders = new()
    {
        [DecoyKind.NetRc]          = Set("git.exe", "git-remote-https.exe", "git-remote-http.exe", "curl.exe"),
        [DecoyKind.GitCredentials] = Set("git.exe", "git-remote-https.exe", "git-remote-http.exe",
                                         "git-credential-manager.exe", "git-credential-manager-core.exe",
                                         "git-credential-wincred.exe", "git-credential-store.exe"),
        [DecoyKind.SshPrivateKey]  = Set("ssh.exe", "scp.exe", "sftp.exe", "ssh-add.exe", "ssh-keygen.exe", "plink.exe"),
        [DecoyKind.AwsCredentials] = Set("aws.exe"),
        [DecoyKind.Npmrc]          = Set("npm.exe", "node.exe", "npx.exe", "pnpm.exe", "yarn.exe"),
        [DecoyKind.DockerConfig]   = Set("docker.exe", "com.docker.cli.exe",
                                         "docker-credential-desktop.exe", "docker-credential-wincred.exe"),
        [DecoyKind.KubeConfig]     = Set("kubectl.exe", "helm.exe"),
        [DecoyKind.PypiRc]         = Set("twine.exe", "pip.exe"),
    };

    private static HashSet<string> Set(params string[] images) =>
        new(images, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// True when <paramref name="readerImage"/> is the genuine Windows Search indexer content-gathering process
    /// (SearchProtocolHost / SearchIndexer / SearchFilterHost) running from its real System32 path. These crawl
    /// file CONTENT to build the search index and will read a home-root bait decoy on every pass — benign OS
    /// behaviour, not harvesting. Matched PATH-ANCHORED under \Windows\System32\ so a renamed harvester elsewhere
    /// is NOT exempt: a non-admin cannot write a binary into System32. (If an attacker is already SYSTEM/admin and
    /// can drop into System32, the decoy tripwire is moot anyway.) Public for unit-testing.
    /// </summary>
    public static bool IsBenignSystemIndexer(string? readerImage)
    {
        if (string.IsNullOrWhiteSpace(readerImage)) return false;
        var p = Normalize(readerImage);
        foreach (var img in SystemIndexerImages)
            if (p.EndsWith(img, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static readonly string[] SystemIndexerImages =
    [
        @"\Windows\System32\SearchProtocolHost.exe",
        @"\Windows\System32\SearchIndexer.exe",
        @"\Windows\System32\SearchFilterHost.exe",
    ];

    /// <summary>
    /// The bare executable name from a 4663 ProcessName. Handles a \\?\ prefix, the \Device\HarddiskVolumeN\…
    /// kernel form, and either separator. (A renamed binary can still spoof this — that is exactly why the
    /// canonical allowlist is paired with image-agnostic bait decoys.)
    /// </summary>
    public static string ImageBasename(string image)
    {
        var p = image.Trim();
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p[4..];
        p = p.Replace('/', '\\').TrimEnd('\\');
        var i = p.LastIndexOf('\\');
        return i >= 0 ? p[(i + 1)..] : p;
    }

    /// <summary>Normalises a Windows path for comparison: strips a \\?\ long-path prefix, unifies separators.</summary>
    public static string Normalize(string path)
    {
        var p = path.Trim();
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p[4..];
        return p.Replace('/', '\\').TrimEnd('\\');
    }
}
