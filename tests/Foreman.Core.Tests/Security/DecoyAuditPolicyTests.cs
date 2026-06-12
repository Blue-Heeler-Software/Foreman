using System.Text.Json;
using Foreman.Core.Ipc;
using Foreman.Core.Security;

namespace Foreman.Core.Tests.Security;

public sealed class DecoyAuditPolicyTests
{
    private static readonly string[] Decoys =
        [@"C:\Users\u\.aws\credentials", @"C:\Users\u\.npmrc"];
    private static readonly int[] Excluded = [1000, 1001];   // Foreman app + sidecar

    // The full set Foreman actually read-audits (canonical .npmrc + bait) plus canonical paths used to
    // exercise the expected-reader allowlist. The path being tested must be in this set or IsDecoyRead
    // short-circuits at the path-match step.
    private static readonly string[] AllDecoys =
    [
        @"C:\Users\u\.aws\credentials", @"C:\Users\u\.npmrc", @"C:\Users\u\.netrc",
        @"C:\Users\u\.git-credentials", @"C:\Users\u\.ssh\id_rsa", @"C:\Users\u\.pypirc",
        @"C:\Users\u\.npmrc.bak", @"C:\Users\u\secrets.env",
    ];

    private const string Foreign = "evil.exe";   // in no allowlist
    private const string GitHttps = @"C:\Program Files\Git\mingw64\libexec\git-core\git-remote-https.exe";

    [Fact]
    public void DecoyReadByForeignProcess_IsADecoyRead() =>
        Assert.True(DecoyAuditPolicy.IsDecoyRead(@"C:\Users\u\.aws\credentials", 4242, Foreign, Decoys, Excluded));

    [Fact]
    public void ReadByForeman_IsExcluded() =>   // Foreman reads decoys during sentinel re-validation
        Assert.False(DecoyAuditPolicy.IsDecoyRead(@"C:\Users\u\.aws\credentials", 1000, Foreign, Decoys, Excluded));

    [Fact]
    public void ReadOfNonDecoyPath_IsNot() =>
        Assert.False(DecoyAuditPolicy.IsDecoyRead(@"C:\Users\u\project\readme.md", 4242, Foreign, Decoys, Excluded));

    [Theory]
    [InlineData(@"c:\users\u\.AWS\Credentials")]        // case-insensitive
    [InlineData(@"\\?\C:\Users\u\.aws\credentials")]    // long-path prefix stripped
    [InlineData(@"C:/Users/u/.aws/credentials")]        // forward separators
    public void PathNormalisationMatches(string objectName) =>
        Assert.True(DecoyAuditPolicy.IsDecoyRead(objectName, 4242, Foreign, Decoys, Excluded));

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void EmptyObjectName_IsNot(string? objectName) =>
        Assert.False(DecoyAuditPolicy.IsDecoyRead(objectName, 4242, Foreign, Decoys, Excluded));

    // ── Expected-reader allowlist: the git-push false positive that started this ────────────────

    [Fact]   // the exact event that mis-escalated 'codex': git's HTTPS helper reading ~/.netrc on push
    public void GitHttpsHelperReadingNetrc_IsSuppressed() =>
        Assert.False(DecoyAuditPolicy.IsDecoyRead(@"C:\Users\u\.netrc", 72000, GitHttps, AllDecoys, Excluded));

    [Theory]   // same suppression survives every form the 4663 ProcessName can take
    [InlineData(@"C:\Program Files\Git\mingw64\libexec\git-core\GIT-REMOTE-HTTPS.EXE")]
    [InlineData(@"git-remote-https.exe")]
    [InlineData(@"\\?\C:\Program Files\Git\mingw64\libexec\git-core\git-remote-https.exe")]
    [InlineData(@"\Device\HarddiskVolume3\Program Files\Git\mingw64\libexec\git-core\git-remote-https.exe")]
    [InlineData(@"C:/Program Files/Git/mingw64/libexec/git-core/git-remote-https.exe")]
    public void GitHttpsHelper_ImageFormsAllNormalize(string image) =>
        Assert.False(DecoyAuditPolicy.IsDecoyRead(@"C:\Users\u\.netrc", 72000, image, AllDecoys, Excluded));

    [Fact]
    public void GitReadingGitCredentials_IsSuppressed() =>
        Assert.False(DecoyAuditPolicy.IsDecoyRead(@"C:\Users\u\.git-credentials", 5, "git.exe", AllDecoys, Excluded));

    [Fact]   // THE verified must-keep case: powershell is not a legit .npmrc reader → still fires
    public void PowershellReadingNpmrc_StillFires() =>
        Assert.True(DecoyAuditPolicy.IsDecoyRead(
            @"C:\Users\u\.npmrc", 78456, @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", AllDecoys, Excluded));

    [Theory]   // a shell reading any cred file is harvester behaviour, never suppressed
    [InlineData(@"C:\Users\u\.aws\credentials", "bash.exe")]
    [InlineData(@"C:\Users\u\.ssh\id_rsa", "cmd.exe")]
    [InlineData(@"C:\Users\u\.netrc", "pwsh.exe")]
    public void ShellReadingDecoy_AlwaysFires(string path, string image) =>
        Assert.True(DecoyAuditPolicy.IsDecoyRead(path, 4242, image, AllDecoys, Excluded));

    [Fact]   // an allowlisted tool reading a decoy it does NOT own still fires (cross-path)
    public void AllowlistedToolReadingDifferentDecoy_Fires() =>
        Assert.True(DecoyAuditPolicy.IsDecoyRead(@"C:\Users\u\.aws\credentials", 4242, GitHttps, AllDecoys, Excluded));

    [Theory]   // each canonical path's own tool is suppressed
    [InlineData(@"C:\Users\u\.ssh\id_rsa", "ssh.exe")]
    [InlineData(@"C:\Users\u\.aws\credentials", "aws.exe")]
    [InlineData(@"C:\Users\u\.npmrc", "npm.exe")]
    [InlineData(@"C:\Users\u\.npmrc", "node.exe")]
    [InlineData(@"C:\Users\u\.pypirc", "twine.exe")]
    public void EachPathsOwnTool_IsSuppressed(string path, string image) =>
        Assert.False(DecoyAuditPolicy.IsDecoyRead(path, 4242, image, AllDecoys, Excluded));

    [Theory]   // bait decoys have no legit reader → ANY image fires, even one allowlisted for the canonical twin
    [InlineData(@"C:\Users\u\.npmrc.bak", "node.exe")]
    [InlineData(@"C:\Users\u\secrets.env", "node.exe")]
    [InlineData(@"C:\Users\u\secrets.env", "git-remote-https.exe")]
    public void BaitPathReadByAnyImage_AlwaysFires(string path, string image) =>
        Assert.True(DecoyAuditPolicy.IsDecoyRead(path, 4242, image, AllDecoys, Excluded));

    [Fact]   // a 4663 with no ProcessName must not silently suppress a foreign read
    public void NullReaderImage_FiresForForeignRead() =>
        Assert.True(DecoyAuditPolicy.IsDecoyRead(@"C:\Users\u\.aws\credentials", 4242, null, AllDecoys, Excluded));

    [Theory]   // deliberate allowlist tightenings — these must still FIRE
    [InlineData(@"C:\Users\u\.ssh\id_rsa", "git.exe")]    // git is NOT a trusted SSH-key reader
    [InlineData(@"C:\Users\u\.pypirc", "python.exe")]     // a python harvester reading .pypirc fires
    public void DroppedAllowlistEntries_StillFire(string path, string image) =>
        Assert.True(DecoyAuditPolicy.IsDecoyRead(path, 4242, image, AllDecoys, Excluded));

    [Fact]   // excluded PID wins regardless of image
    public void ExcludedPid_WinsOverImage() =>
        Assert.False(DecoyAuditPolicy.IsDecoyRead(@"C:\Users\u\.netrc", 1000, Foreign, AllDecoys, Excluded));

    // ── Windows Search indexer (SearchProtocolHost) — the home-root-bait false positive ─────────

    private const string Indexer = @"C:\Windows\System32\SearchProtocolHost.exe";

    [Theory]   // the exact FP: the Search indexer crawling a home-root bait decoy during routine indexing
    [InlineData(@"C:\Users\u\secrets.env")]
    [InlineData(@"C:\Users\u\.npmrc.bak")]
    [InlineData(@"C:\Users\u\.npmrc")]                  // canonical too — the indexer reading it is still benign
    public void SearchIndexerReadingDecoy_IsSuppressed(string path) =>
        Assert.False(DecoyAuditPolicy.IsDecoyRead(path, 9001, Indexer, AllDecoys, Excluded));

    [Theory]   // suppression survives every 4663 ProcessName form + the whole indexer family
    [InlineData(@"\Device\HarddiskVolume3\Windows\System32\SearchProtocolHost.exe")]
    [InlineData(@"\\?\C:\Windows\System32\SearchProtocolHost.exe")]
    [InlineData(@"C:/Windows/System32/searchprotocolhost.exe")]
    [InlineData(@"C:\Windows\System32\SearchIndexer.exe")]
    [InlineData(@"C:\Windows\System32\SearchFilterHost.exe")]
    public void SearchIndexerFamily_AllFormsSuppressed(string image) =>
        Assert.False(DecoyAuditPolicy.IsDecoyRead(@"C:\Users\u\secrets.env", 9001, image, AllDecoys, Excluded));

    [Theory]   // CRITICAL: a harvester named SearchProtocolHost.exe OUTSIDE System32 is NOT exempt (path-anchored)
    [InlineData(@"C:\Users\u\AppData\Local\Temp\SearchProtocolHost.exe")]
    [InlineData(@"C:\Windows\Temp\SearchProtocolHost.exe")]
    [InlineData(@"SearchProtocolHost.exe")]                    // bare name, no System32 path → cannot be trusted
    [InlineData(@"C:\evil\System32\SearchProtocolHost.exe")]   // a "System32" not under \Windows → not the real one
    public void RenamedHarvesterPosingAsIndexer_StillFires(string image) =>
        Assert.True(DecoyAuditPolicy.IsDecoyRead(@"C:\Users\u\secrets.env", 9001, image, AllDecoys, Excluded));

    // ── Pipe protocol: Kind discriminator + back-compat ─────────────────────

    [Fact]
    public void NetworkRatesMessage_RoundTrips_AsNet()
    {
        var json = JsonSerializer.Serialize(new NetworkRatesMessage { Rates = { [7] = 99.0 } });
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("net", doc.RootElement.GetProperty("Kind").GetString());
        Assert.Equal(99.0, JsonSerializer.Deserialize<NetworkRatesMessage>(json)!.Rates[7]);
    }

    [Fact]
    public void LegacyFrameWithoutKind_DefaultsToNet()
    {
        // An older sidecar emits no Kind field; the app must still treat it as a net frame.
        const string legacy = """{ "TimestampUnixMs": 1, "Rates": { "5": 1.0 } }""";
        Assert.Equal("net", JsonSerializer.Deserialize<NetworkRatesMessage>(legacy)!.Kind);
    }

    [Fact]
    public void DecoyReadMessage_RoundTrips_AsDecoyRead()
    {
        var json = JsonSerializer.Serialize(new DecoyReadMessage { Path = @"C:\x\.aws\credentials", Pid = 42, Image = "node.exe" });
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("decoyRead", doc.RootElement.GetProperty("Kind").GetString());
        var back = JsonSerializer.Deserialize<DecoyReadMessage>(json)!;
        Assert.Equal(42, back.Pid);
        Assert.Equal("node.exe", back.Image);
    }
}
