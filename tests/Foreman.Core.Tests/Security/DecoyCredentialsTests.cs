using Foreman.Core.Security;

namespace Foreman.Core.Tests.Security;

public sealed class DecoyCredentialsTests
{
    // In-memory file system so placement/removal is tested without touching disk.
    private sealed class FakeFs : IDecoyFileSystem
    {
        public string HomeDirectory { get; init; } = "HOME";
        public Dictionary<string, string> Files { get; } = new();
        public bool Exists(string p) => Files.ContainsKey(p);
        public string ReadAllText(string p) => Files[p];
        public void WriteAllText(string p, string c) => Files[p] = c;
        public void Delete(string p) => Files.Remove(p);
    }

    private static string Full(string home, string rel) =>
        Path.Combine(home, rel.Replace('/', Path.DirectorySeparatorChar));

    [Fact]
    public void Plant_IsGapsOnly_NeverShadowsARealFile()
    {
        var fs = new FakeFs();
        var realNpmrc = Full("HOME", ".npmrc");
        fs.Files[realNpmrc] = "//registry.npmjs.org/:_authToken=REAL-TOKEN-DO-NOT-TOUCH";

        var result = new DecoyCredentialManager(fs).Plant(new DecoyCredentialSettings());

        Assert.Contains(realNpmrc, result.SkippedExisting);
        Assert.DoesNotContain(realNpmrc, result.Planted);
        Assert.Equal(DecoyCredentialPolicy.Candidates.Count - 1, result.Planted.Count);
        // the real file is byte-for-byte untouched
        Assert.Equal("//registry.npmjs.org/:_authToken=REAL-TOKEN-DO-NOT-TOUCH", fs.Files[realNpmrc]);
    }

    [Fact]
    public void EveryPlantedDecoy_CarriesTheSentinel()
    {
        var fs = new FakeFs();
        var result = new DecoyCredentialManager(fs).Plant(new DecoyCredentialSettings());

        Assert.NotEmpty(result.Planted);
        foreach (var path in result.Planted)
            Assert.True(DecoyCredentialPolicy.IsDecoyContent(fs.Files[path]), $"missing sentinel: {path}");
    }

    [Fact]
    public void AwsCanaryToken_EmbedsTheRealKey_ButStaysRemovable()
    {
        var settings = new DecoyCredentialSettings
        {
            IncludeAwsCanaryToken = true,
            AwsCanaryAccessKeyId = "AKIACANARYTOKEN12345",
            AwsCanarySecretAccessKey = "realCanarySecretValue+abc",
        };

        var content = DecoyCredentialPolicy.GenerateContent(DecoyKind.AwsCredentials, settings);

        Assert.Contains("AKIACANARYTOKEN12345", content);                       // the real canary key is used
        Assert.DoesNotContain(DecoyCredentialPolicy.SentinelAwsKey, content);    // not the fake placeholder key
        Assert.True(DecoyCredentialPolicy.IsDecoyContent(content));              // still marked for safe removal
    }

    [Fact]
    public void Remove_DeletesOnlyForemanDecoys_NotARealFileInADecoySlot()
    {
        var fs = new FakeFs();
        var mgr = new DecoyCredentialManager(fs);
        var result = mgr.Plant(new DecoyCredentialSettings());

        // The user later replaces one decoy with a genuine credential (no sentinel).
        var slot = result.Planted[0];
        fs.Files[slot] = "this is now a real credential the user created";

        var removed = mgr.Remove(result.Planted);

        Assert.DoesNotContain(slot, removed);                 // the real replacement is preserved
        Assert.True(fs.Exists(slot));
        Assert.Equal(result.Planted.Count - 1, removed.Count); // every other (still-decoy) file is gone
        foreach (var r in removed) Assert.False(fs.Exists(r));
    }

    [Fact]
    public void Remove_IgnoresMissingPaths()
    {
        var fs = new FakeFs();
        var removed = new DecoyCredentialManager(fs).Remove(new[] { Full("HOME", ".aws/credentials") });
        Assert.Empty(removed);
    }

    [Fact]
    public void DisabledByDefault()
    {
        var s = new DecoyCredentialSettings();
        Assert.False(s.Enabled);
        Assert.False(s.EnableReadAuditing);
        Assert.False(s.IncludeAwsCanaryToken);
    }
}
