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
    public void Plant_AdoptsAnExistingForemanDecoy_AndRefreshesItsSentinel()
    {
        var fs = new FakeFs();
        // Another lineage planted this decoy earlier (a prior install, or a sandbox-diverged instance): the
        // static marker is present but the per-install sentinel belongs to the OTHER install.
        var slot = Full("HOME", ".npmrc");
        fs.Files[slot] = DecoyCredentialPolicy.GenerateContent(
            DecoyKind.Npmrc, new DecoyCredentialSettings { InstanceSentinel = "OLDINSTANCE00000000000000000000" });

        var settings = new DecoyCredentialSettings();
        var result = new DecoyCredentialManager(fs).Plant(settings);

        // Adopted = tracked (and thus read-audited), never silently skipped as "occupied".
        Assert.Contains(slot, result.Planted);
        Assert.DoesNotContain(slot, result.SkippedExisting);
        // Content refreshed under THIS install's sentinel so cred-040 carries the right token.
        Assert.Contains(settings.InstanceSentinel!, fs.Files[slot]);
        Assert.DoesNotContain("OLDINSTANCE00000000000000000000", fs.Files[slot]);
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
    public void Revalidate_RetiresReclaimedSlots_WithoutDeletingRealCreds()
    {
        var fs = new FakeFs();
        var mgr = new DecoyCredentialManager(fs);
        var planted = mgr.Plant(new DecoyCredentialSettings()).Planted;

        // User runs `aws configure` over one decoy slot (real creds, sentinel gone)...
        var reclaimedSlot = planted[0];
        fs.Files[reclaimedSlot] = "[default]\naws_access_key_id = AKIAREALUSERKEY00000\n";
        // ...and deletes another entirely.
        var deletedSlot = planted[1];
        fs.Files.Remove(deletedSlot);

        var result = mgr.Revalidate(planted);

        Assert.Contains(reclaimedSlot, result.Reclaimed);
        Assert.Contains(deletedSlot, result.Reclaimed);
        Assert.DoesNotContain(reclaimedSlot, result.StillDecoys);
        // The real credentials the user wrote are NOT deleted.
        Assert.True(fs.Exists(reclaimedSlot));
        Assert.Equal("[default]\naws_access_key_id = AKIAREALUSERKEY00000\n", fs.Files[reclaimedSlot]);
        // Untouched decoys remain tracked.
        Assert.Equal(planted.Count - 2, result.StillDecoys.Count);
    }

    [Fact]
    public void Release_FreesOneDecoySlot_ButNotARealFile()
    {
        var fs = new FakeFs();
        var mgr = new DecoyCredentialManager(fs);
        var planted = mgr.Plant(new DecoyCredentialSettings()).Planted;

        Assert.True(mgr.Release(planted[0]));          // a decoy → released
        Assert.False(fs.Exists(planted[0]));

        // A slot the user reclaimed with real creds is never deleted by Release.
        fs.Files[planted[1]] = "real user credential, no sentinel";
        Assert.False(mgr.Release(planted[1]));
        Assert.True(fs.Exists(planted[1]));
    }

    [Fact]
    public void DisabledByDefault()
    {
        var s = new DecoyCredentialSettings();
        Assert.False(s.Enabled);
        Assert.False(s.EnableReadAuditing);
        Assert.False(s.IncludeAwsCanaryToken);
    }

    [Fact]
    public void ReadAuditPaths_IncludesBaitAndCanonicalNpmrc_ExcludesToolReadCanonical()
    {
        const string home = "HOME";
        var planted = new DecoyCredentialManager(new FakeFs { HomeDirectory = home }).Plant(new DecoyCredentialSettings()).Planted;

        var audited = DecoyCredentialPolicy.ReadAuditPaths(home, planted);

        // canonical .npmrc (foreign reader still trips it) + every bait decoy are read-audited
        Assert.Contains(Full(home, ".npmrc"), audited);
        Assert.Contains(Full(home, ".npmrc.bak"), audited);
        Assert.Contains(Full(home, ".aws/credentials.bak"), audited);
        Assert.Contains(Full(home, ".ssh/id_rsa.old"), audited);
        Assert.Contains(Full(home, "secrets.env"), audited);
        Assert.Contains(Full(home, "credentials.txt"), audited);
        Assert.Contains(Full(home, "vault.txt"), audited);

        // the false-positive-prone canonical paths (read by git/aws/ssh/etc.) are NOT read-audited
        Assert.DoesNotContain(Full(home, ".netrc"), audited);
        Assert.DoesNotContain(Full(home, ".git-credentials"), audited);
        Assert.DoesNotContain(Full(home, ".aws/credentials"), audited);
        Assert.DoesNotContain(Full(home, ".ssh/id_rsa"), audited);
        Assert.DoesNotContain(Full(home, ".kube/config"), audited);
        Assert.DoesNotContain(Full(home, ".pypirc"), audited);
        Assert.DoesNotContain(Full(home, ".docker/config.json"), audited);
    }

    [Fact]
    public void GenericSecret_ContentCarriesSentinel_SoItStaysRemovable() =>
        Assert.True(DecoyCredentialPolicy.IsDecoyContent(
            DecoyCredentialPolicy.GenerateContent(DecoyKind.GenericSecret, new DecoyCredentialSettings())));
}
