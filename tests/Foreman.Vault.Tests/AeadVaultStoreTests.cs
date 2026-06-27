using System.Text.Json.Nodes;
using Foreman.Core.Vault;
using Foreman.Vault;

namespace Foreman.Vault.Tests;

public sealed class AeadVaultStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "foreman-vault-test-" + Guid.NewGuid().ToString("N"));
    public AeadVaultStoreTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, recursive: true); } catch { /* best-effort cleanup */ } }

    private string VaultPath => Path.Combine(_dir, "vault.fvault");
    private static readonly byte[] KeyComp = Enumerable.Range(0, 32).Select(i => (byte)(i * 7)).ToArray();
    private const string Pw = "correct horse battery staple";

    private static VaultEntry GitHub() => new()
    {
        Name = "GitHub",
        Origins = { "github.com" },
        Harnesses = { "claude-code" },
        Username = "alice",
        Password = "s3cret",
        TotpSeedBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    };

    [Fact]
    public void Roundtrip_CreateUpsertReopen()
    {
        var store = AeadVaultStore.Create(VaultPath, Pw, KeyComp);
        store.Upsert(GitHub());
        store.WipeInMemoryKeys();
        Assert.False(store.IsUnlocked);

        var reopened = new AeadVaultStore(VaultPath);
        reopened.Open(Pw, KeyComp);
        Assert.True(reopened.IsUnlocked);

        var info = reopened.FindByOrigin("github.com");
        Assert.NotNull(info);
        Assert.True(info!.HasTotp);
        Assert.Equal("s3cret", reopened.GetSecret("github.com", VaultField.Password));
        Assert.Equal("alice", reopened.GetSecret("github.com", VaultField.Username));
    }

    [Fact]
    public void WrongPassword_Throws()
    {
        AeadVaultStore.Create(VaultPath, Pw, KeyComp).Upsert(GitHub());
        Assert.ThrowsAny<Exception>(() => new AeadVaultStore(VaultPath).Open("wrong-password", KeyComp));
    }

    [Fact]
    public void WrongKeyComponent_Throws()
    {
        AeadVaultStore.Create(VaultPath, Pw, KeyComp).Upsert(GitHub());
        var bad = (byte[])KeyComp.Clone();
        bad[0] ^= 0xFF;
        Assert.ThrowsAny<Exception>(() => new AeadVaultStore(VaultPath).Open(Pw, bad));
    }

    [Fact]
    public void TamperedCiphertext_Throws()
    {
        AeadVaultStore.Create(VaultPath, Pw, KeyComp).Upsert(GitHub());
        var node = JsonNode.Parse(File.ReadAllText(VaultPath))!;
        var ct = Convert.FromBase64String(node["CtB64"]!.GetValue<string>());
        ct[0] ^= 0xFF;
        node["CtB64"] = Convert.ToBase64String(ct);
        File.WriteAllText(VaultPath, node.ToJsonString());

        Assert.ThrowsAny<Exception>(() => new AeadVaultStore(VaultPath).Open(Pw, KeyComp));
    }

    [Fact]
    public void GetSecret_Totp_ReturnsSixDigitCode()
    {
        var store = AeadVaultStore.Create(VaultPath, Pw, KeyComp);
        store.Upsert(GitHub());
        var code = store.GetSecret("github.com", VaultField.Totp);
        Assert.NotNull(code);
        Assert.Matches(@"^\d{6}$", code!);
    }

    [Fact]
    public void Resolver_ResolvesReferenceThroughStore()   // full Core + Vault path
    {
        var store = AeadVaultStore.Create(VaultPath, Pw, KeyComp);
        store.Upsert(GitHub());

        var r = new VaultResolver(store)
            .Resolve("login {{vault:github.com/password}}", liveTargetHost: "github.com", harnessId: "claude-code", isOperator: false);

        Assert.True(r.Ok);
        Assert.Equal("login s3cret", r.Resolved);
        Assert.Contains("github.com/password", r.ResolvedRefs);
    }

    [Fact]
    public void Resolver_DeniesWrongLiveTarget_Phishing()
    {
        var store = AeadVaultStore.Create(VaultPath, Pw, KeyComp);
        store.Upsert(GitHub());

        var r = new VaultResolver(store)
            .Resolve("{{vault:github.com/password}}", liveTargetHost: "evil.com", harnessId: "claude-code", isOperator: false);

        Assert.False(r.Ok);
        Assert.Null(r.Resolved);
    }
}
