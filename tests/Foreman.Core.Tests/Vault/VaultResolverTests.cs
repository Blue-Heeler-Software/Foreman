using Foreman.Core.Vault;

namespace Foreman.Core.Tests.Vault;

public sealed class VaultResolverTests
{
    private sealed class FakeStore : IVaultStore
    {
        public bool Unlocked = true;
        public bool IsUnlocked => Unlocked;
        public VaultItemInfo? Info;
        public Dictionary<VaultField, string> Secrets = new();
        public bool Wiped;

        public VaultItemInfo? FindByOrigin(string origin) =>
            Info is not null && Info.Origins.Any(o => VaultDomainBinding.HostMatches(o, origin)) ? Info : null;
        public string? GetSecret(string origin, VaultField field) => Secrets.GetValueOrDefault(field);
        public void WipeInMemoryKeys() => Wiped = true;
    }

    private static FakeStore GitHubStore(string[]? harnesses = null) => new()
    {
        Info = new VaultItemInfo("GitHub", ["github.com"], harnesses ?? [], HasTotp: false),
        Secrets = { [VaultField.Username] = "alice", [VaultField.Password] = "s3cret" },
    };

    [Fact]
    public void Operator_ResolvesWhenTargetMatches()
    {
        var r = new VaultResolver(GitHubStore())
            .Resolve("login {{vault:github.com/password}}", "github.com", harnessId: null, isOperator: true);
        Assert.True(r.Ok);
        Assert.Equal("login s3cret", r.Resolved);
        Assert.Contains("github.com/password", r.ResolvedRefs);
    }

    [Fact]
    public void ListedHarness_Resolves()
    {
        var r = new VaultResolver(GitHubStore(["claude-code"]))
            .Resolve("{{vault:github.com/username}}", "github.com", "claude-code", isOperator: false);
        Assert.True(r.Ok);
        Assert.Equal("alice", r.Resolved);
    }

    [Fact]
    public void UnlistedHarness_Denied()
    {
        var r = new VaultResolver(GitHubStore(["codex"]))
            .Resolve("{{vault:github.com/password}}", "github.com", "claude-code", isOperator: false);
        Assert.False(r.Ok);
        Assert.Null(r.Resolved);
    }

    [Fact]
    public void WrongLiveTarget_Denied_Phishing()
    {
        var r = new VaultResolver(GitHubStore())
            .Resolve("{{vault:github.com/password}}", "evil.com", null, isOperator: true);
        Assert.False(r.Ok);
        Assert.Null(r.Resolved);
        Assert.Contains("evil.com", r.Reason);
    }

    [Fact]
    public void UnknownItem_NotFound_NoExistenceOracle()
    {
        var r = new VaultResolver(GitHubStore())
            .Resolve("{{vault:gitlab.com/password}}", "gitlab.com", null, isOperator: true);
        Assert.False(r.Ok);
        Assert.Equal("credential not found", r.Reason);
    }

    [Fact]
    public void LockedVault_Fails()
    {
        var store = GitHubStore();
        store.Unlocked = false;
        var r = new VaultResolver(store).Resolve("{{vault:github.com/password}}", "github.com", null, isOperator: true);
        Assert.False(r.Ok);
        Assert.Equal("vault is locked", r.Reason);
    }

    [Fact]
    public void NoReference_Passthrough()
    {
        var r = new VaultResolver(GitHubStore()).Resolve("just type this", "github.com", null, isOperator: true);
        Assert.True(r.Ok);
        Assert.Equal("just type this", r.Resolved);
        Assert.Empty(r.ResolvedRefs);
    }
}
