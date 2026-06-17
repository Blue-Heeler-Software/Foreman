using Foreman.Core.Models;
using Foreman.Core.Profiles;

namespace Foreman.Core.Tests.Models;

public sealed class HarnessIntegrationRegistryTests
{
    [Fact]
    public void EveryRegisteredDefaultProfile_IsLoadable()   // locks the "connector added but no profile" gap
    {
        var dir = Path.Combine(Path.GetTempPath(), "foreman-prof-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        try
        {
            using var store = new ProfileStore(dir);
            store.Initialize();
            foreach (var integ in HarnessIntegrationRegistry.All)
                Assert.True(store.Get(integ.DefaultProfileName) is not null,
                    $"registry harness '{integ.HarnessId}' points at default profile " +
                    $"'{integ.DefaultProfileName}' but no built-in profile by that name loads");
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [Theory]
    [InlineData("gemini-cli")]
    [InlineData("github-copilot")]
    [InlineData("lm-studio")]
    [InlineData("cursor")]
    public void NewConnectors_HaveIntegrationMetadata(string harnessId)
    {
        var integ = HarnessIntegrationRegistry.Get(harnessId);
        Assert.NotNull(integ);
        Assert.False(string.IsNullOrWhiteSpace(integ!.DisplayName));
        Assert.False(string.IsNullOrWhiteSpace(integ.SetupHint));
        Assert.Contains("{port}", integ.McpConfigSnippet);   // the snippet is port-templated
    }

    [Fact]
    public void Get_IsCaseInsensitive()
        => Assert.NotNull(HarnessIntegrationRegistry.Get("Gemini-CLI"));
}
