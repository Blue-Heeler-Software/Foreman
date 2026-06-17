using Foreman.Core.Mcp;

namespace Foreman.Core.Tests.Mcp;

public sealed class McpCapabilityClassifierTests
{
    private static McpServerEntry E(string name, string target = "") =>
        new("claude-code", name, "stdio", target, "global", "cfg");

    [Theory]
    [InlineData("computer-use")]
    [InlineData("computer_use")]
    [InlineData("cua")]
    [InlineData("scrapybara")]
    public void Flags_ComputerUse(string name)
    {
        Assert.True(McpCapabilityClassifier.IsComputerUse(E(name)));
        Assert.False(McpCapabilityClassifier.IsBrowserUse(E(name)));
    }

    [Theory]
    [InlineData("playwright", "")]
    [InlineData("puppeteer", "")]
    [InlineData("browsermcp", "")]
    [InlineData("automation", "npx @playwright/mcp@latest")]   // matched via target, not name
    [InlineData("chrome", "claude-in-chrome")]
    public void Flags_BrowserUse(string name, string target)
    {
        Assert.True(McpCapabilityClassifier.IsBrowserUse(E(name, target)));
        Assert.False(McpCapabilityClassifier.IsComputerUse(E(name, target)));
    }

    [Theory]
    [InlineData("filesystem")]
    [InlineData("github")]
    [InlineData("foreman")]
    [InlineData("postgres")]
    public void Benign_NotFlagged(string name)
    {
        var e = E(name);
        Assert.False(McpCapabilityClassifier.IsComputerUse(e));
        Assert.False(McpCapabilityClassifier.IsBrowserUse(e));
    }
}
