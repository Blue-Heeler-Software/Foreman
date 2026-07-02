using Foreman.Core.Security;

namespace Foreman.Core.Tests.Security;

public sealed class DataDirRedirectionTests
{
    [Theory]
    [InlineData(@"\\?\C:\Users\x\AppData\Local\Foreman", @"C:\Users\x\AppData\Local\Foreman")]
    [InlineData(@"\\?\UNC\server\share\Foreman", @"\\server\share\Foreman")]
    [InlineData(@"C:\plain\path", @"C:\plain\path")]
    [InlineData("", "")]
    public void NormalizeFinalPath_StripsWin32Prefixes(string input, string expected) =>
        Assert.Equal(expected, DataDirRedirection.NormalizeFinalPath(input));

    [Fact]
    public void SameDirectory_IsNotRedirected_CaseAndTrailingSeparatorTolerant() =>
        Assert.False(DataDirRedirection.IsRedirected(
            @"C:\Users\x\AppData\Local\Foreman",
            @"\\?\c:\users\X\appdata\local\foreman\"));

    [Fact]
    public void OverlayDirectory_IsRedirected()
    {
        // The observed split-brain shape: a sandboxed launch lands AppData writes in a package's LocalCache.
        Assert.True(DataDirRedirection.IsRedirected(
            @"C:\Users\x\AppData\Local\Foreman",
            @"\\?\C:\Users\x\AppData\Local\Packages\SomeApp_abc123\LocalCache\Local\Foreman"));
    }

    [Fact]
    public void UnknownEmptyPaths_NeverReadAsRedirection()
    {
        // A failed probe must degrade to "no claim", not a false alarm.
        Assert.False(DataDirRedirection.IsRedirected(@"C:\x", ""));
        Assert.False(DataDirRedirection.IsRedirected("", @"C:\x"));
        Assert.False(DataDirRedirection.IsRedirected("", ""));
    }

    [Fact]
    public void Notice_NamesBothPaths_AndTheRemedy()
    {
        var msg = DataDirRedirection.BuildNotice(@"C:\real\Foreman", @"C:\overlay\Foreman");
        Assert.Contains(@"C:\real\Foreman", msg);
        Assert.Contains(@"C:\overlay\Foreman", msg);
        Assert.Contains("tray", msg);   // tells the operator how to launch it properly
    }
}
