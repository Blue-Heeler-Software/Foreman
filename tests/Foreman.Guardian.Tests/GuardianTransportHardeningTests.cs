using System.Text;
using Foreman.Guardian;

namespace Foreman.Guardian.Tests;

public sealed class GuardianTransportHardeningTests
{
    [Fact]
    public void SafeTargetPath_MapsInsideRootAndRejectsEscape()
    {
        var source = Path.Combine(Path.GetTempPath(), "guardian-source");
        var destination = Path.Combine(Path.GetTempPath(), "guardian-destination");
        var mapped = GuardianInstaller.SafeTargetPath(
            source, destination, Path.Combine(source, "nested", "payload.dll"));

        Assert.Equal(Path.Combine(destination, "nested", "payload.dll"), mapped);
        Assert.Throws<InvalidDataException>(() => GuardianInstaller.SafeTargetPath(
            source, destination, Path.Combine(source, "..", "outside.dll")));
    }

    [Fact]
    public async Task BoundedPipeFrame_AcceptsNormalLineAndRejectsOversize()
    {
        await using var normalStream = new MemoryStream(Encoding.UTF8.GetBytes("hello\r\nignored"));
        using var normalReader = new StreamReader(normalStream);
        Assert.Equal("hello", await GuardianPipeServer.ReadBoundedLineAsync(normalReader, 10, CancellationToken.None));

        await using var largeStream = new MemoryStream(Encoding.UTF8.GetBytes("123456\n"));
        using var largeReader = new StreamReader(largeStream);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            GuardianPipeServer.ReadBoundedLineAsync(largeReader, 5, CancellationToken.None));
    }
}
