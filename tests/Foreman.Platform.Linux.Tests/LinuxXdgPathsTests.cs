using Foreman.Platform.Linux;

namespace Foreman.Platform.Linux.Tests;

public sealed class LinuxXdgPathsTests
{
    [Fact]
    public void FromEnvironment_UsesXdgDirectories_WhenPresent()
    {
        var env = new Dictionary<string, string?>
        {
            ["XDG_CONFIG_HOME"] = "/home/a/.configx",
            ["XDG_STATE_HOME"] = "/home/a/.statex",
            ["XDG_DATA_HOME"] = "/home/a/.datax",
            ["XDG_RUNTIME_DIR"] = "/run/user/1000",
        };

        var paths = LinuxXdgPaths.FromEnvironment(k => env.GetValueOrDefault(k), "/home/a");

        Assert.Equal("/home/a/.configx/foreman", paths.ConfigDir);
        Assert.Equal("/home/a/.statex/foreman", paths.StateDir);
        Assert.Equal("/home/a/.datax/foreman", paths.DataDir);
        Assert.Equal("/run/user/1000/foreman", paths.RuntimeDir);
    }

    [Fact]
    public void FromEnvironment_FallsBackToHome_WhenXdgDirectoriesMissing()
    {
        var paths = LinuxXdgPaths.FromEnvironment(_ => null, "/home/a");

        Assert.Equal("/home/a/.config/foreman", paths.ConfigDir);
        Assert.Equal("/home/a/.local/state/foreman", paths.StateDir);
        Assert.Equal("/home/a/.local/share/foreman", paths.DataDir);
        Assert.Equal("/home/a/.local/state/run/foreman", paths.RuntimeDir);
    }
}
