using Foreman.Platform;

namespace Foreman.Platform.Linux;

public static class LinuxXdgPaths
{
    public static ForemanPaths FromCurrentEnvironment() =>
        FromEnvironment(Environment.GetEnvironmentVariable, GetHomeDirectory());

    public static ForemanPaths FromEnvironment(Func<string, string?> getEnv, string homeDirectory)
    {
        if (string.IsNullOrWhiteSpace(homeDirectory))
            throw new ArgumentException("A home directory is required for XDG fallback paths.", nameof(homeDirectory));

        var config = Under(getEnv("XDG_CONFIG_HOME"), homeDirectory, ".config");
        var state = Under(getEnv("XDG_STATE_HOME"), homeDirectory, ".local", "state");
        var data = Under(getEnv("XDG_DATA_HOME"), homeDirectory, ".local", "share");
        var runtime = getEnv("XDG_RUNTIME_DIR");
        if (string.IsNullOrWhiteSpace(runtime))
            runtime = JoinPosix(state, "run");

        return new ForemanPaths(
            JoinPosix(config, "foreman"),
            JoinPosix(state, "foreman"),
            JoinPosix(data, "foreman"),
            JoinPosix(runtime, "foreman"));
    }

    private static string Under(string? value, string homeDirectory, params string[] fallbackParts) =>
        string.IsNullOrWhiteSpace(value)
            ? JoinPosix(homeDirectory, fallbackParts)
            : value;

    private static string GetHomeDirectory() =>
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static string JoinPosix(string root, params string[] parts)
    {
        var result = root.TrimEnd('/');
        foreach (var part in parts)
        {
            if (string.IsNullOrWhiteSpace(part)) continue;
            result += "/" + part.Trim('/');
        }
        return result;
    }
}
