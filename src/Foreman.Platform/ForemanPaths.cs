namespace Foreman.Platform;

public sealed record ForemanPaths(
    string ConfigDir,
    string StateDir,
    string DataDir,
    string RuntimeDir) : IForemanPaths;

public interface IForemanPaths
{
    string ConfigDir { get; }
    string StateDir { get; }
    string DataDir { get; }
    string RuntimeDir { get; }
}
