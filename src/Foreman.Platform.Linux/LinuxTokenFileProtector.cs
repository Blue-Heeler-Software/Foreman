using Foreman.Platform;

namespace Foreman.Platform.Linux;

public sealed class LinuxTokenFileProtector : ITokenFileProtector
{
    public TokenFileProtectionResult Protect(string path)
    {
        if (!OperatingSystem.IsLinux())
            return TokenFileProtectionResult.Degraded("Linux token permissions can only be applied on Linux.");

        try
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
                File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            if (File.Exists(path))
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            return TokenFileProtectionResult.Success();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            return TokenFileProtectionResult.Degraded(ex.Message);
        }
    }
}
