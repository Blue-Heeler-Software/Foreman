namespace Foreman.Platform;

public interface ITokenFileProtector
{
    TokenFileProtectionResult Protect(string path);
}

public sealed record TokenFileProtectionResult(bool Ok, string? Warning = null)
{
    public static TokenFileProtectionResult Success() => new(true);
    public static TokenFileProtectionResult Degraded(string warning) => new(false, warning);
}
