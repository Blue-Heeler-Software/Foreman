namespace Foreman.Core.Vault;

/// <summary>
/// Pure origin-matching for the phishing defense: a credential resolves only when BOTH the requested origin (from the
/// reference) AND the live target (the actual tab origin / bound-window label) are origins the item is registered for.
/// Matching is strict host equality (case-insensitive, trailing-dot/whitespace normalized). Subdomain / registrable-domain
/// matching is deliberately NOT done in v1 (strict is safer). An empty/unknown live target fails closed.
/// </summary>
public static class VaultDomainBinding
{
    public static string NormalizeHost(string? host) =>
        (host ?? string.Empty).Trim().Trim('.').ToLowerInvariant();

    public static bool HostMatches(string? a, string? b)
    {
        var na = NormalizeHost(a);
        return na.Length > 0 && na == NormalizeHost(b);
    }

    /// <summary>Release is allowed only if the item owns BOTH the requested origin and the live target host.</summary>
    public static bool ReleaseAllowed(IReadOnlyList<string> itemOrigins, string requestedOrigin, string? liveTargetHost)
    {
        if (itemOrigins is null || itemOrigins.Count == 0) return false;
        if (string.IsNullOrWhiteSpace(liveTargetHost)) return false;          // no verifiable target → fail closed
        var ownsRequested = itemOrigins.Any(o => HostMatches(o, requestedOrigin));
        var liveMatches   = itemOrigins.Any(o => HostMatches(o, liveTargetHost));
        return ownsRequested && liveMatches;
    }
}
