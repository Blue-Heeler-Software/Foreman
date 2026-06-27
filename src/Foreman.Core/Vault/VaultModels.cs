namespace Foreman.Core.Vault;

/// <summary>A field of a vault item that a <c>{{vault:origin/field}}</c> reference can resolve.</summary>
public enum VaultField { Username, Password, Totp, Note }

/// <summary>
/// Non-secret metadata about a vault item: its name, the origin(s) it is registered for (domain-binding), the
/// harnesses allowed to resolve it, and whether it carries a TOTP seed. Never carries secret values — those come
/// from <see cref="IVaultStore.GetSecret"/> at the injection boundary only.
/// </summary>
public sealed record VaultItemInfo(
    string Name,
    IReadOnlyList<string> Origins,
    IReadOnlyList<string> Harnesses,
    bool HasTotp)
{
    /// <summary>Which fields the item carries — for the management UI only (still no secret values). Default false so
    /// existing resolver-path constructions keep working.</summary>
    public bool HasUsername { get; init; }
    public bool HasPassword { get; init; }

    /// <summary>True if a specific harness is authorized to resolve this item. Empty <see cref="Harnesses"/> =
    /// operator-only (deny by default) — a harness must be explicitly listed. The operator is allowed separately
    /// by the resolver (see <see cref="VaultResolver"/>).</summary>
    public bool AllowsHarness(string? harnessId) =>
        !string.IsNullOrEmpty(harnessId) &&
        Harnesses.Any(h => string.Equals(h, harnessId, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// Result of resolving <c>{{vault:...}}</c> references in a string. On success, <see cref="Resolved"/> carries the
/// plaintext-substituted text — SENSITIVE, valid only at the injection boundary, never logged. On failure it is null
/// (fail-closed, never partially substituted) and <see cref="Reason"/> says why (safe to log). <see cref="ResolvedRefs"/>
/// lists the references that were filled (e.g. "github.com/password") for the masked audit line.
/// </summary>
public sealed record VaultResolveResult(bool Ok, string? Resolved, string Reason, IReadOnlyList<string> ResolvedRefs)
{
    public static VaultResolveResult Passthrough(string text) => new(true, text, "no vault references", []);
    public static VaultResolveResult Success(string resolved, IReadOnlyList<string> refs) => new(true, resolved, "resolved", refs);
    public static VaultResolveResult Fail(string reason) => new(false, null, reason, []);
}
