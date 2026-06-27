namespace Foreman.Core.Vault;

/// <summary>
/// Pure resolution logic over an injected <see cref="IVaultStore"/>: substitutes <c>{{vault:origin/field}}</c>
/// references with real values, enforcing (1) vault unlocked, (2) the item exists, (3) domain-binding — the live target
/// must match the item's origin, (4) the caller is authorized — the operator, or a harness explicitly listed on the
/// item. Fail-closed and all-or-nothing: any failing reference yields a null result plus a safe reason; never a partial
/// substitution and never an existence oracle ("not found" reads the same as "not yours").
/// </summary>
public sealed class VaultResolver(IVaultStore store) : IVaultResolver
{
    private readonly IVaultStore _store = store;

    public VaultResolveResult Resolve(string text, string liveTargetHost, string? harnessId, bool isOperator)
    {
        if (!VaultReference.HasReference(text)) return VaultResolveResult.Passthrough(text);
        if (!_store.IsUnlocked) return VaultResolveResult.Fail("vault is locked");

        var refs = new List<string>();
        string? reason = null;

        var output = VaultReference.Replace(text, (origin, field) =>
        {
            var info = _store.FindByOrigin(origin);
            if (info is null) { reason ??= "credential not found"; return null; }                       // no existence oracle
            if (!VaultDomainBinding.ReleaseAllowed(info.Origins, origin, liveTargetHost))
            { reason ??= $"live target '{liveTargetHost}' does not match the credential's origin"; return null; }
            if (!isOperator && !info.AllowsHarness(harnessId))
            { reason ??= "this harness is not authorized for that credential"; return null; }
            var secret = _store.GetSecret(origin, field);
            if (secret is null) { reason ??= "credential field is empty"; return null; }
            refs.Add($"{VaultDomainBinding.NormalizeHost(origin)}/{field.ToString().ToLowerInvariant()}");
            return secret;
        });

        return output is null
            ? VaultResolveResult.Fail(reason ?? "unresolved vault reference")
            : VaultResolveResult.Success(output, refs);
    }
}
