namespace Foreman.Core.Vault;

/// <summary>
/// Resolves <c>{{vault:...}}</c> references to plaintext at the injection boundary, enforcing domain-binding + ACL. The
/// result's plaintext must never be logged or returned to an agent — only handed to the injector (sidecar/extension).
/// </summary>
public interface IVaultResolver
{
    VaultResolveResult Resolve(string text, string liveTargetHost, string? harnessId, bool isOperator);
}
