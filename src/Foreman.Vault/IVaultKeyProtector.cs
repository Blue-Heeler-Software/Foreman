namespace Foreman.Vault;

/// <summary>
/// Protects the vault's key component at rest, bound to this user + machine. The App provides a DPAPI (CurrentUser)
/// implementation; a future Guardian/TPM-backed implementation can replace it without touching the store. <see
/// cref="Unprotect"/> throws if the blob is presented on a different user/machine or has been tampered with — which,
/// combined with the master password, is what makes a stolen vault file unopenable and the vault PC-bound.
/// </summary>
public interface IVaultKeyProtector
{
    byte[] Protect(byte[] secret);
    byte[] Unprotect(byte[] blob);
}
