using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Foreman.Vault;

namespace Foreman.App.Vault;

/// <summary>
/// Binds the vault's key component to this Windows user + machine via DPAPI (CurrentUser). A stolen component blob
/// cannot be unprotected by another user or on another machine, so moving the vault files elsewhere makes them
/// unopenable; combined with the master password (which is never stored), a stolen vault file stays sealed and the
/// vault is PC-bound. (Future: a Guardian/TPM SYSTEM-principal protector for an even stronger boundary.)
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiVaultKeyProtector : IVaultKeyProtector
{
    // App-specific entropy so the blob can't be cross-unprotected by another app running as the same user.
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Foreman.Vault.KeyComponent.v1");

    public byte[] Protect(byte[] secret) => ProtectedData.Protect(secret, Entropy, DataProtectionScope.CurrentUser);
    public byte[] Unprotect(byte[] blob) => ProtectedData.Unprotect(blob, Entropy, DataProtectionScope.CurrentUser);
}
