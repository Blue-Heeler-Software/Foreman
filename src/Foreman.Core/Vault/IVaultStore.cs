namespace Foreman.Core.Vault;

/// <summary>
/// The credential-store seam. The KDBX-backed implementation lives in the Windows <c>Foreman.Vault</c> project; Core
/// depends only on this interface so it stays cross-platform. <see cref="GetSecret"/> is the ONLY method that returns
/// plaintext and must be called solely at the injection boundary, after the release gate.
/// </summary>
public interface IVaultStore
{
    /// <summary>True once the composite key (master password + TPM-sealed component) has opened the vault this session.</summary>
    bool IsUnlocked { get; }

    /// <summary>Non-secret metadata for the item registered to <paramref name="origin"/>, or null if none.</summary>
    VaultItemInfo? FindByOrigin(string origin, string? entryId = null);

    /// <summary>The plaintext for a field — for <see cref="VaultField.Totp"/>, the CURRENT code. SENSITIVE: injection
    /// boundary only. Null if the field is absent/empty.</summary>
    string? GetSecret(string origin, VaultField field, string? entryId = null);

    /// <summary>Zero/forget the in-memory derived key and any cached plaintext (called on panic / lock / exit).</summary>
    void WipeInMemoryKeys();
}
