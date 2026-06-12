namespace Foreman.Core.Security;

/// <summary>Outcome of a presence assertion — the user tapping Windows Hello or a security key.</summary>
public sealed record PresenceResult(bool Verified, string? AuthenticatorLabel, string? FailureReason)
{
    public static PresenceResult Ok(string? label) => new(true, label, null);
    public static PresenceResult Fail(string reason) => new(false, null, reason);
}

/// <summary>Outcome of enrolling an authenticator: the credential id to pin in settings, or why it failed.</summary>
public sealed record EnrollResult(bool Ok, string? CredentialId, string? AuthenticatorLabel, string? FailureReason)
{
    public static EnrollResult Success(string credentialId, string? label) => new(true, credentialId, label, null);
    public static EnrollResult Fail(string reason) => new(false, null, null, reason);
}

/// <summary>
/// Prompts a hardware user-presence authenticator — Windows Hello (platform: PIN/biometric) OR a roaming
/// FIDO2/U2F security key (YubiKey). Windows' WebAuthn API aggregates all of them in one native picker, so a
/// single implementation covers "all authenticators". The real implementation lives in the Windows app layer
/// (webauthn.dll + a window handle to parent the native dialog); Core depends only on this interface so
/// <see cref="PresenceGate"/> stays pure and unit-testable with a fake. The whole point: a presence tap is the
/// one thing a same-user rogue process can't satisfy programmatically.
/// </summary>
public interface IPresenceVerifier
{
    /// <summary>True if any presence authenticator is usable here (Hello configured and/or a key attachable).</summary>
    bool IsAvailable { get; }

    /// <summary>Enroll an authenticator once (the user taps); returns the credential id to pin in settings.</summary>
    Task<EnrollResult> EnrollAsync(string reason, CancellationToken ct = default);

    /// <summary>Assert presence with the pinned credential. Verified only on a real, fresh human tap.</summary>
    Task<PresenceResult> VerifyAsync(string credentialId, string reason, CancellationToken ct = default);
}
