using Foreman.Core.Security;

namespace Foreman.App.Security;

/// <summary>
/// Routes presence to the right authenticator behind one <see cref="IPresenceVerifier"/> seam. Enrollment
/// prefers the WebAuthn picker (Windows Hello + roaming FIDO2/U2F keys like a YubiKey) when <c>webauthn.dll</c>
/// is available, falling back to the platform-only Hello verifier on older Windows. Verification routes by the
/// PINNED credential id: the Hello-fallback sentinel goes to the Hello verifier; any real FIDO credential id
/// goes to WebAuthn — so a key enrolled via WebAuthn and a Hello-only enrollment both keep working, and the
/// gate + every wired site stay unchanged.
/// </summary>
public sealed class CompositePresenceVerifier : IPresenceVerifier
{
    private readonly HelloPresenceVerifier _hello = new();
    private readonly WebAuthnPresenceVerifier _webauthn = new();

    private IPresenceVerifier Enroller => _webauthn.IsAvailable ? _webauthn : _hello;

    public bool IsAvailable => _webauthn.IsAvailable || _hello.IsAvailable;

    public Task<EnrollResult> EnrollAsync(string reason, CancellationToken ct = default)
        => Enroller.EnrollAsync(reason, ct);

    public Task<PresenceResult> VerifyAsync(string credentialId, string reason, CancellationToken ct = default)
        => (credentialId == HelloPresenceVerifier.CredentialId ? (IPresenceVerifier)_hello : _webauthn)
            .VerifyAsync(credentialId, reason, ct);
}
