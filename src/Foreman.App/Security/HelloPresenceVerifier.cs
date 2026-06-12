using Foreman.Core.Security;
using Windows.Security.Credentials.UI;

namespace Foreman.App.Security;

/// <summary>
/// <see cref="IPresenceVerifier"/> backed by Windows Hello — the platform authenticator (PIN / fingerprint /
/// face) — via WinRT <see cref="UserConsentVerifier"/>. This is the reliable, dependency-free first
/// authenticator: it covers the common case and is live-verifiable immediately. Roaming FIDO2/U2F security keys
/// (YubiKey) need the webauthn.dll picker and are a drop-in second <see cref="IPresenceVerifier"/> behind the
/// same seam — the gate and every wired site are unchanged when that lands.
///
/// Hello consent is a presence check, not a per-credential ceremony, so there is no real credential id —
/// enrollment just confirms Hello works and pins the sentinel <see cref="CredentialId"/> so the gate has a
/// non-empty value to assert against (empty ⇒ fail-closed).
/// </summary>
public sealed class HelloPresenceVerifier : IPresenceVerifier
{
    /// <summary>Sentinel pinned in settings for the platform-Hello verifier (which has no roaming credential id).</summary>
    public const string CredentialId = "windows-hello";

    public bool IsAvailable
    {
        get
        {
            try
            {
                return UserConsentVerifier.CheckAvailabilityAsync().AsTask().GetAwaiter().GetResult()
                    == UserConsentVerifierAvailability.Available;
            }
            catch { return false; }
        }
    }

    public async Task<EnrollResult> EnrollAsync(string reason, CancellationToken ct = default)
    {
        try
        {
            var avail = await UserConsentVerifier.CheckAvailabilityAsync().AsTask().ConfigureAwait(false);
            if (avail != UserConsentVerifierAvailability.Available)
                return EnrollResult.Fail(
                    $"Windows Hello isn't available ({avail}). Set up a PIN or biometric in Windows Settings → Accounts → Sign-in options first.");

            // A confirming tap at enrollment so the user proves the authenticator works before the lock arms.
            var r = await UserConsentVerifier.RequestVerificationAsync(reason).AsTask().ConfigureAwait(false);
            return r == UserConsentVerificationResult.Verified
                ? EnrollResult.Success(CredentialId, "Windows Hello")
                : EnrollResult.Fail($"Enrollment tap not verified ({r}).");
        }
        catch (Exception ex) { return EnrollResult.Fail($"Windows Hello error: {ex.Message}"); }
    }

    public async Task<PresenceResult> VerifyAsync(string credentialId, string reason, CancellationToken ct = default)
    {
        try
        {
            var r = await UserConsentVerifier.RequestVerificationAsync(reason).AsTask().ConfigureAwait(false);
            return r == UserConsentVerificationResult.Verified
                ? PresenceResult.Ok("Windows Hello")
                : PresenceResult.Fail(r.ToString());
        }
        catch (Exception ex) { return PresenceResult.Fail($"Windows Hello error: {ex.Message}"); }
    }
}
