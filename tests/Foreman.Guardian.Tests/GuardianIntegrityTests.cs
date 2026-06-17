using Foreman.Guardian;

namespace Foreman.Guardian.Tests;

/// <summary>
/// Circle-back Phase A, step 6: the guardian's Authenticode gate — used both to authenticate pipe clients (only
/// the same-publisher Foreman may request a seal) and to self-verify before installing as SYSTEM (LPE guard). The
/// pure decision auto-adapts to dev (unsigned reference ⇒ allow) vs release (enforce signer match).
/// </summary>
public sealed class GuardianIntegrityTests
{
    [Fact]
    public void ReferenceUnsigned_Allows() // dev build: no trust anchor → not enforced
        => Assert.True(GuardianIntegrity.Decide(referenceSigner: null, subjectSigner: "ABC").Trusted);

    [Fact]
    public void SubjectUnsigned_ReferenceSigned_Rejects() // signed release vs an unsigned impostor
        => Assert.False(GuardianIntegrity.Decide(referenceSigner: "ABC", subjectSigner: null).Trusted);

    [Fact]
    public void DifferentPublisher_Rejects()
        => Assert.False(GuardianIntegrity.Decide(referenceSigner: "ABC", subjectSigner: "DEF").Trusted);

    [Fact]
    public void SamePublisher_Allows()
        => Assert.True(GuardianIntegrity.Decide(referenceSigner: "ABC", subjectSigner: "abc").Trusted); // case-insensitive thumbprint
}
