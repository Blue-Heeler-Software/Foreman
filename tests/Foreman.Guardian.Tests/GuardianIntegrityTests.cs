using Foreman.Guardian;

namespace Foreman.Guardian.Tests;

/// <summary>
/// Circle-back Phase A, step 6: the guardian's Authenticode gate — used both to authenticate pipe clients (only
/// the same-publisher Foreman may request a seal) and to self-verify before installing as SYSTEM (LPE guard). The
/// pure release decision fails closed for unsigned inputs; the separate install path admits an unsigned developer
/// build only after resolving a live Foreman process and validating the canonical staged layout.
/// </summary>
public sealed class GuardianIntegrityTests
{
    [Fact]
    public void InstallReferenceUnsigned_FailsClosed()
        => Assert.False(GuardianIntegrity.Decide(referenceSigner: null, subjectSigner: "ABC").Trusted);

    [Fact]
    public void SubjectUnsigned_ReferenceSigned_Rejects() // signed release vs an unsigned impostor
        => Assert.False(GuardianIntegrity.Decide(referenceSigner: "ABC", subjectSigner: null).Trusted);

    [Fact]
    public void DifferentPublisher_Rejects()
        => Assert.False(GuardianIntegrity.Decide(referenceSigner: "ABC", subjectSigner: "DEF").Trusted);

    [Fact]
    public void SamePublisher_Allows()
        => Assert.True(GuardianIntegrity.Decide(referenceSigner: "ABC", subjectSigner: "abc").Trusted); // case-insensitive thumbprint

    [Fact]
    public void DevelopmentLayout_RequiresCanonicalGuardianSubdirectory()
    {
        Assert.True(GuardianInstallReference.LayoutMatches(
            @"C:\Foreman-dev\Foreman.exe",
            @"C:\Foreman-dev\guardian\Foreman.Guardian.exe"));
        Assert.False(GuardianInstallReference.LayoutMatches(
            @"C:\Foreman-dev\Foreman.exe",
            @"C:\attacker\Foreman.Guardian.exe"));
    }
}
