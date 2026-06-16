using Foreman.Core.Models;
using Foreman.Core.Settings;

namespace Foreman.Core.Tests.Settings;

public sealed class SettingsSealTests
{
    private const string Secret = "install-secret-abc123";

    private static ForemanSettings Base()
    {
        var s = new ForemanSettings
        {
            RunElevated = false,
            EventLogPersist = true,
            MonitorAllProcesses = false,
            ScanMcpTools = true,
            McpPeerBindingEnforce = true,
            DisabledHarnesses = ["aider", "cline"],
            EmergencyRuleIds = ["cred-004", "net-001"],
            HarnessTrust = new() { ["codex"] = 3, ["claude-code"] = 4 },
        };
        s.PresenceLock.Enabled = true;
        s.DecoyCredentials.EnableReadAuditing = true;
        return s;
    }

    [Fact]   // seal then verify the same settings → Sealed
    public void SealThenVerify_Matches()
    {
        var s = Base();
        var seal = SettingsSeal.Compute(s, Secret);
        Assert.Equal(SettingsSealVerdict.Sealed, SettingsSeal.Verify(s, seal, Secret));
    }

    [Fact]   // no seal yet (first run / upgrade) → Unsealed, not a false tamper
    public void NoSeal_IsUnsealed()
    {
        Assert.Equal(SettingsSealVerdict.Unsealed, SettingsSeal.Verify(Base(), null, Secret));
        Assert.Equal(SettingsSealVerdict.Unsealed, SettingsSeal.Verify(Base(), "", Secret));
    }

    [Theory]   // flipping ANY security-significant field invalidates the seal (the attack we must detect)
    [InlineData("runElevated")]
    [InlineData("eventLogPersist")]
    [InlineData("presence")]
    [InlineData("hashChain")]
    [InlineData("disabled")]
    [InlineData("trust")]
    [InlineData("emergency")]
    [InlineData("decoyRead")]
    [InlineData("peerBinding")]
    [InlineData("mute")]
    public void TamperingASecurityField_IsDetected(string field)
    {
        var s = Base();
        var seal = SettingsSeal.Compute(s, Secret);   // sealed by Foreman

        switch (field)   // ...then an external edit weakens posture
        {
            case "runElevated":     s.RunElevated = true; break;
            case "eventLogPersist": s.EventLogPersist = false; break;
            case "presence":        s.PresenceLock.Enabled = false; break;
            case "hashChain":       s.LogIntegrity.HashChainEnabled = false; break;
            case "disabled":        s.DisabledHarnesses.Add("codex"); break;
            case "trust":           s.HarnessTrust["codex"] = 1; break;
            case "emergency":       s.EmergencyRuleIds = ["cred-004"]; break;   // dropped net-001
            case "decoyRead":       s.DecoyCredentials.EnableReadAuditing = false; break;
            case "peerBinding":     s.McpPeerBindingEnforce = false; break;
            case "mute":            s.Mutes.Add(new MuteEntry { Scope = "category", Value = "cred" }); break;
        }

        Assert.Equal(SettingsSealVerdict.Tampered, SettingsSeal.Verify(s, seal, Secret));
    }

    [Fact]   // changing a NON-security field (noise threshold) does NOT invalidate the seal
    public void NonSecurityField_DoesNotInvalidate()
    {
        var s = Base();
        var seal = SettingsSeal.Compute(s, Secret);
        s.HangThresholdMinutes = 999;
        s.NotifyOnHang = false;
        Assert.Equal(SettingsSealVerdict.Sealed, SettingsSeal.Verify(s, seal, Secret));
    }

    [Fact]   // the seal is order-independent (re-serialization can't cause a false tamper)
    public void ProjectionIsOrderIndependent()
    {
        var a = Base();
        var b = Base();
        b.DisabledHarnesses = ["cline", "aider"];          // reversed
        b.EmergencyRuleIds = ["net-001", "cred-004"];      // reversed
        Assert.Equal(SettingsSeal.Compute(a, Secret), SettingsSeal.Compute(b, Secret));
    }

    [Fact]   // a different install secret can't produce a matching seal (blocks cross-user/offline tamper)
    public void WrongSecret_IsTampered()
    {
        var s = Base();
        var seal = SettingsSeal.Compute(s, Secret);
        Assert.Equal(SettingsSealVerdict.Tampered, SettingsSeal.Verify(s, seal, "different-secret"));
    }
}
