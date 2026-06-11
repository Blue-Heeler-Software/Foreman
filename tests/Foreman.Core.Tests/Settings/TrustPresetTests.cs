using Foreman.Core.Alerts;
using Foreman.Core.Settings;

namespace Foreman.Core.Tests.Settings;

public sealed class TrustPresetTests
{
    [Fact]
    public void Thresholds_Level3_EqualsGlobalBaseline()
    {
        var s = new ForemanSettings { AlertLevelMediumCount = 4, AlarmLevelHighCount = 9, EmergencyLevelTotalAlerts = 99 };
        var t = TrustPreset.Thresholds(3, s);
        var g = EscalationThresholds.FromGlobal(s);
        Assert.Equal(g.AlertLevelMediumCount, t.AlertLevelMediumCount);
        Assert.Equal(g.AlarmLevelHighCount, t.AlarmLevelHighCount);
        Assert.Equal(g.EmergencyLevelTotalAlerts, t.EmergencyLevelTotalAlerts);
        Assert.Equal(g.EmergencyRuleIds, t.EmergencyRuleIds);
    }

    [Fact]
    public void Thresholds_LowerTrust_Stricter_HigherTrust_Looser()
    {
        var s = new ForemanSettings();
        var t1 = TrustPreset.Thresholds(1, s);
        var t3 = TrustPreset.Thresholds(3, s);
        var t5 = TrustPreset.Thresholds(5, s);
        Assert.True(t1.AlertLevelMediumCount < t3.AlertLevelMediumCount);          // fire sooner when locked-down
        Assert.True(t3.AlertLevelMediumCount < t5.AlertLevelMediumCount);          // more rope when hands-off
        Assert.True(t1.EmergencyLevelTotalAlerts < t5.EmergencyLevelTotalAlerts);
        Assert.True(t1.AlarmLevelUniqueRules < t5.AlarmLevelUniqueRules);
    }

    [Fact]
    public void Thresholds_NeverShrinksEmergencyRuleIds_BelowBaseline()   // the always-escalate floor holds at every level
    {
        var s = new ForemanSettings();
        foreach (var lvl in new[] { 1, 2, 3, 4, 5 })
        {
            var ids = TrustPreset.Thresholds(lvl, s).EmergencyRuleIds;
            foreach (var baseId in s.EmergencyRuleIds)
                Assert.Contains(baseId, ids);
        }
    }

    [Fact]
    public void Thresholds_Level1_AddsLockdownEmergencyIds()
    {
        var s = new ForemanSettings();
        var ids = TrustPreset.Thresholds(1, s).EmergencyRuleIds;
        Assert.Contains("cred-001", ids);                       // the meaningful addition at lockdown
        Assert.True(ids.Length >= s.EmergencyRuleIds.Length);
    }

    [Theory]
    [InlineData(0)]    // below range → clamps to 1
    [InlineData(99)]   // above range → clamps to 5
    public void Thresholds_OutOfRange_Clamps_DoesNotThrow(int lvl)
        => Assert.NotEmpty(TrustPreset.Thresholds(lvl, new ForemanSettings()).EmergencyRuleIds);

    [Fact]
    public void Responses_Level1_IsMostAggressive()
    {
        var r = TrustPreset.Responses(1);
        Assert.Equal(EscalationAction.AskHarness, r.OnAlert);
        Assert.True(r.OnEmergency.HasFlag(EscalationAction.RequestSelfCleanup));
    }

    [Fact]
    public void Responses_Level3_AreTheDefaults()
    {
        var r = TrustPreset.Responses(3);
        var d = new AlertResponseSettings();
        Assert.Equal(d.OnAlert, r.OnAlert);
        Assert.Equal(d.OnAlarm, r.OnAlarm);
        Assert.Equal(d.OnEmergency, r.OnEmergency);
    }

    [Fact]
    public void Responses_Level5_QuietButEmergencyStillAsks()   // hands-off never goes fully silent on Emergency
    {
        var r = TrustPreset.Responses(5);
        Assert.Equal(EscalationAction.None, r.OnAlert);
        Assert.Equal(EscalationAction.None, r.OnAlarm);
        Assert.Equal(EscalationAction.AskHarness, r.OnEmergency);
    }

    [Fact]
    public void EffectiveThresholds_UnsetHarness_UsesGlobal()
    {
        var s = new ForemanSettings { AlertLevelMediumCount = 7 };
        Assert.Equal(7, s.EffectiveThresholds("claude-code").AlertLevelMediumCount);   // no Trust entry → global
    }

    [Fact]
    public void EffectiveThresholds_SetHarness_UsesPreset()
    {
        var s = new ForemanSettings();
        s.HarnessTrust["codex"] = 1;
        var t = s.EffectiveThresholds("codex");
        Assert.Equal(1, t.AlertLevelMediumCount);            // level-1 absolute
        Assert.Contains("cred-001", t.EmergencyRuleIds);
    }

    [Fact]
    public void EffectiveThresholds_HarnessKey_IsCaseInsensitive()
    {
        var s = new ForemanSettings();
        s.HarnessTrust["Codex"] = 5;
        Assert.Equal(8, s.EffectiveThresholds("codex").AlertLevelMediumCount);   // level-5, case-insensitive key
    }
}
