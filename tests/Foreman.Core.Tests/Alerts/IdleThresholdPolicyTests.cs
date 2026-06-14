using Foreman.Core.Alerts;

namespace Foreman.Core.Tests.Alerts;

public sealed class IdleThresholdPolicyTests
{
    private static IdleThresholdScalingSettings S(
        bool enabled = true, double maxAway = 3.0, double atRest = 1.5,
        double maxMult = 4.0, int absMax = 180) => new()
    {
        Enabled = enabled, MaxOperatorAwayFactor = maxAway, AtRestFactor = atRest,
        MaxMultiplier = maxMult, AbsoluteMaxThresholdMinutes = absMax,
    };

    private static int Eff(int baseMin, int opIdle, HarnessActivity act, IdleThresholdScalingSettings? s = null) =>
        IdleThresholdPolicy.Effective(baseMin, opIdle, act, s ?? S()).EffectiveMinutes;

    [Fact]   // disabled → flat base, no scaling
    public void Disabled_ReturnsBase()
    {
        Assert.Equal(30, Eff(30, opIdle: 600, act: HarnessActivity.AtRest, s: S(enabled: false)));
    }

    [Fact]   // operator present + harness active → today's behaviour (base)
    public void PresentAndActive_IsBase()
    {
        Assert.Equal(30, Eff(30, opIdle: 0, act: HarnessActivity.Active));
        Assert.Equal(30, Eff(30, opIdle: 25, act: HarnessActivity.Active));  // still within the base window
    }

    [Fact]   // present + at rest → only the at-rest factor applies
    public void PresentAtRest_AppliesAtRestFactorOnly()
    {
        Assert.Equal(45, Eff(30, opIdle: 10, act: HarnessActivity.AtRest));  // 30 × 1.5
    }

    [Fact]   // away + active → only the operator factor applies, ramping with idle time
    public void AwayActive_AppliesOperatorFactorOnly()
    {
        Assert.Equal(60, Eff(30, opIdle: 60, act: HarnessActivity.Active));  // ratio 2.0 → 30×2
        Assert.Equal(90, Eff(30, opIdle: 90, act: HarnessActivity.Active));  // ratio 3.0 → 30×3 (= MaxAway)
    }

    [Fact]   // away + at rest → both factors compound, then the multiplier cap bites
    public void AwayAtRest_CompoundsThenCaps()
    {
        // away factor 3.0 (idle 90 = 3×base) × at-rest 1.5 = 4.5 → capped at MaxMultiplier 4.0 → 120m
        Assert.Equal(120, Eff(30, opIdle: 90, act: HarnessActivity.AtRest));
    }

    [Fact]   // the absolute ceiling always wins so a real stall eventually alerts
    public void AbsoluteCeiling_Bounds()
    {
        // base 60, huge idle, at rest: 60×4 = 240 → absolute cap 180
        Assert.Equal(180, Eff(60, opIdle: 100000, act: HarnessActivity.AtRest, s: S(absMax: 180)));
    }

    [Fact]   // MONOTONIC: the result is never below the base for any input
    public void NeverBelowBase()
    {
        int[] idles = { 0, 1, 5, 29, 30, 31, 120, 100000 };
        HarnessActivity[] acts = { HarnessActivity.Active, HarnessActivity.AtRest, HarnessActivity.Unknown };
        foreach (var idle in idles)
            foreach (var act in acts)
                Assert.True(Eff(30, idle, act) >= 30, $"idle={idle} act={act} dropped below base");
    }

    [Fact]   // Unknown activity is treated as Active (no relaxation on missing data)
    public void UnknownActivity_TreatedAsActive()
    {
        Assert.Equal(Eff(30, opIdle: 60, act: HarnessActivity.Active),
                     Eff(30, opIdle: 60, act: HarnessActivity.Unknown));
    }

    [Fact]   // a misconfigured ceiling below base still never pushes below base
    public void CeilingBelowBase_ClampedToBase()
    {
        Assert.Equal(30, Eff(30, opIdle: 600, act: HarnessActivity.AtRest, s: S(absMax: 10)));
    }

    [Fact]   // factors below 1.0 in settings can't tighten the window (clamped up)
    public void SubUnityFactors_CannotTighten()
    {
        var s = S(maxAway: 0.2, atRest: 0.1, maxMult: 0.5);
        Assert.Equal(30, Eff(30, opIdle: 600, act: HarnessActivity.AtRest, s: s));
    }

    [Fact]   // the reason string is populated when scaling actually kicks in (for the event message)
    public void Reason_DescribesScaling()
    {
        var r = IdleThresholdPolicy.Effective(30, 90, HarnessActivity.AtRest, S());
        Assert.True(r.Multiplier > 1.0);
        Assert.Contains("operator idle 90m", r.Reason);
        Assert.Contains("at rest", r.Reason);
    }
}
