using Foreman.Core.Alerts;
using Foreman.Core.Models;
using Foreman.Core.Settings;

namespace Foreman.Core.Tests.Alerts;

public sealed class AuditRouteResolverTests
{
    private static ProcessRecord Harness(string id, int pid = 100) => new()
    {
        Pid = pid,
        ParentPid = 0,
        Name = $"{id}.exe",
        StartTime = DateTimeOffset.UtcNow,
        IsHarness = true,
        HarnessType = id,
    };

    [Fact]
    public void Resolve_UsesConfiguredPreferenceWhenTargetMatches()
    {
        var settings = new LlmTriageSettings();
        var snapshot = new[] { Harness("codex"), Harness("cursor", 200) };
        var connected = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "codex" };

        var route = AuditRouteResolver.Resolve(settings, "cursor", ForemanSeverity.High, snapshot, connected);

        Assert.False(route.UsedFallback);
        Assert.Equal("codex", route.Selected?.AuditorId);
        Assert.True(route.Selected?.Available);
    }

    [Fact]
    public void Resolve_FallsBackToAnotherRunningHarnessWhenNoPreferenceConfigured()
    {
        var settings = new LlmTriageSettings
        {
            AuditorPreferences =
            [
                new()
                {
                    AuditorId = "codex",
                    TargetHarnessIds = ["claude-code"],
                    MinimumSeverities = ["High", "Critical"],
                },
            ],
        };
        var snapshot = new[] { Harness("codex"), Harness("cursor", 200) };
        var connected = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "codex" };

        var route = AuditRouteResolver.Resolve(settings, "cursor", ForemanSeverity.High, snapshot, connected);

        Assert.True(route.UsedFallback);
        Assert.Equal("codex", route.Selected?.AuditorId);
        Assert.True(route.Selected?.McpConnected);
    }

    [Fact]
    public void Resolve_ExcludesTargetHarnessFromFallback()
    {
        var settings = new LlmTriageSettings { AuditorPreferences = [] };
        var snapshot = new[] { Harness("cursor", 200) };

        var route = AuditRouteResolver.Resolve(settings, "cursor", ForemanSeverity.High, snapshot, connectedHarnessIds: new HashSet<string>(StringComparer.OrdinalIgnoreCase));

        Assert.Null(route.Selected);
        Assert.Contains("no other harness", route.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void UpsertAuditorPreference_AddsTargetToExistingAuditor()
    {
        var settings = new LlmTriageSettings();
        settings.UpsertAuditorPreference("cursor", "codex", "Codex CLI");

        var pref = settings.AuditorPreferences.First(p => p.AuditorId == "codex");
        Assert.Contains("cursor", pref.TargetHarnessIds, StringComparer.OrdinalIgnoreCase);
    }
}
