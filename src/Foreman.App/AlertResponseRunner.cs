using Foreman.Core.Alerts;
using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Settings;

namespace Foreman.App;

/// <summary>
/// Drives the operator-configured automatic responses (Settings → Automatic responses). Subscribes to
/// the EventBus and, when a harness escalates UP to a tier, fires the enabled + gated actions
/// (Ask Harness / Adversarial Audit / Request self-cleanup) via injected delegates — rate-limited per
/// harness+action so an oscillating harness can't trigger a storm. The DECISION (which actions, and the
/// audit-scope guardrail) lives in <see cref="AlertResponsePolicy"/>; this is thin glue.
/// </summary>
public sealed class AlertResponseRunner : IEventSink
{
    private readonly ForemanSettings _settings;
    private readonly object _gate = new();
    private readonly Dictionary<string, DateTimeOffset> _lastFired = new();

    /// <summary>Ask the offending harness to justify/correct. Wired by App.</summary>
    public Action<EscalationEvent>? AskHarness { get; set; }
    /// <summary>Route the alert to a different harness/API for an independent review. Wired by App.</summary>
    public Action<EscalationEvent>? AdversarialAudit { get; set; }
    /// <summary>Ask the harness to wrap up / stop leftover children. Wired by App.</summary>
    public Action<EscalationEvent>? RequestSelfCleanup { get; set; }

    public AlertResponseRunner(ForemanSettings settings) => _settings = settings;

    void IEventSink.OnEvent(ForemanEvent evt)
    {
        if (evt is not EscalationEvent esc) return;
        if (esc.NewLevel <= esc.OldLevel) return;            // only on escalation UP, not on re-publish/decay
        if (esc.NewLevel < EscalationLevel.Alert) return;    // Watch never auto-acts

        // Per-harness Trust selects the auto-response tier; an unset harness uses the global settings.
        var tier = _settings.HarnessTrust.TryGetValue(esc.HarnessId, out var lvl)
            ? TrustPreset.Responses(lvl)
            : _settings.AlertResponses;
        var actions = AlertResponsePolicy.Effective(
            AlertResponsePolicy.ForLevel(tier, esc.NewLevel), esc);
        if (actions == EscalationAction.None) return;

        if (actions.HasFlag(EscalationAction.AskHarness))         Fire(esc, "ask",     AskHarness);
        if (actions.HasFlag(EscalationAction.AdversarialAudit))   Fire(esc, "audit",   AdversarialAudit);
        if (actions.HasFlag(EscalationAction.RequestSelfCleanup)) Fire(esc, "cleanup", RequestSelfCleanup);
    }

    private void Fire(EscalationEvent esc, string action, Action<EscalationEvent>? impl)
    {
        if (impl is null) return;

        var cooldown = TimeSpan.FromMinutes(Math.Max(0, _settings.AlertResponses.CooldownMinutes));
        var key = $"{esc.HarnessId}|{action}";
        lock (_gate)
        {
            if (cooldown > TimeSpan.Zero
                && _lastFired.TryGetValue(key, out var last)
                && DateTimeOffset.UtcNow - last < cooldown)
                return;   // still cooling down for this harness+action
            _lastFired[key] = DateTimeOffset.UtcNow;
        }

        try { impl(esc); }
        catch { /* an auto-response failure must never break the event bus */ }
    }
}
