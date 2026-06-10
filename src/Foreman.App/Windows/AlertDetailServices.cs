using Foreman.Core.Behavior;
using Foreman.Core.Models;
using Foreman.Core.Settings;
using Foreman.McpServer;

namespace Foreman.App.Windows;

/// <summary>
/// The data + action dependencies <see cref="AlertDetailWindow"/> needs, bundled into one object the App
/// composition root sets once — instead of ~11 scattered static hooks each assigned separately. Every
/// member is <c>required</c>, so forgetting to wire one is a COMPILE error, not a silent runtime null.
/// (Navigation like "Open Log" stays a separate tray-owned hook, matching EscalationAlarmWindow.)
/// </summary>
public sealed class AlertDetailServices
{
    /// <summary>Resolves a live ProcessRecord from a PID (process name + harness type for the alert).</summary>
    public required Func<int, ProcessRecord?> GetProcessByPid { get; init; }

    /// <summary>Resolves the BehaviorProfile for a harness key (current escalation level + session alert count).</summary>
    public required Func<string, BehaviorProfile?> GetProfileByHarness { get; init; }

    /// <summary>Walks the process tree to attribute a hook/spawned-shell PID to its harness.</summary>
    public required Func<int, ProcessRecord?> GetHarnessAncestorByPid { get; init; }

    /// <summary>Live process snapshot, for auditor-availability checks.</summary>
    public required Func<IEnumerable<ProcessRecord>> GetProcessSnapshot { get; init; }

    /// <summary>The user-defined LLM-triage routing preferences.</summary>
    public required Func<LlmTriageSettings> GetLlmTriageSettings { get; init; }

    /// <summary>Terminates the alert target (PID + captured start-time identity pin; refused on PID reuse).</summary>
    public required Func<int, DateTimeOffset?, bool> KillProcessByPid { get; init; }

    /// <summary>Persists an operator mute (notification suppression only).</summary>
    public required Action<MuteEntry> AddMute { get; init; }

    /// <summary>The emergency-tier rule ids, so the mute guardrail can protect them.</summary>
    public required Func<IReadOnlyList<string>> GetEmergencyRuleIds { get; init; }

    /// <summary>"Ask Harness": deliver a justify/act prompt to the offender's MCP session. (harnessId, system, user, requestId, ct).</summary>
    public required Func<string, string, string, string?, CancellationToken, Task<AskOffenderResult>> AskOffender { get; init; }

    /// <summary>Queues a durable Ask Harness request so clients that can't receive pushes can poll/reply.</summary>
    public required Func<string, string, string, string, int?, string?, AskHarnessRequest> QueueAskHarnessRequest { get; init; }

    /// <summary>Records a reply against a queued Ask Harness request.</summary>
    public required Func<string, string, string?, string?, int?, bool> RecordAskHarnessReply { get; init; }
}
