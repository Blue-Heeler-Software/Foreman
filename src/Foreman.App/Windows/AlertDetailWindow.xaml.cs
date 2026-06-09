using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Settings;
using Foreman.McpServer;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Media;

namespace Foreman.App.Windows;

public partial class AlertDetailWindow : Window
{
    private readonly ForemanEvent _event;

    /// <summary>Wired up by TrayController so the "Open Log" button can open the log window.</summary>
    public static Action? OpenLogRequested { get; set; }

    /// <summary>
    /// Wired up by App.xaml.cs. Resolves a live ProcessRecord from a PID so the alert
    /// can display which process and harness type triggered the rule.
    /// </summary>
    public static Func<int, ProcessRecord?>? GetProcessByPid { get; set; }

    /// <summary>
    /// Wired up by App.xaml.cs. Resolves the BehaviorProfile for a harness key so the
    /// alert can display the current escalation level and session alert count.
    /// </summary>
    public static Func<string, BehaviorProfile?>? GetProfileByHarness { get; set; }

    /// <summary>
    /// Wired up by App.xaml.cs. Walks the process tree to find the harness a process belongs
    /// to, so a hook or spawned shell (which matches no harness rule itself) is still
    /// attributed to its harness rather than shown as "not a tracked harness".
    /// </summary>
    public static Func<int, ProcessRecord?>? GetHarnessAncestorByPid { get; set; }

    /// <summary>Wired up by App.xaml.cs. Provides a live snapshot for auditor availability checks.</summary>
    public static Func<IEnumerable<ProcessRecord>>? GetProcessSnapshot { get; set; }

    /// <summary>Wired up by App.xaml.cs. Provides the user-defined LLM triage routing preferences.</summary>
    public static Func<LlmTriageSettings>? GetLlmTriageSettings { get; set; }

    /// <summary>
    /// Wired up by App.xaml.cs. Terminates the alert target. The second argument is the target's
    /// captured start time (identity pin) so the kill is refused if the PID was since recycled.
    /// </summary>
    public static Func<int, DateTimeOffset?, bool>? KillProcessByPid { get; set; }

    /// <summary>
    /// Wired up by App.xaml.cs. "Ask Harness": deliver a justify/act prompt to the OFFENDING harness's
    /// own MCP session (sampling round-trip → targeted notification). Returns how it was delivered;
    /// <see cref="AskOutcome.NoSession"/> means the caller falls back to the clipboard.
    /// Args: (harnessId, systemPrompt, userPrompt, cancellationToken).
    /// </summary>
    public static Func<string, string, string, CancellationToken, Task<AskOffenderResult>>? AskOffender { get; set; }

    private AlertDetailWindow(ForemanEvent evt)
    {
        _event = evt;
        InitializeComponent();
        DataContext = new AlertDetailVm(evt);

        // "Send for Audit" is only meaningful for alarming behavior (not hangs/mess/notices).
        SendForAuditButton.Visibility =
            AuditPolicy.QualifiesForAudit(evt) ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>Opens an AlertDetailWindow for the given event and forces it to the foreground.</summary>
    public static void ShowFor(ForemanEvent evt)
    {
        var w = new AlertDetailWindow(evt);
        w.Show();
        WindowActivation.Surface(w);
    }

    private void AcknowledgeClick(object sender, RoutedEventArgs e)
    {
        _event.Acknowledged = true;
        EventBus.Instance.Publish(new InfoEvent(
            DateTimeOffset.UtcNow,
            "Foreman",
            $"Alert acknowledged: [{_event.Id}] {_event.Message[..Math.Min(80, _event.Message.Length)]}"));
        Close();
    }

    private void OpenLogClick(object sender, RoutedEventArgs e)
    {
        try { OpenLogRequested?.Invoke(); }
        catch (Exception ex)
        {
            // Show type + message + partial stack so future failures are diagnosable
            var stackSnippet = ex.StackTrace is { Length: > 0 } st
                ? (st.Length > 400 ? st[..400] + "\n…" : st)
                : "(no stack trace)";
            MessageBox.Show(
                $"Could not open the event log.\n\n" +
                $"{ex.GetType().Name}: {ex.Message}\n\n{stackSnippet}",
                "Foreman", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        Close();
    }

    // "Ask Harness": prompt the OFFENDING harness itself to justify and/or act. Delivered to its own
    // live MCP session when possible (sampling round-trip → targeted notification), else a clipboard
    // prompt scoped to that harness. Applies to every alert type, including hangs/mess.
    private async void AskHarnessClick(object sender, RoutedEventArgs e)
    {
      try
      {
        var harnessId   = ResolveTargetHarnessId();
        var pid         = ResolveTargetPid();
        var processName = ResolveTargetProcessName();
        var prompt      = BuildSelfJustifyPrompt(harnessId, pid, processName);
        const string systemPrompt =
            "You are the AI coding agent that Foreman (a local watchdog on this machine) flagged. " +
            "This is a self-audit. Answer honestly and briefly: say what you were doing and whether it " +
            "is expected, then either justify it or take the corrective action requested.";

        // Try to deliver to the offender's own live MCP session. Bounded so a slow or declining client
        // can't hang the UI; any failure falls through to the clipboard.
        AskOffenderResult? result = null;
        if (AskOffender is not null && !string.IsNullOrWhiteSpace(harnessId))
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
                result = await AskOffender(harnessId!, systemPrompt, prompt, cts.Token);
            }
            catch { result = null; }
        }

        var clipped = TrySetClipboard(prompt);
        const string title = "Foreman - Ask Harness";

        switch (result?.Outcome)
        {
            case AskOutcome.Sampled:
                EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman",
                    $"Ask Harness: {Blank(result.MatchedClient, harnessId ?? "harness")} responded to alert [{_event.Id}]"));
                MessageBox.Show(
                    $"Asked the live {Blank(result.MatchedClient, harnessId ?? "harness")} session to account for this alert.\n\n" +
                    $"Its response:\n\n{Blank(result.ReplyText, "(the harness returned an empty response)")}",
                    title, MessageBoxButton.OK, MessageBoxImage.Information);
                break;

            case AskOutcome.Notified:
                MessageBox.Show(
                    $"Delivered a justify/act request to the live {Blank(result.MatchedClient, harnessId ?? "harness")} MCP session — " +
                    "check that session for its response.\n\n" +
                    "(That client doesn't support being queried directly, so no reply returns to Foreman. " +
                    (clipped ? "The prompt is also on your clipboard.)" : ")"),
                    title, MessageBoxButton.OK, MessageBoxImage.Information);
                break;

            default:  // NoSession, or MCP not wired / harness unresolved
                var owner = pid is int p
                    ? $"the {Blank(harnessId, "harness")} that owns pid {p}"
                    : $"the {Blank(harnessId, "offending harness")}";
                MessageBox.Show(
                    string.IsNullOrWhiteSpace(harnessId)
                        ? "Foreman couldn't attribute this alert to a specific harness."
                        : $"No live {harnessId} session is connected to Foreman's MCP, so the request couldn't be delivered automatically.\n\n" +
                          (clipped
                              ? $"A justify/act prompt is on your clipboard — paste it into {owner}."
                              : "(Copying the prompt to the clipboard failed.)") +
                          ConnectionHelp(harnessId),
                    title, MessageBoxButton.OK, MessageBoxImage.Information);
                break;
        }
      }
      catch (Exception ex)
      {
          MessageBox.Show($"Ask Harness failed.\n\n{ex.GetType().Name}: {ex.Message}",
              "Foreman - Ask Harness", MessageBoxButton.OK, MessageBoxImage.Warning);
      }
    }

    // "Send for Audit": route this alert to a DIFFERENT (non-self) auditor harness/API for an
    // independent second opinion. Shown only for alarming behavior (see AuditPolicy).
    private void SendForAuditClick(object sender, RoutedEventArgs e)
    {
        var targetHarnessId = ResolveTargetHarnessId();
        // A category-qualified alert (flagged command / permission hit) can be Medium; treat it as
        // alarming for routing so it still matches auditors whose minimum severity is High.
        var severity = AuditPolicy.QualifiesForAudit(_event) && _event.Severity < ForemanSeverity.High
            ? ForemanSeverity.High
            : _event.Severity;
        var route  = ResolveAuditRoute(targetHarnessId, severity);
        var prompt = BuildAuditPrompt(targetHarnessId, route.Selected);

        if (!TrySetClipboard(prompt))
        {
            MessageBox.Show("Could not copy the audit prompt to the clipboard.",
                "Foreman - Send for Audit", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman",
            $"Audit prompt prepared for alert [{_event.Id}] via {route.Selected?.DisplayName ?? "manual route"}"));

        MessageBox.Show(BuildAuditMessage(targetHarnessId, route),
            "Foreman - Send for Audit", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private static bool TrySetClipboard(string text)
    {
        try { Clipboard.SetText(text); return true; }
        catch { return false; }
    }

    private static string ConnectionHelp(string? harnessId)
    {
        var agent = string.Equals(harnessId, "codex", StringComparison.OrdinalIgnoreCase)
            ? "Codex"
            : "the agent";
        return $"\n\nTo fix automatic delivery: open Foreman Dashboard or tray menu > Connect agent > {agent} > Connect automatically, then restart {agent}.";
    }

    private string BuildAuditMessage(string? targetHarnessId, AuditRouteSelection route)
    {
        var target = Blank(targetHarnessId, "this process");
        var sb = new StringBuilder();
        sb.AppendLine("An audit prompt for this alert is on your clipboard.");
        sb.AppendLine();

        if (route.Selected is not { } a)
        {
            sb.AppendLine($"No configured reviewer matched {target}, so paste it into whichever harness or API you'd like to review it.");
            return sb.ToString().TrimEnd();
        }

        sb.AppendLine($"Suggested reviewer: {a.DisplayName} (configurable in Settings).");
        if (a.AuditorType.Equals("api", StringComparison.OrdinalIgnoreCase))
        {
            sb.AppendLine(a.Available
                ? $"Send it to the {a.DisplayName} API to review {target}."
                : $"{a.DisplayName} is your preferred reviewer for {target}, but no API endpoint is configured yet.");
        }
        else
        {
            sb.AppendLine(a.Available
                ? $"You have {a.RunningHarnessCount} {a.DisplayName} instance{(a.RunningHarnessCount == 1 ? "" : "s")} running — paste it into one to review {target}."
                : $"{a.DisplayName} is your preferred reviewer for {target}, but isn't running right now — start it, or paste the prompt into any AI.");
        }

        return sb.ToString().TrimEnd();
    }

    // The offender-directed (second-person) "justify and/or act" prompt. Reuses the same event-detail
    // and secret-masking helpers as the audit prompt, but addresses the harness that caused the alert.
    private string BuildSelfJustifyPrompt(string? harnessId, int? pid, string? processName)
    {
        var vm = DataContext as AlertDetailVm;
        var liveProcess = pid is int p ? GetProcessByPid?.Invoke(p) : null;
        var commandLine = ResolveTargetCommandLine(liveProcess);

        var sb = new StringBuilder();
        sb.AppendLine("Foreman — a local watchdog monitoring the AI coding agents on this machine — flagged an action attributed to you. This is a self-audit; account for it.");
        sb.AppendLine();
        sb.AppendLine("Alert");
        sb.AppendLine($"- Id: {_event.Id}");
        sb.AppendLine($"- Type: {vm?.EventTypeLabel ?? _event.GetType().Name}");
        sb.AppendLine($"- Severity: {_event.Severity}");
        sb.AppendLine($"- When: {_event.Timestamp:O}");
        sb.AppendLine($"- What Foreman saw: {_event.Message}");
        sb.AppendLine();
        sb.AppendLine("You");
        sb.AppendLine($"- Harness: {Blank(harnessId, "unknown")}");
        sb.AppendLine($"- Process: {Blank(processName, "unknown")}{(pid is int pp ? $" (pid {pp})" : "")}");

        if (!string.IsNullOrWhiteSpace(commandLine))
        {
            sb.AppendLine();
            sb.AppendLine("Command line (potential secrets masked):");
            sb.AppendLine(RedactSecrets(commandLine));
        }

        AppendEventSpecificDetails(sb);

        if (vm is not null && !string.IsNullOrWhiteSpace(vm.WhyDangerous))
        {
            sb.AppendLine();
            sb.AppendLine("Why Foreman flagged it:");
            sb.AppendLine(vm.WhyDangerous);
        }

        sb.AppendLine();
        sb.AppendLine(BuildAskLine());
        return sb.ToString();
    }

    // The concrete second-person ask, tailored to the alert type. Low/Medium housekeeping alerts may
    // be acknowledged by the harness itself (the AcknowledgeAlert MCP tool is gated to refuse
    // High/Critical, so a serious alert can't be self-silenced).
    private string BuildAskLine() => _event switch
    {
        HangDetectedEvent =>
            "This process has gone silent. Is it still doing useful work, or is it stuck/abandoned? " +
            "If it's stuck or no longer needed, abort it (Ctrl+C) or reap the child; otherwise explain " +
            "what it's waiting on. If this is a false alarm you may acknowledge the alert.",
        OrphanDetectedEvent =>
            "This child process outlived its parent. Is that intentional? If not, terminate it; if it " +
            "is, explain why — you may acknowledge the alert once accounted for.",
        NonzeroExitEvent =>
            "A process you launched exited non-zero. Explain what failed and whether you've handled it. " +
            "You may acknowledge the alert if this is expected.",
        CommandAlertEvent =>
            "Justify this command: what task required it, and is it safe as written? If it was a mistake " +
            "or unnecessary, do not run it (or abort it) and say so.",
        PermissionViolationEvent =>
            "Justify this access against your current task, or confirm it was unintended and stop.",
        EscalationEvent =>
            "Your recent activity tripped Foreman's escalation. Summarize what you're doing and why it " +
            "shouldn't be treated as alarming — or correct course.",
        _ =>
            "Account for this alert: explain whether it's expected and either justify it or take the " +
            "corrective action.",
    };

    private void KillProcessClick(object sender, RoutedEventArgs e)
    {
        var pid = ResolveTargetPid();
        if (pid is null)
        {
            MessageBox.Show(
                "This alert does not identify a single process to terminate. Use Behavior Metrics to kill an entire harness.",
                "Foreman - Kill/End Process",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        var processName = ResolveTargetProcessName() ?? "process";
        var result = MessageBox.Show(
            $"Kill/end \"{processName}\" (pid {pid.Value})?\n\nThis will immediately terminate the process tree rooted at this alert target.",
            "Foreman - Confirm Kill",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result != MessageBoxResult.Yes) return;

        var killed = KillProcessByPid?.Invoke(pid.Value, _event.ProcessStartTime) ?? false;
        if (!killed)
        {
            EventBus.Instance.Publish(new InfoEvent(
                DateTimeOffset.UtcNow,
                "Foreman",
                $"Kill/end failed for alert [{_event.Id}] target pid {pid.Value}"));

            MessageBox.Show(
                $"Foreman could not terminate pid {pid.Value}. It may have already exited, or Windows may have denied access.",
                "Foreman - Kill/End Process",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        _event.Acknowledged = true;
        EventBus.Instance.Publish(new InfoEvent(
            DateTimeOffset.UtcNow,
            "Foreman",
            $"Killed alert target \"{processName}\" (pid {pid.Value}) for alert [{_event.Id}]"));

        MessageBox.Show(
            $"Terminated \"{processName}\" (pid {pid.Value}).",
            "Foreman - Kill/End Process",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
        Close();
    }

    private string BuildAuditPrompt(string? targetHarnessId, AuditCandidate? route)
    {
        var vm = DataContext as AlertDetailVm;
        var targetPid = ResolveTargetPid();
        var processName = ResolveTargetProcessName();
        var liveProcess = targetPid is int pid ? GetProcessByPid?.Invoke(pid) : null;
        var commandLine = ResolveTargetCommandLine(liveProcess);

        var sb = new StringBuilder();
        sb.AppendLine("Foreman alert audit request");
        sb.AppendLine();
        sb.AppendLine("You are acting as an independent safety auditor for another AI coding harness or its child process.");
        sb.AppendLine("Decide whether this alert is expected, benign-but-stuck, risky, or suspicious. Recommend one concrete next action.");
        sb.AppendLine();
        sb.AppendLine("Alert");
        sb.AppendLine($"- Id: {_event.Id}");
        sb.AppendLine($"- Type: {vm?.EventTypeLabel ?? _event.GetType().Name}");
        sb.AppendLine($"- Severity: {_event.Severity}");
        sb.AppendLine($"- Source: {_event.Source}");
        sb.AppendLine($"- Timestamp: {_event.Timestamp:O}");
        sb.AppendLine($"- Message: {_event.Message}");
        sb.AppendLine();
        sb.AppendLine("Target");
        sb.AppendLine($"- Harness being audited: {Blank(targetHarnessId, "unknown")}");
        sb.AppendLine($"- Process: {Blank(processName, "unknown")}{(targetPid is int p ? $" (pid {p})" : "")}");
        if (liveProcess is not null)
        {
            sb.AppendLine($"- Parent pid: {liveProcess.ParentPid}");
            sb.AppendLine($"- Executable: {Blank(liveProcess.ExecutablePath, "unknown")}");
            sb.AppendLine($"- Live state: {liveProcess.State}");
            sb.AppendLine($"- Uptime minutes: {liveProcess.UptimeMinutes}");
            sb.AppendLine($"- Silent minutes: {liveProcess.SilentMinutes}");
        }

        if (!string.IsNullOrWhiteSpace(commandLine))
        {
            sb.AppendLine();
            sb.AppendLine("Command line (potential secrets masked)");
            sb.AppendLine(RedactSecrets(commandLine));
        }

        AppendEventSpecificDetails(sb);

        if (vm is not null)
        {
            sb.AppendLine();
            sb.AppendLine("Foreman assessment");
            sb.AppendLine(vm.WhyDangerous);
            sb.AppendLine();
            sb.AppendLine("Foreman recommended action");
            sb.AppendLine(vm.RecommendedAction);
        }

        sb.AppendLine();
        sb.AppendLine("Auditor route");
        sb.AppendLine(route is null
            ? "- No configured auditor route was selected."
            : $"- Selected auditor: {route.DisplayName} ({route.AuditorType}:{route.AuditorId}), available: {route.Available}, running harness count: {route.RunningHarnessCount}");
        if (route?.ApiEndpoint is { Length: > 0 } endpoint)
            sb.AppendLine($"- API endpoint: {endpoint}");
        if (route?.Model is { Length: > 0 } model)
            sb.AppendLine($"- Model: {model}");

        sb.AppendLine();
        sb.AppendLine("Please answer with: verdict, evidence, recommended action, and whether the process should be left running, interrupted with Ctrl+C, killed, or escalated for manual review.");
        return sb.ToString();
    }

    private void AppendEventSpecificDetails(StringBuilder sb)
    {
        switch (_event)
        {
            case CommandAlertEvent cmd:
                sb.AppendLine();
                sb.AppendLine("Command alert details");
                sb.AppendLine($"- Rule: {cmd.RuleId} - {cmd.RuleName}");
                sb.AppendLine($"- Rule description: {Blank(cmd.RuleDescription, "none")}");
                break;

            case HangDetectedEvent hang:
                sb.AppendLine();
                sb.AppendLine("Hang details");
                sb.AppendLine($"- Uptime minutes: {hang.UptimeMinutes}");
                sb.AppendLine($"- No-I/O minutes: {hang.SilentMinutes}");
                sb.AppendLine($"- Direct spawner: {Blank(hang.SpawnerName, "unknown")}{(hang.SpawnerPid is int spid ? $" (pid {spid})" : "")}");
                sb.AppendLine($"- Owning harness: {Blank(hang.ParentHarnessType, "unknown")}{(hang.ParentHarnessPid is int hpid ? $" (pid {hpid})" : "")}");
                break;

            case OrphanDetectedEvent orphan:
                sb.AppendLine();
                sb.AppendLine("Orphan details");
                sb.AppendLine($"- Dead parent: {orphan.DeadParentName} (pid {orphan.DeadParentPid})");
                sb.AppendLine($"- Orphan uptime minutes: {orphan.UptimeMinutes}");
                break;

            case PermissionViolationEvent perm:
                sb.AppendLine();
                sb.AppendLine("Permission violation details");
                sb.AppendLine($"- Profile: {perm.ProfileName}");
                sb.AppendLine($"- Violation type: {perm.ViolationType}");
                sb.AppendLine($"- Detail: {perm.Detail}");
                break;

            case NonzeroExitEvent exit:
                sb.AppendLine();
                sb.AppendLine("Exit details");
                sb.AppendLine($"- Exit code: {exit.ExitCode}");
                sb.AppendLine($"- Parent harness pid: {exit.ParentHarnessPid?.ToString() ?? "unknown"}");
                break;

            case EscalationEvent esc:
                sb.AppendLine();
                sb.AppendLine("Escalation details");
                sb.AppendLine($"- Harness: {esc.HarnessDisplayName} ({esc.HarnessId})");
                sb.AppendLine($"- Old level: {esc.OldLevel}");
                sb.AppendLine($"- New level: {esc.NewLevel}");
                sb.AppendLine($"- Trigger: {esc.TriggerRuleId} - {esc.TriggerRuleName}");
                sb.AppendLine($"- Reason: {esc.Reason}");
                break;
        }
    }

    private AuditRouteSelection ResolveAuditRoute(string? targetHarnessId, ForemanSeverity severity)
    {
        var settings = GetLlmTriageSettings?.Invoke();
        if (settings is null)
            return new AuditRouteSelection(null, "No LLM triage settings are available.", false);
        if (!settings.Enabled)
            return new AuditRouteSelection(null, "LLM triage routing is disabled in settings.", false);

        var candidates = FindAuditCandidates(settings, targetHarnessId, severity, honorSeverity: true);
        return candidates.Count > 0
            ? new AuditRouteSelection(candidates[0], "Auditor selected from user preference list.", false)
            : new AuditRouteSelection(null, "No auditor preference matched this target harness at this severity.", false);
    }

    private static List<AuditCandidate> FindAuditCandidates(
        LlmTriageSettings settings,
        string? targetHarnessId,
        ForemanSeverity severity,
        bool honorSeverity)
    {
        var snapshot = GetProcessSnapshot?.Invoke().ToList() ?? [];
        var targetKnown = !string.IsNullOrWhiteSpace(targetHarnessId);
        var severityRank = (int)severity;

        return settings.AuditorPreferences
            .Where(p => p.Enabled)
            .Where(p => !targetKnown || TargetMatches(p.TargetHarnessIds, targetHarnessId!))
            .Where(p => !targetKnown ||
                        !settings.PreventSelfAudit ||
                        !string.Equals(p.AuditorId, targetHarnessId, StringComparison.OrdinalIgnoreCase))
            .Where(p => !honorSeverity || HandlesSeverity(p.MinimumSeverities, severityRank))
            .Select(p =>
            {
                var isApi = p.AuditorType.Equals("api", StringComparison.OrdinalIgnoreCase);
                var runningHarnessCount = isApi
                    ? 0
                    : snapshot.Count(proc => string.Equals(proc.HarnessType, p.AuditorId, StringComparison.OrdinalIgnoreCase));
                var available = isApi ? !string.IsNullOrWhiteSpace(p.ApiEndpoint) : runningHarnessCount > 0;

                return new AuditCandidate(
                    p.AuditorId,
                    p.AuditorType,
                    string.IsNullOrWhiteSpace(p.DisplayName) ? p.AuditorId : p.DisplayName,
                    p.Priority,
                    available,
                    runningHarnessCount,
                    p.ApiEndpoint,
                    p.Model);
            })
            .OrderByDescending(c => c.Available)
            .ThenByDescending(c => c.Priority)
            .ThenBy(c => c.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private int? ResolveTargetPid() => _event switch
    {
        CommandAlertEvent cmd when cmd.ProcessId > 0 => cmd.ProcessId,
        HangDetectedEvent hang when hang.ProcessId > 0 => hang.ProcessId,
        OrphanDetectedEvent orphan when orphan.ProcessId > 0 => orphan.ProcessId,
        PermissionViolationEvent perm when perm.ProcessId > 0 => perm.ProcessId,
        NonzeroExitEvent exit when exit.ProcessId > 0 => exit.ProcessId,
        _ => null,
    };

    private string? ResolveTargetProcessName() => _event switch
    {
        CommandAlertEvent cmd => GetProcessByPid?.Invoke(cmd.ProcessId)?.Name ?? ExtractProcessNameFromSource(cmd.Source),
        HangDetectedEvent hang => hang.ProcessName,
        OrphanDetectedEvent orphan => orphan.ProcessName,
        PermissionViolationEvent perm => GetProcessByPid?.Invoke(perm.ProcessId)?.Name ?? ExtractProcessNameFromSource(perm.Source),
        NonzeroExitEvent exit => exit.ProcessName,
        EscalationEvent esc => esc.HarnessDisplayName,
        _ => null,
    };

    private string? ResolveTargetHarnessId() => _event switch
    {
        CommandAlertEvent cmd => ResolveHarnessFromProcess(cmd.ProcessId),
        HangDetectedEvent hang => FirstNonBlank(
            hang.ParentHarnessType,
            hang.ParentHarnessPid is int hp ? ResolveHarnessFromProcess(hp) : null,
            ResolveHarnessFromProcess(hang.ProcessId)),
        OrphanDetectedEvent orphan => ResolveHarnessFromProcess(orphan.ProcessId),
        PermissionViolationEvent perm => ResolveHarnessFromProcess(perm.ProcessId),
        NonzeroExitEvent exit => FirstNonBlank(
            exit.ParentHarnessPid is int hp ? ResolveHarnessFromProcess(hp) : null,
            ResolveHarnessFromProcess(exit.ProcessId)),
        EscalationEvent esc => esc.HarnessId,
        _ => null,
    };

    private string? ResolveTargetCommandLine(ProcessRecord? liveProcess)
    {
        if (_event is CommandAlertEvent cmd && !string.IsNullOrWhiteSpace(cmd.CommandLine))
            return cmd.CommandLine;

        return string.IsNullOrWhiteSpace(liveProcess?.CommandLine) ? null : liveProcess.CommandLine;
    }

    // The audit prompt is copied to the clipboard for pasting into a (possibly third-party) LLM.
    // A flagged command line can carry credentials, so mask the obvious ones first. Best-effort
    // hygiene, not a guarantee — the prompt header notes that masking was applied.
    private static readonly Regex[] _secretPatterns =
    [
        new(@"(?i)\b(authorization:\s*(?:[a-z]+\s+)?)\S+", RegexOptions.Compiled),  // Bearer / token / Basic / none
        new(@"(?i)(--(?:password|token|api[-_]?key|secret|access[-_]?key|client[-_]?secret)[ =]+)\S+", RegexOptions.Compiled),
        new(@"(?i)\b((?:password|passwd|pwd|token|api[-_]?key|apikey|secret|access[-_]?key)\s*=\s*)[^\s;,""']+", RegexOptions.Compiled),
        new(@"\bAKIA[0-9A-Z]{16}\b", RegexOptions.Compiled),
    ];

    private static string RedactSecrets(string commandLine)
    {
        var s = commandLine;
        s = _secretPatterns[0].Replace(s, "$1***");
        s = _secretPatterns[1].Replace(s, "$1***");
        s = _secretPatterns[2].Replace(s, "$1***");
        s = _secretPatterns[3].Replace(s, "***");
        return s;
    }

    private static string? ResolveHarnessFromProcess(int pid)
    {
        if (pid <= 0) return null;

        var rec = GetProcessByPid?.Invoke(pid);
        if (!string.IsNullOrWhiteSpace(rec?.HarnessType))
            return rec.HarnessType;

        var ancestor = GetHarnessAncestorByPid?.Invoke(pid);
        return string.IsNullOrWhiteSpace(ancestor?.HarnessType) ? null : ancestor.HarnessType;
    }

    private static string? ExtractProcessNameFromSource(string source)
    {
        var idx = source.IndexOf(" (pid", StringComparison.Ordinal);
        return idx > 0 ? source[..idx] : null;
    }

    private static string? FirstNonBlank(params string?[] values) =>
        values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));

    private static string Blank(string? value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value;

    private static bool TargetMatches(string[] targets, string targetHarnessId) =>
        targets.Length == 0 ||
        targets.Any(t => t == "*" || string.Equals(t, targetHarnessId, StringComparison.OrdinalIgnoreCase));

    private static bool HandlesSeverity(string[] minimumSeverities, int severityRank)
    {
        if (minimumSeverities.Length == 0) return true;
        return minimumSeverities
            .Select(s => Enum.TryParse<ForemanSeverity>(s, true, out var parsed) ? (int)parsed : -1)
            .Where(r => r >= 0)
            .Any(min => severityRank >= min);
    }

    private sealed record AuditRouteSelection(
        AuditCandidate? Selected,
        string Reason,
        bool UsedSeverityFallback);

    private sealed record AuditCandidate(
        string AuditorId,
        string AuditorType,
        string DisplayName,
        int Priority,
        bool Available,
        int RunningHarnessCount,
        string? ApiEndpoint,
        string? Model);

    private void CloseClick(object sender, RoutedEventArgs e) => Close();
}

// ─────────────────────────────────────────────────────────────────────────────

public sealed class AlertDetailVm
{
    public string  SeverityLabel      { get; }
    public Brush   SeverityBackground { get; }
    public string  EventTypeLabel     { get; }
    public string  TimestampLabel     { get; }
    public string  Source             { get; }

    public Visibility RuleInfoVisibility    { get; }
    public string     RuleId               { get; }
    public string     RuleName             { get; }
    public Visibility CommandLineVisibility { get; }
    public string     CommandLine          { get; }

    // ── Process identification (CommandAlertEvent) ────────────────────────
    public Visibility ProcessInfoVisibility { get; }
    public string     ProcessLine          { get; }   // "cmd.exe  ·  pid 1234"
    public string     HarnessLine          { get; }   // "Harness type: claude-code"
    public Visibility HarnessLineVisibility { get; }

    // ── Escalation / behavior profile summary ────────────────────────────
    public Visibility EscalationLineVisibility { get; }
    public string     EscalationLevelLabel      { get; }   // "ALERT", "ALARM", etc.
    public Brush      EscalationBadgeBg        { get; }
    public Brush      EscalationBadgeFg        { get; }
    public string     EscalationSummary        { get; }   // "7 alerts  ·  3 rules"

    public string WhyDangerous     { get; }
    public string RecommendedAction { get; }

    public AlertDetailVm(ForemanEvent evt)
    {
        SeverityLabel      = evt.Severity.ToString().ToUpperInvariant();
        SeverityBackground = SeverityToBrush(evt.Severity);
        TimestampLabel     = evt.Timestamp.LocalDateTime.ToString("yyyy-MM-dd  HH:mm:ss.fff");
        Source             = evt.Source;

        // defaults — overridden per event type below
        RuleInfoVisibility    = Visibility.Collapsed;
        RuleId                = string.Empty;
        RuleName              = string.Empty;
        CommandLineVisibility = Visibility.Collapsed;
        CommandLine           = string.Empty;
        ProcessInfoVisibility    = Visibility.Collapsed;
        ProcessLine              = string.Empty;
        HarnessLine              = string.Empty;
        HarnessLineVisibility    = Visibility.Collapsed;
        EscalationLineVisibility = Visibility.Collapsed;
        EscalationLevelLabel     = string.Empty;
        EscalationBadgeBg        = new SolidColorBrush(Color.FromRgb(0x1A, 0x1C, 0x24));
        EscalationBadgeFg        = new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90));
        EscalationSummary        = string.Empty;
        WhyDangerous             = string.Empty;
        RecommendedAction     = string.Empty;

        switch (evt)
        {
            case CommandAlertEvent cmd:
                EventTypeLabel        = "Command Alert";
                RuleInfoVisibility    = Visibility.Visible;
                RuleId                = cmd.RuleId;
                RuleName              = cmd.RuleName;
                CommandLineVisibility = Visibility.Visible;
                CommandLine           = cmd.CommandLine;

                // Resolve the originating process from the live process tree
                if (cmd.ProcessId > 0)
                {
                    var rec = AlertDetailWindow.GetProcessByPid?.Invoke(cmd.ProcessId);
                    ProcessInfoVisibility = Visibility.Visible;

                    string? harnessKey;
                    if (rec is not null)
                    {
                        ProcessLine = $"{rec.Name}  ·  pid {cmd.ProcessId}";
                        string? ancestorHt = null;
                        if (rec.IsHarness && rec.HarnessType is not null)
                        {
                            HarnessLine           = $"Harness type: {rec.HarnessType}";
                            HarnessLineVisibility = Visibility.Visible;
                        }
                        else if (rec.HarnessType is not null)
                        {
                            HarnessLine           = $"Child of {rec.HarnessType} harness  ·  parent pid {rec.ParentPid}";
                            HarnessLineVisibility = Visibility.Visible;
                        }
                        else
                        {
                            // The process matched no harness rule itself — but it may be a child
                            // of one (e.g. a PowerShell hook or shell spawned by claude-code).
                            // Walk the process tree to attribute it.
                            ancestorHt = AlertDetailWindow.GetHarnessAncestorByPid?.Invoke(cmd.ProcessId)?.HarnessType;
                            HarnessLine = ancestorHt is not null
                                ? $"Child of {ancestorHt} harness  ·  parent pid {rec.ParentPid}"
                                : $"Unclassified (not a tracked harness)  ·  parent pid {rec.ParentPid}";
                            HarnessLineVisibility = Visibility.Visible;
                        }
                        // Harness key matches how BehaviorTracker keys profiles
                        harnessKey = rec.HarnessType ?? ancestorHt ?? $"proc:{rec.Name}";
                    }
                    else
                    {
                        // Process has already exited by the time the user opened the detail;
                        // derive the key the same way BehaviorTracker.GetHarnessKey does.
                        ProcessLine           = $"pid {cmd.ProcessId}  ·  process has since exited";
                        HarnessLineVisibility = Visibility.Collapsed;
                        var idx  = cmd.Source.IndexOf(" (pid", StringComparison.Ordinal);
                        var name = idx > 0 ? cmd.Source[..idx] : cmd.Source;
                        harnessKey = $"proc:{name}";
                    }

                    // Show the harness's current escalation level and session alert totals
                    var profile = AlertDetailWindow.GetProfileByHarness?.Invoke(harnessKey);
                    if (profile is not null)
                    {
                        EscalationLineVisibility = Visibility.Visible;
                        EscalationLevelLabel     = profile.CurrentLevel.ToString().ToUpperInvariant();
                        (EscalationBadgeBg, EscalationBadgeFg) = EscalationColors(profile.CurrentLevel);

                        var parts = new List<string>
                        {
                            $"{profile.TotalAlerts} alert{(profile.TotalAlerts == 1 ? "" : "s")} this session"
                        };
                        if (profile.UniqueRulesCount > 1)
                            parts.Add($"{profile.UniqueRulesCount} unique rules");
                        if (profile.CategoryCount > 1)
                            parts.Add($"{profile.CategoryCount} categories");
                        EscalationSummary = string.Join("  ·  ", parts);
                    }
                }

                WhyDangerous = string.IsNullOrWhiteSpace(cmd.RuleDescription)
                    ? "This command matched a pattern associated with malicious or unsafe behaviour."
                    : cmd.RuleDescription;

                RecommendedAction = string.IsNullOrWhiteSpace(cmd.RuleGuidance)
                    ? GetDefaultGuidance(cmd.RuleId)
                    : cmd.RuleGuidance;
                break;

            case HangDetectedEvent hang:
                EventTypeLabel = "Process Hang Detected";
                WhyDangerous =
                    $"\"{hang.ProcessName}\" (pid {hang.ProcessId}) has been running for {hang.UptimeMinutes} minutes " +
                    $"with no I/O activity for {hang.SilentMinutes} minutes.{ResolveHarnessOwner(hang)}\n\n" +
                    $"This means the process is stuck — waiting for input that will never come, " +
                    $"caught in an infinite loop, or blocked on a locked resource. Hung harness " +
                    $"children can accumulate silently and consume memory or file handles.";
                RecommendedAction =
                    "1. Check whether the harness is prompting for input in its terminal.\n" +
                    "2. If the hang is unintentional, send Ctrl+C to the harness terminal or kill " +
                    $"pid {hang.ProcessId} in Task Manager.\n" +
                    "3. Review the harness's most recent output to understand what it was doing before stalling.";
                break;

            case OrphanDetectedEvent orphan:
                EventTypeLabel = "Orphaned Process";
                WhyDangerous =
                    $"\"{orphan.ProcessName}\" (pid {orphan.ProcessId}) is still running even though " +
                    $"its parent \"{orphan.DeadParentName}\" (pid {orphan.DeadParentPid}) has exited.\n\n" +
                    $"The orphan has been running for {orphan.UptimeMinutes} minutes unsupervised. " +
                    $"Orphaned harness children can continue executing tasks, mutating files, or making " +
                    $"network requests without the parent harness to oversee them.";
                RecommendedAction =
                    "1. If this process is expected (e.g. a deliberate background daemon), you can safely ignore this alert.\n" +
                    $"2. Otherwise, terminate pid {orphan.ProcessId} from Task Manager.\n" +
                    "3. Review what task the harness was running when it exited to understand what the orphan may be doing.";
                break;

            case PermissionViolationEvent perm:
                EventTypeLabel = "Permission Violation";
                WhyDangerous =
                    $"Profile \"{perm.ProfileName}\" was violated.\n\n" +
                    $"Violation type: {perm.ViolationType}\n" +
                    $"Detail: {perm.Detail}\n\n" +
                    $"The harness attempted an action outside the boundaries configured for it in Foreman's permission profiles.";
                RecommendedAction =
                    "1. Review the harness's current task to determine if this action was intentional.\n" +
                    "2. If the action is legitimate, update the permission profile in Foreman's Profiles editor.\n" +
                    "3. If unexpected, terminate the harness and audit its recent command history in the event log.";
                break;

            case NonzeroExitEvent exit:
                EventTypeLabel = "Non-Zero Exit";
                WhyDangerous =
                    $"\"{exit.ProcessName}\" (pid {exit.ProcessId}) exited with code {exit.ExitCode}.\n\n" +
                    $"Non-zero exit codes indicate a failure. In a harness context this may mean " +
                    $"a tool call failed, a script encountered an unhandled exception, or a system " +
                    $"command was rejected (e.g. access denied). Depending on the harness, it may " +
                    $"retry the operation with different parameters or escalate privileges.";
                RecommendedAction =
                    "1. Check the harness's terminal output for error messages near this timestamp.\n" +
                    "2. Review what command or tool the harness was executing when the process exited.\n" +
                    "3. Watch for follow-up actions — an AI harness may attempt alternative approaches after a failure.";
                break;

            case EscalationEvent esc:
                EventTypeLabel = $"Escalation — {esc.NewLevel.ToString().ToUpperInvariant()}";
                WhyDangerous =
                    $"\"{esc.HarnessDisplayName}\" crossed the {esc.NewLevel} threshold " +
                    $"(was {esc.OldLevel}) based on accumulated behavior this session.\n\n" +
                    $"Trigger rule: {esc.TriggerRuleId}  {esc.TriggerRuleName}\n" +
                    $"Session totals: {esc.TotalAlerts} alert(s) · {esc.UniqueRules} unique rule(s) · " +
                    $"{esc.CategoryCount} threat categor{(esc.CategoryCount == 1 ? "y" : "ies")}" +
                    (esc.CategoryList.Length > 0 ? $" ({string.Join(", ", esc.CategoryList).ToUpperInvariant()})" : "") +
                    $"\n\nReason: {esc.Reason}";

                RecommendedAction = esc.NewLevel switch
                {
                    EscalationLevel.Emergency =>
                        "IMMEDIATE ACTION RECOMMENDED:\n" +
                        "1. Open the Behavior Metrics window and review the full session history.\n" +
                        "2. If the activity was not authorised, use 'Kill Harness' to terminate the harness.\n" +
                        "3. Review the event log for the specific commands that triggered escalation.\n" +
                        "4. Consider disabling the harness in Foreman until you can audit its behaviour.",
                    EscalationLevel.Alarm =>
                        "1. Open the Behavior Metrics window and review the alert pattern.\n" +
                        "2. Check the event log for the specific commands that crossed the alarm threshold.\n" +
                        "3. If the alerts are from a legitimate task, acknowledge this event — Foreman will continue monitoring.\n" +
                        "4. If unexpected, terminate the harness or disable it in the Harnesses window.",
                    _ =>
                        "1. Review the event log for the alerts that contributed to this escalation.\n" +
                        "2. If all alerts were from legitimate tasks, acknowledge this event — Foreman will continue monitoring.\n" +
                        "3. Open Behavior Metrics to see the full picture across this session.",
                };
                break;

            default:
                EventTypeLabel = "System Event";
                WhyDangerous = evt.Message;
                RecommendedAction = "No action required for informational events.";
                break;
        }
    }

    // ── Guidance fallback by rule category ───────────────────────────────────

    private static string GetDefaultGuidance(string ruleId)
    {
        var category = ruleId.Split('-')[0].ToLowerInvariant();
        return category switch
        {
            "cred" =>
                "1. Immediately review what the harness was attempting to do.\n" +
                "2. If you did not explicitly ask it to access credentials, terminate it now.\n" +
                "3. Change any browser passwords or secrets that may have been exposed.\n" +
                "4. Review the harness's full command history in the event log.",

            "priv" =>
                "1. Do not grant elevated permissions unless you explicitly requested a privileged task.\n" +
                "2. Terminate the harness if privilege escalation was not expected.\n" +
                "3. Review what files or resources the harness was targeting.",

            "win" =>
                "1. Verify whether the detected Windows-specific operation was part of your requested task.\n" +
                "2. If unexpected, terminate the harness and audit its recent activity.\n" +
                "3. Re-enable any security features (Defender, firewall) that may have been altered.",

            "net" =>
                "1. Verify that outbound network activity was expected for the current task.\n" +
                "2. Be especially wary of curl/wget piped to execution — this is a common code-injection vector.\n" +
                "3. If unexpected, terminate the harness and check what was downloaded.",

            "del" or "cmd" =>
                "1. Review whether the harness was asked to perform destructive disk or system operations.\n" +
                "2. Terminate immediately if a destructive command like format, diskpart, or rm -rf was run unexpectedly.\n" +
                "3. Check the harness's output for signs of what it was attempting.",

            _ =>
                "1. Review the harness's current task to determine if this command was expected.\n" +
                "2. If unexpected, terminate the harness and audit its recent activity in the event log.\n" +
                "3. Acknowledge this alert in Foreman once you have reviewed and understood what happened.",
        };
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>Names the harness a hung/orphaned child belongs to, for the alert text.</summary>
    private static string ResolveHarnessOwner(HangDetectedEvent hang)
    {
        var parts = new List<string>();

        if (hang.SpawnerPid is int spawnerPid)
        {
            var spawner = AlertDetailWindow.GetProcessByPid?.Invoke(spawnerPid);
            var spawnerName = spawner?.Name ?? hang.SpawnerName;
            if (hang.ParentHarnessPid == spawnerPid && !string.IsNullOrWhiteSpace(hang.ParentHarnessType))
            {
                parts.Add(string.IsNullOrWhiteSpace(spawnerName)
                    ? $"Spawned by the {hang.ParentHarnessType} harness (pid {spawnerPid})."
                    : $"Spawned by the {hang.ParentHarnessType} harness ({spawnerName}, pid {spawnerPid}).");
            }
            else
            {
                parts.Add(string.IsNullOrWhiteSpace(spawnerName)
                    ? $"Spawned by parent process pid {spawnerPid}."
                    : $"Spawned by {spawnerName} (pid {spawnerPid}).");
            }
        }

        if (hang.ParentHarnessPid is int hp && hp != hang.SpawnerPid)
        {
            var rec = AlertDetailWindow.GetProcessByPid?.Invoke(hp);
            var harnessType = rec?.HarnessType ?? hang.ParentHarnessType;
            var processName = rec?.Name ?? hang.ParentHarnessName;

            if (!string.IsNullOrWhiteSpace(harnessType) && !string.IsNullOrWhiteSpace(processName))
                parts.Add($"Owned by the {harnessType} harness ({processName}, pid {hp}).");
            else if (!string.IsNullOrWhiteSpace(harnessType))
                parts.Add($"Owned by the {harnessType} harness (pid {hp}).");
            else if (!string.IsNullOrWhiteSpace(processName))
                parts.Add($"Owned by harness process {processName} (pid {hp}).");
            else
                parts.Add($"Owned by harness process pid {hp}.");
        }

        return parts.Count == 0 ? "" : " " + string.Join(" ", parts);
    }

    private static (Brush bg, Brush fg) EscalationColors(EscalationLevel level) => level switch
    {
        EscalationLevel.Emergency => (new SolidColorBrush(Color.FromRgb(0x44, 0x0A, 0x0A)),
                                      new SolidColorBrush(Color.FromRgb(0xFF, 0x66, 0x66))),
        EscalationLevel.Alarm     => (new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x08)),
                                      new SolidColorBrush(Color.FromRgb(0xFF, 0xAA, 0x44))),
        EscalationLevel.Alert     => (new SolidColorBrush(Color.FromRgb(0x30, 0x28, 0x08)),
                                      new SolidColorBrush(Color.FromRgb(0xE8, 0xB2, 0x3C))),
        _                         => (new SolidColorBrush(Color.FromRgb(0x1A, 0x1C, 0x24)),
                                      new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90))),
    };

    private static Brush SeverityToBrush(ForemanSeverity s) => s switch
    {
        ForemanSeverity.Critical => new SolidColorBrush(Color.FromRgb(0xCC, 0x22, 0x22)),
        ForemanSeverity.High     => new SolidColorBrush(Color.FromRgb(0xCC, 0x55, 0x22)),
        ForemanSeverity.Medium   => new SolidColorBrush(Color.FromRgb(0xAA, 0x77, 0x11)),
        ForemanSeverity.Low      => new SolidColorBrush(Color.FromRgb(0x33, 0x77, 0x33)),
        _                        => new SolidColorBrush(Color.FromRgb(0x33, 0x66, 0x99)),
    };
}
