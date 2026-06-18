using Foreman.Core.Alerts;
using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Mcp;
using Foreman.Core.Models;
using ModelContextProtocol.Server;
using System.ComponentModel;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Foreman.McpServer;

/// <summary>
/// All tools exposed to AI harnesses via MCP.
/// The state bag is injected at server startup and shared across requests.
/// </summary>
[McpServerToolType]
public static class ForemanMcpTools
{
    private static ForemanState? _state;
    private static readonly string BuildVersion =
        typeof(ForemanMcpTools).Assembly.GetName().Version?.ToString(3) ?? "0.1.0";

    internal static void SetState(ForemanState state) => _state = state;

    [McpServerTool, Description("Returns Foreman Agent Safety's current overall health summary.")]
    public static object ForemanStatus()
    {
        var state = _state ?? new ForemanState();
        return new
        {
            status = state.ActiveAlerts == 0 ? "green" : state.HasCritical ? "red" : "amber",
            activeAlerts = state.ActiveAlerts,
            monitoredProcesses = state.ProcessCount,
            pendingAskHarnessRequests = state.PendingAskHarnessCount,
            uptimeSeconds = (int)(DateTimeOffset.UtcNow - state.StartTime).TotalSeconds,
            version = BuildVersion,
        };
    }

    [McpServerTool, Description(
        "Scans a directory's AI-agent configuration supply chain for the Miasma 'rules file backdoor' attack " +
        "class: auto-run hooks in .claude/.gemini settings.json, .cursor rules with alwaysApply, .vscode " +
        "tasks.json with runOn:folderOpen, the .github/setup.js dropper, obfuscated scripts, prompt-injection " +
        "or IOC strings in CLAUDE.md/AGENTS.md, and suspicious package.json scripts. Use this to vet a " +
        "repository BEFORE opening it in an agent — opening a poisoned repo is enough to run its payload. " +
        "Read-only; makes no network connections.")]
    public static object ScanRepoForAgentConfig(
        [Description("Absolute path to the repository/directory to scan")] string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
            return new { scanned = false, reason = "Path does not exist or is not a directory." };

        var findings = Foreman.Core.Security.AgentConfigScanner.ScanDirectory(path);
        var highest = findings.Count == 0 ? ForemanSeverity.Info : findings.Max(f => f.Severity);
        return new
        {
            scanned = true,
            path,
            findingCount = findings.Count,
            highestSeverity = findings.Count == 0 ? "none" : highest.ToString(),
            verdict = highest >= ForemanSeverity.High
                ? "SUSPICIOUS — review the flagged files before opening this repo in an agent."
                : findings.Count == 0 ? "clean" : "low-signal findings only",
            findings = findings
                .OrderByDescending(f => f.Severity)
                .Select(f => new { file = f.FilePath, severity = f.Severity.ToString(), signal = f.Signal.ToString(), detail = f.Detail })
                .ToArray(),
        };
    }

    [McpServerTool, Description(
        "Lists MCP clients currently connected to Foreman, including their self-announced identity " +
        "and whether they support sampling. Use this to debug Ask Harness delivery. The identity is " +
        "self-declared by the client and is not an authorization boundary.")]
    public static object ListConnectedMcpClients(
        Microsoft.AspNetCore.Http.IHttpContextAccessor? http = null)
    {
        var state = _state ?? new ForemanState();
        var caller = CallerScope.From(http);
        var clients = state.GetMcpClients?.Invoke() ?? [];
        // A per-harness token sees only its OWN connection — not a roster of every sibling client.
        if (!caller.IsOperator)
            clients = clients.Where(c => SseSessionManager.MatchesHarness(c.Name, null, caller.HarnessId)).ToList();
        return new
        {
            count = clients.Count,
            clients = clients.Select(c => new
            {
                c.Name,
                c.Version,
                c.Sampling,
                c.Elicitation,
            }).ToArray(),
        };
    }

    [McpServerTool, Description("Lists all AI harness processes Foreman Agent Safety is monitoring.")]
    public static object ListMonitoredProcesses(
        [Description("Include child processes of harnesses")] bool includeChildren = true,
        [Description("Optional harness ID to scope results, e.g. 'claude-code' or 'codex'")] string? harnessId = null,
        [Description("Optional caller process ID; used to infer the caller's harness tree")] int? processId = null,
        Microsoft.AspNetCore.Http.IHttpContextAccessor? http = null)
    {
        var state = _state ?? new ForemanState();
        var caller = CallerScope.From(http);
        // A per-harness token sees only its own tree; the requested harnessId/processId is ignored for
        // a scoped caller so it can't enumerate a sibling's processes. Operator sees everything.
        var resolvedHarness = caller.IsOperator
            ? state.ResolveHarnessId(harnessId, processId)
            : caller.HarnessId;
        var procs = resolvedHarness is not null
            ? state.GetProcessesForHarness(resolvedHarness, includeChildren)
            : state.GetProcesses(includeChildren);
        // Egress to a connected agent: mask secret-shaped text in the command line (the live
        // record stays raw for the local UI and detector). Same shape, redacted CommandLine.
        var redacted = procs.Select(p => p.WithCommandLine(Core.Security.SecretRedactor.Redact(p.CommandLine)));
        return new { harnessId = resolvedHarness, processes = redacted };
    }

    [McpServerTool, Description("Returns detailed information about a specific process by PID.")]
    public static object QueryProcessDetail(
        [Description("Process ID to query")] int pid,
        Microsoft.AspNetCore.Http.IHttpContextAccessor? http = null)
    {
        var state = _state ?? new ForemanState();
        var proc = state.GetProcess(pid);
        if (proc is null) return new { error = $"No process found with PID {pid}" };

        // A per-harness token may only inspect processes in its own tree.
        var caller = CallerScope.From(http);
        if (!caller.IsOperator)
        {
            var owner = proc.HarnessType ?? state.ResolveHarnessId(null, pid);
            if (!caller.CanAccess(owner))
                return new { error = $"PID {pid} is outside your harness scope." };
        }

        return new
        {
            pid = proc.Pid,
            name = proc.Name,
            commandLine = Core.Security.SecretRedactor.Redact(proc.CommandLine),
            state = proc.State.ToString(),
            uptimeMinutes = proc.UptimeMinutes,
            silentMinutes = proc.SilentMinutes,
            isHarness = proc.IsHarness,
            harnessType = proc.HarnessType,
            profileName = proc.ProfileName,
            ioCountersUnavailable = proc.IoCountersUnavailable,
        };
    }

    [McpServerTool, Description(
        "Marks a Foreman alert as acknowledged, suppressing further notifications for it. " +
        "High and Critical alerts cannot be acknowledged over MCP — the operator must acknowledge " +
        "those in the Foreman UI so a harness cannot silence a serious alert about itself.")]
    public static object AcknowledgeAlert(
        [Description("The alert ID to acknowledge")] string alertId,
        [Description("Optional reason for acknowledgement")] string? reason = null,
        Microsoft.AspNetCore.Http.IHttpContextAccessor? http = null)
    {
        var state = _state ?? new ForemanState();

        var evt = state.GetAlert(alertId);
        if (evt is null)
            return new { acknowledged = false, reason = "No active alert with that ID." };

        // A per-harness token may only acknowledge alerts about ITSELF — it can't clear a sibling's
        // alert to hide its tracks. Unattributable alerts are operator-only.
        var caller = CallerScope.From(http);
        if (!caller.CanMutate)
            return new { acknowledged = false, reason = "Refused: this per-harness token was presented by a different process than the harness it claims (possible token theft)." };
        if (!caller.IsOperator && !caller.CanAccess(state.ResolveAlertHarness(evt)))
            return new { acknowledged = false, reason = "That alert does not belong to your harness." };

        // Operator stays authoritative over serious alerts: a (possibly adversarial) harness
        // must not be able to flip the tray green by acking its own High/Critical alert.
        if (evt.Severity >= ForemanSeverity.High)
            return new
            {
                acknowledged = false,
                reason = "High/Critical alerts must be acknowledged by the operator in the Foreman UI, not over MCP.",
            };

        var acknowledged = state.AcknowledgeAlert(alertId);
        return new { acknowledged, reason };
    }

    [McpServerTool, Description("Returns recent Foreman events from the event log.")]
    public static object ListRecentEvents(
        [Description("Maximum number of events to return")] int limit = 50,
        [Description("Filter by minimum severity: Info, Low, Medium, High, Critical")] string? severity = null,
        Microsoft.AspNetCore.Http.IHttpContextAccessor? http = null)
    {
        var state = _state ?? new ForemanState();
        ForemanSeverity? minSev = severity is not null
            ? Enum.TryParse<ForemanSeverity>(severity, true, out var s) ? s : null
            : null;

        // A per-harness token sees only events attributable to itself — not a sibling's command activity.
        var events = state.GetEvents(limit, minSev, CallerScope.From(http).ScopeHarness);
        return new { events };
    }

    [McpServerTool, Description("Pre-flight check a command line. Foreman heuristically evaluates it and returns allow / allow_once / escalate / block.")]
    public static object ReportSuspiciousCommand(
        [Description("The command line to evaluate")] string commandLine,
        [Description("What the harness is trying to accomplish")] string context = "",
        [Description("Optional harness ID, e.g. 'claude-code' or 'codex'")] string? harnessId = null,
        [Description("Optional caller process ID for live profile attribution")] int? processId = null,
        [Description("Optional explicit profile name, e.g. 'codex-default'")] string? profileName = null)
    {
        var state = _state ?? new ForemanState();
        var profile = state.ResolveProfile(profileName, harnessId, processId);
        var resolvedHarness = state.ResolveHarnessId(harnessId, processId);
        var match = Core.Heuristics.CommandAnalyzer.Instance.Analyze(commandLine, profile: profile);
        if (match is null)
            return new
            {
                decision = "allow",
                reason = "No heuristic rules matched",
                matchedRule = (string?)null,
                harnessId = resolvedHarness,
                profileName = profile?.Name,
            };

        var profileBlocked =
            profile is not null &&
            !string.Equals(profile.Commands.EnforceMode, "monitor", StringComparison.OrdinalIgnoreCase) &&
            profile.Commands.BlockedPatterns.Contains(match.RuleId, StringComparer.OrdinalIgnoreCase);

        var decision = profileBlocked && string.Equals(profile!.Commands.EnforceMode, "block", StringComparison.OrdinalIgnoreCase)
            ? "block"
            : profileBlocked
                ? "escalate"
                : match.Severity switch
        {
            ForemanSeverity.Critical => "block",
            ForemanSeverity.High     => "escalate",
            _                        => "allow_once",
        };

        // MCP-originated alerts never designate a kill target. A harness must not be able to point
        // Foreman's one-click Kill action at any PID — not an arbitrary one, and not even a tracked
        // sibling's. Profile attribution still uses the processId parameter above; the published
        // event deliberately carries no kill PID (0).
        const string source = "MCP.ReportSuspiciousCommand";

        // Log the check through the normal event bus so tray state, behavior metrics,
        // MCP state, and connected clients all see the same alert stream.
        EventBus.Instance.Publish(new CommandAlertEvent(
            DateTimeOffset.UtcNow,
            match.Severity,
            source,
            $"Harness pre-checked command [{match.RuleId}]: {commandLine[..Math.Min(80, commandLine.Length)]}"
                + (string.IsNullOrWhiteSpace(context) ? "" : $" — context: {context[..Math.Min(200, context.Length)]}"),
            commandLine,
            match.RuleId,
            match.RuleName,
            match.Description,
            match.Guidance,
            0
        ));

        if (profileBlocked)
        {
            EventBus.Instance.Publish(new PermissionViolationEvent(
                DateTimeOffset.UtcNow,
                "MCP.ReportSuspiciousCommand",
                $"[{profile!.Name}] CommandBlocked: [{match.RuleId}] {match.RuleName}",
                0,
                profile.Name,
                "CommandBlocked",
                $"Blocked rule [{match.RuleId}] {match.RuleName}: {match.Description}"));
        }

        return new
        {
            decision,
            reason = profileBlocked
                ? $"Profile '{profile!.Name}' blocks [{match.RuleId}] {match.RuleName}"
                : match.RuleName,
            matchedRule = match.RuleId,
            severity = match.Severity.ToString(),
            harnessId = resolvedHarness,
            profileName = profile?.Name,
            profileBlocked,
            context = string.IsNullOrWhiteSpace(context) ? null : context,   // echoed back so the harness sees its intent was recorded
        };
    }

    [McpServerTool, Description(
        "Returns behavioral escalation metrics for every monitored harness. " +
        "Levels: Watch (0) → Alert (1) → Alarm (2) → Emergency (3). " +
        "Use this to check whether Foreman has raised an alarm about you or a sibling harness.")]
    public static object GetBehaviorMetrics(Microsoft.AspNetCore.Http.IHttpContextAccessor? http = null)
    {
        var state    = _state ?? new ForemanState();
        var profiles = state.GetBehaviorProfiles?.Invoke() ?? [];

        // A per-harness token sees only its own metrics, not a sibling's escalation state.
        var caller = CallerScope.From(http);
        if (!caller.IsOperator)
            profiles = profiles.Where(p => caller.CanAccess(p.HarnessId));

        return new
        {
            harnesses = profiles.Select(p => new
            {
                harnessId             = p.HarnessId,
                displayName           = p.DisplayName,
                escalationLevel       = p.CurrentLevel.ToString().ToLowerInvariant(),
                escalationLevelNum    = (int)p.CurrentLevel,
                totalAlerts           = p.TotalAlerts,
                uniqueRules           = p.UniqueRulesCount,
                categories            = p.Categories.ToArray(),
                sessionDurationSeconds = (int)p.SessionDuration.TotalSeconds,
            }).OrderByDescending(h => h.escalationLevelNum).ThenByDescending(h => h.totalAlerts).ToArray(),
        };
    }

    [McpServerTool, Description(
        "Resets behavioral escalation metrics for a specific harness back to the Watch level. " +
        "Call this when starting a new, unrelated task to prevent prior session activity from " +
        "contributing to escalation thresholds. Pass your own harnessId (e.g. 'claude-code').")]
    public static object ResetBehaviorMetrics(
        [Description("The harness ID to reset, e.g. 'claude-code', 'codex', or 'proc:node'")] string harnessId,
        Microsoft.AspNetCore.Http.IHttpContextAccessor? http = null)
    {
        var state = _state ?? new ForemanState();
        // A per-harness token may only reset ITS OWN metrics — it can't wipe a sibling's escalation.
        var caller = CallerScope.From(http);
        if (!caller.CanMutate)
            return new { reset = false, harnessId, reason = "Refused: this per-harness token was presented by a different process than the harness it claims (possible token theft)." };
        if (!caller.IsOperator && !caller.CanAccess(harnessId))
            return new { reset = false, harnessId, reason = "You can only reset your own harness's metrics." };

        ResetAndAnnounce(state, harnessId, "MCP.ResetBehaviorMetrics");
        return new { reset = true, harnessId };
    }

    [McpServerTool, Description(
        "Announces that the harness is starting a new task. Foreman logs the announcement " +
        "in the event log so operators can correlate task boundaries with alert patterns. " +
        "Optionally resets behavioral metrics if this is a fresh, unrelated task.")]
    public static object ReportTaskStart(
        [Description("Human-readable description of the new task")] string taskDescription,
        [Description("Reset behavioral escalation metrics for a fresh start")] bool resetMetrics = false,
        [Description("Harness ID for metric reset (only used when resetMetrics=true), e.g. 'claude-code'")] string? harnessId = null,
        Microsoft.AspNetCore.Http.IHttpContextAccessor? http = null)
    {
        var state = _state ?? new ForemanState();
        var caller = CallerScope.From(http);
        EventBus.Instance.Publish(new InfoEvent(
            DateTimeOffset.UtcNow,
            "MCP.TaskStart",
            $"New task announced: {taskDescription[..Math.Min(120, taskDescription.Length)]}"));

        if (!caller.IsOperator)
        {
            if (harnessId is not null && !caller.CanAccess(harnessId))
            {
                return new
                {
                    acknowledged = true,
                    taskDescription,
                    metricsReset = false,
                    harnessId = caller.HarnessId,
                    pendingAskHarnessRequests = caller.HarnessId is null ? 0 : state.CountAskHarnessRequests(caller.HarnessId),
                    reason = "Task start recorded, but you can only reset your own harness's metrics.",
                    hint = "If pendingAskHarnessRequests is non-zero, call list_ask_harness_requests and answer with reply_to_ask_harness_request.",
                };
            }

            harnessId = caller.HarnessId;
        }

        // The metric reset is a STATE MUTATION — gate it behind CanMutate exactly like reset_behavior_metrics,
        // so a peer-mismatched (stolen) token can't self-exonerate by wiping its escalation through this path
        // even when peer-binding enforcement is off. (S-1)
        var didReset = resetMetrics && harnessId is not null && caller.CanMutate;
        if (didReset)
            ResetAndAnnounce(state, harnessId!, "MCP.TaskStart");

        return new
        {
            acknowledged = true,
            taskDescription,
            metricsReset = didReset,
            harnessId,
            metricsResetRefused = resetMetrics && harnessId is not null && !caller.CanMutate
                ? "Metric reset refused: this token was presented by a different process than the harness it claims (possible token theft)."
                : null,
            pendingAskHarnessRequests = harnessId is null
                ? state.CountAskHarnessRequests()
                : state.CountAskHarnessRequests(harnessId),
            hint = "If pendingAskHarnessRequests is non-zero, call list_ask_harness_requests and answer with reply_to_ask_harness_request.",
        };
    }

    [McpServerTool, Description(
        "Lists pending Foreman 'Ask Harness' prompts for a harness. Call this when Foreman flags you, " +
        "when foreman_status or report_task_start reports pendingAskHarnessRequests, or at task boundaries. " +
        "Then answer each prompt with reply_to_ask_harness_request.")]
    public static object ListAskHarnessRequests(
        [Description("Optional harness ID to scope prompts, e.g. 'codex' or 'claude-code'")] string? harnessId = null,
        [Description("Optional caller process ID; used to infer the caller's harness tree")] int? processId = null,
        [Description("Include already answered requests as well as pending ones")] bool includeAnswered = false,
        [Description("Maximum requests to return")] int limit = 10,
        Microsoft.AspNetCore.Http.IHttpContextAccessor? http = null)
    {
        var state = _state ?? new ForemanState();
        // A per-harness token sees only ITS OWN prompts; identity comes from the token, not the parameter.
        var caller = CallerScope.From(http);
        if (!caller.IsOperator) { harnessId = caller.HarnessId; processId = null; }
        var resolvedHarness = state.ResolveHarnessId(harnessId, processId);
        var requests = state.ListAskHarnessRequests(resolvedHarness ?? harnessId, processId, includeAnswered, limit);
        return new
        {
            harnessId = resolvedHarness ?? harnessId,
            pendingCount = requests.Count(r => r.Status == "pending"),
            requests = requests.Select(AskRequestShape).ToArray(),
            nextAction = "If any request is pending, answer with reply_to_ask_harness_request(requestId, response, actionTaken, harnessId/processId).",
        };
    }

    [McpServerTool, Description(
        "Replies to a Foreman 'Ask Harness' prompt. Use this after list_ask_harness_requests returns a " +
        "pending request for your harness. Be factual: explain what you were doing, whether it was expected, " +
        "and what corrective action you took or recommend.")]
    public static object ReplyToAskHarnessRequest(
        [Description("The requestId returned by list_ask_harness_requests")] string requestId,
        [Description("Your reply to Foreman Agent Safety's prompt")] string response,
        [Description("Optional concise action taken, e.g. 'stopped pid 1234', 'left running', 'needs operator review'")] string? actionTaken = null,
        [Description("Optional harness ID, e.g. 'codex' or 'claude-code'")] string? harnessId = null,
        [Description("Optional caller process ID; used to infer the caller's harness tree")] int? processId = null,
        Microsoft.AspNetCore.Http.IHttpContextAccessor? http = null)
    {
        var state = _state ?? new ForemanState();
        if (string.IsNullOrWhiteSpace(response))
            return new { accepted = false, reason = "Response must not be empty." };

        // Identity comes from the token: a per-harness caller can only answer ITS OWN prompts, and
        // can't impersonate another harness by passing a different harnessId. (ForemanState still
        // enforces request ownership against this resolved identity.)
        var caller = CallerScope.From(http);
        if (!caller.CanMutate)
            return new { accepted = false, reason = "Refused: this per-harness token was presented by a different process than the harness it claims (possible token theft)." };
        if (!caller.IsOperator) { harnessId = caller.HarnessId; processId = null; }

        var result = state.ReplyToAskHarnessRequest(requestId, response.Trim(), actionTaken, harnessId, processId);
        if (!result.Ok)
            return new { accepted = false, reason = result.Reason, request = result.Request is null ? null : AskRequestShape(result.Request) };

        EventBus.Instance.Publish(new InfoEvent(
            DateTimeOffset.UtcNow,
            "MCP.AskHarnessReply",
            $"Ask Harness reply from '{result.Request!.HarnessId}' for alert [{result.Request.AlertId}]: {Truncate(response, 160)}"));

        return new
        {
            accepted = true,
            reason = result.Reason,
            request = AskRequestShape(result.Request),
        };
    }

    [McpServerTool, Description(
        "Reports this harness's remaining context/token budget so the operator can see how much room each agent " +
        "has left on the dashboard. Call it at task boundaries or when your context crosses a threshold (e.g. drops " +
        "below 50%). All values optional — send percentRemaining, or tokensUsed + tokensBudget, or just a note.")]
    public static object ReportUsage(
        [Description("Percent of the context window REMAINING (0-100), if known")] double? percentRemaining = null,
        [Description("Tokens used so far, if known")] long? tokensUsed = null,
        [Description("Total token budget / context window size, if known")] long? tokensBudget = null,
        [Description("Optional short note, e.g. 'compacting soon'")] string? note = null,
        [Description("Optional harness ID; ignored for a scoped per-harness token (it reports for itself)")] string? harnessId = null,
        [Description("Optional caller process ID")] int? processId = null,
        Microsoft.AspNetCore.Http.IHttpContextAccessor? http = null)
    {
        var state = _state ?? new ForemanState();
        // A per-harness token reports for ITSELF; only the operator may report on behalf of a named harness.
        var caller = CallerScope.From(http);
        if (!caller.IsOperator) { harnessId = caller.HarnessId; processId = null; }
        var resolved = state.ResolveHarnessId(harnessId, processId);
        if (string.IsNullOrWhiteSpace(resolved))
            return new { recorded = false, reason = "Couldn't resolve which harness this usage belongs to. Pass harnessId, or present a per-harness token." };

        var usage = new HarnessContextUsage(
            percentRemaining is { } p ? Math.Clamp(p, 0, 100) : null,
            tokensUsed, tokensBudget,
            string.IsNullOrWhiteSpace(note) ? null : note.Trim(),
            DateTimeOffset.UtcNow);
        state.SetContextUsage(resolved, usage);
        return new { recorded = true, harnessId = resolved, remainingPercent = usage.RemainingPercent, note = usage.Note };
    }

    [McpServerTool, Description("Returns the permission profile that applies to the calling harness.")]
    public static object GetMyPermissions(
        [Description("Optional harness ID, e.g. 'claude-code' or 'codex'")] string? harnessId = null,
        [Description("Optional caller process ID for live profile attribution")] int? processId = null,
        [Description("Optional explicit profile name, e.g. 'codex-default'")] string? profileName = null,
        Microsoft.AspNetCore.Http.IHttpContextAccessor? http = null)
    {
        var state = _state ?? new ForemanState();
        // A per-harness token may only read ITS OWN profile (get_MY_permissions). Ignore the requested
        // harnessId/processId/profileName for a scoped caller so it can't read a sibling's enforcement posture
        // (blocked patterns, denied paths). The raw install token authenticates as operator and may read any.
        var caller = CallerScope.From(http);
        if (!caller.IsOperator) { harnessId = caller.HarnessId; processId = null; profileName = null; }
        var resolvedHarness = state.ResolveHarnessId(harnessId, processId);
        var profile = state.ResolveProfile(profileName, resolvedHarness, processId);
        if (profile is null)
        {
            return new
            {
                harnessId = resolvedHarness,
                profileName = (string?)null,
                error = "No matching profile. Pass harnessId, processId, or profileName.",
            };
        }

        return new
        {
            harnessId = resolvedHarness,
            profileName = profile.Name,
            description = profile.Description,
            commands = new
            {
                enforceMode = profile.Commands.EnforceMode,
                blockedPatterns = profile.Commands.BlockedPatterns,
            },
            fileSystem = new
            {
                enforceMode = profile.FileSystem.EnforceMode,
                deniedPaths = profile.FileSystem.DeniedPaths,
                allowedWritePaths = profile.FileSystem.AllowedWritePaths,
            },
            launcherPolicy = new
            {
                trustedHookPathMarkers = profile.Alerts.TrustedHookPathMarkers,
                launcherSuppressedRuleIds = profile.Alerts.LauncherSuppressedRuleIds,
            },
            askHarness = new
            {
                pendingRequests = resolvedHarness is null ? 0 : state.CountAskHarnessRequests(resolvedHarness),
                receiveTool = "list_ask_harness_requests",
                replyTool = "reply_to_ask_harness_request",
            },
        };
    }

    [McpServerTool, Description(
        "Returns the basic self-service modalities (house-rules) the calling harness should honour — small, " +
        "structured operations like log-report and self-check, designed to run even on a tiny local model.")]
    public static object GetMyInstructions(
        Microsoft.AspNetCore.Http.IHttpContextAccessor? http = null,
        [Description("Optional harness ID; defaults to the caller's token identity")] string? harnessId = null,
        [Description("Optional caller process ID")] int? processId = null)
    {
        var state = _state ?? new ForemanState();
        var caller = CallerScope.From(http);
        // Scoped caller reads only its own modalities; the token identity wins over the param (the doc says
        // "defaults to the caller's token identity"). Operator may query any harness.
        if (!caller.IsOperator) { harnessId = caller.HarnessId; processId = null; }
        var resolved = state.ResolveHarnessId(harnessId ?? caller.ScopeHarness, processId);

        var enabledIds = resolved is not null
            && state.HarnessModalities.TryGetValue(resolved, out var ids) && ids.Count > 0
            ? (IReadOnlyList<string>)ids
            : ModalityCatalog.DefaultAgentModalities;

        var modalities = enabledIds
            .Select(id => ModalityCatalog.Get(id))
            .Where(m => m is { Audience: ModalityAudience.Agent })
            .Select(m => new { id = m!.Id, title = m.Title, instruction = m.Instruction })
            .ToArray();

        return new
        {
            harnessId = resolved,
            note = "Honour these when asked, or proactively. Keep replies terse — don't pad.",
            modalities,
        };
    }

    [McpServerTool, Description("Returns setup instructions for connecting a supported harness to Foreman Agent Safety's MCP server.")]
    public static object GetIntegrationInstructions(
        [Description("Harness ID, e.g. 'claude-code' or 'codex'")] string harnessId)
    {
        var state = _state ?? new ForemanState();
        var integration = HarnessIntegrationRegistry.Get(harnessId);
        if (integration is null)
            return new { error = $"No integration metadata for harness '{harnessId}'." };

        var port = state.McpPort;
        return new
        {
            harnessId = integration.HarnessId,
            displayName = integration.DisplayName,
            defaultProfileName = integration.DefaultProfileName,
            setupHint = integration.SetupHint.Replace("{port}", port.ToString(), StringComparison.Ordinal),
            mcpConfigSnippet = integration.McpConfigSnippet.Replace("{port}", port.ToString(), StringComparison.Ordinal),
            authentication = new
            {
                required = true,
                scheme = "Bearer",
                header = "Authorization: Bearer <token>",
                tokenFile = @"%LocalAppData%\Foreman\mcp.token",
                setupFile = @"%LocalAppData%\Foreman\mcp-setup.txt",
                note = "The /mcp endpoint requires this token in an Authorization header; copy it from the token file into your client config. /health stays open.",
            },
            askHarness = new
            {
                receive = "Call list_ask_harness_requests with your harnessId or processId to receive pending Ask Harness prompts, including queued audit prompts.",
                reply = "Call reply_to_ask_harness_request with the requestId and your response so Foreman Agent Safety records the answer.",
            },
            note = "Pass harnessId or processId to Foreman Agent Safety MCP tools so permissions, process listings, and Ask Harness requests can be scoped to this harness.",
        };
    }

    [McpServerTool, Description("Checks whether Foreman Agent Safety can see a harness, its profile, and any MCP sessions.")]
    public static object ValidateHarnessIntegration(
        [Description("Harness ID, e.g. 'claude-code' or 'codex'")] string harnessId,
        Microsoft.AspNetCore.Http.IHttpContextAccessor? http = null)
    {
        var state = _state ?? new ForemanState();
        var caller = CallerScope.From(http);
        // A per-harness token may only validate its OWN integration — not probe a sibling's profile/sessions.
        if (!caller.CanAccess(harnessId))
            return new { harnessId, error = "You can only validate your own harness integration." };
        var integration = HarnessIntegrationRegistry.Get(harnessId);
        var profileName = integration?.DefaultProfileName;
        var profile = profileName is not null ? state.GetProfileByName?.Invoke(profileName) : null;
        var processes = state.GetProcessesForHarness(harnessId, includeChildren: true).ToArray();

        return new
        {
            harnessId,
            knownHarness = HarnessIntegrationRegistry.GetKnownHarness(harnessId) is not null,
            integrationMetadata = integration is not null,
            defaultProfileName = profileName,
            profileLoaded = profile is not null,
            runningProcessCount = processes.Length,
            runningHarnessCount = processes.Count(p => string.Equals(p.HarnessType, harnessId, StringComparison.OrdinalIgnoreCase)),
            mcpSessions = state.McpSessionCount,
            connectedClients = (state.GetMcpClients?.Invoke() ?? [])
                .Select(c => new
                {
                    c.Name,
                    c.Version,
                    c.Sampling,
                    c.Elicitation,
                    matchesHarness = SseSessionManager.MatchesHarness(c.Name, null, harnessId),
                })
                // A scoped caller sees only its own connection, not the names of sibling clients.
                .Where(c => caller.IsOperator || c.matchesHarness)
                .ToArray(),
            pendingAskHarnessRequests = state.CountAskHarnessRequests(harnessId),
            status = integration is not null && profile is not null
                ? "configured"
                : "incomplete",
        };
    }

    [McpServerTool, Description("Lists configured LLM auditor preferences for cross-harness triage.")]
    public static object ListAuditPreferences(
        Microsoft.AspNetCore.Http.IHttpContextAccessor? http = null)
    {
        var state = _state ?? new ForemanState();
        var caller = CallerScope.From(http);
        var settings = state.LlmTriage;
        var prefs = settings.AuditorPreferences.AsEnumerable();
        // A per-harness token sees only the preferences that route to IT (who reviews this harness) —
        // not the full cross-harness routing table or other harnesses' auditor endpoints.
        if (!caller.IsOperator)
            prefs = prefs.Where(p => p.TargetHarnessIds.Length == 0
                || p.TargetHarnessIds.Any(t => t == "*" || string.Equals(t, caller.HarnessId, StringComparison.OrdinalIgnoreCase)));
        return new
        {
            enabled = settings.Enabled,
            preventSelfAudit = settings.PreventSelfAudit,
            maxEventsPerReview = settings.MaxEventsPerReview,
            preferences = prefs
                .OrderByDescending(p => p.Priority)
                .Select(p => new
                {
                    p.Enabled,
                    p.AuditorId,
                    p.AuditorType,
                    p.DisplayName,
                    p.TargetHarnessIds,
                    p.MinimumSeverities,
                    p.Priority,
                    p.ApiEndpoint,
                    p.Model,
                })
                .ToArray(),
        };
    }

    [McpServerTool, Description(
        "Selects the preferred auditor harness/API for reviewing another harness's actions. " +
        "Use this before asking one AI to audit another.")]
    public static object GetAuditRoute(
        [Description("Harness being audited, e.g. 'claude-code' or 'codex'")] string targetHarnessId,
        [Description("Severity to route, e.g. Medium, High, Critical")] string severity = "High",
        [Description("Only return currently available auditors")] bool requireAvailable = false,
        Microsoft.AspNetCore.Http.IHttpContextAccessor? http = null)
    {
        var state = _state ?? new ForemanState();
        var caller = CallerScope.From(http);
        // A per-harness token may only resolve the audit route FOR ITSELF — not discover who audits a sibling.
        if (!caller.CanAccess(targetHarnessId))
            return new { targetHarnessId, error = "You can only resolve the audit route for your own harness." };
        var settings = state.LlmTriage;
        if (!Enum.TryParse<ForemanSeverity>(severity, ignoreCase: true, out var parsedSeverity))
            parsedSeverity = ForemanSeverity.High;

        var snapshot = state.GetProcessSnapshot?.Invoke().ToList() ?? [];
        var connected = BuildConnectedHarnessIds(state);

        var selection = AuditRouteResolver.Resolve(settings, targetHarnessId, parsedSeverity, snapshot, connected);
        var candidates = selection.Candidates
            .Where(c => !requireAvailable || c.Available)
            .Select(ToAuditRouteDto)
            .ToArray();

        object? selected = null;
        string reason = selection.Reason;
        if (selection.Selected is { } primary && (!requireAvailable || primary.Available))
        {
            selected = ToAuditRouteDto(primary);
        }
        else if (requireAvailable)
        {
            var available = selection.Candidates.FirstOrDefault(c => c.Available);
            if (available is not null)
            {
                selected = ToAuditRouteDto(available);
                reason = available.IsFallback
                    ? selection.Reason
                    : "Auditor selected from user preference list.";
            }
            else
            {
                reason = $"No available auditor matched {targetHarnessId} at this severity.";
            }
        }

        // Echo the EFFECTIVE severity (an unrecognised input was coerced to High above); note the coercion in
        // reason so the caller isn't told a route was computed for the string it sent when it wasn't.
        if (!string.Equals(severity, parsedSeverity.ToString(), StringComparison.OrdinalIgnoreCase))
            reason = $"Unrecognised severity '{severity}' — routed as {parsedSeverity}. " + reason;

        return new
        {
            enabled = settings.Enabled,
            targetHarnessId,
            severity = parsedSeverity.ToString(),
            selected,
            candidates,
            usedFallback = selection.UsedFallback,
            reason,
        };
    }

    private static HashSet<string> BuildConnectedHarnessIds(ForemanState state)
    {
        var clients = state.GetMcpClients?.Invoke() ?? [];
        var connected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var harness in KnownHarnesses.All)
        {
            if (clients.Any(c => SseSessionManager.MatchesHarness(c.Name, null, harness.Id)))
                connected.Add(harness.Id);
        }
        return connected;
    }

    private static object ToAuditRouteDto(AuditRouteResolver.Candidate c) => new
    {
        c.AuditorId,
        c.AuditorType,
        displayName = c.DisplayName,
        c.Priority,
        available = c.Available,
        runningHarnessCount = c.RunningHarnessCount,
        mcpConnected = c.McpConnected,
        isFallback = c.IsFallback,
        c.ApiEndpoint,
        c.Model,
    };

    // Resets a harness's escalation and announces it. If the harness had actually escalated
    // (above Watch), the reset is published as a visible Medium alert rather than a silent Info,
    // so a (possibly adversarial) harness cannot quietly wipe a real escalation to self-exonerate.
    private static void ResetAndAnnounce(ForemanState state, string harnessId, string source)
    {
        var priorLevel = state.GetEscalationLevel(harnessId);
        state.ResetBehaviorProfile?.Invoke(harnessId);

        if (priorLevel is { } lvl && lvl > EscalationLevel.Watch)
        {
            // High, so it cannot be self-acknowledged over MCP (the ack gate refuses >= High) and
            // it can't be silently cleared — wiping a real escalation should make noise.
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow,
                ForemanSeverity.High,
                source,
                $"Behavior metrics for '{harnessId}' were reset from {lvl.ToString().ToUpperInvariant()} via MCP — escalation history cleared."));
        }
        else
        {
            EventBus.Instance.Publish(new InfoEvent(
                DateTimeOffset.UtcNow,
                source,
                $"Behavior metrics reset for '{harnessId}' via MCP."));
        }
    }

    [McpServerTool, Description(
        "Lists the MCP servers Foreman discovered configured across your AI harnesses " +
        "(name, transport, target, scope). Useful for spotting an unexpected or newly-added MCP server.")]
    public static object ListMcpServers(
        Microsoft.AspNetCore.Http.IHttpContextAccessor? http = null)
    {
        var state = _state ?? new ForemanState();
        var caller = CallerScope.From(http);
        var servers = state.GetMcpInventory?.Invoke() ?? [];
        // A per-harness token sees only the MCP servers configured under ITS harness, not the whole machine's.
        if (!caller.IsOperator)
            servers = servers.Where(s => string.Equals(s.Harness, caller.HarnessId, StringComparison.OrdinalIgnoreCase)).ToList();
        return new
        {
            servers = servers
                .OrderBy(s => s.Harness, StringComparer.OrdinalIgnoreCase)
                .ThenBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
                // Target is a url or a stdio command+args; the latter can embed a token (e.g. an
                // Authorization header passed as an arg). Mask secret-shaped text at egress.
                .Select(s => new { s.Harness, s.Name, s.Transport, Target = Core.Security.SecretRedactor.Redact(s.Target), s.Scope })
                .ToArray(),
        };
    }

    [McpServerTool, Description(
        "Reports the latest MCP tool-description injection scan (server, tool, matched signal, excerpt). " +
        "Opt-in via Foreman Settings → Scan MCP tools; returns the cached result of the last scan — no live network call.")]
    public static object ListMcpToolFindings(
        Microsoft.AspNetCore.Http.IHttpContextAccessor? http = null)
    {
        var state = _state ?? new ForemanState();
        if (state.GetMcpToolScan is null)
            return new { enabled = false, message = "MCP tool scanning is off. Enable it in Foreman Settings → Scan MCP tools." };

        var caller = CallerScope.From(http);
        var (findings, summary) = state.GetMcpToolScan();
        var scoped = findings.AsEnumerable();
        // A per-harness token sees only findings for MCP servers configured under ITS harness — it can't
        // enumerate what (possibly suspicious) servers a sibling harness has wired up.
        if (!caller.IsOperator)
        {
            var mine = new HashSet<string>(
                (state.GetMcpInventory?.Invoke() ?? [])
                    .Where(s => string.Equals(s.Harness, caller.HarnessId, StringComparison.OrdinalIgnoreCase))
                    .Select(s => s.Name),
                StringComparer.OrdinalIgnoreCase);
            scoped = scoped.Where(f => mine.Contains(f.Server));
        }
        return new
        {
            enabled  = true,
            summary,
            findings = scoped.Select(f => new { f.Server, f.Tool, f.Signal, f.Excerpt }).ToArray(),
        };
    }

    private static object AskRequestShape(AskHarnessRequest request) => new
    {
        request.RequestId,
        request.CreatedAt,
        request.AlertId,
        request.HarnessId,
        request.ProcessId,
        request.ProcessName,
        request.Status,
        // Redact at egress: the prompt is built from the alert's Message/command, which can carry a secret
        // fragment, and a peer auditor harness receives this via list_ask_harness_requests. Mask here too,
        // mirroring the event-stream egress in ForemanState — so the leak is closed regardless of how the
        // prompt was stored. (S-4)
        SystemPrompt = Core.Security.SecretRedactor.Redact(request.SystemPrompt),
        Prompt = Core.Security.SecretRedactor.Redact(request.Prompt),
        request.RepliedAt,
        request.ReplyText,
        request.ActionTaken,
    };

    private static string Truncate(string text, int max) =>
        text.Length <= max ? text : text[..max] + "...";
}
