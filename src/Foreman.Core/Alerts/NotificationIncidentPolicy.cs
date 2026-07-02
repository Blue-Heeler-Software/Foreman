using Foreman.Core.Models;
using System.Text;

namespace Foreman.Core.Alerts;

/// <summary>
/// Classifies user-facing tray notifications into incident keys. This governs popups only: the raw event has
/// already been published and remains logged, counted, and escalated. Critical alerts are deliberately excluded.
/// </summary>
public static class NotificationIncidentPolicy
{
    public static NotificationIncident? Classify(ForemanEvent evt)
    {
        if (evt.Severity >= ForemanSeverity.Critical) return null;

        return evt switch
        {
            HangDetectedEvent h => new(
                "hang/" + CleanPart(h.ParentHarnessType ?? h.ParentHarnessName ?? "unattributed"),
                HumanHarness(h.ParentHarnessType ?? h.ParentHarnessName) + " process hang (no I/O)"),

            OrphanDetectedEvent o => new(
                "orphan/" + CleanPart(o.HarnessType ?? o.HarnessName ?? "unattributed"),
                HumanHarness(o.HarnessType ?? o.HarnessName) + " orphaned process"),

            CommandAlertEvent c => new(
                "command/" + CleanPart(string.IsNullOrWhiteSpace(c.RuleId) ? c.RuleName : c.RuleId),
                $"command alert {DisplayRule(c)}"),

            PermissionViolationEvent p => new(
                "permission/" + CleanPart(p.ProfileName) + "/" + CleanPart(p.ViolationType),
                $"{p.ProfileName} permission violation"),

            MonitoringNoticeEvent m => ClassifyMonitoring(m),

            _ => null,
        };
    }

    public static string ReadableClassKey(string classKey)
    {
        if (classKey.StartsWith("hang/", StringComparison.OrdinalIgnoreCase))
        {
            var owner = classKey["hang/".Length..];
            return HumanHarness(owner) + " process hang (no I/O)";
        }
        if (classKey.StartsWith("orphan/", StringComparison.OrdinalIgnoreCase))
        {
            var owner = classKey["orphan/".Length..];
            return HumanHarness(owner) + " orphaned process";
        }
        if (classKey.StartsWith("command/", StringComparison.OrdinalIgnoreCase))
            return "repeated command alert " + classKey["command/".Length..];
        if (classKey.StartsWith("permission/", StringComparison.OrdinalIgnoreCase))
            return "permission violation";
        if (classKey.StartsWith("mcp-auth/stale-token/", StringComparison.OrdinalIgnoreCase))
            return classKey["mcp-auth/stale-token/".Length..] + " stale MCP token";
        if (classKey.StartsWith("monitoring/", StringComparison.OrdinalIgnoreCase))
        {
            var rest = classKey["monitoring/".Length..];
            var source = rest.Split('/', 2)[0].Replace('-', '.');
            return source + " notice";
        }
        return classKey;
    }

    private static NotificationIncident? ClassifyMonitoring(MonitoringNoticeEvent evt)
    {
        if (string.Equals(evt.Source, "Foreman.McpAuth", StringComparison.OrdinalIgnoreCase)
            && TryExtractQuotedHarness(evt.Message, out var id))
        {
            return new("mcp-auth/stale-token/" + CleanPart(id), $"{id} stale MCP token");
        }

        return new(
            "monitoring/" + CleanPart(evt.Source) + "/" + CleanPart(ShortMessageKey(evt.Message)),
            evt.Source + " notice");
    }

    private static bool TryExtractQuotedHarness(string message, out string id)
    {
        id = "";
        const string savedTokenSuffix = "'s saved token";
        var end = message.IndexOf(savedTokenSuffix, StringComparison.OrdinalIgnoreCase);
        if (end <= 0) return false;

        var start = message.LastIndexOf('\'', end - 1);
        if (start < 0 || end <= start + 1) return false;

        id = message[(start + 1)..end];
        return id.Length <= 64;
    }

    private static string DisplayRule(CommandAlertEvent evt)
    {
        if (!string.IsNullOrWhiteSpace(evt.RuleId)) return $"({evt.RuleId})";
        return string.IsNullOrWhiteSpace(evt.RuleName) ? "" : $"({evt.RuleName})";
    }

    private static string HumanHarness(string? id)
    {
        if (string.IsNullOrWhiteSpace(id) || string.Equals(id, "unattributed", StringComparison.OrdinalIgnoreCase))
            return "Unattributed";
        return KnownHarnesses.GetById(id)?.DisplayName ?? id;
    }

    private static string ShortMessageKey(string message)
    {
        var s = message.Trim();
        return s.Length <= 48 ? s : s[..48];
    }

    private static string CleanPart(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "unknown";
        var sb = new StringBuilder(value.Length);
        foreach (var ch in value.Trim().ToLowerInvariant())
        {
            if (char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_' or ':' or '.')
                sb.Append(ch);
            else if (sb.Length == 0 || sb[^1] != '-')
                sb.Append('-');
        }
        return sb.ToString().Trim('-') is { Length: > 0 } cleaned ? cleaned : "unknown";
    }
}

public sealed record NotificationIncident(string ClassKey, string Label);
