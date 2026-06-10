using Foreman.Core.Models;

namespace Foreman.Core.Alerts;

/// <summary>
/// The ONE definition of an "active" alert, shared by every consumer (tray icon/tooltip, dashboard
/// summary + counts, and the MCP ForemanStatus). Before this, the tray, dashboard, and MCP state each
/// had a slightly different predicate, so their counts could disagree. They now all call <see cref="IsActive"/>.
///
/// Active = a real alert (above Info) that is neither operator-acknowledged nor auto-resolved.
/// </summary>
public static class AlertActivity
{
    public static bool IsActive(ForemanEvent evt)
        => evt.Severity > ForemanSeverity.Info && !evt.Acknowledged && !evt.AutoResolved;
}
