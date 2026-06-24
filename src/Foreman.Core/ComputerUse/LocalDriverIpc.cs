namespace Foreman.Core.ComputerUse;

/// <summary>
/// Wire contract for the Local Agent Host (the local AI driver) -> Foreman.CuPilot shim -> App (spec INV-12). The
/// frame a driver sends is STRUCTURALLY incapable of carrying a bound window, an epoch, a modality, or a caller
/// identity - it has no such fields - so even a buggy or hostile forwarder cannot smuggle them. The App builds the
/// real <see cref="CuAction"/> from scratch with App-set Modality + ByHarness, and the broker stamps the authoritative
/// bound window at delivery. The agent can only PROPOSE.
/// </summary>
public sealed record DriverSubmit(string ActionId, string Verb, IReadOnlyDictionary<string, string> Args, string? Justification = null);

/// <summary>Shim/App -> driver outcome. Advisory only - the operator + the broker are authoritative.</summary>
public sealed record DriverResult(string ActionId, bool Ok, string? Error = null, string? Reason = null);

/// <summary>Builds the trusted <see cref="CuAction"/> from an untrusted <see cref="DriverSubmit"/> and the fixed id.</summary>
public static class LocalDriverIpc
{
    /// <summary>The single authenticated id the shim stamps on every relayed submit (App-set, never agent-supplied).</summary>
    public const string LocalAgentHostId = "local-agent-host";

    // Even though DriverSubmit has no hwnd/identity FIELDS, the free-form Args map could still smuggle these keys to try
    // to pre-stamp the bound window or spoof identity - so they are stripped when the App builds the action (INV-12/17).
    private static readonly string[] Reserved = { "hwnd", "epoch", "modality", "byharness", "isolation", "sessionid" };

    /// <summary>
    /// Build the trusted desktop CuAction from a driver's proposal: App-set Modality=Desktop, App-set
    /// ByHarness=<see cref="LocalAgentHostId"/>, and Args with every reserved key STRIPPED so a smuggled bound window
    /// or identity cannot ride through. The broker stamps the authoritative hwnd/epoch at delivery.
    /// </summary>
    public static CuAction BuildAction(DriverSubmit s)
    {
        var safe = new Dictionary<string, string>(StringComparer.Ordinal);
        if (s.Args is not null)
            foreach (var kv in s.Args)
                if (!Reserved.Contains(kv.Key.Trim().ToLowerInvariant()))
                    safe[kv.Key] = kv.Value;

        return new CuAction(CuModality.Desktop, s.Verb ?? string.Empty, safe,
            ByHarness: LocalAgentHostId, ActionId: string.IsNullOrWhiteSpace(s.ActionId) ? null : s.ActionId);
    }
}
