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

/// <summary>App -> shim (HOP A): launch the operator-configured local agent. The shim spawns it, hands it the HOP B
/// pipe name + session secret via an inherited handle (the agent's stdin), and pins the launched PID. The command is
/// operator config - never agent-supplied - and arming the host is presence-gated (INV-16).</summary>
public sealed record StartAgentArgs(string Command, string? Arguments, string? WorkingDir);

/// <summary>shim -> App (HOP A, poll result): the batch of DriverSubmit proposals the agent has sent since the last
/// poll. The App builds a trusted CuAction from each via <see cref="LocalDriverIpc.BuildAction"/> and submits it
/// IN-PROCESS (L5); the agent can only propose.</summary>
public sealed record DriverSubmitBatch(IReadOnlyList<DriverSubmit> Items);

/// <summary>Builds the trusted <see cref="CuAction"/> from an untrusted <see cref="DriverSubmit"/> and the fixed id.</summary>
public static class LocalDriverIpc
{
    /// <summary>The single authenticated id the shim stamps on every relayed submit (App-set, never agent-supplied).</summary>
    public const string LocalAgentHostId = "local-agent-host";

    // Reserved keys an agent must NOT be able to assert via the free-form Args map: the bound window / identity /
    // modality (INV-12), AND the descriptors the Desktop AUDITOR judges - windowClass/windowTitle (the consent-surface
    // Block) + targetLabel/targetRole (the sensitive-control Hold and the no-target Hold). Those must be supplied by
    // the trusted probe at delivery (INV-1), never agent-asserted, or a hostile agent steers its own audit verdict
    // (claim targetLabel="OK", omit windowClass/windowTitle, and a click on a real credential dialog sails through).
    private static readonly string[] Reserved =
    {
        "hwnd", "epoch", "modality", "byharness", "isolation", "sessionid",
        "windowclass", "windowtitle", "targetlabel", "targetrole", "justification",
    };

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

        // The agent's claimed rationale travels ONLY via the typed field, into a reserved slot it cannot write directly
        // (a free-form "justification" arg is stripped above) - the HUD/gate renders this as agent-CLAIMED, not trusted.
        if (!string.IsNullOrWhiteSpace(s.Justification)) safe["agentJustification"] = s.Justification!.Trim();

        return new CuAction(CuModality.Desktop, s.Verb ?? string.Empty, safe,
            ByHarness: LocalAgentHostId, ActionId: string.IsNullOrWhiteSpace(s.ActionId) ? null : s.ActionId);
    }
}
