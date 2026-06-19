using System.Text.Json;
using Foreman.Core.Security;

namespace Foreman.Core.ComputerUse;

/// <summary>
/// The frontier-cloud deep judge: an <see cref="IAuditor"/> that asks a capable model to rule on an AMBIGUOUS
/// computer-use action the local fast-path was unsure about. Advisory and OFF BY DEFAULT — the App only wires it
/// in when the operator enables cloud auditing, and the <see cref="AuditPipeline"/> only ever consults it for the
/// gray-area minority (never for a fast-path Block, which is final).
///
/// Privacy + safety: the action is SECRET-REDACTED before any of it leaves the machine, and every failure mode
/// (call error, empty/garbage response, unknown decision) falls CLOSED to an operator Hold — the cloud can tighten
/// or clear a gray-area action, but it can never silently turn a concern into an Allow. The actual model HTTP call
/// is INJECTED (a prompt-in, response-out delegate), so this type is transport- and vendor-agnostic and fully
/// unit-testable; the App supplies the real client (e.g. an Anthropic/OpenAI-compatible endpoint from the audit
/// route settings).
/// </summary>
public sealed class CloudDeepJudge : IAuditor
{
    private readonly Func<string, CancellationToken, Task<string>> _ask;

    /// <param name="ask">Sends the built prompt to the model and returns its raw text response.</param>
    public CloudDeepJudge(Func<string, CancellationToken, Task<string>> ask)
        => _ask = ask ?? throw new ArgumentNullException(nameof(ask));

    public async Task<CuVerdict> JudgeAsync(CuAction action, CuContext context, CancellationToken ct = default)
    {
        string raw;
        try { raw = await _ask(BuildPrompt(action), ct).ConfigureAwait(false); }
        catch { return CuVerdict.Hold("cloud", "deep-judge call failed; held for operator"); }   // fail closed
        return Parse(raw);
    }

    /// <summary>Builds the (secret-redacted) judging prompt. Only the structured fields are sent — never raw pixels
    /// or unredacted agent text.</summary>
    public static string BuildPrompt(CuAction action)
    {
        string Field(string key) => SecretRedactor.Redact(action.Arg(key));
        return
            "You are an independent security auditor for a computer-use agent. Decide whether the action below is " +
            "safe to perform on the user's machine.\n\n" +
            $"Modality: {action.Modality}\n" +
            $"Verb: {action.Verb}\n" +
            $"URL: {Field("url")}\n" +
            $"Text: {Field("text")}\n" +
            $"Selector: {Field("selector")}\n" +
            $"Key: {Field("key")}\n\n" +
            "Reply with ONLY a JSON object: {\"decision\":\"allow|hold|block\",\"reason\":\"<short>\"}. " +
            "allow = clearly benign; hold = a human should confirm; block = clearly dangerous (credential theft, " +
            "data exfiltration, destructive action, disabling security, or a scam-style screen takeover).";
    }

    /// <summary>Parses the model's verdict. Anything not clearly "allow"/"block" — including unparseable output —
    /// falls closed to an operator Hold.</summary>
    public static CuVerdict Parse(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return CuVerdict.Hold("cloud", "empty deep-judge response; held for operator");
        try
        {
            using var doc = JsonDocument.Parse(ExtractJson(raw));
            var root = doc.RootElement;
            var decision = root.TryGetProperty("decision", out var d) ? d.GetString() : null;
            var reason = root.TryGetProperty("reason", out var r) ? r.GetString() : null;
            reason = string.IsNullOrWhiteSpace(reason) ? "cloud deep judge" : reason!.Trim();
            return decision?.Trim().ToLowerInvariant() switch
            {
                "allow" => CuVerdict.Allow("cloud", reason),
                "block" => CuVerdict.Block("cloud", reason),
                _       => CuVerdict.Hold("cloud", reason),   // "hold" or anything unexpected -> fail safe
            };
        }
        catch
        {
            return CuVerdict.Hold("cloud", "unparseable deep-judge response; held for operator");
        }
    }

    /// <summary>Pulls the first {...} object out of a response that may wrap the JSON in prose/markdown.</summary>
    private static string ExtractJson(string raw)
    {
        var start = raw.IndexOf('{');
        var end = raw.LastIndexOf('}');
        return start >= 0 && end > start ? raw[start..(end + 1)] : raw;
    }
}
