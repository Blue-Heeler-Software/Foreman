namespace Foreman.Core.Power;

public sealed record WakeRequestEntry(
    string Category,
    string RequesterType,
    string Image,
    string Detail);

public sealed record WakeRequestSnapshot(
    bool Available,
    IReadOnlyList<WakeRequestEntry> Requests,
    string? Error = null)
{
    public static WakeRequestSnapshot Unavailable(string? error = null) => new(false, [], error);
}

public static class WakeRequestParser
{
    private static readonly HashSet<string> Categories = new(StringComparer.OrdinalIgnoreCase)
    {
        "DISPLAY", "SYSTEM", "AWAYMODE", "EXECUTION", "PERFBOOST", "ACTIVELOCKSCREEN"
    };

    public static WakeRequestSnapshot ParsePowercfgRequests(string output)
    {
        var requests = new List<WakeRequestEntry>();
        var category = string.Empty;
        WakeRequestEntry? pending = null;

        foreach (var raw in output.Replace("\r\n", "\n").Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;

            if (line.EndsWith(':') &&
                Categories.Contains(line.TrimEnd(':')))
            {
                Flush();
                category = line.TrimEnd(':').ToUpperInvariant();
                continue;
            }

            if (line.Equals("None.", StringComparison.OrdinalIgnoreCase))
            {
                Flush();
                continue;
            }

            if (line.StartsWith("[", StringComparison.Ordinal))
            {
                Flush();
                var close = line.IndexOf(']');
                if (close > 1)
                {
                    pending = new WakeRequestEntry(
                        category,
                        line[1..close].Trim().ToUpperInvariant(),
                        line[(close + 1)..].Trim(),
                        string.Empty);
                }
                continue;
            }

            if (pending is not null)
                pending = pending with { Detail = AppendDetail(pending.Detail, line) };
        }

        Flush();
        return new WakeRequestSnapshot(true, requests);

        void Flush()
        {
            if (pending is not null)
            {
                requests.Add(pending);
                pending = null;
            }
        }
    }

    private static string AppendDetail(string current, string line) =>
        string.IsNullOrWhiteSpace(current) ? line : current + " " + line;
}
