using Foreman.Core.Models;

namespace Foreman.App;

/// <summary>Rolls up per-process sampler metrics into one harness-level usage snapshot for dashboard lights.</summary>
public sealed record HarnessUsage(
    double CpuPercent,
    long MemoryBytes,
    double IoBytesPerSec,
    double? GpuPercent,
    double? NetBytesPerSec,
    int ProcessCount);

public static class HarnessUsageAggregator
{
    public static HarnessUsage Aggregate(
        IEnumerable<ProcessRecord> processes,
        IReadOnlyDictionary<int, ResourceSampler.Metrics> metrics,
        Func<int, double?>? netRate)
    {
        var list = processes.ToList();
        if (list.Count == 0)
            return new HarnessUsage(0, 0, 0, null, null, 0);

        double cpu = 0, io = 0, gpuSum = 0;
        int gpuCount = 0;
        long mem = 0;
        double? netSum = null;

        foreach (var p in list)
        {
            if (metrics.TryGetValue(p.Pid, out var m))
            {
                cpu += m.CpuPercent;
                mem += m.MemoryBytes;
                io += m.IoBytesPerSec;
                if (m.GpuPercent is { } g)
                {
                    gpuSum += g;
                    gpuCount++;
                }
            }

            var n = netRate?.Invoke(p.Pid);
            if (n is > 0)
                netSum = (netSum ?? 0) + n.Value;
        }

        return new HarnessUsage(
            cpu,
            mem,
            io,
            gpuCount > 0 ? gpuSum : null,
            netSum,
            list.Count);
    }

    public static string FormatCpu(double pct) => pct < 0.5 ? "0%" : $"{pct:0}%";
    public static string FormatMem(long bytes)
    {
        if (bytes <= 0) return "0";
        var mb = bytes / (1024.0 * 1024.0);
        return mb >= 1024 ? $"{mb / 1024:0.1} GB" : $"{mb:0} MB";
    }

    public static string FormatRate(double bytesPerSec)
    {
        if (bytesPerSec < 1024) return $"{bytesPerSec:0} B/s";
        if (bytesPerSec < 1024 * 1024) return $"{bytesPerSec / 1024:0} KB/s";
        return $"{bytesPerSec / (1024 * 1024):0.1} MB/s";
    }
}
