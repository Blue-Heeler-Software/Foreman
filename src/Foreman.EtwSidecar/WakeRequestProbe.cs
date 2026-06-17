using System.Diagnostics;
using Foreman.Core.Power;

namespace Foreman.EtwSidecar;

internal static class WakeRequestProbe
{
    public static WakeRequestSnapshot Read()
    {
        try
        {
            return ReadAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            return WakeRequestSnapshot.Unavailable(ex.Message);
        }
    }

    private static async Task<WakeRequestSnapshot> ReadAsync()
    {
        try
        {
            using var proc = Process.Start(new ProcessStartInfo("powercfg.exe", "/requests")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            if (proc is null)
                return WakeRequestSnapshot.Unavailable("powercfg.exe did not start.");

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var outputTask = proc.StandardOutput.ReadToEndAsync(timeout.Token);
            var errorTask = proc.StandardError.ReadToEndAsync(timeout.Token);
            try
            {
                await proc.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return WakeRequestSnapshot.Unavailable("powercfg.exe timed out.");
            }

            var output = await outputTask.ConfigureAwait(false);
            var error = await errorTask.ConfigureAwait(false);
            if (proc.ExitCode != 0)
                return WakeRequestSnapshot.Unavailable(string.IsNullOrWhiteSpace(error) ? $"powercfg.exe exited {proc.ExitCode}." : error.Trim());

            return WakeRequestParser.ParsePowercfgRequests(output);
        }
        catch (Exception ex)
        {
            return WakeRequestSnapshot.Unavailable(ex.Message);
        }
    }
}
