using Foreman.Platform;

namespace Foreman.Platform.Linux;

public sealed class LinuxProcessIoReader : IProcessIoReader
{
    private readonly string _procRoot;

    public LinuxProcessIoReader(string procRoot = "/proc")
    {
        _procRoot = procRoot;
    }

    public bool TryReadIo(int pid, out ulong readOps, out ulong writeOps, out string? unavailableReason)
    {
        readOps = 0;
        writeOps = 0;
        unavailableReason = null;

        try
        {
            var path = Path.Combine(_procRoot, pid.ToString(), "io");
            if (!File.Exists(path))
            {
                unavailableReason = "process exited or /proc io file is unavailable";
                return false;
            }

            if (LinuxProcParser.TryParseIo(File.ReadAllText(path), out readOps, out writeOps))
                return true;

            unavailableReason = "io file did not contain syscr/syscw counters";
            return false;
        }
        catch (UnauthorizedAccessException ex)
        {
            unavailableReason = ex.Message;
            return false;
        }
        catch (IOException ex)
        {
            unavailableReason = ex.Message;
            return false;
        }
    }
}
