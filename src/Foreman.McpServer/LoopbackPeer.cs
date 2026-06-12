using System.Runtime.InteropServices;

namespace Foreman.McpServer;

/// <summary>
/// Maps a loopback TCP connection's CLIENT endpoint to the owning process PID via <c>GetExtendedTcpTable</c>
/// (iphlpapi) — the OS truth of "which process opened this socket". Used to bind a per-harness MCP token to the
/// process actually presenting it (<see cref="Foreman.Core.Mcp.PeerIdentityPolicy"/>). Windows-only; any
/// failure returns null and the caller treats null as "unattributed", never as an attack.
///
/// A PID read from a LIVE connection is inherently current (no stale (pid,startTime) gap to spoof via PID
/// reuse), and the caller classifies it against the live process tree at the same instant.
/// </summary>
internal static class LoopbackPeer
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        nint pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, int reserved);

    /// <summary>
    /// PID owning the loopback socket whose LOCAL endpoint is <paramref name="clientPort"/> connected to
    /// <paramref name="serverPort"/> — i.e. the MCP client process. Returns null if not found, not Windows,
    /// or on any lookup error (caller treats null as "unattributed").
    /// </summary>
    public static int? FindOwningPid(int clientPort, int serverPort, bool ipv6)
    {
        if (clientPort <= 0 || serverPort <= 0) return null;
        try
        {
            return ipv6
                ? Scan(AF_INET6, rowSize: 56, addrLen: 16, clientPort, serverPort)
                : Scan(AF_INET,  rowSize: 24, addrLen: 4,  clientPort, serverPort);
        }
        catch { return null; }
    }

    private static int? Scan(int af, int rowSize, int addrLen, int clientPort, int serverPort)
    {
        var size = 0;
        GetExtendedTcpTable(nint.Zero, ref size, false, af, TCP_TABLE_OWNER_PID_ALL, 0);   // size probe
        if (size <= 4) return null;

        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buf, ref size, false, af, TCP_TABLE_OWNER_PID_ALL, 0) != 0) return null;

            var count = Marshal.ReadInt32(buf);          // DWORD dwNumEntries, then the row array
            const int baseOff = 4;
            for (var i = 0; i < count; i++)
            {
                var row = baseOff + i * rowSize;
                if (row + rowSize > size) break;          // defensive: never read past the buffer

                // IPv4 MIB_TCPROW_OWNER_PID:  state(4) localAddr(4) localPort(4) remoteAddr(4) remotePort(4) pid(4)
                // IPv6 MIB_TCP6ROW_OWNER_PID: localAddr(16) localScope(4) localPort(4) remoteAddr(16) remoteScope(4) remotePort(4) state(4) pid(4)
                var localPortOff  = af == AF_INET ? row + 8  : row + addrLen + 4;
                var remotePortOff = af == AF_INET ? row + 16 : row + addrLen + 4 + 4 + addrLen + 4;
                var pidOff        = af == AF_INET ? row + 20 : row + rowSize - 4;

                if (NetPort(Marshal.ReadInt32(buf, localPortOff)) != clientPort) continue;
                if (NetPort(Marshal.ReadInt32(buf, remotePortOff)) != serverPort) continue;
                return Marshal.ReadInt32(buf, pidOff);
            }
            return null;
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    // dwXxxPort carries the port in the low 16 bits in network byte order — swap to host order.
    private static int NetPort(int raw) => ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);
}
