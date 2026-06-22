using System.Threading;
using System.Threading.Tasks;

namespace Foreman.Core.ComputerUse;

/// <summary>Outcome of executing one approved <see cref="CuAction"/> via an <see cref="ICuExecutor"/>.</summary>
public sealed record CuExecResult(bool Ok, object? Result, string? Error);

/// <summary>
/// Executes APPROVED computer-use actions for one modality. The broker owns audit, confinement, and panic; an
/// executor only runs actions the broker already cleared and reports the outcome. Per the desktop-CU spec (INV-5)
/// every self-report is cross-checked App-side against independent OS state, so this result is advisory, not trusted.
/// </summary>
public interface ICuExecutor
{
    /// <summary>The modality this executor handles (e.g. Desktop). The pump routes actions by modality.</summary>
    CuModality Modality { get; }

    /// <summary>True when the executor is connected and able to run actions (e.g. the sidecar handshake completed).</summary>
    bool IsReady { get; }

    Task<CuExecResult> ExecuteAsync(CuBrokerItem item, CancellationToken ct = default);
}
