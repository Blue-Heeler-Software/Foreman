using Foreman.Core.Profiles;

namespace Foreman.Core.ComputerUse;

/// <summary>Context an auditor may use to judge an action: the calling harness and its permission profile.</summary>
public sealed record CuContext(string? HarnessId = null, HarnessProfile? Profile = null);

/// <summary>
/// Judges a <see cref="CuAction"/> BEFORE it executes. The pluggable seam: the deterministic local fast-path, a
/// frontier cloud deep-judge, and (later) a local-vision judge all implement this. Async because a deep judge calls
/// out over the network; the fast-path simply returns a completed task.
/// </summary>
public interface IAuditor
{
    Task<CuVerdict> JudgeAsync(CuAction action, CuContext context, CancellationToken ct = default);
}
