using Foreman.McpServer;

namespace Foreman.McpServer.Tests;

/// <summary>
/// B6 / deep-review #3,#30: a per-harness token presented by a DIFFERENT process (PeerMismatch) is token theft.
/// Such a caller may still read (governed by CanAccess) but must NOT invoke the state-mutating tools
/// (acknowledge / reset-metrics / reply-to-ask) — that's how a stolen token would self-exonerate — even when
/// peer-binding enforcement is off. The operator is always allowed.
/// </summary>
public sealed class CallerScopeMutateTests
{
    [Fact] public void Operator_CanMutate()
        => Assert.True(new CallerScope(null, IsOperator: true).CanMutate);

    [Fact] public void ScopedHarness_PeerOk_CanMutate()
        => Assert.True(new CallerScope("codex", IsOperator: false).CanMutate);

    [Fact] public void ScopedHarness_PeerMismatch_CannotMutate()
        => Assert.False(new CallerScope("codex", IsOperator: false, PeerMismatch: true).CanMutate);
}
