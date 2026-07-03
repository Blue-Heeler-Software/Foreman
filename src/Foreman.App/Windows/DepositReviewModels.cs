namespace Foreman.App.Windows;

/// <summary>One queued locked-time sign-up, shown to the operator for review. Carries NO secret - just the agent's
/// (unverified) claims (site / harness / time) and an opaque id the App maps back to the real deposit.</summary>
public sealed record DepositReviewItem(string Id, string Origin, string Harness, string CreatedAt)
{
    public string Title => $"{Origin}   ·   claims harness: {Harness}";
    public string Sub => $"created (claimed): {CreatedAt}";
}

/// <summary>A drained snapshot: the reviewable items + how many queue lines failed to decrypt + whether the deposit
/// key itself was swapped (tamper). Failed/tamper are surfaced as warnings; nothing auto-commits.</summary>
public sealed record DepositReviewSnapshot(IReadOnlyList<DepositReviewItem> Items, int Failed, bool KeyTampered);
