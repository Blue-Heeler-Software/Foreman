namespace Foreman.Core.ComputerUse;

/// <summary>
/// The operator "AI is piloting" HUD, as the executor pump sees it (spec INV-8 / INV-18). Before delivering any desktop
/// input the pump must obtain a FRESH adversarial confirmation that the banner is actually visible RIGHT NOW - topmost,
/// not DWM-cloaked, on a real monitor, and its screen rectangle NOT occluded by another window - never a self-reported
/// "I set myself topmost". If it can't be confirmed, the pump withholds the input (fail closed) so piloting can never be
/// invisible. Implemented App-side (user32/DWM kept out of Core); a fake drives the pump tests.
/// </summary>
public interface IHudAck
{
    /// <summary>Raise/keep the piloting banner up (sticky). Idempotent; safe to call every pump tick.</summary>
    void EnsureShown();

    /// <summary>Adversarial: true ONLY if the banner is topmost, painted, un-cloaked, and its rectangle is not occluded
    /// by any other window AT THIS INSTANT. Must be safe to call off the UI thread.</summary>
    bool ConfirmVisible();
}
