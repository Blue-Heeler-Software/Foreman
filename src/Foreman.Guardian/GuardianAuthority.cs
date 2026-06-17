using Foreman.Core.Ipc.Guardian;

namespace Foreman.Guardian;

/// <summary>
/// The guardian's authority logic, kept independent of the pipe transport so it is unit-testable without any
/// process/IPC (per the design plan). This is where the operations that move behind the SYSTEM boundary will live
/// — signing the event-log head with the SYSTEM-held key, and computing/verifying the settings seal with the
/// SYSTEM-held secret.
///
/// STEP 3 (scaffold): only <see cref="Hello"/> is implemented; <see cref="HeadKeyAvailable"/> is false because the
/// SYSTEM key custody lands in the next step. Everything else is intentionally absent so the wiring + contract can
/// be verified end-to-end before any real authority is granted.
/// </summary>
public sealed class GuardianAuthority
{
    /// <summary>Three-part assembly version string, surfaced in Hello + the --version smoke verb.</summary>
    public static string Version =>
        typeof(GuardianAuthority).Assembly.GetName().Version?.ToString(3) ?? "0.1";

    /// <summary>True once the guardian holds a usable SYSTEM head-seal key (no-TPM box ⇒ false). Step 3: false.</summary>
    public bool HeadKeyAvailable => false;

    public HelloResult Hello() => new() { GuardianVersion = Version, HeadKeyAvailable = HeadKeyAvailable };
}
