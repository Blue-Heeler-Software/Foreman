using System.Threading;
using Foreman.Core.Guardian;
using Foreman.Core.Settings;

namespace Foreman.App;

/// <summary>
/// Chooses the event-log head signer at startup (circle-back Phase A, step 6c). When the opt-in guardian service
/// is installed AND the pipe is confirmed SYSTEM-owned, sealing is routed through it (the key lives behind the
/// SYSTEM boundary, unforgeable by the agent); otherwise it falls back to the per-user local path
/// (<see cref="HeadSealFactory"/>) — the casual user is byte-identical to today.
///
/// Fail-safe everywhere: discovery off, can't confirm SYSTEM ownership (squatter / no rights), the guardian has no
/// key (no-TPM), or any error ⇒ local path. Bounded by a short timeout so startup never hangs on the pipe.
/// </summary>
internal static class GuardianSignerFactory
{
    public static HeadSealBuild Build(ForemanSettings settings, Action<ForemanSettings> saveSettings)
    {
        if (!GuardianDiscovery.IsGuardianInstalled())
            return HeadSealFactory.Build(settings, saveSettings);

        try
        {
            var client = new GuardianPipeClient();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));

            // Anti-squat: only trust a pipe owned by LocalSystem before adopting its key.
            if (!client.IsServerSystemOwnedAsync(cts.Token).GetAwaiter().GetResult())
                return HeadSealFactory.Build(settings, saveSettings);

            var keyB64 = client.GetPinnedHeadKeyAsync(cts.Token).GetAwaiter().GetResult();
            if (string.IsNullOrEmpty(keyB64))
                return HeadSealFactory.Build(settings, saveSettings);   // guardian has no usable TPM key

            // Adopt the guardian's public key. Enabling hardened mode required a UAC-elevated install, and the pipe
            // is confirmed SYSTEM-owned above, so re-pinning here is authorized — no false "key changed" alarm.
            if (!string.Equals(settings.LogIntegrity.PinnedHeadPublicKeyB64, keyB64, StringComparison.Ordinal))
            {
                settings.LogIntegrity.PinnedHeadPublicKeyB64 = keyB64;
                try { saveSettings(settings); } catch { /* best-effort; verify-only still works this run */ }
            }

            var pinned = Convert.FromBase64String(keyB64);
            return new HeadSealBuild(new GuardianSigner(client, pinned), Notice: null, NoticeIsHigh: false, Owns: null);
        }
        catch
        {
            return HeadSealFactory.Build(settings, saveSettings);
        }
    }
}
