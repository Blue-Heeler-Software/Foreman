using Foreman.Guardian;

// Foreman Guardian (circle-back Phase A) — the OPT-IN LocalSystem authority that will hold the event-log
// head-seal key and the settings-seal secret behind the SYSTEM boundary, so a same-user (medium-IL) agent can
// neither use the key nor read the secret to forge a seal.
//
// STEP 3 (scaffold): a console-hostable duplex pipe server that answers Hello only. The SYSTEM key custody, the
// SealHead / settings-seal RPCs, the SCM service-host wiring, and the elevated --install/--uninstall verbs arrive
// in the following steps. Runnable now for a smoke test:  Foreman.Guardian.exe  (then connect + send Hello).

if (args.Length > 0 && args[0] is "--version" or "-v")
{
    Console.WriteLine(GuardianAuthority.Version);
    return 0;
}

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

// Open (or create) the TPM/PCP head-seal key in THIS process's context. Run as the LocalSystem service, the key
// is SYSTEM-scoped and unusable by the medium-IL agent; run in a console for smoke tests, it's user-scoped.
using var authority = GuardianAuthority.CreateWithTpmKey();
Console.WriteLine($"Foreman Guardian {GuardianAuthority.Version} — pipe '{GuardianPipeServer.PipeName}', headKey={(authority.HeadKeyAvailable ? "available" : "unavailable (no TPM)")} (Ctrl+C to stop).");

var server = new GuardianPipeServer(authority);
try
{
    await server.RunAsync(cts.Token);
}
catch (OperationCanceledException) { /* clean shutdown */ }

return 0;
