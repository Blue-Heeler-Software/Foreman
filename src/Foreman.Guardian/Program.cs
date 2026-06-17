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

Console.WriteLine($"Foreman Guardian {GuardianAuthority.Version} — listening on pipe '{GuardianPipeServer.PipeName}' (Ctrl+C to stop).");

var server = new GuardianPipeServer(new GuardianAuthority());
try
{
    await server.RunAsync(cts.Token);
}
catch (OperationCanceledException) { /* clean shutdown */ }

return 0;
