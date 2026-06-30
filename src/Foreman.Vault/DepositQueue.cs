using System.Security.Cryptography;
using System.Text.Json;

namespace Foreman.Vault;

/// <summary>
/// A clear, append-only file of ECIES-encrypted deposits (one JSON <see cref="DepositCrypto.Envelope"/> per line). An
/// agent self-signup while the vault is LOCKED appends here (encrypt-only, public key); on unlock the operator drains,
/// reviews, and commits. The file is never secret-bearing in the clear - each line is ciphertext to the vault's deposit
/// key, decryptable only with the private key sealed inside the vault. Locked-safe (enqueue + count need no key).
///
/// The clear public key means ANY same-user process can append a valid (forged) envelope, so this layer enforces a hard
/// size CAP (anti-flood) and a per-line RESILIENT drain (one junk line can't deny the operator the real deposits);
/// authenticity rests entirely on the operator reviewing + committing each drained deposit (see VaultService / the
/// review UI). Nothing here auto-commits.
/// </summary>
public sealed class DepositQueue(string path)
{
    private readonly string _path = path;
    private readonly object _gate = new();

    /// <summary>Hard cap on queued deposits: a flood of forged appends can't grow the file without bound while locked
    /// (which would pressure the operator into bulk-accepting on unlock). Persists across relaunch, unlike the in-memory
    /// signup rate window. Hitting it is itself an abuse signal the caller should surface.</summary>
    public const int MaxQueued = 50;

    /// <summary>The cleartext deposit an agent created while the vault was locked, surfaced to the operator on unlock.
    /// Origin/ByHarness/CreatedAtUtc are the (unauthenticated) caller's CLAIMS - the review UI must present them as such.</summary>
    public sealed record PendingDeposit(string Origin, string? Username, string Password, string ByHarness, string CreatedAtUtc);

    /// <summary>A drain result: the deposits that decrypted cleanly, plus a count of lines that did NOT (wrong key /
    /// tamper / corruption), so the operator can be warned the queue is suspect without losing the readable deposits.</summary>
    public sealed record DrainResult(IReadOnlyList<PendingDeposit> Deposits, int Failed);

    /// <summary>Number of queued deposits (line count) - readable while locked, without the private key.</summary>
    public int Count { get { lock (_gate) return CountLocked(); } }

    private int CountLocked() =>
        File.Exists(_path) ? File.ReadAllLines(_path).Count(l => !string.IsNullOrWhiteSpace(l)) : 0;

    /// <summary>Encrypt <paramref name="deposit"/> to the deposit public key and append it. Locked-safe (public key
    /// only). Returns false (appending nothing) if the queue is already at <see cref="MaxQueued"/> - the caller should
    /// treat a full queue as an abuse/flood signal and alert, not retry.</summary>
    public bool Enqueue(byte[] publicSpki, PendingDeposit deposit)
    {
        var line = JsonSerializer.Serialize(DepositCrypto.Encrypt(publicSpki, JsonSerializer.Serialize(deposit)));
        lock (_gate)
        {
            if (CountLocked() >= MaxQueued) return false;
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.AppendAllText(_path, line + Environment.NewLine);
            return true;
        }
    }

    /// <summary>Decrypt every queued deposit with the vault's private key (unlock-time). Per-line RESILIENT: a line that
    /// fails to parse / decrypt / authenticate is COUNTED (<see cref="DrainResult.Failed"/>) and skipped, never throwing
    /// away the good deposits in the same file - a single junk line must not DoS the operator's real pending credentials.
    /// Bad lines are left in place (Clear is a separate, post-review step) for forensics.</summary>
    public DrainResult Drain(byte[] privatePkcs8)
    {
        lock (_gate)
        {
            if (!File.Exists(_path)) return new DrainResult([], 0);
            var deposits = new List<PendingDeposit>();
            var failed = 0;
            foreach (var line in File.ReadAllLines(_path))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var env = JsonSerializer.Deserialize<DepositCrypto.Envelope>(line)
                              ?? throw new FormatException("corrupt deposit queue line");
                    var json = DepositCrypto.Decrypt(privatePkcs8, env);   // throws on wrong key / tamper
                    deposits.Add(JsonSerializer.Deserialize<PendingDeposit>(json)
                                 ?? throw new FormatException("corrupt deposit record"));
                }
                catch (Exception ex) when (ex is CryptographicException or FormatException or JsonException or ArgumentException or NotSupportedException)
                {
                    failed++;   // suspect line: surfaced via the count, never poisons the readable deposits
                }
            }
            return new DrainResult(deposits, failed);
        }
    }

    /// <summary>Remove the queue file (only AFTER the operator has reviewed + committed/rejected the drained deposits).</summary>
    public void Clear()
    {
        lock (_gate) { if (File.Exists(_path)) File.Delete(_path); }
    }
}
