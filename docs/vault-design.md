# Foreman Vault — design & threat model

A credential vault + TOTP generator that Foreman makes usable by AI agents during mediated
computer/browser use (CU/BU), **without the agent ever seeing the secret**. Built on the same
audited → confined → held → executed → logged pipeline as the rest of Foreman.

## The keystone invariant: agents reference, never see

An agent never receives a credential — not in an MCP response, not in its context, not in the
cloud-judge payload, not in the audit log. It sends a **reference**:

```
type {{vault:github.com/password}}
type {{vault:github.com/totp}}
```

Foreman resolves the reference to the real value at the **last moment, at the injection boundary**,
and the HUD/log show the reference (`type {{vault:github.com/password}}`), never the secret.

### Where plaintext lives (and for how long)

The vault is unlocked **in the App process only** (one place holds the key). Resolution therefore
happens in the App, *after* the release gate, immediately before the action is dispatched:

- **Desktop CU:** `DesktopCuExecutor` resolves, then sends the resolved input to the sidecar over the
  existing owner-only, HMAC'd pipe. The sidecar types it and never persists it.
- **Browser CU:** the broker/executor resolves, then the value crosses to the paired extension over the
  existing loopback + peer-bound channel; the extension fills the field and never persists it.

Plaintext is transient (resolve → dispatch → drop) and confined to the App + the secure local channel.
The vault **key** never leaves the App. The submitting agent only ever held the reference.

## Storage & keys

- **Format:** KDBX 4 via `KeePassLib.Standard` (GPL-2.0-or-later, compatible with Foreman's
  GPL-3.0-or-later). We do **not** hand-roll the KDBX format. **TOTP:** `Otp.NET` (MIT, RFC-6238).
- **Unlock (composite):** master password (KDBX Argon2id KDF) **+** a high-entropy key-file component
  that Foreman **TPM-seals via the Guardian** and releases only on a **Windows Hello tap**. A stolen
  vault file is useless without the TPM (PC-bound); same-user malware is useless without the master
  password. The derived key lives in memory only while unlocked and is **wiped on panic/lock/exit**.

## Release gate (per resolution)

- `WeakeningAction.ResolveVaultCredential` → presence tap per release, OR bounded auto-release inside an
  operator-armed CU session (mirrors the CU auto-grant).
- **Domain-binding (the phishing defense):** each item is registered to one or more origins. A
  reference resolves only if BOTH the requested origin AND the **live target** are origins the item
  owns. Browser: the live target is the tab origin (strong). Desktop: the bound-window identity +
  operator-confirmed label (weaker — noted). So an injected agent can't make Foreman type your GitHub
  password into `evil.com`, or into a field on a page it controls.
- **ACL:** a harness may resolve only items it is listed on; the operator may resolve any. **All
  mutations (add / import / rotate / reveal) are operator-only** — never harness-accessible.
- Unknown reference → "not found" (never reveals existence). Resolution is **fail-closed and
  all-or-nothing** (never partially substituted). The vault file is ACL-locked + SACL-audited (reuses
  the decoy read-audit path).

## Threat model

| Attack | Defense (Foreman primitive) |
|---|---|
| Agent requests credential for the WRONG target | Domain-binding: live target must match item origin |
| Agent tries to have the secret ECHOED back | Never returned to caller; `SecretRedactor` at every egress |
| Agent reads the vault file directly | File ACL + SACL read-audit (decoy path) + TPM-sealed key |
| Agent triggers mass rotation / exfil | Mutations operator-only + rate-limit + Ask/Audit gate |
| Master-key brute force | Argon2id KDF + TPM binding (key is PC-bound, not just password) |
| Malicious browser import | Operator-only, format-validated, logged with source + timestamp |
| Forged / typo'd `{{vault:...}}` reference | "not found" (no existence oracle) + suspicious-activity log |
| Secret leaks into log / cloud-judge payload | Reference shown not value; redaction at every egress; hash-chain detects tampering |
| Second agent races a release | Per-item lock + version compare-and-swap on inject |

## Module layout

- **`Foreman.Core/Vault/`** (cross-platform, no KeePassLib): `VaultReference` (parse/extract/replace),
  `VaultDomainBinding` (pure origin match), `VaultTotp` (Otp.NET), `IVaultStore`/`IVaultResolver`,
  `VaultResolver` (pure logic over an injected store), models. Plus
  `WeakeningAction.ResolveVaultCredential`.
- **`Foreman.Vault/`** (Windows, P1.2): `KdbxVaultStore : IVaultStore` (KeePassLib + Otp.NET),
  composite-key open, TPM-seal of the key-file component, in-memory wipe.
- **`Foreman.App`** wires the resolver into the executor (the injection hooks — small, surgical,
  done last to avoid colliding with concurrent CU work), the tray UI, panic-wipe, and the seal.

## Phasing

- **P1** — vault core (this), KDBX store + TPM-seal + panic-wipe, resolver + release gate, the two
  injection hooks. Delivers: use stored creds + Foreman 2FA; generate + self-signup.
- **P2** — browser import (Chrome/Edge DPAPI), agent-driven rotate-all, KDBX import/export.

Each phase ends with a threat-model pass + adversarial review, as with the CU layers.
