# Foreman Agent Safety Release Checklist

Use this before publishing a public binary release.

## Required

- Run `dotnet test .\Foreman.slnx -c Release --verbosity minimal`.
- Run `dotnet build .\src\Foreman.App\Foreman.App.csproj -c Release`.
- Verify a clean install on a fresh Windows 10/11 x64 VM.
- Verify uninstall removes app files and run-at-login registration.
- Verify first run opens the Connect Agent path and supports Claude Code and Codex.
- Verify `/health` is reachable and `/mcp` rejects missing or wrong bearer tokens.
- Verify a connected Claude Code or Codex session appears in the dashboard.
- Verify Ask Harness delivery for at least one connected client.
- Verify MCP inventory treats Foreman Agent Safety's own `foreman` loopback server as informational.
- Capture fresh screenshots for README/release notes.
- Attach SHA-256 checksums to the release.
- State clearly whether the installer is signed or unsigned (see **Code Signing** below).

## Recommended

- Test installer upgrade over a previous version.
- Test run-at-login on/off.
- Test `RunElevated` sidecar opt-in and opt-out.
- Test `ScanMcpTools` with a harmless HTTP MCP server.
- Confirm all screenshots avoid exposing user paths, tokens, project names, or private terminal output.
- Confirm release notes mention `.NET 10 preview` until the target moves to a stable SDK.
- Review SECURITY.md and README.md for claims that drifted since the last release.

## Code Signing (SignPath Foundation)

Foreman signs via **SignPath Foundation** — free Authenticode (OV) signing for OSS, done in SignPath's
cloud HSM. The release workflow's signing steps are **opt-in**: they run only when the repo variable
`SIGNPATH_ORGANIZATION_ID` is set. Until then, releases build and ship **unsigned** (checksums only) and
nothing in CI breaks. Why OV-via-SignPath and not EV/a purchased cert: see
[docs/audit-2026-06-10.md] notes and the README — in 2026 EV no longer shortcuts SmartScreen, and OV is
the only $0 path that produces a real signature whose reputation transfers across releases.

### One-time setup

1. **Apply to SignPath Foundation** at <https://signpath.io/open-source> (GPL-3.0 qualifies). Link the
   GitHub repo and enable MFA on both SignPath and GitHub. *Note:* SignPath's terms exclude malware/PUP,
   and Foreman's process-monitoring / ETW / config-writing behaviour is exactly what gets tools
   *misclassified*. Be ready to explain the project; if they decline, the fallback is Azure Artifact
   Signing (~$10/mo, US/Canada individuals) — same workflow shape, different action.
2. In SignPath, create the **project** and a **signing policy** (e.g. `release-signing`). **Enable
   timestamping in the policy** — signatures must outlive the (short-lived) cert.
3. Create **two artifact configurations**:
   - **App** (`SIGNPATH_APP_ARTIFACT_CONFIG_SLUG`): input is the uploaded `publish` folder (a zip). Sign
     `Foreman.exe` **and** `sidecar/Foreman.EtwSidecar.exe`; pass everything else through. Both inner PEs
     must be signed before the installer is built around them.
   - **Installer** (`SIGNPATH_INSTALLER_ARTIFACT_CONFIG_SLUG`): input is the single
     `Foreman-Agent-Safety-Setup-*.exe`; sign it.
4. Generate a SignPath **API token**.

### GitHub configuration

Settings → Secrets and variables → Actions:

| Kind | Name | Value |
| --- | --- | --- |
| Secret | `SIGNPATH_API_TOKEN` | the SignPath API token |
| Variable | `SIGNPATH_ORGANIZATION_ID` | SignPath organization id (**this var is the on/off switch**) |
| Variable | `SIGNPATH_PROJECT_SLUG` | SignPath project slug |
| Variable | `SIGNPATH_SIGNING_POLICY_SLUG` | e.g. `release-signing` |
| Variable | `SIGNPATH_APP_ARTIFACT_CONFIG_SLUG` | the App artifact-configuration slug |
| Variable | `SIGNPATH_INSTALLER_ARTIFACT_CONFIG_SLUG` | the Installer artifact-configuration slug |

### How the workflow signs (nested order)

`publish` → **sign app payload** (Foreman.exe + sidecar) → build Inno installer from the signed payload →
**sign installer** → checksums (over the signed installer) → attach to release. Signing only the installer
would leave the inner exes untrusted at runtime, so the order matters. The workflow uses
`signpath/github-action-submit-signing-request@v2`: it `actions/upload-artifact`s each stage, submits the
artifact id to SignPath, and writes the signed result back via `output-artifact-directory`.

### Reality check (set release-note expectations)

Even once signed, early releases still show SmartScreen "unrecognized app" until the cert/file-hash earns
reputation (Microsoft: weeks + hundreds of clean installs). For a niche tool that may never fully accrue —
keep the SHA-256 checksums, walk users through "More info → Run anyway" in the install docs, and **sign
every release with the same identity** so reputation compounds. Do **not** buy EV (no SmartScreen benefit
in 2026; only needed for kernel drivers, which Foreman doesn't ship).

## Current Alpha Gates

- Real app screenshots are still needed before broader announcement.
- OpenCode and T3 Code profiles are included but need field verification.
- LLM triage preferences are configurable in JSON; a full UI editor is still roadmap.
