# Foreman Release Checklist

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
- Verify MCP inventory treats Foreman's own `foreman` loopback server as informational.
- Capture fresh screenshots for README/release notes.
- Attach SHA-256 checksums to the release.
- State clearly whether the installer is signed or unsigned.

## Recommended

- Test installer upgrade over a previous version.
- Test run-at-login on/off.
- Test `RunElevated` sidecar opt-in and opt-out.
- Test `ScanMcpTools` with a harmless HTTP MCP server.
- Confirm all screenshots avoid exposing user paths, tokens, project names, or private terminal output.
- Confirm release notes mention `.NET 10 preview` until the target moves to a stable SDK.
- Review SECURITY.md and README.md for claims that drifted since the last release.

## Current Alpha Gates

- Real app screenshots are still needed before broader announcement.
- OpenCode and T3 Code profiles are included but need field verification.
- LLM triage preferences are configurable in JSON; a full UI editor is still roadmap.
