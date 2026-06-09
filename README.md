<p align="center">
  <img src="docs/assets/foreman-social-preview.png" alt="Foreman - safety oversight for AI coding agents">
</p>

<h1 align="center">Foreman</h1>

<p align="center">
  A Windows safety monitor for AI coding agents: watch for unwanted behaviour, inspect risky actions and route one AI to audit another.
</p>

<p align="center">
  <strong>Built to keep agent work visible, accountable and reviewable before it burns tokens, CPU and power.</strong>
</p>

[![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)

> Status: alpha. Built on a .NET 10 preview SDK. Windows 10/11 x64 only. See [Project status & roadmap](#project-status--roadmap) before you rely on it.

<!-- screenshots: tray menu, dashboard, alert window -->

## Why

AI coding agents can act quickly across shells, files, credentials and networked tools. Most of the time that is useful. Sometimes it is surprising, unsafe or simply not what you asked for. Foreman exists so a human operator can keep an eye on that behaviour without reading every terminal line.

Foreman is a safety monitor, not a sandbox or policy enforcer. It runs at medium integrity (no admin, no UAC), sits in the tray and raises explainable alerts when an agent does something worth reviewing. Its MCP bridge also lets one harness or API act as the auditor for another, so you can use a second AI to triage the first AI's actions.

It can also save real money. Every runaway loop caught early is fewer wasted tokens, PC resources and lower power bills.

## What it does

- Watches process trees so spawned commands, hung children and orphaned processes remain visible.
- Flags shell commands by category — destructive/deletion commands, network-borne code execution, privilege escalation, credential-access tooling and Windows-specific defense-evasion or persistence.
- Tracks per-agent behavior across a session and **escalates** through four levels (Watch → Alert → Alarm → Emergency) as alerts accumulate.
- Classifies known agents automatically (Claude Code, Codex, and others) from process name and command line; you can register custom executable names.
- Exposes an **MCP server** an agent can call to check its own status, pre-flight a command, see whether Foreman has raised an alarm about it and announce task boundaries.
- **Ask Harness** — prompts the *offending* agent itself to justify and/or act on an alert (any type, including hangs and other mess). When that agent is connected to Foreman's MCP it's delivered to its own session — a sampling round-trip if the client supports it, otherwise a notification — and falls back to a clipboard prompt scoped to that agent.
- **Send for Audit** — routes *alarming* behavior (flagged commands, permission violations, Alarm-level escalations) to a *different* agent or API from your preference list for an independent second opinion. Shown only for alerts that qualify; hangs/mess never route to a peer auditor.
- Keeps a searchable, exportable event log and an at-a-glance dashboard, with tray notifications for critical alerts.

## Product standards

Foreman is safety tooling, but it should not feel hostile or ugly. The target experience is a quiet tray app people want to keep running: clear status at a glance, explainable alerts, fast detail views and enough visual care that contributors and users can trust the project is maintained deliberately.



## Supported agents

Auto-classified by process name and command line:

| ID | Agent | Vendor |
| --- | --- | --- |
| `claude-code` | Claude Code | Anthropic |
| `codex` | Codex CLI | OpenAI |
| `t3-code` | T3 Code | T3 Tools |
| `opencode` | OpenCode | Anomaly |
| `gemini-cli` | Gemini CLI | Google |
| `amazon-q` | Amazon Q Developer | Amazon / AWS |
| `aider` | Aider | Paul Gauthier |
| `github-copilot` | GitHub Copilot CLI | GitHub / Microsoft |
| `cursor` | Cursor | Anysphere |
| `cline` | Cline / Continue / Roo | Community |

Anything else can be added as a custom harness executable name in settings.

## How it works

Four moving parts, kept deliberately separate.

**Tray app.** A WPF tray icon (green / amber / red) is the main operator surface. Left-click opens the Dashboard (session metrics, per-agent status chips and a recent-alert feed). Double-click opens the Event Log (filter, search, export). The right-click menu also reaches Process Monitor, Harnesses, Behavior Metrics, Settings and a "Send test alert" action. A critical alert raises a tray notification; clicking it opens an Alert window that explains why the action is risky and what to do.

**Heuristic engine.** Around 30 compiled-regex rules across five categories, loaded from JSON. Each rule carries an id, name, severity (info / low / medium / high / critical), description, target platforms, and false-positive tags. A false-positive filter suppresses Foreman's own process and known-safe contexts. The rule sources live in [`data/patterns/`](data/patterns/) and are embedded into `Foreman.Core` at build time — read those files if you want the exact coverage; they are the source of truth, not this README.

**Process monitoring.** A WMI watcher subscribes to process create/terminate events. A process-tree tracker maps harness children, an I/O poller samples counters (`GetProcessIoCounters`) to tell "working" from "stuck" and hang/orphan detectors raise events when a child goes silent or loses its parent.

**Behavior escalation.** Each agent session accumulates a profile. Configurable thresholds — medium- and high-alert counts, unique rules fired, distinct categories touched, total alerts, and a set of high-risk rule IDs — drive escalation across four levels:

| Level | Roughly triggered by | Action |
| --- | --- | --- |
| Watch | default | logged only |
| Alert | a high-severity alert, several medium alerts, or multiple categories | tray turns red, notification |
| Alarm | a critical alert, enough unique rules or categories | notification + MCP push to the connected agent |
| Emergency | an emergency-tier rule, or too many alerts across the major categories at once | alarm window auto-opens with Kill / Disable actions |

**MCP supply-chain watch.** Foreman reads the MCP servers your agents are configured to use (e.g. Claude Code's `.claude.json`, global and per-project) and raises a medium alert when a new or changed-target server appears — a "who added this MCP server?" check. This is on by default and costs nothing: config-file reads only, no network, no elevation. Optionally (Settings → *Scan MCP tools*, off by default) Foreman can go further and connect to the HTTP/SSE servers, enumerate their tools, and flag tool names or descriptions that read like prompt injection or data exfil — a tool description is fed to the model verbatim, so it is a real injection vector. The opt-in scan is the only feature that makes outbound connections to third-party servers; stdio servers are never launched. See [`docs/oversight-model.md`](docs/oversight-model.md) for the full response model (Ask Harness vs. Send for Audit) and the supply-chain tiers.

**MCP bridge.** An embedded ASP.NET Core Kestrel host runs an MCP server (ModelContextProtocol SDK) over HTTP+SSE at `http://localhost:54321/mcp`, plus a `/health` endpoint. The tools exposed to an agent:

| Tool | What it does |
| --- | --- |
| `ForemanStatus` | overall health summary (green/amber/red, active alerts, process count, uptime) |
| `ListMonitoredProcesses` | the agent processes Foreman is tracking |
| `QueryProcessDetail` | details for one PID |
| `ReportSuspiciousCommand` | pre-flight a command line; returns allow / allow_once / escalate / block |
| `ListRecentEvents` | recent events, optionally filtered by minimum severity |
| `AcknowledgeAlert` | acknowledge an alert and suppress further notifications for it |
| `GetBehaviorMetrics` | escalation level and counts for every monitored agent |
| `ResetBehaviorMetrics` | reset one agent's escalation back to Watch (e.g. starting an unrelated task) |
| `ReportTaskStart` | announce a new task so operators can correlate task boundaries with alerts |
| `GetMyPermissions` | the permission profile resolved from `harnessId`, `processId`, or `profileName` |
| `GetIntegrationInstructions` | generated MCP setup instructions for a supported harness |
| `ValidateHarnessIntegration` | checks whether a harness profile, process tree, and MCP sessions are visible |
| `ListAuditPreferences` | user-configured LLM auditor preference list |
| `GetAuditRoute` | selects the preferred non-self auditor harness or API for cross-agent triage |
| `ListMcpServers` | the MCP servers Foreman discovered across your harness configs (name, transport, target, scope) |
| `ListMcpToolFindings` | latest opt-in MCP tool-description injection scan results (off unless enabled in Settings) |

## Install

### From Releases (recommended)

Download the installer from [GitHub Releases](https://github.com/aXL333/Foreman/releases). It installs per-user to `%LocalAppData%\Foreman` with no admin prompt, and offers an optional run-at-login entry. The released build is a self-contained single-file exe, so no separate .NET runtime is required.

### From source

Prerequisites:

- Windows 10/11 x64
- .NET 10 SDK (preview — the project currently tracks a preview build)

```
dotnet build Foreman.slnx -c Release
dotnet test  Foreman.slnx -c Release
```

The solution uses the newer `.slnx` (XML) format. To run the tray app from a source build:

```
dotnet run --project src/Foreman.App
```

To produce the same kind of single-file exe the release workflow ships:

```
dotnet publish src/Foreman.App/Foreman.App.csproj ^
  -c Release -r win-x64 --self-contained true ^
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```

## Connect your agent

Foreman's MCP server listens on `http://localhost:54321/mcp` while the tray app is running. The `/mcp` endpoint requires a per-install **bearer token** (the `/health` endpoint stays open). Your token is generated on first run and stored, owner-only, at `%LocalAppData%\Foreman\mcp.token`.

**Easiest — in the app:** on first run, or any time via the tray menu → **Connect agent…** (also a button on the Dashboard), Foreman opens a short guide. For Claude Code it's one click — Foreman adds the user-scope `foreman` entry to your `~/.claude.json` (token and all, with a backup). For any other MCP client it shows a copy-paste config with the URL + token. Restart the agent afterwards. The rest of this section is the manual equivalent.

The simplest manual way to connect Claude Code (user scope, so every project picks it up):

```bash
claude mcp add --transport http foreman http://localhost:54321/mcp \
  --header "Authorization: Bearer <paste-token-from-mcp.token>" \
  --scope user
```

Or add it to your MCP config (`~/.claude.json` or a project `.mcp.json`) directly:

```json
{
  "mcpServers": {
    "foreman": {
      "type": "http",
      "url": "http://localhost:54321/mcp",
      "headers": { "Authorization": "Bearer <paste-token-from-mcp.token>" }
    }
  }
}
```

Without the token the connection is refused with `401` and Foreman shows **no session** for that agent (so Ask Harness falls back to the clipboard). Any MCP client that speaks streamable HTTP can connect the same way; confirm the server is up with `GET http://localhost:54321/health`.

## Configuration

Settings are stored at `%LocalAppData%\Foreman\settings.json` and editable from the tray Settings window. The knobs that matter most:

| Setting | Default | Purpose |
| --- | --- | --- |
| `McpPort` | `54321` | MCP / health server port |
| `HangThresholdMinutes` | `10` | silence before a child is treated as hung |
| `HookJamThresholdMinutes` | `5` | silence before a hook is treated as jammed |
| `IoPollerIntervalSeconds` | `30` | how often I/O counters are sampled |
| `MonitorAllProcesses` | `false` | `false` = harness children only |
| `CustomHarnessExes` | `[]` | extra executable names to treat as agents |
| `DisabledHarnesses` | `[]` | agents to detect but not alert on |
| `RunElevated` | `false` | opt-in: launch the elevated ETW sidecar for the per-process Network column |
| `ScanMcpTools` | `false` | opt-in: connect to HTTP/SSE MCP servers and scan tool descriptions for injection |
| `LlmTriage` | enabled | auditor preference routing for one harness/API to review another |

Per-session escalation thresholds (medium-alert count, high-alert count, unique-rule count, category count, total-alert count, and the set of emergency-tier rule IDs) live in the same file. So does the LLM triage preference list: each auditor entry can target specific harness IDs, require a minimum severity, and point either to another running harness or to an API endpoint. The built-in audit routes let Claude Code, Codex and OpenCode review each other, and let those agents review T3 Code as a control plane. Defaults are in [`src/Foreman.Core/Settings/ForemanSettings.cs`](src/Foreman.Core/Settings/ForemanSettings.cs).

## Project status & roadmap

Honest accounting. This is alpha software on a preview runtime. At the time of this writing only Claude and Codex desktop have been tested.

Built and working:

- Tray app with dashboard, event log, process monitor, harnesses, behavior-metrics, and settings windows
- Heuristic engine and the five-category pattern library
- WMI process monitoring with hang and orphan detection
- Permission profiles and behavior escalation
- MCP server and the tool set above
- CI build/test and a release workflow that publishes the single-file exe wrapped in an Inno Setup installer

Roadmap (not done yet — don't rely on these):

- An elevated ETW sidecar for pre-execution command capture
- True server-initiated SSE push (the dispatcher is wired, full proactive push is not complete)
- Native Windows toast notifications (currently tray balloons)
- A settings / profile editor UI and a first-run wizard
- Per-caller identification over MCP session metadata (`GetMyPermissions` currently returns a default profile)

## Contributing

Contributions are welcome under the project's license. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and conventions. Security reports go to xredux@protonmail.com — please don't open a public issue for a vulnerability.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE). Contributions are accepted under the same license.

## Support

Foreman is free and GPL. If it helped you keep agent work safer, saved tokens or trimmed a power bill and you want to chip in, there's a Ko-fi: <https://ko-fi.com/aXL333>
