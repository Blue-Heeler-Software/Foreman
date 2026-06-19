# Foreman Agent Safety — browser extension

A Manifest V3 extension that links your browser to the **local** Foreman desktop app over loopback — the
closed-loop, on-device design in [`../docs/closed-loop-spec.md`](../docs/closed-loop-spec.md). Nothing it does
ever touches the network: it talks only to `http://127.0.0.1:54321`.

> **Status: pairing + status + inbox + on-device Nano working** (alpha). Pairing, `/health` liveness,
> `foreman_status`, the Ask-Harness inbox, and on-device Gemini Nano are implemented. Attestation (signed-release
> hash verification at pairing) and icons are the remaining items. Reload the unpacked extension after pulling.

## What it does

- **Pairing** (one-time): proves it holds Foreman's on-screen code via a challenge/response (HMAC; the code
  never crosses the wire), then stores the scoped bearer token Foreman issues and gets its origin allow-listed.
  The token is scoped to the `browser-extension` harness — the extension only ever sees/acts as itself, never a
  sibling harness's data.
- **Status**: polls `/health`, calls `foreman_status` over MCP, shows a **`🔒 On-device · verified`** badge
  (the loopback handshake is verified; code-signing attestation is a later step) and a structured status grid.
- **Ask-Harness inbox**: lists prompts Foreman routed to the browser (`list_ask_harness_requests`, scoped) and
  lets you reply (`reply_to_ask_harness_request`). Empty until orchestration routes work to the browser.
- **On-device AI (Gemini Nano)**: optional, never required. When Chrome's built-in model is present it can draft
  a reply or summarise the status entirely on-device (nothing leaves the machine). Absent/sub-spec browsers show
  `unavailable` and everything else still works (Pillar 1: Nano is the fast lane, not the gate).
- **LiveWeave mode**: pair the same extension as the `liveweave` harness to poll Foreman's `liveweave_*`
  broker tools and render edits into `liveweave.html`, a local extension-owned canvas. It does not drive
  arbitrary tabs. A selected driver harness is required before non-operator agents can enqueue commands;
  an empty driver means operator-token only, and `any` is the explicit all-harness mode.

## Load it

1. Build/run Foreman (the desktop app) so its MCP server is listening on `127.0.0.1:54321`.
2. Chrome → `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select this `extension/` folder.
3. In Foreman, open **Connect agent → Pair browser extension** — it shows a code like `ABCDE-FGHJK`.
4. Click the extension's **Details → Extension options**, type the code, hit **Pair**.
5. Open the side panel (click the toolbar icon). It should read **🔒 On-device · verified** with live alert counts.

## Security model (see the whitepaper)

- `host_permissions` are loopback-only (`127.0.0.1`, `localhost`) — the service worker can reach the local
  server without CORS, and can reach nothing else.
- The pairing code is the auth root; it's never sent — only `HMAC(code, nonce)` is. Foreman's server validates
  the request **Host** is loopback (DNS-rebinding defence) and the **Origin** is this paired extension.
- The bearer token lives in `chrome.storage.local` (extension-scoped). It is a local secret, as safe as the
  profile holding it.

## Files

| File | Role |
|---|---|
| `manifest.json` | MV3 manifest (loopback host_permissions, side panel, options) |
| `mcp-client.js` | streamable-HTTP MCP client (`initialize` → `notifications/initialized` → `tools/call`) |
| `background.js` | service worker: pairing, health poll, MCP session, inbox fetch/reply, side-panel port |
| `liveweave.html` / `liveweave.js` | local LiveWeave canvas for Foreman-brokered page edits |
| `nano.js` | on-device Gemini Nano adapter (availability detection + a constrained `prompt` turn) |
| `settings.js` | `chrome.storage.local` helpers |
| `options.html` / `options.js` | enter the pairing code |
| `sidepanel.html` / `sidepanel.js` | status grid, verified badge, Ask-Harness inbox, on-device summary |

## TODO (next iterations)

- **Attestation** (closed-loop spec step 4): SignPath-sign the extension, publish `version → hash → signature`,
  and have `Foreman.exe` verify the running extension's hash at pairing. Needs SignPath live (#41).
- Icons (toolbar + store).
