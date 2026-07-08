# Foreman LiveWeave — browser extension

A Manifest V3 extension that links your browser to the **local** Foreman desktop app over loopback and renders
Foreman-brokered page edits into `liveweave.html`, a local, **extension-owned** canvas. It does **not** drive
arbitrary tabs and never touches the network: it talks only to `http://127.0.0.1:54321`.

> Split out from the **Foreman Agent Safety** extension so the page-builder feature lives on its own, with its
> own pairing/token, separate from the safety watchdog (which now hosts mediated **browser use**).

## What it does

- **Pairing** (one-time): proves it holds Foreman's on-screen code via a challenge/response (HMAC; the code never
  crosses the wire), then stores the scoped bearer token and gets its origin allow-listed. It pairs as the
  `liveweave` harness.
- **LiveWeave canvas**: polls Foreman's `liveweave_*` broker (`liveweave_poll_commands` /
  `liveweave_complete_command`) and applies builder actions (`apply_page`, `apply_section`, `apply_inner`,
  `set_style`, `set_background`, `new_canvas`, `generate`, `template`, `undo`, `scan`, `outline`,
  `start_builder`, `stop_builder`) into a local extension page. A selected driver harness is required before
  non-operator agents can enqueue commands; an empty driver means operator-token only, and `any` is the explicit
  all-harness mode. Commands that change the canvas bring the canvas tab forward so the operator can see the result.

## Load it

1. Build/run Foreman (the desktop app) so its MCP server is listening on `127.0.0.1:54321`.
2. Chrome → `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select this `extension-liveweave/` folder.
3. In Foreman, open **Connect agent → Pair browser extension** — it shows a code like `ABCDE-FGHJK`.
4. Click the extension's **Details → Extension options**, optionally set the driver harness, type the code, hit **Pair**.
5. Open the side panel (click the toolbar icon) → **Open canvas**. Foreman-brokered edits render live.

## Security model

- `host_permissions` are loopback-only (`127.0.0.1`, `localhost`) — the service worker can reach the local server
  without CORS, and can reach nothing else.
- The pairing code is the auth root; it's never sent — only `HMAC(code, nonce)` is. Foreman validates the request
  **Host** is loopback (DNS-rebinding defence) and the **Origin** is this paired extension.
- The canvas is an `<iframe sandbox="allow-scripts allow-forms">` of stored HTML/CSS — Foreman-brokered content,
  never live third-party pages.

## Files

| File | Role |
|---|---|
| `manifest.json` | MV3 manifest (loopback host_permissions, side panel, options) |
| `mcp-client.js` | streamable-HTTP MCP client (`initialize` → `notifications/initialized` → `tools/call`) |
| `background.js` | service worker: pairing, health poll, MCP session, `liveweave_*` poll/execute, canvas, side-panel port |
| `liveweave.html` / `liveweave.js` | local LiveWeave canvas for Foreman-brokered page edits |
| `settings.js` | `chrome.storage.local` helpers (defaults to the `liveweave` harness) |
| `options.html` / `options.js` | enter the pairing code + driver harness |
| `sidepanel.html` / `sidepanel.js` | connection status + open-canvas |
