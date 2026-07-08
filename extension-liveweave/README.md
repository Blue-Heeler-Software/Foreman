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
  `liveweave_complete_command`) and applies builder actions into a local extension page:
  - **Author**: `apply_page` (whole page), `apply_section` (append/prepend a section, optionally into a target
    selector), `apply_inner` (sets a selector's inner HTML via an offscreen DOM — real targeting, idempotent;
    surfaces a `not_found` when the selector matches nothing), `set_style` / `set_background` (upsert one rule per
    selector, so re-styling doesn't grow the sheet), `new_canvas`, `generate` / `template` (a single static
    scaffold — NOT an on-device model), `undo` / `redo`.
  - **Inspect**: `scan` (full source + a structural summary), `outline` (just the concise structure — heading
    tree, ids, duplicate-id warnings, landmark counts).
  - Missing required params return a structured `{ok:false, code, field}`; every successful edit returns
    `htmlLength`/`cssLength` so the driving agent can confirm the change landed.
- **Export**: the canvas header has **Copy** and **Download** to take the built page out as one self-contained
  `.html` file (CSS inlined).
- A selected driver harness is required before non-operator agents can enqueue commands; an empty driver means
  operator-token only, and `any` is the explicit all-harness mode. Editing commands bring the canvas tab forward.

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
- The canvas is a `sandbox="allow-scripts"` iframe of stored HTML/CSS carrying a strict Content-Security-Policy as
  its first `<head>` element: `default-src 'none'` — only `data:` images/fonts and inline styles/scripts, **no
  network of any kind**. So agent-authored content genuinely cannot beacon or POST off-machine — "nothing leaves
  your machine" is *enforced*, not merely asserted. (Residual: an agent script could self-navigate the frame to
  leak its own embedded data; the sandbox still blocks top-navigation, same-origin, forms, and storage. It renders
  Foreman-brokered content, never live third-party pages.)
- Least privilege: no `tabs` permission (the canvas tab is tracked by id); the loopback endpoint defaults to
  `127.0.0.1:54321` and is configurable.

## Files

| File | Role |
|---|---|
| `manifest.json` | MV3 manifest (loopback host_permissions, side panel, options) |
| `mcp-client.js` | streamable-HTTP MCP client (`initialize` → `notifications/initialized` → `tools/call`) |
| `background.js` | service worker: pairing, health poll, MCP session, `liveweave_*` poll/execute, canvas, side-panel port |
| `liveweave.html` / `liveweave.js` | local LiveWeave canvas for Foreman-brokered page edits (+ Copy/Download export) |
| `offscreen.html` / `offscreen.js` | hidden offscreen DOM used for true CSS-selector targeting + structure inspection |
| `settings.js` | `chrome.storage.local` helpers (defaults to the `liveweave` harness) |
| `options.html` / `options.js` | enter the pairing code + driver harness; unpair / forget token |
| `sidepanel.html` / `sidepanel.js` | connection status, open-canvas, operator controls (New/Undo/Redo) + a recent-command log |
