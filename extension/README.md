# Foreman Agent Safety — browser extension (scaffold)

A Manifest V3 extension that links your browser to the **local** Foreman desktop app over loopback — the
closed-loop, on-device design in [`../docs/closed-loop-spec.md`](../docs/closed-loop-spec.md). Nothing it does
ever touches the network: it talks only to `http://127.0.0.1:54321`.

> **Status: scaffold.** The pairing handshake and `/health` liveness are complete; the MCP `tools/call`
> (foreman_status) path is best-effort and needs in-Chrome verification (the streamable-HTTP initialize/session
> handshake is the likely spot to adjust). Built to be loaded unpacked and iterated.

## What it does

- **Pairing** (one-time): proves it holds Foreman's on-screen code via a challenge/response (HMAC; the code
  never crosses the wire), then stores the scoped bearer token Foreman issues and gets its origin allow-listed.
- **Connected**: polls `/health`, shows a **`🔒 On-device · verified`** badge in the side panel, and (once the
  MCP path is verified) Foreman's status/alerts.

## Load it

1. Build/run Foreman (the desktop app) so its MCP server is listening on `127.0.0.1:54321`.
2. Chrome → `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select this `extension/` folder.
3. In Foreman, open **Pair browser extension** — it shows a code like `ABCDE-FGHJK`.
4. Click the extension's **Details → Extension options**, type the code, hit **Pair**.
5. Open the side panel (click the toolbar icon). It should read **🔒 On-device · verified**.

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
| `background.js` | service worker: pairing, health poll, MCP call, side-panel port |
| `settings.js` | `chrome.storage.local` helpers |
| `options.html` / `options.js` | enter the pairing code |
| `sidepanel.html` / `sidepanel.js` | status + the verified badge |

## TODO (next iterations)

- Verify/finish the MCP streamable-HTTP client (`initialize` → `tools/call`).
- Wire the Foreman-side **Pair browser extension** GUI action (`BeginExtensionPairing()` is exposed).
- Add the on-device Gemini Nano tiered-inference path (modalities) + the publicly-attested release verification.
- Icons.
