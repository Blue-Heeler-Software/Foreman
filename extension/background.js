/**
 * Foreman Agent Safety — extension service worker.
 *
 * Bridges the browser to the LOCAL Foreman desktop app over loopback HTTP (never the network). Two phases:
 *   1. Pairing (one-time): the user clicks "Pair browser extension" in Foreman → Foreman shows a short code →
 *      the user types it on the options page → we prove we hold it via a challenge/response (the code never
 *      crosses the wire) → Foreman allow-lists our origin and hands back a scoped bearer token.
 *   2. Connected: we poll /health for liveness and call the MCP endpoint (with the token) for status/alerts,
 *      and feed the side panel.
 *
 * The extension has host_permissions for 127.0.0.1/localhost, so the service worker can fetch the loopback
 * server cross-origin without CORS. Nothing here ever talks to a remote host.
 */
import { loadSettings, saveSettings, onSettingsChanged } from './settings.js';

let cfg = { host: '127.0.0.1', port: 54321, token: '', pairedOrigin: '' };
let connected = false;
let lastStatus = null;          // last foreman_status payload (or null)
let sidePanelPort = null;
let pollTimer = null;
const POLL_MS = 5000;

const base = () => `http://${cfg.host}:${cfg.port}`;
const selfOrigin = () => `chrome-extension://${chrome.runtime.id}`;

// ── Pairing ────────────────────────────────────────────────────────────────

// HMAC-SHA256(code, challenge) as UPPERCASE hex — must match Foreman's
// ChallengeResponse.Respond (Convert.ToHexString of HMACSHA256.HashData(UTF8(key), UTF8(challenge))).
async function hmacHex(key, message) {
    const enc = new TextEncoder();
    const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', k, enc.encode(message));
    return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

async function pair(code) {
    const clean = (code || '').trim().toUpperCase();
    if (!clean) return { ok: false, error: 'Enter the code shown in Foreman.' };
    try {
        const cr = await fetch(`${base()}/pair/challenge`);
        if (cr.status === 409) return { ok: false, error: 'No pairing window is open. Click "Pair browser extension" in Foreman first.' };
        if (!cr.ok) return { ok: false, error: `Foreman returned ${cr.status} for the challenge.` };
        const { challenge } = await cr.json();

        const response = await hmacHex(clean, challenge);
        const done = await fetch(`${base()}/pair/complete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ response, origin: selfOrigin() }),
        });
        const body = await done.json().catch(() => ({}));
        if (!done.ok || !body.ok) return { ok: false, error: body.reason || `Pairing failed (${done.status}).` };

        cfg = { ...cfg, token: body.token || '', pairedOrigin: body.origin || selfOrigin() };
        await saveSettings({ token: cfg.token, pairedOrigin: cfg.pairedOrigin });
        await refresh();
        return { ok: true };
    } catch (e) {
        return { ok: false, error: `Could not reach Foreman at ${base()} — is it running? (${e})` };
    }
}

// ── Connection / status ──────────────────────────────────────────────────────

async function checkHealth() {
    try {
        const r = await fetch(`${base()}/health`);
        return r.ok;
    } catch { return false; }
}

// Minimal MCP-over-HTTP call (streamable HTTP). The token proves we're the paired extension.
// NOTE: the MCP initialize/session handshake is the part most likely to need tweaking in-browser —
// verify against the running server. Falls back gracefully: if this fails we still show liveness from /health.
async function mcpStatus() {
    if (!cfg.token) return null;
    try {
        const headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
            'Authorization': `Bearer ${cfg.token}`,
        };
        const init = await fetch(`${base()}/mcp`, {
            method: 'POST',
            headers,
            body: JSON.stringify({
                jsonrpc: '2.0', id: 1, method: 'initialize',
                params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'foreman-extension', version: '0.1.0' } },
            }),
        });
        const sessionId = init.headers.get('Mcp-Session-Id');
        if (!sessionId) return null;   // handshake shape differs — leave for in-Chrome verification
        if (sessionId) headers['Mcp-Session-Id'] = sessionId;

        const res = await fetch(`${base()}/mcp`, {
            method: 'POST', headers,
            body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'foreman_status', arguments: {} } }),
        });
        const text = await res.text();
        // streamable HTTP may wrap the result in SSE ("data: {...}"); pull the last JSON object out.
        const jsonLine = text.split('\n').reverse().find((l) => l.trim().startsWith('{') || l.startsWith('data:'));
        if (!jsonLine) return null;
        const parsed = JSON.parse(jsonLine.replace(/^data:\s*/, ''));
        return parsed?.result ?? null;
    } catch {
        return null;
    }
}

async function refresh() {
    connected = await checkHealth();
    lastStatus = connected ? await mcpStatus() : null;
    broadcast();
}

function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(refresh, POLL_MS);
    refresh();
}

// ── Side panel plumbing ──────────────────────────────────────────────────────

chrome.runtime.onConnect.addListener((port) => {
    if (port.name !== 'foreman-sidepanel') return;
    sidePanelPort = port;
    broadcast();
    port.onMessage.addListener(async (msg) => {
        if (msg?.kind === 'pair') {
            const r = await pair(msg.code);
            safePost({ kind: 'pair-result', ...r });
        } else if (msg?.kind === 'refresh') {
            await refresh();
        }
    });
    port.onDisconnect.addListener(() => { if (sidePanelPort === port) sidePanelPort = null; });
});

function broadcast() {
    safePost({
        kind: 'status',
        connected,
        paired: !!cfg.token,
        // The closed-loop assurance: paired + connected over loopback with a token == on-device, verified.
        verified: !!cfg.token && connected,
        base: base(),
        status: lastStatus,
    });
}

function safePost(message) {
    if (!sidePanelPort) return;
    try { sidePanelPort.postMessage(message); }
    catch { sidePanelPort = null; }
    finally { try { void chrome.runtime.lastError; } catch { /* ok */ } }
}

chrome.action.onClicked.addListener(async (tab) => {
    if (tab?.windowId !== undefined) await chrome.sidePanel.open({ windowId: tab.windowId });
});
try { chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }); } catch { /* Chrome < 114 */ }

// Pairing can also be driven from the options page.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.kind === 'pair') { pair(msg.code).then(sendResponse); return true; }
    return false;
});

// ── Boot ─────────────────────────────────────────────────────────────────────

async function bootstrap() {
    try { cfg = { ...cfg, ...(await loadSettings()) }; } catch { /* defaults */ }
    startPolling();
}
onSettingsChanged(async () => { try { cfg = { ...cfg, ...(await loadSettings()) }; } catch { /* keep */ } });
chrome.runtime.onStartup.addListener(bootstrap);
chrome.runtime.onInstalled.addListener(bootstrap);
bootstrap();
