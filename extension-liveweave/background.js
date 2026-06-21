/**
 * Foreman LiveWeave — extension service worker.
 *
 * Bridges the browser to the LOCAL Foreman desktop app over loopback HTTP (never the network). Pairs as the
 * `liveweave` harness (closed-loop challenge/response; the code never crosses the wire), then polls Foreman's
 * `liveweave_*` broker and renders Foreman-brokered edits into `liveweave.html` — a local, extension-owned
 * canvas. It does NOT drive arbitrary tabs.
 *
 * Split out from the Foreman Agent Safety extension so the page-builder feature lives on its own, with its own
 * pairing/token, separate from the safety watchdog arm.
 */
import { loadSettings, saveSettings, onSettingsChanged } from './settings.js';
import { callMcpTool, openMcpSession } from './mcp-client.js';

let cfg = { host: '127.0.0.1', port: 54321, token: '', pairedOrigin: '', harnessId: 'liveweave', liveweaveDriver: '' };
let connected = false;
let lastMcpError = null;
let sidePanelPort = null;
let pollTimer = null;
let mcpSession = null;
const POLL_MS = 5000;

const base = () => `http://${cfg.host}:${cfg.port}`;
const selfOrigin = () => `chrome-extension://${chrome.runtime.id}`;

// ── Pairing ────────────────────────────────────────────────────────────────

async function hmacHex(key, message) {
    const enc = new TextEncoder();
    const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', k, enc.encode(message));
    return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

async function pair(code, liveweaveDriver = cfg.liveweaveDriver) {
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
            body: JSON.stringify({ response, origin: selfOrigin(), harnessId: 'liveweave' }),
        });
        const body = await done.json().catch(() => ({}));
        if (!done.ok || !body.ok) return { ok: false, error: body.reason || `Pairing failed (${done.status}).` };

        cfg = { ...cfg, token: body.token || '', pairedOrigin: body.origin || selfOrigin(), harnessId: 'liveweave', liveweaveDriver: liveweaveDriver || '' };
        await saveSettings({ token: cfg.token, pairedOrigin: cfg.pairedOrigin, harnessId: 'liveweave', liveweaveDriver: cfg.liveweaveDriver });
        mcpSession = null;
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

async function ensureMcpSession() {
    if (!cfg.token) return null;
    if (mcpSession) return mcpSession;
    mcpSession = await openMcpSession(base(), cfg.token);
    return mcpSession;
}

// Single place that opens (or reuses) the MCP session and calls a tool. On any failure it drops the cached
// session so the next call reopens — Foreman uses short-lived per-request sessions, so a stale id is expected.
async function mcpCall(name, args = {}) {
    if (!cfg.token) return null;
    try {
        const session = await ensureMcpSession();
        return await callMcpTool(session, name, args);
    } catch (e) {
        mcpSession = null;
        lastMcpError = String(e?.message || e);
        return null;
    }
}

// ── LiveWeave canvas ───────────────────────────────────────────────────────

const DEFAULT_CANVAS = {
    title: 'LiveWeave Canvas',
    html: '<main style="font-family: system-ui, sans-serif; padding: 32px;"><h1>LiveWeave Canvas</h1><p>Ready for Foreman-brokered edits.</p></main>',
    css: '',
    updatedAt: '',
};

async function readCanvas() {
    const s = await chrome.storage.local.get({ liveweaveCanvas: DEFAULT_CANVAS, liveweaveHistory: [] });
    return {
        canvas: { ...DEFAULT_CANVAS, ...(s.liveweaveCanvas || {}) },
        history: Array.isArray(s.liveweaveHistory) ? s.liveweaveHistory : [],
    };
}

async function saveCanvas(canvas, pushHistory = true) {
    const prior = await readCanvas();
    const next = { ...DEFAULT_CANVAS, ...canvas, updatedAt: new Date().toISOString() };
    const patch = { liveweaveCanvas: next };
    if (pushHistory) patch.liveweaveHistory = [...prior.history.slice(-9), prior.canvas];
    await chrome.storage.local.set(patch);
    await openLiveWeaveCanvas();
    return next;
}

async function openLiveWeaveCanvas() {
    const url = chrome.runtime.getURL('liveweave.html');
    const tabs = await chrome.tabs.query({ url });
    if (tabs[0]?.id != null) return;
    await chrome.tabs.create({ url, active: false });
}

function textParam(params, name, fallback = '') {
    const v = params?.[name];
    return v == null ? fallback : String(v);
}

async function executeLiveWeaveCommand(cmd) {
    const action = String(cmd.action || '').toLowerCase();
    const params = cmd.parameters || {};
    const { canvas, history } = await readCanvas();

    switch (action) {
        case 'new_canvas':
            return { ok: true, canvas: await saveCanvas({ ...DEFAULT_CANVAS, title: textParam(params, 'title', 'LiveWeave Canvas') }) };

        case 'apply_page':
            return {
                ok: true,
                canvas: await saveCanvas({
                    title: textParam(params, 'title', canvas.title),
                    html: textParam(params, 'html', canvas.html),
                    css: textParam(params, 'css', canvas.css),
                }),
            };

        case 'apply_section': {
            const html = textParam(params, 'html');
            const css = textParam(params, 'css');
            const placement = textParam(params, 'placement', 'append').toLowerCase();
            const nextHtml = placement === 'prepend' ? `${html}\n${canvas.html}` : `${canvas.html}\n${html}`;
            return { ok: true, canvas: await saveCanvas({ ...canvas, html: nextHtml, css: `${canvas.css || ''}\n${css}` }) };
        }

        case 'apply_inner': {
            const html = textParam(params, 'html');
            const path = textParam(params, 'path', 'body');
            const marker = `\n<!-- liveweave:${path} -->\n${html}`;
            return { ok: true, canvas: await saveCanvas({ ...canvas, html: `${canvas.html}${marker}`, css: `${canvas.css || ''}\n${textParam(params, 'css')}` }) };
        }

        case 'set_style': {
            const path = textParam(params, 'path', 'body');
            const styles = textParam(params, 'styles');
            return { ok: true, canvas: await saveCanvas({ ...canvas, css: `${canvas.css || ''}\n${path}{${styles}}` }) };
        }

        case 'set_background': {
            const value = textParam(params, 'value', textParam(params, 'background', '#ffffff'));
            return { ok: true, canvas: await saveCanvas({ ...canvas, css: `${canvas.css || ''}\nbody{background:${value};}` }) };
        }

        case 'undo': {
            if (history.length === 0) return { ok: false, error: 'Nothing to undo.' };
            const previous = history[history.length - 1];
            await chrome.storage.local.set({ liveweaveCanvas: previous, liveweaveHistory: history.slice(0, -1) });
            await openLiveWeaveCanvas();
            return { ok: true, canvas: previous };
        }

        case 'scan':
        case 'outline':
            return {
                ok: true,
                title: canvas.title,
                html: canvas.html,
                css: canvas.css,
                htmlLength: canvas.html.length,
                cssLength: canvas.css.length,
            };

        default:
            return { ok: false, error: `Unsupported LiveWeave action '${action}'. Supported: new_canvas, apply_page, apply_section, apply_inner, set_style, set_background, undo, scan, outline.` };
    }
}

async function liveweaveTabInfo() {
    const { canvas } = await readCanvas();
    return {
        url: chrome.runtime.getURL('liveweave.html'),
        title: canvas.title || 'LiveWeave Canvas',
        kind: 'extension-canvas',
        editable: true,
    };
}

async function pollLiveWeave() {
    if (!cfg.token || !connected) return;
    const tabInfoJson = JSON.stringify(await liveweaveTabInfo());
    const batch = await mcpCall('liveweave_poll_commands', {
        limit: 5,
        tabInfoJson,
        nanoStatus: 'unavailable',
        driverHarness: cfg.liveweaveDriver || '',
    });
    const commands = Array.isArray(batch?.commands) ? batch.commands : [];
    for (const cmd of commands) {
        let result;
        try {
            result = await executeLiveWeaveCommand(cmd);
        } catch (e) {
            result = { ok: false, error: String(e?.message || e) };
        }
        await mcpCall('liveweave_complete_command', {
            commandId: cmd.commandId,
            ok: !!result.ok,
            resultJson: result.ok ? JSON.stringify(result) : null,
            error: result.ok ? null : (result.error || 'LiveWeave command failed.'),
        });
    }
}

async function refresh() {
    connected = await checkHealth();
    lastMcpError = null;
    await pollLiveWeave();
    broadcast();
}

function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(refresh, POLL_MS);
    refresh();
}

// ── Side panel plumbing ──────────────────────────────────────────────────────

chrome.runtime.onConnect.addListener((port) => {
    if (port.name !== 'foreman-liveweave-sidepanel') return;
    sidePanelPort = port;
    broadcast();                 // show last-known state immediately…
    refresh();                   // …then pull fresh state (the SW may have been suspended)
    port.onMessage.addListener(async (msg) => {
        if (msg?.kind === 'pair') {
            const r = await pair(msg.code, msg.liveweaveDriver);
            safePost({ kind: 'pair-result', ...r });
        } else if (msg?.kind === 'refresh') {
            mcpSession = null;
            await refresh();
        } else if (msg?.kind === 'open-canvas') {
            await openLiveWeaveCanvas();
        }
    });
    port.onDisconnect.addListener(() => { if (sidePanelPort === port) sidePanelPort = null; });
});

function broadcast() {
    safePost({
        kind: 'status',
        connected,
        paired: !!cfg.token,
        base: base(),
        liveweaveDriver: cfg.liveweaveDriver || '',
        mcpError: lastMcpError,
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

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.kind === 'pair') { pair(msg.code, msg.liveweaveDriver).then(sendResponse); return true; }
    return false;
});

// ── Boot ─────────────────────────────────────────────────────────────────────

async function bootstrap() {
    try { cfg = { ...cfg, ...(await loadSettings()) }; } catch { /* defaults */ }
    startPolling();
}
onSettingsChanged(async () => {
    try {
        cfg = { ...cfg, ...(await loadSettings()) };
        mcpSession = null;
    } catch { /* keep */ }
});
chrome.runtime.onStartup.addListener(bootstrap);
chrome.runtime.onInstalled.addListener(bootstrap);
bootstrap();
