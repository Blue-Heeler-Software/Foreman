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
let canvasPort = null;       // open while the canvas tab is up — keeps the SW alive for fast, responsive polling
let pollTimer = null;
let polling = false;         // re-entrancy guard: never let two polls execute commands concurrently (storage races)
let needsPair = false;       // set when the token is rejected (401/403) — stop polling a dead token, prompt re-pair
let mcpSession = null;

// MV3 reliability: a service worker is torn down after ~30s idle, which kills setInterval — so agent commands
// would silently stall until something woke the worker. Two mechanisms cover this: a chrome.alarms heartbeat that
// WAKES the worker to poll even when it's suspended (durable, ~30s floor), plus a fast interval that runs while an
// extension page (side panel or canvas) holds a port open and keeps the worker alive (responsive during building).
const FAST_POLL_MS = 3000;
const POLL_ALARM = 'liveweave-poll';
const POLL_ALARM_PERIOD_MIN = 0.5;   // idle heartbeat. Chrome 120+ honours a 30s floor; older clamps sub-1-min to
                                     // 60s. Sub-minute responsiveness comes from FAST_POLL while a page holds a port.

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
        needsPair = false;   // fresh token — resume polling
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
        if (e?.authFailed) needsPair = true;   // revoked/rotated token — stop hammering it, prompt re-pair
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
    // Ensure the canvas exists so the edit is visible, but DON'T steal focus on every brokered micro-edit (a burst
    // of agent commands used to yank the tab forward up to 5x per poll). The canvas re-renders live from storage;
    // explicit user actions (start_builder, side-panel "Open canvas") are the ones that raise it.
    await openLiveWeaveCanvas({ active: false });
    return next;
}

// Track our OWN canvas tab by id (persisted — the service worker is ephemeral) instead of querying tabs by URL.
// chrome.tabs.get/update/create all work without the broad "tabs" permission (which grants read across every tab
// and contradicted this extension's "does not drive arbitrary tabs" scope); querying by URL needed it.
async function openLiveWeaveCanvas({ active = false } = {}) {
    const url = chrome.runtime.getURL('liveweave.html');
    const { liveweaveTabId } = await chrome.storage.local.get({ liveweaveTabId: null });
    if (liveweaveTabId != null) {
        try {
            await chrome.tabs.get(liveweaveTabId);          // rejects if the tab was closed
            if (active) await chrome.tabs.update(liveweaveTabId, { active: true });
            return;
        } catch { /* tab gone — recreate below */ }
    }
    const tab = await chrome.tabs.create({ url, active });
    if (tab?.id != null) await chrome.storage.local.set({ liveweaveTabId: tab.id });
}

// Forget the tracked tab when it's closed, so the next open cleanly recreates instead of racing a stale id.
chrome.tabs.onRemoved.addListener(async (tabId) => {
    const { liveweaveTabId } = await chrome.storage.local.get({ liveweaveTabId: null });
    if (liveweaveTabId === tabId) await chrome.storage.local.remove('liveweaveTabId');
});

function textParam(params, name, fallback = '') {
    const v = params?.[name];
    return v == null ? fallback : String(v);
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function generatedCanvas(params, current) {
    const instruction = textParam(params, 'instruction', textParam(params, 'prompt', ''));
    const title = textParam(params, 'title', instruction.match(/named\s+([^.,]+)/i)?.[1] || current.title || 'LiveWeave Page');
    const theme = escapeHtml(title);
    const detail = escapeHtml(instruction || `A polished landing page for ${title}.`);
    return {
        title,
        html: `<main class="lw-page"><section class="lw-hero"><p class="lw-kicker">Generated locally</p><h1>${theme}</h1><p>${detail}</p><a href="#details">Explore</a></section><section id="details" class="lw-grid"><article><h2>Fresh offer</h2><p>Clear, conversion-focused copy with a focused call to action.</p></article><article><h2>Designed to scan</h2><p>Responsive sections, readable spacing, and simple visual hierarchy.</p></article><article><h2>Ready to refine</h2><p>Use apply_page or apply_section for exact agent-authored markup.</p></article></section></main>`,
        css: `body{margin:0;font-family:Inter,ui-sans-serif,system-ui,sans-serif;background:#fff8f3;color:#24151f}.lw-hero{min-height:70vh;display:grid;align-content:center;gap:18px;padding:clamp(32px,7vw,96px);background:linear-gradient(135deg,#fff8f3,#fde9ef 52%,#d8f7f2)}.lw-kicker{margin:0;color:#9b2354;font-size:12px;font-weight:850;letter-spacing:.12em;text-transform:uppercase}.lw-hero h1{max-width:10ch;margin:0;font-size:clamp(48px,8vw,104px);line-height:.9}.lw-hero p{max-width:760px;margin:0;color:#553847;font-size:clamp(18px,2vw,23px);line-height:1.5}.lw-hero a{display:inline-flex;width:max-content;align-items:center;min-height:48px;padding:0 22px;border-radius:8px;background:#ef3e6f;color:#fff;font-weight:850;text-decoration:none}.lw-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;padding:clamp(32px,6vw,80px)}.lw-grid article{padding:22px;border-radius:8px;background:#fff;box-shadow:0 18px 40px rgb(83 44 61 / 10%)}@media(max-width:800px){.lw-grid{grid-template-columns:1fr}}`,
    };
}

// ── Offscreen DOM (true CSS-selector targeting; the service worker has no DOM) ─

let offscreenReady = null;
async function ensureOffscreen() {
    if (!chrome.offscreen) return false;   // Chrome < 109 — caller falls back to string handling
    try {
        if (await chrome.offscreen.hasDocument?.()) return true;
        if (!offscreenReady) {
            offscreenReady = chrome.offscreen.createDocument({
                url: 'offscreen.html',
                reasons: ['DOM_PARSER'],
                justification: 'Target and inspect the LiveWeave canvas by CSS selector (the service worker has no DOM).',
            }).catch(() => {}).finally(() => { offscreenReady = null; });
        }
        await offscreenReady;
        return (await chrome.offscreen.hasDocument?.()) ?? true;
    } catch { return false; }
}

// Run a DOM op in the offscreen document; returns its {ok,...} result, or null when offscreen is unavailable so the
// caller can fall back. Command execution is serialized by the poll mutex, so these calls never overlap.
async function domOp(op, payload) {
    if (!(await ensureOffscreen())) return null;
    try { return await chrome.runtime.sendMessage({ target: 'liveweave-offscreen', op, ...payload }); }
    catch { return null; }
}

// ── Command helpers: validation, structure, safe CSS slots ───────────────────

const escapeRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const stripOk = ({ ok, ...rest }) => rest;   // drop the transport flag from an inspect result

// Missing/blank required param → a STRUCTURED error the driving agent can branch on, instead of the old silent
// ok:true no-op (apply_page with no html kept the old html; set_style with no styles wrote `sel{}` — both looked
// like success). This is the core agent-feedback contract.
function requireParams(params, names) {
    for (const n of names) {
        const v = params?.[n];
        if (v == null || String(v).trim() === '')
            return { ok: false, code: 'missing_param', field: n, error: `LiveWeave '${n}' is required for this action.` };
    }
    return null;
}

// Structured slots are DATA, not markup. Reject values that would break out of the CSS rule / HTML block they're
// interpolated into (apply_page is the path for raw markup). Returns the cleaned value, or null to reject.
const safeSelector = (path) => {
    const p = String(path || '').trim();
    return !p || /[{}<>]|-->/.test(p) ? null : p;   // real selectors never contain these
};
const safeDeclarations = (styles) => {
    const s = String(styles ?? '');
    return /[{}<]|-->/.test(s) ? null : s;           // a declaration body can't contain braces or tags
};

// Upsert a comment-MARKED single-line CSS rule so repeated set_style/set_background for the same target REPLACE
// their own prior rule (no more stylesheet growing forever) without ever touching the user's apply_page CSS.
function upsertMarked(css, marker, rule) {
    const line = `\n/*${marker}*/${String(rule).replace(/\s*\n\s*/g, ' ')}`;
    const re = new RegExp(`\\n?\\/\\*${escapeRe(marker)}\\*\\/[^\\n]*`);
    return re.test(css || '') ? css.replace(re, line) : `${css || ''}${line}`;
}

// Best-effort structural outline of the stored HTML. The service worker has no DOM, so this is a regex pass — not a
// full parser, but enough for an agent to learn what headings/landmarks/ids exist to target (vs re-reading the raw
// source it already wrote). scan returns this plus the full source; outline returns just this.
function outlineOf(html) {
    const h = String(html || '');
    const headings = [...h.matchAll(/<(h[1-6])\b[^>]*>([\s\S]*?)<\/\1>/gi)]
        .map((m) => ({ level: Number(m[1][1]), text: m[2].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim().slice(0, 120) }));
    const ids = [...h.matchAll(/\bid\s*=\s*["']([^"']+)["']/gi)].map((m) => m[1]);
    const duplicateIds = [...new Set(ids.filter((v, i) => ids.indexOf(v) !== i))];
    const landmarks = [...h.matchAll(/<(header|nav|main|section|article|aside|footer|form)\b/gi)]
        .reduce((acc, m) => { const t = m[1].toLowerCase(); acc[t] = (acc[t] || 0) + 1; return acc; }, {});
    const elementCount = (h.match(/<[a-z][a-z0-9-]*\b/gi) || []).length;
    return { headings, ids, duplicateIds, landmarks, elementCount };
}

async function executeLiveWeaveCommand(cmd) {
    const action = String(cmd.action || '').toLowerCase();
    const params = cmd.parameters || {};
    const { canvas, history } = await readCanvas();
    // Effect confirmation appended to every successful mutation so the agent can verify the edit actually landed.
    const effect = (c) => ({ appliedTitle: c.title, htmlLength: (c.html || '').length, cssLength: (c.css || '').length });

    switch (action) {
        case 'start_builder':
            await openLiveWeaveCanvas({ active: true });
            return { ok: true, title: canvas.title, opened: true };

        case 'stop_builder': {
            // Truthful stop: close the canvas tab. (Never clearInterval(pollTimer) — polling is the ONLY command
            // channel, so stopping it would strand the extension.) Brokered edits still apply + reopen the canvas.
            const { liveweaveTabId } = await chrome.storage.local.get({ liveweaveTabId: null });
            if (liveweaveTabId != null) { try { await chrome.tabs.remove(liveweaveTabId); } catch { /* already closed */ } }
            return { ok: true, stopped: true, note: 'Canvas tab closed; a later edit reopens it.' };
        }

        case 'new_canvas':
            return { ok: true, ...effect(await saveCanvas({ ...DEFAULT_CANVAS, title: textParam(params, 'title', 'LiveWeave Canvas') })) };

        case 'generate':
            return { ok: true, ...effect(await saveCanvas(generatedCanvas(params, canvas))) };

        case 'template':
            return { ok: true, ...effect(await saveCanvas(generatedCanvas({ ...params, instruction: textParam(params, 'instruction', textParam(params, 'template', 'Template landing page')) }, canvas))) };

        case 'apply_page': {
            const bad = requireParams(params, ['html']);
            if (bad) return bad;
            const c = await saveCanvas({
                title: textParam(params, 'title', canvas.title),
                html: textParam(params, 'html', canvas.html),
                css: textParam(params, 'css', canvas.css),
            });
            return { ok: true, ...effect(c) };
        }

        case 'apply_section': {
            const bad = requireParams(params, ['html']);
            if (bad) return bad;
            const section = textParam(params, 'html');
            const css = textParam(params, 'css');
            const placement = textParam(params, 'placement', 'append').toLowerCase();
            const targetRaw = textParam(params, 'target');
            const target = targetRaw ? safeSelector(targetRaw) : null;
            if (targetRaw && !target) return { ok: false, code: 'bad_selector', error: 'target must be a plain CSS selector.' };
            // Insert into a target container via the offscreen DOM (or at document top level); a real "target not
            // found" is surfaced. Falls back to a document-level sibling concat when offscreen is unavailable.
            const dom = await domOp('apply_section', { html: canvas.html, section, placement, target });
            if (dom?.code === 'not_found') return dom;
            const nextHtml = dom?.ok ? dom.html : (placement === 'prepend' ? `${section}\n${canvas.html}` : `${canvas.html}\n${section}`);
            const c = await saveCanvas({ ...canvas, html: nextHtml, css: css ? `${canvas.css || ''}\n${css}` : canvas.css });
            return { ok: true, placement, target: target || undefined, targeted: !!dom?.ok, ...effect(c) };
        }

        case 'apply_inner': {
            const bad = requireParams(params, ['path', 'html']);
            if (bad) return bad;
            const sel = safeSelector(textParam(params, 'path'));
            if (!sel) return { ok: false, code: 'bad_selector', error: 'path must be a plain CSS selector (no { } < > or -->).' };
            const html = textParam(params, 'html');
            const css = safeDeclarations(textParam(params, 'css')) ?? '';
            // TRUE selector targeting via the offscreen DOM: resolve `sel` and set its innerHTML. A genuine
            // "selector not found" is surfaced to the agent. If offscreen is unavailable, fall back to a delimited,
            // idempotent block per selector (repeats replace, never duplicate).
            const dom = await domOp('apply_inner', { html: canvas.html, path: sel, inner: html });
            if (dom?.code === 'not_found') return dom;
            if (dom?.ok) {
                const c = await saveCanvas({ ...canvas, html: dom.html, css: css ? `${canvas.css || ''}\n${css}` : canvas.css });
                return { ok: true, target: sel, targeted: true, ...effect(c) };
            }
            const open = `<!-- liveweave:begin ${sel} -->`, close = `<!-- liveweave:end ${sel} -->`;
            const block = `\n${open}\n${html}\n${close}`;
            const re = new RegExp(`\\n?${escapeRe(open)}[\\s\\S]*?${escapeRe(close)}`);
            const replaced = re.test(canvas.html);
            const nextHtml = replaced ? canvas.html.replace(re, block) : `${canvas.html}${block}`;
            const c = await saveCanvas({ ...canvas, html: nextHtml, css: css ? `${canvas.css || ''}\n${css}` : canvas.css });
            return { ok: true, target: sel, targeted: false, replaced, note: 'Delimited-block fallback (offscreen DOM unavailable).', ...effect(c) };
        }

        case 'set_style': {
            const bad = requireParams(params, ['path', 'styles']);
            if (bad) return bad;
            const sel = safeSelector(textParam(params, 'path'));
            const body = safeDeclarations(textParam(params, 'styles'));
            if (!sel || body == null) return { ok: false, code: 'bad_slot', error: 'path/styles must be plain CSS (no braces or tags).' };
            const c = await saveCanvas({ ...canvas, css: upsertMarked(canvas.css || '', `lw:s:${sel}`, `${sel}{${body}}`) });
            return { ok: true, selector: sel, ...effect(c) };
        }

        case 'set_background': {
            const value = String(textParam(params, 'value', textParam(params, 'background', '#ffffff')));
            if (/[{}<]/.test(value)) return { ok: false, code: 'bad_slot', error: 'background value must be a plain CSS value.' };
            const c = await saveCanvas({ ...canvas, css: upsertMarked(canvas.css || '', 'lw:bg', `body{background:${value};}`) });
            return { ok: true, ...effect(c) };
        }

        case 'undo': {
            if (history.length === 0) return { ok: false, error: 'Nothing to undo.' };
            const previous = history[history.length - 1];
            await chrome.storage.local.set({ liveweaveHistory: history.slice(0, -1) });
            const c = await saveCanvas(previous, false);   // route through saveCanvas so updatedAt refreshes (was stale)
            return { ok: true, ...effect(c) };
        }

        case 'scan': {   // full source + structure — for an agent that lost context
            const dom = await domOp('inspect', { html: canvas.html });
            const structure = dom?.ok ? stripOk(dom) : outlineOf(canvas.html);   // real DOM structure, or regex fallback
            return { ok: true, title: canvas.title, html: canvas.html, css: canvas.css,
                     htmlLength: canvas.html.length, cssLength: canvas.css.length, structure };
        }

        case 'outline': {   // concise structure only — cheap for targeting decisions
            const dom = await domOp('inspect', { html: canvas.html });
            const s = dom?.ok ? stripOk(dom) : outlineOf(canvas.html);
            return { ok: true, title: canvas.title, htmlLength: canvas.html.length, cssLength: canvas.css.length, ...s };
        }

        default:
            return { ok: false, error: `Unsupported LiveWeave action '${action}'. Supported: start_builder, stop_builder, new_canvas, generate, template, apply_page, apply_section, apply_inner, set_style, set_background, undo, scan, outline.` };
    }
}

// Honest on-device model availability (was hardcoded 'unavailable'). Chrome's Prompt API is a document-context
// API, so it is usually absent in the service worker — in which case we correctly report 'unavailable'. If a
// future channel exposes it here (or an offscreen document is added), this reports the real state. Clamped by
// Foreman's SanitizeNanoStatus to {available, downloadable, downloading, unavailable}.
async function nanoStatus() {
    try {
        if (typeof self.LanguageModel?.availability === 'function') {
            const a = await self.LanguageModel.availability();
            return ['available', 'downloadable', 'downloading', 'unavailable'].includes(a) ? a : 'unavailable';
        }
        const caps = await self.ai?.languageModel?.capabilities?.();
        if (caps?.available === 'readily') return 'available';
        if (caps?.available === 'after-download') return 'downloadable';
        return 'unavailable';
    } catch {
        return 'unavailable';
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
    if (needsPair) return; // token rejected — don't hammer a dead token; the operator must re-pair
    if (polling) return;   // a poll is already draining the queue — don't run commands concurrently (storage races)
    polling = true;
    try {
        const tabInfoJson = JSON.stringify(await liveweaveTabInfo());
        const batch = await mcpCall('liveweave_poll_commands', {
            limit: 5,
            tabInfoJson,
            nanoStatus: await nanoStatus(),
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
    } finally {
        polling = false;
    }
}

async function refresh() {
    connected = await checkHealth();
    lastMcpError = null;
    await pollLiveWeave();
    broadcast();
}

// Fast interval for responsive building. It only runs while the worker is alive; a connected side-panel or canvas
// port keeps it alive, and the chrome.alarms heartbeat below revives polling after the worker is suspended.
function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(refresh, FAST_POLL_MS);
    ensurePollAlarm();
    refresh();
}

// Durable heartbeat: an alarm wakes a suspended worker so queued commands still get applied when nobody is looking
// at the canvas. create() is idempotent (same name replaces). Registered from the top-level alarm listener too.
function ensurePollAlarm() {
    try { chrome.alarms.create(POLL_ALARM, { periodInMinutes: POLL_ALARM_PERIOD_MIN }); } catch { /* no alarms API */ }
}

chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm?.name === POLL_ALARM) refresh();
});

// ── Side panel + canvas plumbing ─────────────────────────────────────────────

chrome.runtime.onConnect.addListener((port) => {
    // The canvas page holds a port open while it's up; that keeps the worker alive so the fast interval runs and
    // building stays responsive. We don't need to do anything per-message — just poll on connect and on disconnect
    // fall back to the alarm heartbeat.
    if (port.name === 'foreman-liveweave-canvas') {
        canvasPort = port;
        refresh();
        port.onDisconnect.addListener(() => { if (canvasPort === port) canvasPort = null; });
        return;
    }
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
        needsPair,
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
// Only react to REAL settings changes. The canvas + history + tracked tab id also live in storage.local and are
// rewritten on every brokered edit; without this filter each edit reloaded settings and dropped the cached MCP
// session, forcing an extra initialize handshake per command.
const SETTINGS_KEYS = ['host', 'port', 'token', 'pairedOrigin', 'harnessId', 'liveweaveDriver'];
onSettingsChanged(async (changes) => {
    if (changes && !SETTINGS_KEYS.some((k) => k in changes)) return;
    try {
        cfg = { ...cfg, ...(await loadSettings()) };
        mcpSession = null;
    } catch { /* keep */ }
});
chrome.runtime.onStartup.addListener(bootstrap);
chrome.runtime.onInstalled.addListener(bootstrap);
bootstrap();
