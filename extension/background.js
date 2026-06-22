/**
 * Foreman Agent Safety — extension service worker.
 *
 * Bridges the browser to the LOCAL Foreman desktop app over loopback HTTP (never the network). Two phases:
 *   1. Pairing (one-time): the user clicks "Pair browser extension" in Foreman → Foreman shows a short code →
 *      the user types it on the options page → we prove we hold it via a challenge/response (the code never
 *      crosses the wire) → Foreman allow-lists our origin and hands back a scoped bearer token.
 *   2. Connected: we poll /health for liveness and call the MCP endpoint (with the token) for status/alerts,
 *      feed the side panel, surface the Ask-Harness inbox, and act as the executor for Foreman's audited
 *      browser-use (BU) broker.
 *
 * The extension has host_permissions for 127.0.0.1/localhost, so the service worker can fetch the loopback
 * server cross-origin without CORS. Nothing here ever talks to a remote host.
 *
 * (LiveWeave, the local page builder, now lives in its own extension — `extension-liveweave/`.)
 */
import { loadSettings, saveSettings, onSettingsChanged } from './settings.js';
import { callMcpTool, openMcpSession } from './mcp-client.js';

let cfg = { host: '127.0.0.1', port: 54321, token: '', pairedOrigin: '', harnessId: 'browser-extension' };
let connected = false;
let lastStatus = null;          // last foreman_status payload (or null)
let lastAsks = [];              // pending Ask-Harness requests scoped to this extension
let lastMcpError = null;
let sidePanelPort = null;
let pollTimer = null;
let mcpSession = null;
let pinnedTab = null;           // operator's shared-attention pin (tab id) set by pressing the toolbar icon; null = none
let lastReportedPin = null;     // last pin value pushed to Foreman, so we re-report changes (incl. clears) exactly once
const POLL_MS = 5000;

// Persist the pin to session storage so a service-worker restart reloads it (in bootstrap) instead of dropping to
// null — otherwise the broker would keep a stale pin while we resolved actions against the active tab.
function persistPin() { try { chrome.storage.session.set({ pinnedTab }); } catch { /* session storage unavailable */ } }

const base = () => `http://${cfg.host}:${cfg.port}`;
const selfOrigin = () => `chrome-extension://${chrome.runtime.id}`;

// ── Pairing ────────────────────────────────────────────────────────────────

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
            body: JSON.stringify({ response, origin: selfOrigin(), harnessId: 'browser-extension' }),
        });
        const body = await done.json().catch(() => ({}));
        if (!done.ok || !body.ok) return { ok: false, error: body.reason || `Pairing failed (${done.status}).` };

        cfg = { ...cfg, token: body.token || '', pairedOrigin: body.origin || selfOrigin(), harnessId: body.harnessId || 'browser-extension' };
        await saveSettings({ token: cfg.token, pairedOrigin: cfg.pairedOrigin, harnessId: cfg.harnessId });
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

// Reply to one Ask-Harness prompt. Surfaced to the side panel; returns {ok} so the UI can confirm.
async function replyAsk(requestId, response) {
    if (!requestId || !response?.trim()) return { ok: false, error: 'Empty reply.' };
    const r = await mcpCall('reply_to_ask_harness_request', { requestId, response: response.trim() });
    const ok = r && r.accepted !== false && !r.error;
    // NB: caller posts the ask-reply-result FIRST, then refreshes — so the panel's "✓ Reply sent"
    // confirmation lands before the status rebuild removes the (now answered) card.
    return ok ? { ok: true } : { ok: false, error: (r && (r.reason || r.error)) || lastMcpError || 'Reply was not accepted.' };
}

// ── Browser use (BU) — executor for Foreman's audited cu_* broker ───────────────
// Foreman AUDITS every action (and holds risky ones for operator approval) BEFORE it reaches here; this
// extension is only the executor for actions Foreman already APPROVED. Bounded mode (tabs API only, no
// scripting/host perms): navigate (new tab), goto (same tab), back/forward (tab history), read (tab metadata).
// click/type/scroll/screenshot need `scripting` + host permissions (a future broad-mode operator opt-in) and
// return a clear error until then.

// Resolve which tab an action acts on: an explicit args.tabId wins; else the operator's pinned focus; else the
// active tab. So when a tab is pinned, an action with NO tabId runs IN the pinned tab and can never silently drift.
async function resolveTargetTab(args) {
    const explicit = args.tabId;
    if (explicit !== undefined && explicit !== null && String(explicit) !== '') {
        const s = String(explicit).trim();
        // Only a clean base-10 integer names a tab, matching the broker's canonical parse. Reject 0x2A / 1e3 /
        // trailing-garbage so the executor never acts on a tab the broker reasoned about differently.
        if (!/^\d+$/.test(s)) return null;
        return parseInt(s, 10);
    }
    if (pinnedTab != null) return pinnedTab;
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab?.id ?? null;
}

async function executeCuAction(act) {
    const verb = String(act.verb || '').toLowerCase();
    const args = act.args || {};
    switch (verb) {
        case 'navigate': {
            const url = String(args.url || '');
            // Scheme-gate to http(s) (rejects javascript:/data:/file:/chrome:/about:), then confirm it parses.
            // Defense-in-depth even though Foreman already audited the action upstream.
            if (!/^https?:\/\//i.test(url)) return { ok: false, error: 'navigate requires an http(s) url.' };
            try { new URL(url); } catch { return { ok: false, error: 'navigate requires a valid url.' }; }
            const tab = await chrome.tabs.create({ url, active: true });
            return { ok: true, result: { tabId: tab.id ?? null, url } };
        }
        case 'list_tabs':
        case 'tabs': {
            // Enumerate every window / group / tab so the driver can target one by name ("use my Gmail tab").
            const wins = await chrome.windows.getAll({ populate: true });
            let groups = [];
            try { groups = await chrome.tabGroups.query({}); } catch { /* tabGroups perm absent */ }
            const groupName = (gid) => groups.find((g) => g.id === gid)?.title ?? null;
            const tabs = [];
            for (const w of wins) for (const t of (w.tabs || [])) {
                tabs.push({
                    tabId: t.id, windowId: w.id, title: t.title ?? '', url: t.url ?? '',
                    active: !!t.active, pinned: !!t.pinned,
                    group: (t.groupId != null && t.groupId > -1) ? (groupName(t.groupId) || `group ${t.groupId}`) : null,
                    isAttentionPin: t.id === pinnedTab,
                });
            }
            return { ok: true, result: { tabs, pinnedTab, windowCount: wins.length } };
        }
        case 'read': {
            const tabId = await resolveTargetTab(args);
            if (tabId == null) return { ok: false, error: 'No tab to read.' };
            const tab = await chrome.tabs.get(tabId).catch(() => null);
            if (!tab) return { ok: false, error: `Tab ${tabId} not found.` };
            // Bounded: tab metadata only. Page CONTENT (DOM/text) needs scripting (broad mode).
            return { ok: true, result: { tabId, url: tab.url ?? '', title: tab.title ?? '' } };
        }
        case 'goto': {
            // Navigate the TARGET tab (explicit/pinned/active) in place, vs 'navigate' which opens a new one.
            const url = String(args.url || '');
            if (!/^https?:\/\//i.test(url)) return { ok: false, error: 'goto requires an http(s) url.' };
            try { new URL(url); } catch { return { ok: false, error: 'goto requires a valid url.' }; }
            const tabId = await resolveTargetTab(args);
            if (tabId == null) return { ok: false, error: 'No tab to navigate.' };
            const updated = await chrome.tabs.update(tabId, { url });
            return { ok: true, result: { tabId: updated?.id ?? tabId, url } };
        }
        case 'back':
        case 'forward': {
            // Tab history navigation via the tabs API (no scripting). Back from a fresh tab is a no-op (no history).
            const tabId = await resolveTargetTab(args);
            if (tabId == null) return { ok: false, error: 'No tab.' };
            if (verb === 'back') await chrome.tabs.goBack(tabId);
            else await chrome.tabs.goForward(tabId);
            return { ok: true, result: { tabId, action: verb } };
        }
        case 'click':
        case 'type':
        case 'scroll':
        case 'screenshot':
            return { ok: false, error: `'${verb}' needs broad browser-use mode (scripting + host permissions), which is not enabled in this build.` };
        default:
            return { ok: false, error: `Unsupported browser-use verb '${verb}'.` };
    }
}

async function pollCu() {
    if (!cfg.token || !connected) return;
    const batch = await mcpCall('cu_poll_actions', { limit: 5 });
    const actions = Array.isArray(batch?.actions) ? batch.actions : [];
    for (const act of actions) {
        let result;
        // This extension executes BROWSER actions only. No desktop executor exists yet, so all cu actions are
        // browser; when the desktop sidecar lands, cu_poll_actions should filter by modality so we never claim a
        // desktop action we cannot run.
        if (String(act.modality || '').toLowerCase() !== 'browser') {
            result = { ok: false, error: 'Browser extension cannot execute non-browser actions.' };
        } else {
            try { result = await executeCuAction(act); }
            catch (e) { result = { ok: false, error: String(e?.message || e) }; }
        }
        await mcpCall('cu_complete_action', {
            actionId: act.actionId,
            ok: !!result.ok,
            resultJson: result.ok ? JSON.stringify(result.result ?? result) : null,
            error: result.ok ? null : (result.error || 'Browser-use action failed.'),
        });
    }
}

// Tell Foreman which tab the operator pinned as shared attention, so the broker holds off-focus state changes.
async function reportAttention() {
    await mcpCall('cu_set_attention', { tabId: pinnedTab == null ? '' : String(pinnedTab) });
}

async function refresh() {
    connected = await checkHealth();
    lastMcpError = null;
    lastStatus = connected ? await mcpCall('foreman_status') : null;
    // Re-assert the pin each cycle so it survives a Foreman restart, and push a CLEAR exactly once when it goes to
    // null, so a restarted worker (or an unpin) always reconciles the broker to our true state before pollCu runs.
    if (connected && (pinnedTab != null || lastReportedPin != null)) {
        await reportAttention();
        lastReportedPin = pinnedTab;
    }
    await pollCu();
    // The inbox is scoped to THIS extension's harness ("browser-extension") by the token — it only ever shows
    // prompts Foreman routed to us, never a sibling's. Empty until orchestration routes work to the browser.
    const asks = connected && cfg.token ? await mcpCall('list_ask_harness_requests', { includeAnswered: false, limit: 10 }) : null;
    lastAsks = Array.isArray(asks?.requests) ? asks.requests : [];
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
    broadcast();                 // show last-known state immediately…
    refresh();                   // …then pull fresh status + inbox (the SW may have been suspended)
    port.onMessage.addListener(async (msg) => {
        if (msg?.kind === 'pair') {
            const r = await pair(msg.code);
            safePost({ kind: 'pair-result', ...r });
        } else if (msg?.kind === 'refresh') {
            mcpSession = null;
            await refresh();
        } else if (msg?.kind === 'ask-reply') {
            const r = await replyAsk(msg.requestId, msg.response);
            safePost({ kind: 'ask-reply-result', requestId: msg.requestId, ...r });   // confirm first…
            if (r.ok) await refresh();                                                // …then drop the answered card
        }
    });
    port.onDisconnect.addListener(() => { if (sidePanelPort === port) sidePanelPort = null; });
});

function broadcast() {
    safePost({
        kind: 'status',
        connected,
        paired: !!cfg.token,
        verified: !!cfg.token && connected && !!lastStatus,
        base: base(),
        harnessId: cfg.harnessId,
        status: lastStatus,
        asks: lastAsks,
        mcpError: lastMcpError,
        pinnedTab,                 // shared-attention pin so the panel can show "Claude's attention: this tab"
    });
}

function safePost(message) {
    if (!sidePanelPort) return;
    try { sidePanelPort.postMessage(message); }
    catch { sidePanelPort = null; }
    finally { try { void chrome.runtime.lastError; } catch { /* ok */ } }
}

// Pressing the pinned toolbar icon toggles the shared-attention pin on that tab (press again = unpin, press a
// DIFFERENT tab = move the pin), reports it to Foreman, and opens the side panel. openPanelOnActionClick MUST be
// false here — otherwise Chrome opens the panel itself and never fires onClicked, so we'd never see the press.
chrome.action.onClicked.addListener(async (tab) => {
    if (tab?.id !== undefined && tab.id !== chrome.tabs.TAB_ID_NONE) {
        pinnedTab = (pinnedTab === tab.id) ? null : tab.id;
        persistPin();
        await reportAttention();
        lastReportedPin = pinnedTab;
        broadcast();
    }
    if (tab?.windowId !== undefined) { try { await chrome.sidePanel.open({ windowId: tab.windowId }); } catch { /* ok */ } }
});
try { chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false }); } catch { /* Chrome < 114 */ }

// If the pinned tab closes, drop the pin (and tell Foreman) so a stale id can't linger as the "focus".
chrome.tabs.onRemoved.addListener((tabId) => {
    if (pinnedTab === tabId) { pinnedTab = null; persistPin(); reportAttention().then(() => { lastReportedPin = null; }); broadcast(); }
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.kind === 'pair') { pair(msg.code).then(sendResponse); return true; }
    return false;
});

// ── Boot ─────────────────────────────────────────────────────────────────────

const KEEPALIVE_ALARM = 'foreman-keepalive';

async function bootstrap() {
    try { cfg = { ...cfg, ...(await loadSettings()) }; } catch { /* defaults */ }
    // Reload the shared-attention pin a prior worker instance saved, so a service-worker restart doesn't silently
    // drop the focus to null (which would let no-tabId actions resolve to the active tab). refresh() then reconciles
    // it to the broker. lastReportedPin stays null so the first refresh re-pushes the reloaded pin.
    try { const s = await chrome.storage.session.get('pinnedTab'); if (s && typeof s.pinnedTab === 'number') pinnedTab = s.pinnedTab; } catch { /* no session storage */ }
    // MV3 service workers sleep after ~30s idle, which stops the poll loop — so an APPROVED browser-use action
    // would sit unclaimed unless the side panel is open. A periodic alarm wakes the worker (~1 min) to poll
    // cu_poll_actions / status / inbox even when nothing else fires; the 5s interval still drives the awake bursts.
    try { chrome.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: 1 }); } catch { /* alarms unavailable */ }
    startPolling();
}
// Registered at top level so the alarm can WAKE a suspended worker; it then reloads cfg + resumes polling.
chrome.alarms.onAlarm.addListener((alarm) => { if (alarm.name === KEEPALIVE_ALARM) bootstrap(); });
onSettingsChanged(async () => {
    try {
        cfg = { ...cfg, ...(await loadSettings()) };
        mcpSession = null;
    } catch { /* keep */ }
});
chrome.runtime.onStartup.addListener(bootstrap);
chrome.runtime.onInstalled.addListener(bootstrap);
bootstrap();
