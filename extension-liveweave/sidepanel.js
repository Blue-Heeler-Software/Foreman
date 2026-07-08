const port = chrome.runtime.connect({ name: 'foreman-liveweave-sidepanel' });
const $ = (id) => document.getElementById(id);

port.onMessage.addListener((m) => {
    if (m?.kind === 'status') render(m);
    // (no pair-result branch: pairing lives in the options page, which gets its result via sendMessage directly)
});
$('refresh').addEventListener('click', () => port.postMessage({ kind: 'refresh' }));
$('openCanvas').addEventListener('click', () => port.postMessage({ kind: 'open-canvas' }));
// Operator builder controls (New/Undo/Redo) — drive the same executor as brokered commands.
document.querySelectorAll('[data-cmd]').forEach((b) =>
    b.addEventListener('click', () => port.postMessage({ kind: 'command', action: b.dataset.cmd })));

function setHint(text) { $('hint').textContent = text; }

function render(m) {
    const badge = $('badge');
    $('controls').style.display = 'none';   // shown only in the connected state below
    if (!m.paired) {
        badge.textContent = '🔌 Not paired';
        badge.className = 'warn';
        $('hint').innerHTML = 'Open the extension <a id="opt" href="#">options</a> to pair with Foreman as the LiveWeave driver.';
        $('body').innerHTML = '';
        const opt = document.getElementById('opt');
        if (opt) opt.onclick = (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); };   // href makes it keyboard-focusable
        return;
    }

    if (m.needsPair) {
        badge.textContent = '⚠ Token rejected — re-pair';
        badge.className = 'bad';
        $('hint').innerHTML = 'Foreman rejected the saved token. Open the extension <a id="opt" href="#">options</a> and pair again.';
        $('body').innerHTML = '';
        const opt = document.getElementById('opt');
        if (opt) opt.onclick = (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); };
        return;
    }

    if (m.connected) { badge.textContent = '🔒 On-device · paired'; badge.className = 'ok'; }
    else { badge.textContent = '⚠ Paired — Foreman offline'; badge.className = 'warn'; }

    setHint(`${m.base} · nothing leaves this machine`);
    const driver = m.liveweaveDriver ? esc(m.liveweaveDriver) : 'operator only';
    $('body').innerHTML = `
        <div class="grid">
            <div><span class="label">Role</span><strong>LiveWeave driver</strong></div>
            <div><span class="label">Driver harness</span><strong>${driver}</strong></div>
        </div>
        <p class="muted" style="margin-top:10px">Foreman-brokered edits render into the local canvas. ${m.mcpError ? 'MCP: ' + esc(m.mcpError) : ''}</p>`;
    $('controls').style.display = m.connected ? 'flex' : 'none';   // can only drive while Foreman is reachable
    renderLog(m.log || []);
}

function renderLog(log) {
    const el = $('log');
    if (!log.length) { el.innerHTML = ''; return; }
    el.innerHTML = log.slice().reverse().map((e) => {
        const time = new Date(e.ts).toLocaleTimeString();
        const detail = e.ok ? '' : ` <span class="bad">${esc(e.error || 'failed')}</span>`;
        return `<div class="ln"><span class="${e.ok ? 'ok' : 'bad'}">${e.ok ? '✓' : '✗'}</span><span>${esc(e.action)}</span>` +
            `<span class="muted" style="margin-left:auto">${time}</span>${detail}</div>`;
    }).join('');
}

function esc(v) {
    return String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
