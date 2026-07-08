const port = chrome.runtime.connect({ name: 'foreman-liveweave-sidepanel' });
const $ = (id) => document.getElementById(id);

port.onMessage.addListener((m) => {
    if (m?.kind === 'status') render(m);
    else if (m?.kind === 'pair-result' && !m.ok) setHint(m.error || 'Pairing failed.', 'bad');
});
$('refresh').addEventListener('click', () => port.postMessage({ kind: 'refresh' }));
$('openCanvas').addEventListener('click', () => port.postMessage({ kind: 'open-canvas' }));

function setHint(text, _cls) { $('hint').textContent = text; }

function render(m) {
    const badge = $('badge');
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
}

function esc(v) {
    return String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
