const port = chrome.runtime.connect({ name: 'foreman-sidepanel' });
const $ = (id) => document.getElementById(id);

port.onMessage.addListener((m) => { if (m?.kind === 'status') render(m); });
$('refresh').addEventListener('click', () => port.postMessage({ kind: 'refresh' }));

function render(m) {
    const badge = $('badge');
    if (!m.paired) {
        badge.textContent = '🔌 Not paired';
        badge.className = 'warn';
        $('hint').innerHTML = 'Open the extension <a id="opt">options</a> to pair with Foreman.';
        $('status').textContent = '';
        const opt = document.getElementById('opt');
        if (opt) opt.onclick = () => chrome.runtime.openOptionsPage();
        return;
    }
    if (m.verified) {
        badge.textContent = '🔒 On-device · verified';
        badge.className = 'ok';
    } else {
        badge.textContent = '⚠ Paired — Foreman offline';
        badge.className = 'warn';
    }
    $('hint').textContent = `${m.base} · nothing leaves this machine`;
    $('status').textContent = m.status
        ? JSON.stringify(m.status, null, 2)
        : (m.connected ? 'Connected. Status pending — verify the MCP handshake in Chrome.' : 'Foreman is not reachable. Is it running?');
}
