const port = chrome.runtime.connect({ name: 'foreman-sidepanel' });
const $ = (id) => document.getElementById(id);

port.onMessage.addListener((m) => {
    if (m?.kind === 'status') render(m);
    if (m?.kind === 'pair-result' && !m.ok) {
        $('hint').textContent = m.error || 'Pairing failed.';
        $('hint').className = 'warn-text';
    }
});
$('refresh').addEventListener('click', () => port.postMessage({ kind: 'refresh' }));

function render(m) {
    const badge = $('badge');
    if (!m.paired) {
        badge.textContent = '🔌 Not paired';
        badge.className = 'warn';
        $('hint').innerHTML = 'Open the extension <a id="opt">options</a> to pair with Foreman.';
        $('hint').className = '';
        $('status').innerHTML = '';
        const opt = document.getElementById('opt');
        if (opt) opt.onclick = () => chrome.runtime.openOptionsPage();
        return;
    }

    if (m.verified) {
        badge.textContent = '🔒 On-device · verified';
        badge.className = 'ok';
    } else if (m.connected) {
        badge.textContent = '⚠ Paired — MCP status pending';
        badge.className = 'warn';
    } else {
        badge.textContent = '⚠ Paired — Foreman offline';
        badge.className = 'warn';
    }

    $('hint').textContent = `${m.base} · nothing leaves this machine`;
    $('hint').className = '';

    if (m.status) {
        const s = m.status;
        const statusClass = s.status === 'green' ? 'ok' : s.status === 'red' ? 'bad' : 'warn';
        $('status').innerHTML = `
            <div class="grid">
                <div><span class="label">Status</span><span class="pill ${statusClass}">${esc(s.status)}</span></div>
                <div><span class="label">Active alerts</span><strong>${esc(s.activeAlerts)}</strong></div>
                <div><span class="label">Monitored processes</span><strong>${esc(s.monitoredProcesses)}</strong></div>
                <div><span class="label">Pending Ask Harness</span><strong>${esc(s.pendingAskHarnessRequests ?? 0)}</strong></div>
                <div><span class="label">Uptime</span><strong>${formatUptime(s.uptimeSeconds)}</strong></div>
                <div><span class="label">Foreman</span><strong>v${esc(s.version ?? '?')}</strong></div>
            </div>`;
    } else if (m.mcpError) {
        $('status').innerHTML = `<div class="err">MCP: ${esc(m.mcpError)}</div>`;
    } else {
        $('status').innerHTML = m.connected
            ? '<div class="muted">Connected to Foreman. Waiting for MCP status…</div>'
            : '<div class="muted">Foreman is not reachable. Is the tray app running?</div>';
    }
}

function formatUptime(sec) {
    if (sec == null) return '?';
    if (sec < 60) return `${sec}s`;
    if (sec < 3600) return `${Math.floor(sec / 60)}m`;
    if (sec < 86400) return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
    return `${Math.floor(sec / 86400)}d`;
}

function esc(v) {
    return String(v ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}
