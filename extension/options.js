const $ = (id) => document.getElementById(id);

function setMsg(text, cls) { const m = $('msg'); m.textContent = text; m.className = cls || ''; }

$('pair').addEventListener('click', () => {
    const code = $('code').value;
    setMsg('Pairing…');
    chrome.runtime.sendMessage({ kind: 'pair', code }, (r) => {
        if (chrome.runtime.lastError) { setMsg(chrome.runtime.lastError.message, 'err'); return; }
        if (r?.ok) setMsg('✓ Paired. You can close this page and open the side panel.', 'ok');
        else setMsg(r?.error || 'Pairing failed.', 'err');
    });
});

$('code').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('pair').click(); });
