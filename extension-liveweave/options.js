const $ = (id) => document.getElementById(id);

function setMsg(text, cls) { const m = $('msg'); m.textContent = text; m.className = cls || ''; }

async function loadOptions() {
    const s = await chrome.storage.local.get({ liveweaveDriver: '' });
    $('driver').value = s.liveweaveDriver || '';
}

$('pair').addEventListener('click', () => {
    const code = $('code').value;
    const liveweaveDriver = $('driver').value.trim().toLowerCase();
    chrome.storage.local.set({ harnessId: 'liveweave', liveweaveDriver });
    setMsg('Pairing…');
    chrome.runtime.sendMessage({ kind: 'pair', code, liveweaveDriver }, (r) => {
        if (chrome.runtime.lastError) { setMsg(chrome.runtime.lastError.message, 'err'); return; }
        if (r?.ok) setMsg('✓ Paired. Click Close, then open the side panel.', 'ok');
        else setMsg(r?.error || 'Pairing failed.', 'err');
    });
});

$('code').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('pair').click(); });

// Close this options pane. tabs.getCurrent/remove need no "tabs" permission; window.close() is the fallback
// (and the path when options are embedded rather than opened as a tab). Esc closes too.
function closePane() {
    try {
        if (chrome.tabs?.getCurrent) {
            chrome.tabs.getCurrent((tab) => {
                if (chrome.runtime.lastError || tab?.id == null) window.close();
                else chrome.tabs.remove(tab.id);
            });
        } else {
            window.close();
        }
    } catch { window.close(); }
}
$('close').addEventListener('click', closePane);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closePane(); });
loadOptions();
