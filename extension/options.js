const $ = (id) => document.getElementById(id);

function setMsg(text, cls) { const m = $('msg'); m.textContent = text; m.className = cls || ''; }

async function loadOptions() {
    const s = await chrome.storage.local.get({ harnessId: 'browser-extension', liveweaveDriver: '' });
    const mode = s.harnessId === 'liveweave' ? 'liveweave' : 'browser-extension';
    const radio = document.querySelector(`input[name="mode"][value="${mode}"]`);
    if (radio) radio.checked = true;
    $('driver').value = s.liveweaveDriver || '';
}

function selectedMode() {
    return document.querySelector('input[name="mode"]:checked')?.value || 'browser-extension';
}

$('pair').addEventListener('click', () => {
    const code = $('code').value;
    const harnessId = selectedMode();
    const liveweaveDriver = $('driver').value.trim().toLowerCase();
    chrome.storage.local.set({ harnessId, liveweaveDriver });
    setMsg('Pairing…');
    chrome.runtime.sendMessage({ kind: 'pair', code, harnessId, liveweaveDriver }, (r) => {
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
