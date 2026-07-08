const $ = (id) => document.getElementById(id);

function setMsg(text, cls) { const m = $('msg'); m.textContent = text; m.className = cls || ''; }

async function loadOptions() {
    const s = await chrome.storage.local.get({ liveweaveDriver: '', token: '' });
    $('driver').value = s.liveweaveDriver || '';
    $('pairedBlock').style.display = s.token ? 'block' : 'none';   // show Unpair only when a token is stored
}

// Forget the stored token/origin/driver. The service worker watches these settings keys and drops its in-memory
// token + MCP session on the change, so no explicit message is needed.
$('unpair').addEventListener('click', async () => {
    await chrome.storage.local.remove(['token', 'pairedOrigin', 'liveweaveDriver']);
    $('driver').value = '';
    $('pairedBlock').style.display = 'none';
    setMsg('Unpaired — token forgotten. Pair again to reconnect.', 'ok');
});

$('pair').addEventListener('click', () => {
    const code = $('code').value;
    const liveweaveDriver = $('driver').value.trim().toLowerCase();
    setMsg('Pairing…');
    // Persist the chosen driver only AFTER pairing succeeds (background.js saves it on success too) — a failed
    // pair used to leave a driver id stored against no token.
    chrome.runtime.sendMessage({ kind: 'pair', code, liveweaveDriver }, (r) => {
        if (chrome.runtime.lastError) { setMsg(chrome.runtime.lastError.message, 'err'); return; }
        if (r?.ok) { chrome.storage.local.set({ harnessId: 'liveweave', liveweaveDriver }); setMsg('✓ Paired. Click Close, then open the side panel.', 'ok'); }
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
