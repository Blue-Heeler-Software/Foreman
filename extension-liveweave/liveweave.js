const DEFAULT_CANVAS = {
    title: 'LiveWeave Canvas',
    html: '<main style="font-family: system-ui, sans-serif; padding: 32px;"><h1>LiveWeave Canvas</h1><p>Ready for Foreman-brokered edits.</p></main>',
    css: '',
    updatedAt: new Date().toISOString(),
};

const $ = (id) => document.getElementById(id);

async function loadCanvas() {
    const s = await chrome.storage.local.get({ liveweaveCanvas: DEFAULT_CANVAS });
    return { ...DEFAULT_CANVAS, ...(s.liveweaveCanvas || {}) };
}

function render(canvas) {
    $('title').textContent = canvas.title || DEFAULT_CANVAS.title;
    $('meta').textContent = canvas.updatedAt ? `updated ${new Date(canvas.updatedAt).toLocaleTimeString()}` : 'local extension page';
    $('preview').srcdoc = `<!doctype html><html><head><meta charset="utf-8"><style>${canvas.css || ''}</style></head><body>${canvas.html || ''}</body></html>`;
}

chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.liveweaveCanvas) {
        render({ ...DEFAULT_CANVAS, ...(changes.liveweaveCanvas.newValue || {}) });
    }
});

// Hold a port open to the service worker while this canvas is up: a connected port keeps the MV3 worker alive, so
// its fast poll loop runs and Foreman-brokered edits apply promptly while you're actively building. When the canvas
// closes the port drops and the worker falls back to its alarm heartbeat. Reconnect if the worker recycles the port.
function keepWorkerAwake() {
    try {
        const port = chrome.runtime.connect({ name: 'foreman-liveweave-canvas' });
        port.onDisconnect.addListener(() => {
            void chrome.runtime.lastError;                 // swallow "worker was suspended" disconnects
            setTimeout(keepWorkerAwake, 1000);             // re-establish so building stays responsive
        });
    } catch { /* extension context gone — nothing to keep awake */ }
}
keepWorkerAwake();

render(await loadCanvas());
