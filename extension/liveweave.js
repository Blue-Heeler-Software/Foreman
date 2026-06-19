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

render(await loadCanvas());
