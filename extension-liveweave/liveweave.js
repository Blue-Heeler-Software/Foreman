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

// The canvas renders AGENT-authored HTML/CSS. Without a policy it would inherit the permissive default and an
// agent could beacon data out on render via <img>/<link>/CSS url()/fetch to any host — falsifying LiveWeave's
// "nothing leaves your machine" guarantee. This CSP (first child of <head>, so it governs everything after it)
// blocks ALL network: only data: images/fonts and inline styles/scripts are allowed. Inline scripts still run
// (interactive previews), but cannot phone home. Residual: a script could still self-navigate the frame to an
// external URL (CSP has no reliable navigate directive); the sandbox blocks top-nav, storage, and same-origin,
// so that leaks only agent-embedded data, never operator secrets or tokens.
const CANVAS_CSP =
    "default-src 'none'; img-src data:; font-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; " +
    "base-uri 'none'; form-action 'none'";

let current = DEFAULT_CANVAS;   // latest rendered canvas, for export

function render(canvas) {
    current = canvas;
    $('title').textContent = canvas.title || DEFAULT_CANVAS.title;
    $('meta').textContent = canvas.updatedAt ? `updated ${new Date(canvas.updatedAt).toLocaleTimeString()}` : 'local extension page';
    $('preview').srcdoc = `<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="${CANVAS_CSP}">` +
        `<meta charset="utf-8"><style>${canvas.css || ''}</style></head><body>${canvas.html || ''}</body></html>`;
}

// The built page as one self-contained file (CSS inlined) — no export CSP, since this is the artifact the operator
// takes OUT of the tool, not the sandboxed preview.
function exportDocument(canvas) {
    const title = (canvas.title || 'LiveWeave Page').replace(/</g, '&lt;');
    return `<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n` +
        `<title>${title}</title>\n<style>\n${canvas.css || ''}\n</style>\n</head>\n<body>\n${canvas.html || ''}\n</body>\n</html>\n`;
}

function slugify(s) {
    return (String(s || 'liveweave-page').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')) || 'liveweave-page';
}

async function copyHtml() {
    try { await navigator.clipboard.writeText(exportDocument(current)); flashMeta('copied ✓'); }
    catch { flashMeta("couldn't copy"); }
}

function downloadHtml() {
    const blob = new Blob([exportDocument(current)], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${slugify(current.title)}.html`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    flashMeta('downloaded ✓');
}

let flashTimer = null;
function flashMeta(text) {
    const el = $('meta');
    const prior = el.textContent;
    el.textContent = text;
    clearTimeout(flashTimer);
    flashTimer = setTimeout(() => { el.textContent = prior; }, 1500);
}

$('copyBtn').addEventListener('click', copyHtml);
$('downloadBtn').addEventListener('click', downloadHtml);

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
