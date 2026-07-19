import { canvasCsp, exportDocument, slugify } from './project-model.mjs';

const DEFAULT_CANVAS = {
    title: 'LiveWeave Canvas',
    html: '<main style="font-family:system-ui,sans-serif;padding:32px"><h1>LiveWeave Canvas</h1><p>Ready for edits.</p></main>',
    css: '',
    projectId: '',
    sourceUrl: '',
    revision: 0,
    dirty: false,
    updatedAt: new Date().toISOString(),
};

const $ = (id) => document.getElementById(id);
const INSPECTOR_CSS =
    'html[data-liveweave-picking],html[data-liveweave-picking] body,html[data-liveweave-picking] body *{cursor:crosshair !important}' +
    '[data-liveweave-hover]{outline:2px solid #5b8cff !important;outline-offset:2px !important;cursor:crosshair !important}' +
    '[data-liveweave-selected]{outline:2px solid #20b66a !important;outline-offset:2px !important}';

let current = DEFAULT_CANVAS;
let selectionMode = false;
let workerPort = null;
let previewLoaded = false;
let previewToken = '';

async function loadCanvas() {
    const state = await chrome.storage.local.get({ liveweaveCanvas: DEFAULT_CANVAS });
    return { ...DEFAULT_CANVAS, ...(state.liveweaveCanvas || {}) };
}

function inspectorBridge(enabled) {
    const token = arguments.length > 1 ? String(arguments[1]) : 'fixture-token';
    return `(() => {
      let enabled = ${enabled ? 'true' : 'false'};
      const token = ${JSON.stringify(token)};
      let hovered = null;
      let selected = null;
      const post = (kind, detail = {}) => parent.postMessage({ source: 'liveweave-preview', token, kind, ...detail }, '*');
      const esc = (value) => globalThis.CSS && CSS.escape ? CSS.escape(String(value)) : String(value).replace(/[^a-zA-Z0-9_-]/g, (c) => '\\\\' + c);
      const clearHover = () => { if (hovered) hovered.removeAttribute('data-liveweave-hover'); hovered = null; };
      const setEnabled = (value) => {
        enabled = !!value;
        document.documentElement.toggleAttribute('data-liveweave-picking', enabled);
        if (!enabled) clearHover();
        post('selection-ready', { enabled });
      };
      const count = (selector) => {
        try { return document.querySelectorAll(selector).length; }
        catch { return 0; }
      };
      const selectorFor = (element) => {
        if (element.id) {
          const byId = '#' + esc(element.id);
          if (count(byId) === 1) return byId;
        }
        const parts = [];
        let node = element;
        while (node && node.nodeType === 1 && node !== document.body && parts.length < 7) {
          let part = node.tagName.toLowerCase();
          const classes = [...node.classList].filter(Boolean).slice(0, 2);
          if (classes.length) part += classes.map((name) => '.' + esc(name)).join('');
          const parent = node.parentElement;
          if (parent) {
            const same = [...parent.children].filter((child) => child.tagName === node.tagName);
            if (same.length > 1) part += ':nth-of-type(' + (same.indexOf(node) + 1) + ')';
          }
          parts.unshift(part);
          const candidate = parts.join(' > ');
          if (count(candidate) === 1) return candidate;
          node = parent;
        }
        return parts.join(' > ');
      };
      const targetFor = (value) => {
        let target = value instanceof Element ? value : null;
        if (target && target.ownerSVGElement && target.tagName.toLowerCase() !== 'svg') target = target.closest('svg') || target;
        return target;
      };
      const px = (value) => Number.parseFloat(value) || 0;
      const describe = (element) => {
        const style = getComputedStyle(element);
        return {
          path: selectorFor(element).slice(0, 500),
          tag: element.tagName.toLowerCase().slice(0, 40),
          id: String(element.id || '').slice(0, 160),
          classes: [...element.classList].slice(0, 8).map((value) => String(value).slice(0, 120)),
          text: element.childElementCount === 0 ? String(element.textContent || '').trim().slice(0, 1000) : '',
          canEditText: element.childElementCount === 0,
          styles: {
            backgroundColor: style.backgroundColor,
            color: style.color,
            fontSize: px(style.fontSize),
            fontWeight: style.fontWeight,
            textAlign: style.textAlign,
            padding: px(style.paddingTop),
            margin: px(style.marginTop),
            borderRadius: px(style.borderRadius),
            borderWidth: px(style.borderTopWidth),
            borderColor: style.borderTopColor,
            width: style.width,
            display: style.display
          }
        };
      };
      addEventListener('message', (event) => {
        if (event.data && event.data.source === 'liveweave-parent' && event.data.token === token && event.data.kind === 'selection-mode') {
          setEnabled(event.data.enabled);
        }
      });
      document.addEventListener('submit', (event) => {
        event.preventDefault();
        event.stopImmediatePropagation();
      }, true);
      document.addEventListener('pointermove', (event) => {
        if (!enabled) return;
        const target = targetFor(event.target);
        if (!target || target === document.documentElement || target === document.body) return;
        if (target === hovered) return;
        clearHover();
        hovered = target;
        hovered.setAttribute('data-liveweave-hover', '');
      }, true);
      document.addEventListener('pointerleave', () => { if (enabled) clearHover(); }, true);
      document.addEventListener('click', (event) => {
        const clicked = targetFor(event.target);
        if (clicked?.closest?.('a[href],area[href]')) {
          event.preventDefault();
          event.stopImmediatePropagation();
          if (!enabled) return;
        }
        if (!enabled) return;
        const target = clicked;
        if (!target || target === document.documentElement || target === document.body) return;
        event.preventDefault();
        event.stopImmediatePropagation();
        if (selected) selected.removeAttribute('data-liveweave-selected');
        selected = target;
        selected.setAttribute('data-liveweave-selected', '');
        post('selection', { selection: describe(selected) });
        setEnabled(false);
        post('selection-complete');
      }, true);
      document.addEventListener('keydown', (event) => {
        if (enabled && event.key === 'Escape') {
          event.preventDefault();
          setEnabled(false);
          post('selection-complete');
        }
      }, true);
      setEnabled(enabled);
      post('runtime-ready');
    })();`;
}

function randomPreviewToken() {
    const bytes = new Uint8Array(24);
    crypto.getRandomValues(bytes);
    return [...bytes].map((value) => value.toString(16).padStart(2, '0')).join('');
}

function previewBody(html) {
    const template = document.createElement('template');
    template.innerHTML = String(html || '');
    template.content.querySelectorAll('base,meta[http-equiv]').forEach((node) => {
        if (node.tagName === 'BASE' || String(node.getAttribute('http-equiv') || '').toLowerCase() === 'refresh')
            node.remove();
    });
    return template.innerHTML;
}

function previewCss(css) {
    return String(css || '').replace(/<\/style/gi, '<\\/style');
}

function render(canvas) {
    current = canvas;
    previewLoaded = false;
    previewToken = randomPreviewToken();
    const nonce = previewToken;
    workerPort?.postMessage({ kind: 'preview-loading', version: chrome.runtime.getManifest().version });
    $('title').textContent = canvas.title || DEFAULT_CANVAS.title;
    $('source').textContent = canvas.sourceUrl ? safeHost(canvas.sourceUrl) : 'Local project';
    $('originalBtn').disabled = !canvas.sourceUrl;
    $('dirty').textContent = canvas.dirty ? '| unsaved' : '';
    $('meta').firstChild.textContent = canvas.updatedAt ? `Updated ${new Date(canvas.updatedAt).toLocaleTimeString()} ` : 'Ready ';
    $('preview').srcdoc = `<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="${canvasCsp(nonce)}">` +
        `<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><style>${previewCss(canvas.css)}</style>` +
        `<style>${INSPECTOR_CSS}</style><script nonce="${nonce}">${inspectorBridge(selectionMode, previewToken)}<\/script>` +
        `</head><body>${previewBody(canvas.html)}</body></html>`;
}

function safeHost(url) {
    try { return new URL(url).hostname || url; } catch { return 'Imported page'; }
}

function sanitizeSelection(value) {
    const styles = value?.styles || {};
    const short = (input, max = 160) => String(input ?? '').slice(0, max);
    const number = (input) => Math.max(0, Math.min(Number(input) || 0, 10000));
    return {
        path: short(value?.path, 500),
        tag: short(value?.tag, 40),
        id: short(value?.id),
        classes: Array.isArray(value?.classes) ? value.classes.slice(0, 8).map((item) => short(item, 120)) : [],
        text: short(value?.text, 1000),
        canEditText: !!value?.canEditText,
        styles: {
            backgroundColor: short(styles.backgroundColor, 80),
            color: short(styles.color, 80),
            fontSize: number(styles.fontSize),
            fontWeight: short(styles.fontWeight, 40),
            textAlign: short(styles.textAlign, 40),
            padding: number(styles.padding),
            margin: number(styles.margin),
            borderRadius: number(styles.borderRadius),
            borderWidth: number(styles.borderWidth),
            borderColor: short(styles.borderColor, 80),
            width: short(styles.width, 80),
            display: short(styles.display, 40),
        },
    };
}

function setSelectionMode(enabled) {
    selectionMode = !!enabled;
    $('selectBtn').classList.toggle('active', selectionMode);
    $('selectBtn').textContent = selectionMode ? 'Selecting' : 'Select';
    $('selectBtn').setAttribute('aria-pressed', String(selectionMode));
    $('stage').classList.toggle('selecting', selectionMode);
    $('preview').contentWindow?.postMessage({ source: 'liveweave-parent', token: previewToken, kind: 'selection-mode', enabled: selectionMode }, '*');
}

async function copyHtml() {
    try {
        await navigator.clipboard.writeText(exportDocument(current));
        flashMeta('Copied');
    } catch { flashMeta('Copy failed'); }
}

function downloadHtml() {
    const blob = new Blob([exportDocument(current)], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${slugify(current.title)}.html`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    flashMeta('Downloaded');
}

let flashTimer = null;
function flashMeta(text) {
    const meta = $('meta');
    const prior = meta.firstChild.textContent;
    meta.firstChild.textContent = `${text} `;
    clearTimeout(flashTimer);
    flashTimer = setTimeout(() => { meta.firstChild.textContent = prior; }, 1500);
}

$('selectBtn').addEventListener('click', () => {
    setSelectionMode(!selectionMode);
    workerPort?.postMessage({ kind: 'selection-mode-changed', enabled: selectionMode });
});
$('copyBtn').addEventListener('click', copyHtml);
$('downloadBtn').addEventListener('click', downloadHtml);
$('originalBtn').addEventListener('click', () => {
    if (current.sourceUrl) chrome.tabs.create({ url: current.sourceUrl });
});
document.querySelectorAll('[data-width]').forEach((button) => button.addEventListener('click', () => {
    const mode = button.dataset.width;
    $('frameShell').className = mode === 'desktop' ? '' : mode;
    document.querySelectorAll('[data-width]').forEach((candidate) => candidate.classList.toggle('active', candidate === button));
    flashMeta(mode === 'desktop' ? 'Desktop viewport' : mode === 'tablet' ? 'Tablet viewport 768px' : 'Mobile viewport 390px');
}));

window.addEventListener('message', (event) => {
    if (event.source !== $('preview').contentWindow ||
        event.data?.source !== 'liveweave-preview' ||
        event.data?.token !== previewToken) return;
    if (event.data.kind === 'runtime-ready') {
        previewLoaded = true;
        $('preview').contentWindow?.postMessage({
            source: 'liveweave-parent', token: previewToken, kind: 'selection-mode', enabled: selectionMode,
        }, '*');
        workerPort?.postMessage({ kind: 'preview-ready', version: chrome.runtime.getManifest().version });
    } else if (event.data.kind === 'selection') {
        const selection = sanitizeSelection(event.data.selection);
        if (selection.path) workerPort?.postMessage({ kind: 'preview-selection', selection });
    } else if (event.data.kind === 'selection-complete') {
        setSelectionMode(false);
        workerPort?.postMessage({ kind: 'selection-mode-changed', enabled: false });
    }
});

$('preview').addEventListener('load', () => {
    $('preview').contentWindow?.postMessage({
        source: 'liveweave-parent', token: previewToken, kind: 'selection-mode', enabled: selectionMode,
    }, '*');
});

document.addEventListener('keydown', (event) => {
    if (selectionMode && event.key === 'Escape') {
        setSelectionMode(false);
        workerPort?.postMessage({ kind: 'selection-mode-changed', enabled: false });
    }
});

chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.liveweaveCanvas) {
        render({ ...DEFAULT_CANVAS, ...(changes.liveweaveCanvas.newValue || {}) });
    }
});

function keepWorkerAwake() {
    try {
        const port = chrome.runtime.connect({ name: 'foreman-liveweave-canvas' });
        workerPort = port;
        port.postMessage({ kind: 'canvas-ready', version: chrome.runtime.getManifest().version });
        if (previewLoaded) port.postMessage({ kind: 'preview-ready', version: chrome.runtime.getManifest().version });
        port.onMessage.addListener((message) => {
            if (message?.kind === 'selection-mode') setSelectionMode(!!message.enabled);
        });
        port.onDisconnect.addListener(() => {
            if (workerPort === port) workerPort = null;
            void chrome.runtime.lastError;
            setTimeout(keepWorkerAwake, 1000);
        });
    } catch { /* extension context closed */ }
}

keepWorkerAwake();
render(await loadCanvas());
