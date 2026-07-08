/**
 * LiveWeave offscreen DOM helper.
 *
 * The MV3 service worker has no DOM, so builder operations that need a real CSS-selector engine — targeting an
 * element by selector, inserting into a container, computing structure — run in this hidden offscreen document and
 * return serialized HTML / plain data. It never touches storage or the network; it's a pure string transformer the
 * worker calls, with the worker falling back to string handling if offscreen is unavailable.
 */

const parser = new DOMParser();

// Parse a canvas HTML fragment inside a <body> so top-level nodes are addressable and serialization round-trips.
function parse(html) {
    return parser.parseFromString(`<!doctype html><html><body>${html || ''}</body></html>`, 'text/html');
}

function inspect(doc) {
    const headings = [...doc.querySelectorAll('h1,h2,h3,h4,h5,h6')].map((h) => ({
        level: Number(h.tagName[1]),
        text: (h.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 120),
        id: h.id || undefined,
    }));
    const ids = [...doc.querySelectorAll('[id]')].map((e) => e.id);
    const duplicateIds = [...new Set(ids.filter((v, i) => ids.indexOf(v) !== i))];
    const landmarks = {};
    for (const t of ['header', 'nav', 'main', 'section', 'article', 'aside', 'footer', 'form']) {
        const n = doc.querySelectorAll(t).length;
        if (n) landmarks[t] = n;
    }
    // Shallow manifest of the top-level structural children (what an agent would target next).
    const root = doc.querySelector('main') || doc.body;
    const children = [...root.children].map((el) => ({
        tag: el.tagName.toLowerCase(),
        id: el.id || undefined,
        classes: el.className ? String(el.className).split(/\s+/).filter(Boolean) : undefined,
        text: (el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 60) || undefined,
    }));
    return { headings, ids, duplicateIds, landmarks, elementCount: doc.body.querySelectorAll('*').length, children };
}

function handle(msg) {
    switch (msg.op) {
        case 'apply_inner': {
            const doc = parse(msg.html);
            const el = doc.querySelector(msg.path);
            if (!el) return { ok: false, code: 'not_found', error: `No element matches selector '${msg.path}'.` };
            el.innerHTML = msg.inner ?? '';
            return { ok: true, html: doc.body.innerHTML };
        }
        case 'apply_section': {
            const doc = parse(msg.html);
            const where = msg.placement === 'prepend' ? 'afterbegin' : 'beforeend';
            if (msg.target) {
                const el = doc.querySelector(msg.target);
                if (!el) return { ok: false, code: 'not_found', error: `No element matches target '${msg.target}'.` };
                el.insertAdjacentHTML(where, String(msg.section || ''));
            } else {
                doc.body.insertAdjacentHTML(where, String(msg.section || ''));
            }
            return { ok: true, html: doc.body.innerHTML };
        }
        case 'inspect':
            return { ok: true, ...inspect(parse(msg.html)) };
        default:
            return { ok: false, error: `Unknown offscreen op '${msg.op}'.` };
    }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.target !== 'liveweave-offscreen') return false;   // not ours — let other listeners handle it
    try { sendResponse(handle(msg)); }
    catch (e) { sendResponse({ ok: false, error: String(e?.message || e) }); }
    return false;   // response sent synchronously
});
