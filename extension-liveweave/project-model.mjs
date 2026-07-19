export const SOURCE_FILES = ['html', 'css'];
export const MAX_SOURCE_READ_CHARS = 48 * 1024;
export const MAX_SCAN_INLINE_CHARS = 40 * 1024;
const MAX_SCAN_RESULT_TARGET = 52 * 1024;

export function canvasCsp(nonce) {
    const value = String(nonce || '');
    if (!/^[a-f0-9]{32,128}$/i.test(value)) throw new Error('A strong hexadecimal preview nonce is required.');
    return "default-src 'none'; img-src data:; font-src data:; style-src 'unsafe-inline'; " +
        `script-src 'nonce-${value}'; base-uri 'none'; form-action 'none'; object-src 'none'`;
}

function nowIso() {
    return new Date().toISOString();
}

function nextId() {
    if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
    return `lw-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function createProject({ title, html = '', css = '', sourceUrl = '', warnings = [], kind = 'blank' } = {}) {
    const now = nowIso();
    return {
        id: nextId(),
        title: String(title || 'Untitled LiveWeave Page').slice(0, 240),
        html: String(html || ''),
        css: String(css || ''),
        source: {
            kind,
            url: String(sourceUrl || '').slice(0, 4096),
            capturedAt: kind === 'imported' ? now : '',
        },
        warnings: Array.isArray(warnings) ? warnings.map((value) => String(value).slice(0, 500)).slice(0, 50) : [],
        revision: 1,
        dirty: true,
        createdAt: now,
        updatedAt: now,
        savedAt: '',
    };
}

export function canvasFromProject(project) {
    return {
        projectId: project.id,
        title: project.title,
        html: project.html,
        css: project.css,
        sourceUrl: project.source?.url || '',
        revision: Number(project.revision || 1),
        dirty: !!project.dirty,
        updatedAt: project.updatedAt || nowIso(),
    };
}

export function updateProjectFromCanvas(project, canvas, { markDirty = true } = {}) {
    const changed = project.title !== canvas.title || project.html !== canvas.html || project.css !== canvas.css;
    const revision = changed ? Number(project.revision || 0) + 1 : Number(project.revision || 1);
    return {
        ...project,
        title: String(canvas.title || project.title || 'Untitled LiveWeave Page').slice(0, 240),
        html: String(canvas.html || ''),
        css: String(canvas.css || ''),
        revision,
        dirty: changed && markDirty ? true : !!project.dirty,
        updatedAt: nowIso(),
    };
}

export function markProjectSaved(project) {
    const now = nowIso();
    return { ...project, dirty: false, savedAt: now, updatedAt: now };
}

function sourceFor(project, file) {
    const key = String(file || '').toLowerCase();
    if (!SOURCE_FILES.includes(key)) throw new Error("file must be 'html' or 'css'.");
    return { key, text: String(project?.[key] || '') };
}

export function readProjectSource(project, file, offset = 0, length = MAX_SOURCE_READ_CHARS) {
    const { key, text } = sourceFor(project, file);
    const start = Math.max(0, Math.min(Number(offset) || 0, text.length));
    const take = Math.max(1, Math.min(Number(length) || MAX_SOURCE_READ_CHARS, MAX_SOURCE_READ_CHARS));
    const content = text.slice(start, start + take);
    const nextOffset = start + content.length;
    return {
        file: key,
        content,
        offset: start,
        length: content.length,
        totalLength: text.length,
        nextOffset,
        eof: nextOffset >= text.length,
        revision: Number(project?.revision || 0),
    };
}

export function searchProjectSource(project, query, file = '', limit = 20) {
    const needle = String(query || '');
    if (!needle) throw new Error('query is required.');
    const keys = file ? [sourceFor(project, file).key] : SOURCE_FILES;
    const max = Math.max(1, Math.min(Number(limit) || 20, 50));
    const matches = [];
    for (const key of keys) {
        const text = String(project?.[key] || '');
        const lower = text.toLowerCase();
        const wanted = needle.toLowerCase();
        let from = 0;
        while (matches.length < max) {
            const index = lower.indexOf(wanted, from);
            if (index < 0) break;
            const line = text.slice(0, index).split('\n').length;
            matches.push({
                file: key,
                index,
                line,
                context: text.slice(Math.max(0, index - 80), Math.min(text.length, index + needle.length + 120)),
            });
            from = index + Math.max(1, needle.length);
        }
        if (matches.length >= max) break;
    }
    return { query: needle, matches, limited: matches.length >= max, revision: Number(project?.revision || 0) };
}

export function replaceProjectSource(project, { file, start, end, text = '', expectedRevision } = {}) {
    const currentRevision = Number(project?.revision || 0);
    if (Number(expectedRevision) !== currentRevision) {
        return {
            ok: false,
            code: 'revision_conflict',
            error: `Project changed: expected revision ${expectedRevision}, current revision is ${currentRevision}.`,
            revision: currentRevision,
        };
    }
    const source = sourceFor(project, file);
    const from = Math.max(0, Math.min(Number(start) || 0, source.text.length));
    const to = Math.max(from, Math.min(Number(end) || 0, source.text.length));
    const nextText = source.text.slice(0, from) + String(text ?? '') + source.text.slice(to);
    const next = {
        ...project,
        [source.key]: nextText,
        revision: currentRevision + 1,
        dirty: true,
        updatedAt: nowIso(),
    };
    return { ok: true, project: next, file: source.key, start: from, end: to, insertedLength: String(text ?? '').length };
}

export function boundedScan(project, structure = {}) {
    const html = String(project?.html || '');
    const css = String(project?.css || '');
    const total = html.length + css.length;
    const cappedStructure = capStructure(structure);
    const sourceBudget = Math.max(4 * 1024,
        Math.min(MAX_SCAN_INLINE_CHARS, MAX_SCAN_RESULT_TARGET - JSON.stringify(cappedStructure).length - 2048));
    const files = [
        { file: 'html', length: html.length },
        { file: 'css', length: css.length },
    ];
    const base = {
        title: String(project?.title || 'LiveWeave Canvas').slice(0, 240),
        projectId: String(project?.id || project?.projectId || '').slice(0, 120),
        sourceOrigin: sourceOrigin(project?.source?.url || project?.sourceUrl || ''),
        revision: Number(project?.revision || 0),
        files,
        structure: cappedStructure,
    };
    if (total <= sourceBudget) return { ...base, html, css, truncated: false };
    const htmlBudget = Math.min(html.length, Math.floor(sourceBudget * 0.7));
    const cssBudget = Math.min(css.length, sourceBudget - htmlBudget);
    return {
        ...base,
        html: html.slice(0, htmlBudget),
        css: css.slice(0, cssBudget),
        truncated: true,
        note: 'Source preview was truncated. Use read_source with file/offset/length to pull the complete project.',
    };
}

export function capStructure(structure = {}) {
    const short = (value, length = 240) => String(value ?? '').slice(0, length);
    return {
        headings: Array.isArray(structure.headings) ? structure.headings.slice(0, 20).map((heading) => ({
            level: Math.max(1, Math.min(Number(heading?.level || 1), 6)),
            text: short(heading?.text, 120),
            id: heading?.id ? short(heading.id, 120) : undefined,
        })) : [],
        ids: Array.isArray(structure.ids) ? structure.ids.slice(0, 40).map((id) => short(id, 120)) : [],
        duplicateIds: Array.isArray(structure.duplicateIds) ? structure.duplicateIds.slice(0, 10).map((id) => short(id, 120)) : [],
        landmarks: structure.landmarks && typeof structure.landmarks === 'object' ? structure.landmarks : {},
        elementCount: Number(structure.elementCount || 0),
        children: Array.isArray(structure.children) ? structure.children.slice(0, 15).map((child) => ({
            tag: short(child?.tag, 40),
            id: child?.id ? short(child.id, 120) : undefined,
            classes: Array.isArray(child?.classes) ? child.classes.slice(0, 4).map((item) => short(item, 40)) : undefined,
            text: child?.text ? short(child.text, 80) : undefined,
        })) : undefined,
    };
}

function sourceOrigin(value) {
    try {
        const url = new URL(String(value || ''));
        return /^https?:$/.test(url.protocol) ? url.origin : url.protocol;
    } catch { return ''; }
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

export function exportDocument(project) {
    return `<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n` +
        `<meta name="viewport" content="width=device-width, initial-scale=1">\n<title>${escapeHtml(project?.title || 'LiveWeave Page')}</title>\n` +
        `<style>\n${project?.css || ''}\n</style>\n</head>\n<body>\n${project?.html || ''}\n</body>\n</html>\n`;
}

export function slugify(value) {
    return String(value || 'liveweave-page').toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '') || 'liveweave-page';
}
