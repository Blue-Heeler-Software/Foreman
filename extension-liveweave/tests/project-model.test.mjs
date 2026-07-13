import test from 'node:test';
import assert from 'node:assert/strict';
import {
    boundedScan,
    createProject,
    exportDocument,
    readProjectSource,
    replaceProjectSource,
    searchProjectSource,
} from '../project-model.mjs';
import { buildNanoEditPrompt, parseNanoEditResponse } from '../nano-model.mjs';
import { canvasNeedsReload, canvasRuntimeReady } from '../canvas-runtime.mjs';

test('readProjectSource pages through a large source file', () => {
    const project = createProject({ html: 'x'.repeat(60000), css: 'body{}' });
    const first = readProjectSource(project, 'html', 0, 48000);
    const second = readProjectSource(project, 'html', first.nextOffset, 48000);
    assert.equal(first.length, 48000);
    assert.equal(first.eof, false);
    assert.equal(second.length, 12000);
    assert.equal(second.eof, true);
});

test('boundedScan keeps broker results bounded and advertises chunked reads', () => {
    const project = createProject({ html: `<main>${'a'.repeat(50000)}</main>`, css: 'body{}', sourceUrl: 'https://example.test/private?q=secret', kind: 'imported' });
    const result = boundedScan(project, { ids: Array.from({ length: 500 }, (_, i) => `id-${i}-${'x'.repeat(1000)}`) });
    assert.equal(result.truncated, true);
    assert.equal(result.structure.ids.length, 40);
    assert.equal(result.structure.ids[0].length, 120);
    assert.equal(result.sourceOrigin, 'https://example.test');
    assert.match(result.note, /read_source/);
    assert.ok(JSON.stringify(result).length < 64 * 1024);
});

test('search and revision-safe replacement operate on project source', () => {
    const project = createProject({ html: '<main>Fresh lollies</main>', css: '.hero{color:red}' });
    const found = searchProjectSource(project, 'lollies');
    assert.equal(found.matches[0].file, 'html');
    const conflict = replaceProjectSource(project, { file: 'html', start: 6, end: 19, text: 'Candy', expectedRevision: 99 });
    assert.equal(conflict.code, 'revision_conflict');
    const replaced = replaceProjectSource(project, { file: 'html', start: 6, end: 19, text: 'Candy', expectedRevision: project.revision });
    assert.equal(replaced.ok, true);
    assert.equal(replaced.project.html, '<main>Candy</main>');
    assert.equal(replaced.project.revision, project.revision + 1);
});

test('exportDocument escapes the title and includes project HTML and CSS', () => {
    const html = exportDocument({ title: 'A < B', html: '<main>Hello</main>', css: 'main{color:red}' });
    assert.match(html, /<title>A &lt; B<\/title>/);
    assert.match(html, /main\{color:red\}/);
    assert.match(html, /<main>Hello<\/main>/);
});

test('Nano edit prompt marks imported markup as untrusted and caps context', () => {
    const prompt = buildNanoEditPrompt({
        instruction: 'Make this card readable',
        path: '#card',
        outerHtml: `<section>${'x'.repeat(20000)}</section>`,
        styles: { color: 'rgb(0, 0, 0)' },
    });
    assert.match(prompt, /BEGIN UNTRUSTED TARGET MARKUP/);
    assert.match(prompt, /Make this card readable/);
    assert.ok(prompt.length < 17000);
});

test('Nano edit response accepts bounded HTML and declaration patches', () => {
    const parsed = parseNanoEditResponse('```json\n{"innerHtml":"<h2>Fixed</h2>","styles":"padding:24px;color:#111","summary":"Improved the card."}\n```');
    assert.equal(parsed.ok, true);
    assert.equal(parsed.innerHtml, '<h2>Fixed</h2>');
    assert.equal(parsed.styles, 'padding:24px;color:#111');
});

test('Nano edit response rejects active CSS and empty edits', () => {
    assert.equal(parseNanoEditResponse('{"innerHtml":null,"styles":"background:url(https://x.test/a)","summary":"x"}').ok, false);
    assert.equal(parseNanoEditResponse('{"innerHtml":null,"styles":"","summary":"x"}').ok, false);
});

test('canvas runtime requires matching toolbar and sandbox handshakes', () => {
    const ready = { hasPort: true, canvasVersion: '0.4.1', previewVersion: '0.4.1', extensionVersion: '0.4.1' };
    assert.equal(canvasRuntimeReady(ready), true);
    assert.equal(canvasNeedsReload({ ...ready, previewVersion: '' }), true);
    assert.equal(canvasNeedsReload({ ...ready, canvasVersion: '0.4.0' }), true);
    assert.equal(canvasNeedsReload({ ...ready, hasPort: false }), true);
});
