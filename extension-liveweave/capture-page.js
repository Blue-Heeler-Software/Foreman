(() => {
    const MAX_CAPTURE_CHARS = 2 * 1024 * 1024;
    const warnings = [];
    const stats = {
        scriptsRemoved: 0,
        handlersRemoved: 0,
        framesRemoved: 0,
        formsNeutralized: 0,
        inaccessibleStylesheets: 0,
        externalAssets: 0,
    };

    const absoluteUrl = (value, base) => {
        const text = String(value || '').trim();
        if (!text || text.startsWith('#') || /^(data|blob|mailto|tel):/i.test(text)) return text;
        if (/^javascript:/i.test(text)) return '#';
        try { return new URL(text, base).href; } catch { return text; }
    };

    const rewriteCssUrls = (css, base) => String(css || '').replace(/url\(\s*(['"]?)([^)'"\s]+)\1\s*\)/gi,
        (_all, quote, url) => `url(${quote}${absoluteUrl(url, base)}${quote})`);

    const clone = document.documentElement.cloneNode(true);
    const base = document.baseURI || location.href;

    const cssParts = [];
    for (const sheet of document.styleSheets) {
        try {
            const sheetBase = sheet.href || base;
            const text = [...sheet.cssRules].map((rule) => rule.cssText).join('\n');
            if (text) cssParts.push(rewriteCssUrls(text, sheetBase));
        } catch {
            stats.inaccessibleStylesheets++;
            if (sheet.href) warnings.push(`Stylesheet could not be read: ${sheet.href}`);
        }
    }

    stats.scriptsRemoved = clone.querySelectorAll('script').length;
    clone.querySelectorAll('script,base,meta[http-equiv="refresh"],object,embed').forEach((el) => el.remove());
    clone.querySelectorAll('style,link[rel~="stylesheet"]').forEach((el) => el.remove());

    clone.querySelectorAll('iframe,frame').forEach((frame) => {
        const placeholder = document.createElement('div');
        placeholder.setAttribute('data-liveweave-placeholder', 'frame');
        placeholder.textContent = `Embedded frame omitted: ${absoluteUrl(frame.getAttribute('src'), base) || 'inline frame'}`;
        frame.replaceWith(placeholder);
        stats.framesRemoved++;
    });

    const urlAttrs = ['src', 'href', 'xlink:href', 'poster', 'action', 'cite', 'background'];
    clone.querySelectorAll('*').forEach((el) => {
        for (const attr of [...el.attributes]) {
            if (/^on/i.test(attr.name)) {
                el.removeAttribute(attr.name);
                stats.handlersRemoved++;
            }
        }
        for (const name of urlAttrs) {
            if (!el.hasAttribute(name)) continue;
            const resolved = absoluteUrl(el.getAttribute(name), base);
            el.setAttribute(name, resolved);
            if (!['href', 'xlink:href', 'action', 'cite'].includes(name) && /^https?:/i.test(resolved)) stats.externalAssets++;
        }
        if (el.hasAttribute('srcset')) {
            const next = el.getAttribute('srcset').split(',').map((entry) => {
                const parts = entry.trim().split(/\s+/);
                return [absoluteUrl(parts.shift(), base), ...parts].join(' ');
            }).join(', ');
            el.setAttribute('srcset', next);
        }
        if (el.hasAttribute('style')) el.setAttribute('style', rewriteCssUrls(el.getAttribute('style'), base));
    });

    clone.querySelectorAll('form').forEach((form) => {
        form.removeAttribute('action');
        form.setAttribute('data-liveweave-form', 'disabled-in-preview');
        stats.formsNeutralized++;
    });

    const html = clone.querySelector('body')?.innerHTML || '';
    const css = cssParts.join('\n\n');
    if (stats.scriptsRemoved) warnings.push(`${stats.scriptsRemoved} script element(s) were removed for safe preview.`);
    if (stats.handlersRemoved) warnings.push(`${stats.handlersRemoved} inline event handler(s) were removed.`);
    if (stats.framesRemoved) warnings.push(`${stats.framesRemoved} embedded frame(s) were replaced with placeholders.`);
    if (stats.externalAssets) warnings.push('External assets were left as absolute URLs and are blocked by the offline preview policy.');
    if (document.querySelector('canvas')) warnings.push('Canvas pixels are not represented in the HTML snapshot.');
    if (html.length + css.length > MAX_CAPTURE_CHARS) {
        return { ok: false, code: 'capture_too_large', error: 'Rendered page exceeds the 2 MB LiveWeave import limit.' };
    }

    return {
        ok: true,
        title: document.title || location.hostname || 'Imported page',
        url: location.href,
        html,
        css,
        warnings: warnings.slice(0, 50),
        stats,
    };
})();
