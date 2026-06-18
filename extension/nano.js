/**
 * On-device inference via Chrome's built-in AI (Gemini Nano) — Pillar 1 of the closed-loop spec.
 *
 * Nano is the FAST LANE, never the gate: Google gates it at the API level (Chrome 138+, ~22 GB free, a one-time
 * ~4 GB model download), so most users won't have it. Every entry point here degrades cleanly — if Nano is
 * absent or the model isn't downloaded, callers get 'unavailable' and the UI says so rather than breaking.
 *
 * Runs in the SIDE PANEL (an extension page), not the service worker — the LanguageModel global is exposed to
 * page contexts. Nothing here touches the network: Nano runs entirely on the device.
 */

// Resolve whichever shape of the API this Chrome exposes: the stabilised global `LanguageModel`, or the older
// origin-trial `ai.languageModel`. Returns null when neither exists.
function api() {
    if (typeof LanguageModel !== 'undefined' && LanguageModel) return { kind: 'global', m: LanguageModel };
    const ai = (typeof self !== 'undefined' && self.ai) || (typeof globalThis !== 'undefined' && globalThis.ai);
    if (ai?.languageModel) return { kind: 'ai', m: ai.languageModel };
    return null;
}

function normalize(state) {
    switch (String(state)) {
        case 'available':
        case 'readily': return 'available';
        case 'downloadable':
        case 'after-download': return 'downloadable';
        case 'downloading': return 'downloading';
        default: return 'unavailable';
    }
}

/** 'available' | 'downloadable' | 'downloading' | 'unavailable' — never throws. */
export async function nanoAvailability() {
    const a = api();
    if (!a) return 'unavailable';
    try {
        if (a.kind === 'global') return normalize(await a.m.availability());
        const caps = await a.m.capabilities();
        return normalize(caps?.available);
    } catch {
        return 'unavailable';
    }
}

// Create a session, tolerating builds that reject temperature/topK or systemPrompt params: fall back step by
// step to a bare create() rather than failing the whole call over an option shape.
async function createSession(a, systemPrompt, temperature) {
    const sys = systemPrompt
        ? (a.kind === 'global'
            ? { initialPrompts: [{ role: 'system', content: systemPrompt }] }
            : { systemPrompt })
        : {};
    const attempts = [
        { ...sys, temperature, topK: 1 },
        { ...sys, temperature },
        { ...sys },
        {},
    ];
    let lastErr;
    for (const opts of attempts) {
        try { return await a.m.create(opts); }
        catch (e) { lastErr = e; }
    }
    throw lastErr ?? new Error('Could not create an on-device model session.');
}

/**
 * Run one constrained on-device turn. Throws with a friendly message when Nano is unavailable, so the caller
 * can show it inline. Keep prompts tiny and single-job (Pillar 2): a small quantised model is only reliable on
 * narrow, validated micro-tasks.
 */
export async function nanoRun(systemPrompt, userPrompt, { temperature = 0 } = {}) {
    const a = api();
    if (!a) throw new Error('On-device AI (Gemini Nano) is not available in this browser. Use Chrome 138+ with the built-in AI model installed.');
    const avail = await nanoAvailability();
    if (avail === 'unavailable') throw new Error('On-device AI model is not installed. See chrome://components → Optimization Guide On Device Model.');
    if (avail === 'downloading' || avail === 'downloadable') throw new Error('On-device AI model is still downloading — try again once it finishes.');

    let session;
    try {
        session = await createSession(a, systemPrompt, temperature);
        const out = await session.prompt(userPrompt);
        return String(out ?? '').trim();
    } finally {
        try { session?.destroy?.(); } catch { /* ok */ }
    }
}
