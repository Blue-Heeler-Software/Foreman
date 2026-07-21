export function canvasRuntimeStateFromPorts(portStates, extensionVersion) {
    const states = [...portStates.values()];
    const expected = String(extensionVersion || '');
    const ready = states.find((s) => String(s.canvasVersion || '') === expected
        && String(s.previewVersion || '') === expected);
    const representative = ready || states[0] || {};
    return {
        hasPort: states.length > 0,
        canvasVersion: String(representative.canvasVersion || ''),
        previewVersion: String(representative.previewVersion || ''),
        extensionVersion: expected,
    };
}

// One poll at a time, with a hard deadline so a lost callback/network request cannot wedge an MV3 worker forever.
// A timed-out task is observed to avoid an unhandled rejection; callers may start a new poll after the gate releases.
export function createAsyncDeadlineGate(timeoutMs, timers = globalThis) {
    let active = false;
    return {
        get active() { return active; },
        async run(task) {
            if (active) return { started: false, timedOut: false, value: undefined, error: null };
            active = true;
            let timer = null;
            const work = Promise.resolve().then(task);
            const settled = work.then(
                (value) => ({ kind: 'value', value }),
                (error) => ({ kind: 'error', error }));
            const deadline = new Promise((resolve) => {
                timer = timers.setTimeout(() => resolve({ kind: 'timeout' }), timeoutMs);
            });
            try {
                const result = await Promise.race([settled, deadline]);
                if (result.kind === 'timeout') {
                    settled.catch(() => {});
                    return { started: true, timedOut: true, value: undefined, error: null };
                }
                if (result.kind === 'error')
                    return { started: true, timedOut: false, value: undefined, error: result.error };
                return { started: true, timedOut: false, value: result.value, error: null };
            } finally {
                if (timer !== null) timers.clearTimeout(timer);
                active = false;
            }
        },
    };
}
