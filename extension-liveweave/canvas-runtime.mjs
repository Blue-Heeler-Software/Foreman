export function canvasRuntimeReady({ hasPort, canvasVersion, previewVersion, extensionVersion }) {
    const expected = String(extensionVersion || '');
    return !!hasPort
        && !!expected
        && String(canvasVersion || '') === expected
        && String(previewVersion || '') === expected;
}

export function canvasNeedsReload(state) {
    return !canvasRuntimeReady(state);
}
