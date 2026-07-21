import test from 'node:test';
import assert from 'node:assert/strict';
import { canvasRuntimeStateFromPorts, createAsyncDeadlineGate } from '../service-worker-state.mjs';

test('canvas runtime is ready when any connected canvas has matching versions', () => {
    const ports = new Map([
        [{ id: 1 }, { canvasVersion: 'old', previewVersion: 'old' }],
        [{ id: 2 }, { canvasVersion: '0.4.1', previewVersion: '0.4.1' }],
    ]);
    assert.deepEqual(canvasRuntimeStateFromPorts(ports, '0.4.1'), {
        hasPort: true,
        canvasVersion: '0.4.1',
        previewVersion: '0.4.1',
        extensionVersion: '0.4.1',
    });
});

test('deadline gate prevents overlap and releases after a stuck poll times out', async () => {
    let release;
    const stuck = new Promise((resolve) => { release = resolve; });
    const gate = createAsyncDeadlineGate(15);
    const first = gate.run(() => stuck);

    assert.equal((await gate.run(() => 'overlap')).started, false);
    const timedOut = await first;
    assert.equal(timedOut.timedOut, true);
    assert.equal(gate.active, false);

    const recovered = await gate.run(() => 'recovered');
    assert.equal(recovered.value, 'recovered');
    release();
});
