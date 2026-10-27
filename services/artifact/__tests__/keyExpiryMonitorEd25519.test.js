'use strict';

// FINAL LOCAL CLOSURE / early-warning half: the periodic key-expiry monitor must also cover the
// transparency and checkpoint Ed25519 stores (checked only at startup before this change, so a long-running gateway gave
// no warning before their day-180 expiry and the next restart was a startup FATAL). Same loading pattern as
// keyExpiryMonitor.test.js.

const fs = require('fs');
const os = require('os');
const path = require('path');

let logger; let metrics; let tStore; let cStore;
let tmpDir;

function makeGauge() { return { set: jest.fn() }; }

function loadModule({ transparency, checkpoint, artifact = { expiringKeys: [], overdueKeys: [] } }) {
  jest.resetModules();
  delete process.env.QODIQA_KEY_EXPIRY_MONITOR_ENABLED;
  process.env.QODIQA_KEY_EXPIRY_CHECK_INTERVAL_MS = '1000';
  jest.doMock('../../logger', () => ({ emit: jest.fn() }));
  jest.doMock('../../../src/observability/metrics', () => ({
    keyExpiryMonitorRunsTotal: { inc: jest.fn() },
    keyExpiryApproachingCount: makeGauge(),
    keyRotationOverdueCount: makeGauge(),
  }));
  jest.doMock('../keyStore', () => ({ validateKeyStore: jest.fn(() => artifact) }));
  jest.doMock('../../../src/core/transparency/transparencyKeyStore', () => transparency);
  jest.doMock('../../../src/core/audit/checkpoint/checkpointKeyStore', () => checkpoint);
  logger = require('../../logger');
  metrics = require('../../../src/observability/metrics');
  tStore = require('../../../src/core/transparency/transparencyKeyStore');
  cStore = require('../../../src/core/audit/checkpoint/checkpointKeyStore');
  return require('../keyExpiryMonitor');
}

function storeAt(file, result) {
  return { DATA_PATH: file, validateKeyStore: typeof result === 'function' ? jest.fn(result) : jest.fn(() => result) };
}
const empty = { expiredKeys: [], expiringKeys: [], overdueKeys: [] };
const events = (name) => logger.emit.mock.calls.filter((c) => c[1] === name).map((c) => c[2]);

beforeEach(() => {
  jest.useFakeTimers();
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-kem-ed-'));
  fs.writeFileSync(path.join(tmpDir, 'transparency-keys.json'), '{}');
  fs.writeFileSync(path.join(tmpDir, 'checkpoint-keys.json'), '{}');
});
afterEach(() => {
  jest.useRealTimers();
  delete process.env.QODIQA_KEY_EXPIRY_CHECK_INTERVAL_MS;
  for (const m of ['../../logger', '../../../src/observability/metrics', '../keyStore',
    '../../../src/core/transparency/transparencyKeyStore', '../../../src/core/audit/checkpoint/checkpointKeyStore']) jest.dontMock(m);
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('keyExpiryMonitor — transparency and checkpoint stores', () => {
  test('KEM-ED-01 an expiring transparency key emits KEY_EXPIRING_SOON (store=transparency) and counts in the gauge', () => {
    const mod = loadModule({
      transparency: storeAt(path.join(tmpDir, 'transparency-keys.json'), { ...empty, expiringKeys: [{ keyId: 'tr:key_v1', daysRemaining: 12 }] }),
      checkpoint: storeAt(path.join(tmpDir, 'checkpoint-keys.json'), empty),
      artifact: { expiringKeys: [{ clientId: 'c', keyId: 'c:key_v1', daysRemaining: 5 }], overdueKeys: [] },
    });
    mod.initialize(); jest.advanceTimersByTime(1000); mod.shutdown();
    expect(events('KEY_EXPIRING_SOON')).toEqual(expect.arrayContaining([
      expect.objectContaining({ store: 'transparency', keyId: 'tr:key_v1', daysRemaining: 12, source: 'PERIODIC_MONITOR' }),
    ]));
    expect(metrics.keyExpiryApproachingCount.set).toHaveBeenLastCalledWith({}, 2);
  });

  test('KEM-ED-02 an EXPIRED checkpoint key emits KEY_EXPIRED (ERROR) and keeps the expiry alert firing', () => {
    const mod = loadModule({
      transparency: storeAt(path.join(tmpDir, 'transparency-keys.json'), empty),
      checkpoint: storeAt(path.join(tmpDir, 'checkpoint-keys.json'), { ...empty, expiredKeys: [{ keyId: 'cp:key_v1', expiresAt: '2026-01-01T00:00:00Z' }] }),
    });
    mod.initialize(); jest.advanceTimersByTime(1000); mod.shutdown();
    const err = logger.emit.mock.calls.find((c) => c[1] === 'KEY_EXPIRED');
    expect(err && err[0]).toBe('ERROR');
    expect(err[2]).toEqual(expect.objectContaining({ store: 'checkpoint', keyId: 'cp:key_v1' }));
    expect(metrics.keyExpiryApproachingCount.set).toHaveBeenLastCalledWith({}, 1);
  });

  test('KEM-ED-03 a store whose key file does not exist is skipped (never bootstrapped by the monitor)', () => {
    const mod = loadModule({
      transparency: storeAt(path.join(tmpDir, 'absent-transparency.json'), empty),
      checkpoint: storeAt(path.join(tmpDir, 'absent-checkpoint.json'), empty),
    });
    mod.initialize(); jest.advanceTimersByTime(1000); mod.shutdown();
    expect(tStore.validateKeyStore).not.toHaveBeenCalled();
    expect(cStore.validateKeyStore).not.toHaveBeenCalled();
    expect(metrics.keyExpiryApproachingCount.set).toHaveBeenLastCalledWith({}, 0);
  });

  test('KEM-ED-04 a failing store check is reported per store and never hides the artifact figures', () => {
    const mod = loadModule({
      transparency: storeAt(path.join(tmpDir, 'transparency-keys.json'), () => { throw new Error('boom'); }),
      checkpoint: storeAt(path.join(tmpDir, 'checkpoint-keys.json'), { ...empty, overdueKeys: [{ keyId: 'cp:key_v1', daysOverdue: 3 }] }),
      artifact: { expiringKeys: [{ clientId: 'c', keyId: 'c:key_v1', daysRemaining: 5 }], overdueKeys: [] },
    });
    mod.initialize(); jest.advanceTimersByTime(1000); mod.shutdown();
    expect(events('KEY_EXPIRY_MONITOR_CHECK_FAILED')).toEqual([expect.objectContaining({ store: 'transparency', error: 'boom' })]);
    expect(events('KEY_ROTATION_OVERDUE')).toEqual([expect.objectContaining({ store: 'checkpoint', daysOverdue: 3 })]);
    expect(metrics.keyExpiryApproachingCount.set).toHaveBeenLastCalledWith({}, 1);
    expect(metrics.keyRotationOverdueCount.set).toHaveBeenLastCalledWith({}, 1);
  });

  // K1: the early warning now points at the supported rotation path for each store.
  test('KEM-ED-05 every Ed25519-store expiry event names the rotate-offline command for that store', () => {
    const mod = loadModule({
      transparency: storeAt(path.join(tmpDir, 'transparency-keys.json'), { ...empty, expiredKeys: [{ keyId: 'tr:key_v1', expiresAt: '2026-01-01T00:00:00Z' }] }),
      checkpoint: storeAt(path.join(tmpDir, 'checkpoint-keys.json'), { ...empty, expiringKeys: [{ keyId: 'cp:key_v1', daysRemaining: 3 }], overdueKeys: [{ keyId: 'cp:key_v1', daysOverdue: 2 }] }),
    });
    mod.initialize(); jest.advanceTimersByTime(1000); mod.shutdown();
    const cmd = (s) => `node scripts/keys/rotate-offline.js --store ${s} --mode graceful --operator <id> --reason "<text>" --confirm-offline-recovery`;
    expect(events('KEY_EXPIRED')).toEqual([expect.objectContaining({ store: 'transparency', rotateCommand: cmd('transparency'),
      message: expect.stringContaining(cmd('transparency')) })]);
    expect(events('KEY_EXPIRING_SOON')).toEqual([expect.objectContaining({ store: 'checkpoint', rotateCommand: cmd('checkpoint') })]);
    expect(events('KEY_ROTATION_OVERDUE')).toEqual([expect.objectContaining({ store: 'checkpoint', rotateCommand: cmd('checkpoint') })]);
  });
});
