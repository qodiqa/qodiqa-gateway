'use strict';

/**
 * anchor-export and witness FAILURE during checkpoint publication, driving the REAL
 * checkpointWriter.createSignedCheckpoint() and the REAL anchors.publishAnchor() (real files in a per-test temp dir;
 * pgPool disabled; an in-memory Ed25519 checkpoint key; only fs.writeSync / the witness are faulted).
 *
 * Gap closed: checkpointWriter.test.js CW-06/CW-08 mock publish() wholesale; anchors.js's own export write
 * (open/write/fsync) and a failing witness were never exercised underneath a real checkpoint run.
 *
 *   AWF-01  the export write fails with ENOSPC (nothing written): the checkpoint is still signed and in the sidecar,
 *           AUDIT_ANCHOR_EXPORT_FAILED is emitted, the export holds no partial line; once space returns the next
 *           checkpoint is exported and the export reads back cleanly (recovery without restart)
 *   AWF-02  a witness whose cosign REJECTS: the checkpoint is signed and exported without that cosignature, and the
 *           failure is reported (AUDIT_ANCHOR_WITNESS_FAILED), never hidden
 *   AWF-03  an fsync EIO on the export: reported as AUDIT_ANCHOR_EXPORT_FAILED (the checkpoint itself survives)
 *
 * The SHORT-write variant (write(2) returning fewer bytes, no error) is a production defect — PH16-D2 —
 * reproduced outside this gating suite:
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const anchors = require('../../src/core/audit/anchoring/anchors');
const cpw = require('../../src/core/audit/checkpoint/checkpointWriter');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const key = { keyId: 'ph16-awf', version: 1, privDer: privateKey.export({ format: 'der', type: 'pkcs8' }) };
const pubDer = publicKey.export({ format: 'der', type: 'spki' });

let dir; let logPath; let exportPath; let length; let events; let witnesses;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-ph16-awf-'));
  logPath = path.join(dir, 'audit.log'); exportPath = path.join(dir, 'anchors.jsonl');
  length = 0; events = []; witnesses = [];
});
afterEach(() => { jest.restoreAllMocks(); fs.rmSync(dir, { recursive: true, force: true }); });

const deps = () => ({
  auditLog: { memorySnapshot: () => ({ modernCount: length }), getModernEntryAt: async (i) => ({ hash: crypto.createHash('sha256').update(String(i)).digest('hex') }) },
  pgPool: { isEnabled: () => false }, registrar: null, logStore: null, logPath,
  emit: (level, event, data) => events.push({ level, event, data }),
  keyStore: { ensureActiveKey: () => key, resolve: () => pubDer },
  anchoring: {
    enabled: () => true, exportPath: () => exportPath,
    publish: (signed) => anchors.publishAnchor(signed, { witnesses, exportPath, trustedWitnessKeys: { keys: [] } }),
    read: (p) => anchors.readAnchors(p),
  },
});
const checkpoint = async (n) => { length = n; return cpw.createSignedCheckpoint({ trigger: 'ph16', ...deps() }); };
const fail = (code) => Object.assign(new Error(`${code}: injected`), { code });

test('AWF-01 export ENOSPC: checkpoint survives in the sidecar, failure reported, no partial line; recovers when space returns', async () => {
  await checkpoint(10);
  const realWrite = fs.writeSync;
  const spy = jest.spyOn(fs, 'writeSync').mockImplementation((fd, data, ...rest) => {
    if (String(Buffer.isBuffer(data) ? data.toString('utf8') : data).includes('"anchorVersion"')) throw fail('ENOSPC'); // string or Buffer (PH16-D2 helper writes Buffers)
    return realWrite.call(fs, fd, data, ...rest);
  });
  const signed = await checkpoint(20);
  expect(signed.payload.chainLength).toBe(20);
  expect(cpw.readSidecar(logPath).map((c) => c.payload.chainLength)).toEqual([10, 20]);
  expect(events.filter((e) => e.event === 'AUDIT_ANCHOR_EXPORT_FAILED')).toHaveLength(1);
  expect(anchors.readAnchors(exportPath).map((a) => a.checkpoint.payload.chainLength)).toEqual([10]);
  expect(fs.readFileSync(exportPath, 'utf8').endsWith('\n')).toBe(true);         // no torn tail left behind
  spy.mockRestore();
  await checkpoint(30);                                                           // space is back
  expect(anchors.readAnchors(exportPath).map((a) => a.checkpoint.payload.chainLength)).toEqual([10, 30]);
  expect(events.filter((e) => e.event === 'AUDIT_ANCHOR_EXPORT_FAILED')).toHaveLength(1);
});

test('AWF-02 a witness whose cosign rejects: checkpoint signed and exported, failure reported', async () => {
  witnesses = [{ witnessId: 'ph16-broken-witness', cosign: async () => { throw fail('WITNESS_UNREACHABLE'); } }];
  await checkpoint(10);
  const [a] = anchors.readAnchors(exportPath);
  expect(a.checkpoint.payload.chainLength).toBe(10);
  expect(a.cosignatures).toEqual([]);
  const w = events.filter((e) => e.event === 'AUDIT_ANCHOR_WITNESS_FAILED');
  expect(w).toHaveLength(1);
  expect(w[0].data).toMatchObject({ witnessId: 'ph16-broken-witness', code: 'WITNESS_UNREACHABLE' });
});

test('AWF-03 fsync EIO on the export: reported as AUDIT_ANCHOR_EXPORT_FAILED; the checkpoint survives', async () => {
  const realFsync = fs.fsyncSync; let armed = true;
  jest.spyOn(fs, 'openSync');
  jest.spyOn(fs, 'fsyncSync').mockImplementation((fd) => {
    const exportFd = fs.openSync.mock.calls.findIndex((c) => c[0] === exportPath) >= 0
      ? fs.openSync.mock.results[fs.openSync.mock.calls.findIndex((c) => c[0] === exportPath)].value : null;
    if (armed && fd === exportFd) { armed = false; throw fail('EIO'); }
    return realFsync.call(fs, fd);
  });
  const signed = await checkpoint(10);
  expect(signed.payload.chainLength).toBe(10);
  expect(cpw.readSidecar(logPath)).toHaveLength(1);
  expect(armed).toBe(false);
  expect(events.filter((e) => e.event === 'AUDIT_ANCHOR_EXPORT_FAILED')).toHaveLength(1);
});
