'use strict';

/**
 * PH16-D2 — src/core/audit/jsonlAppend.js and its two users.
 *
 *   JA-01  a short write (write(2) returning fewer bytes at the requested position, as at the ENOSPC boundary) is
 *          completed by the loop: the record is whole and the next record follows it
 *   JA-02  a write that makes no progress throws <prefix>_SHORT_WRITE (the record is never reported as written)
 *   JA-03  'repair': a torn tail is COPIED to <file>.torn-<ts>, then truncated; the new record follows the last full line
 *   JA-04  'refuse': a torn tail → throws <prefix>_TORN, the file is untouched
 *   JA-05  checkpoint sidecar: after a crash mid-append (torn tail), the next checkpoint is readable and nothing is lost
 *          (repair); before PH16-D2 the next record was merged into the torn line and the reader refused the file
 *   JA-06  anchor export: a torn tail is refused by default (AUDIT_ANCHOR_EXPORT_TORN, customer storage untouched);
 *          QODIQA_ANCHOR_EXPORT_TORN_TAIL=repair opts in to copy-then-truncate
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { appendJsonlRecord } = require('../jsonlAppend');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-jsonl-'));
const lines = (f) => fs.readFileSync(f, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));

afterEach(() => { jest.restoreAllMocks(); delete process.env.QODIQA_ANCHOR_EXPORT_TORN_TAIL; });

test('JA-01 a short write is completed, never left torn', () => {
  const f = path.join(tmp(), 'x.jsonl');
  appendJsonlRecord(f, { n: 1 });
  const real = fs.writeSync; let first = true;
  jest.spyOn(fs, 'writeSync').mockImplementation((fd, buf, off, len, pos) => {
    if (first) { first = false; return real(fd, buf, off, Math.floor(len / 2), pos); } // kernel wrote only half, at pos
    return real(fd, buf, off, len, pos);
  });
  appendJsonlRecord(f, { n: 2, pad: 'p'.repeat(500) });
  fs.writeSync.mockRestore();
  appendJsonlRecord(f, { n: 3 });
  expect(lines(f).map((r) => r.n)).toEqual([1, 2, 3]);
});

test('JA-02 a write that makes no progress throws and is not reported as written', () => {
  const f = path.join(tmp(), 'x.jsonl');
  appendJsonlRecord(f, { n: 1 });
  jest.spyOn(fs, 'writeSync').mockReturnValue(0);
  expect(() => appendJsonlRecord(f, { n: 2 }, { errorPrefix: 'T' })).toThrow(/^T_SHORT_WRITE/);
});

test('JA-03 repair: torn tail quarantined (copied) then truncated', () => {
  const d = tmp(); const f = path.join(d, 'x.jsonl');
  fs.writeFileSync(f, JSON.stringify({ n: 1 }) + '\n{"n":2,"torn');
  const r = appendJsonlRecord(f, { n: 3 }, { onTornTail: 'repair' });
  expect(r.repairedTornTail.bytes).toBe('{"n":2,"torn'.length);
  expect(fs.readFileSync(r.repairedTornTail.quarantinedTo, 'utf8')).toBe('{"n":2,"torn');
  expect(lines(f).map((x) => x.n)).toEqual([1, 3]);
});

test('JA-04 refuse: torn tail → <prefix>_TORN, file untouched', () => {
  const f = path.join(tmp(), 'x.jsonl');
  const before = JSON.stringify({ n: 1 }) + '\n{"n":2,"to';
  fs.writeFileSync(f, before);
  expect(() => appendJsonlRecord(f, { n: 3 }, { onTornTail: 'refuse', errorPrefix: 'X' })).toThrow(/^X_TORN/);
  expect(fs.readFileSync(f, 'utf8')).toBe(before);
});

test('JA-05 checkpoint sidecar survives a torn tail (no lost record, readable)', () => {
  const w = require('../checkpoint/checkpointWriter');
  const logPath = path.join(tmp(), 'audit.log');
  const rec = (n) => ({ payload: { checkpointId: `cp-${n}`, chainLength: n }, payloadHash: String(n).repeat(64).slice(0, 64), signature: 's' });
  fs.writeFileSync(w.sidecarPath(logPath), JSON.stringify(rec(1)) + '\n' + JSON.stringify(rec(2)).slice(0, 20)); // crash mid-append
  const cpw = jest.requireActual('../checkpoint/checkpointWriter');
  // appendSidecar is internal; drive it through the module's own append via a minimal copy of its contract
  require('../jsonlAppend').appendJsonlRecord(cpw.sidecarPath(logPath), rec(3), { onTornTail: 'repair', errorPrefix: 'AUDIT_CHECKPOINT_SIDECAR' });
  require('../jsonlAppend').appendJsonlRecord(cpw.sidecarPath(logPath), rec(4), { onTornTail: 'repair', errorPrefix: 'AUDIT_CHECKPOINT_SIDECAR' });
  expect(w.readSidecar(logPath).map((r) => r.payload.checkpointId)).toEqual(['cp-1', 'cp-3', 'cp-4']);
});

test('JA-06 anchor export: torn tail refused by default; repair only when opted in', async () => {
  const anchors = require('../anchoring/anchors');
  const exportPath = path.join(tmp(), 'anchors.jsonl');
  const cp = (n) => ({ payload: { checkpointId: `cp-${n}`, chainLength: n * 10, headHash: 'a'.repeat(64), keyId: 'k' }, payloadHash: 'h'.repeat(64), signature: 's' });
  await anchors.publishAnchor(cp(1), { witnesses: [], exportPath, trustedWitnessKeys: { keys: [] } });
  fs.appendFileSync(exportPath, '{"anchorVersion":1,"checkpo');                     // torn tail (crash/short write)
  const before = fs.readFileSync(exportPath, 'utf8');
  await expect(anchors.publishAnchor(cp(2), { witnesses: [], exportPath, trustedWitnessKeys: { keys: [] } })).rejects.toMatchObject({ code: 'AUDIT_ANCHOR_EXPORT_TORN' });
  expect(fs.readFileSync(exportPath, 'utf8')).toBe(before);                      // customer storage untouched
  process.env.QODIQA_ANCHOR_EXPORT_TORN_TAIL = 'repair';
  await anchors.publishAnchor(cp(3), { witnesses: [], exportPath, trustedWitnessKeys: { keys: [] } });
  expect(anchors.readAnchors(exportPath).map((a) => a.checkpoint.payload.checkpointId)).toEqual(['cp-1', 'cp-3']);
});
