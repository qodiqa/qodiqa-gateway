'use strict';

/**
 * Audit remediation 2026-10-27, item 12: regenerating or drift-checking test-vectors/webhook-v1.json must not change the file when
 * the vectors are unchanged (the always-changing generatedBy.generatedAt used to dirty `git diff` on every run).
 *
 *   WVD-01 two consecutive checkDrift() runs that write their output leave the file byte-identical to the committed one
 *   WVD-02 a real vector change still rewrites the file and reports the drifting ids
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { checkDrift } = require('../../../../test-vectors/check-vector-drift');
const { DEFAULT_OUTPUT_PATH } = require('../../../../test-vectors/generate-webhook-vectors');

describe('webhook vector file is deterministic', () => {
  let dir; let copy; let committed;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wvd-'));
    copy = path.join(dir, 'webhook-v1.json');
    committed = fs.readFileSync(DEFAULT_OUTPUT_PATH);
    fs.writeFileSync(copy, committed);
  });
  afterEach(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* temp dir */ } });

  test('WVD-01 two consecutive writing runs leave the bytes unchanged', () => {
    const r1 = checkDrift({ vectorsPath: copy, writeOutputPath: copy });
    const after1 = fs.readFileSync(copy);
    const r2 = checkDrift({ vectorsPath: copy, writeOutputPath: copy });
    const after2 = fs.readFileSync(copy);
    expect(r1.drift).toBe(false);
    expect(r2.drift).toBe(false);
    expect(after1.equals(committed)).toBe(true);
    expect(after2.equals(committed)).toBe(true);
  });

  test('WVD-02 a changed vector is still detected and the file is rewritten', () => {
    const obj = JSON.parse(committed.toString('utf8'));
    obj.vectors[0].expectedSignature = 'tampered';
    fs.writeFileSync(copy, JSON.stringify(obj, null, 2) + '\n');
    const r = checkDrift({ vectorsPath: copy, writeOutputPath: copy });
    expect(r.drift).toBe(true);
    expect(r.changedVectorIds).toContain(obj.vectors[0].id);
    expect(JSON.parse(fs.readFileSync(copy, 'utf8')).vectors[0].expectedSignature).not.toBe('tampered');
  });
});
