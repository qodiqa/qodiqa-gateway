'use strict';

/**
 * ANCHOR-1. Acceptance A-1..A-4:
 *
 * Real audit-log, real checkpoint writer and key store, real anchors.publishAnchorBacklog / verifyChainAgainstAnchors,
 * a real LocalFileWitness behind a switch that simulates its outage.
 *
 *   AH-0  negative control: the previous path (publish without requireCosignature) exports a 0-cosignature record and the
 *         next boot fails ANCHOR_NOT_WITNESSED — the defect
 *   AH-1  witness down: checkpoints are HELD (WARN AUDIT_ANCHOR_HELD), nothing unwitnessed reaches the export
 *   AH-2  boot during the outage: fails with the bootstrap-clearable ANCHOR_EXPORT_TRUNCATED — never ANCHOR_NOT_WITNESSED
 *   AH-3  witness back: the next checkpoint exports the held ones first, in chain order, each with a cosignature that
 *         verifies under the trusted witness key; the boot check then passes
 *   AH-4  a cosignature that does not verify under the trusted keys does not count: the checkpoint stays held
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { EMPTY_OUTPUT_HASH } = require('../../entryBuilder');

const fields = () => ({ artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: EMPTY_OUTPUT_HASH, signature: 's'.repeat(64),
  requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true });

describe('ANCHOR-1 hold and catch up', () => {
  let dir; let auditLog; let w; let anchors; let events; let witness; let down; let exportPath; let trusted;

  function anchoringApi({ legacy = false, trustOverride = null } = {}) {
    const proxy = { witnessId: witness.witnessId, cosign: async (cp) => { if (down) { const e = new Error('connect ECONNREFUSED'); e.code = 'WITNESS_UNAVAILABLE'; throw e; } return witness.cosign(cp); },
      head: () => witness.head() };
    const keys = trustOverride || trusted;
    return {
      enabled: () => true,
      exportPath: () => exportPath,
      read: (p) => anchors.readAnchors(p),
      publish: (signed, opts = {}) => anchors.publishAnchor(signed, { witnesses: [proxy], exportPath, trustedWitnessKeys: keys, requireCosignature: !!opts.requireCosignature }),
      ...(legacy ? {} : { publishWithBacklog: (signed, backlog) => anchors.publishAnchorBacklog(signed, { witnesses: [proxy], exportPath, trustedWitnessKeys: keys, backlog }) }),
      verify: (args) => anchors.verifyChainAgainstAnchors(args),
      trustedWitnessKeys: () => keys,
      witnesses: () => [proxy],
      independence: () => 'none-local-witness',
    };
  }
  const opts = (api) => ({ registrar: null, anchoring: api, emit: (l, t, d) => events.push({ l, t, d }) });
  async function checkpoint(api) { for (let i = 0; i < 5; i++) await auditLog.append(fields()); return w.createSignedCheckpoint(opts(api)); }
  async function boot(api) { try { return { ok: true, r: await w.verifyAnchorsAtBoot(opts(api)) }; } catch (e) { return { ok: false, code: e.code, findings: (e.findings || []).map((f) => f.code) }; } }

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-anchor1-'));
    process.env.QODIQA_AUDIT_LOG = path.join(dir, 'audit.log');
    jest.resetModules();
    events = []; down = false;
    auditLog = require('../../audit-log'); w = require('../checkpointWriter'); anchors = require('../../anchoring/anchors');
    const { LocalFileWitness } = require('../../anchoring/witness');
    witness = new LocalFileWitness({ witnessId: 'pilot-witness', keyPath: path.join(dir, 'witness', 'key.json'), logPath: path.join(dir, 'witness', 'log.jsonl') });
    trusted = { keys: [witness.publicKeyRecord()] };
    exportPath = path.join(dir, 'customer', 'anchors.jsonl');
  });
  afterEach(() => {
    w._resetSchedulerStateForTests();
    delete process.env.QODIQA_AUDIT_LOG;
    jest.resetModules();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const exported = () => (fs.existsSync(exportPath) ? anchors.readAnchors(exportPath) : []);

  test('AH-0 negative control: the previous path exports an unwitnessed record and the next boot fails ANCHOR_NOT_WITNESSED', async () => {
    const legacy = anchoringApi({ legacy: true });
    await checkpoint(legacy);
    down = true;
    await checkpoint(legacy);
    expect(exported().map((a) => a.cosignatures.length)).toEqual([1, 0]);
    down = false;
    const b = await boot(legacy);
    expect(b.ok).toBe(false);
    expect(b.findings).toContain('ANCHOR_NOT_WITNESSED');
  });

  test('AH-1..AH-3 held during the outage, bootstrap-clearable boot, exported in order once the witness is back', async () => {
    const api = anchoringApi();
    const cp1 = await checkpoint(api);
    expect(exported()).toHaveLength(1);
    down = true;
    const held = [await checkpoint(api), await checkpoint(api), await checkpoint(api)];
    expect(exported()).toHaveLength(1);                                   // AH-1: nothing unwitnessed exported
    expect(events.filter((e) => e.t === 'AUDIT_ANCHOR_HELD').map((e) => e.d.held)).toEqual([1, 2, 3]);

    const during = await boot(api);                                        // AH-2
    expect(during.ok).toBe(false);
    expect(during.findings).toContain('ANCHOR_EXPORT_TRUNCATED');
    expect(during.findings).not.toContain('ANCHOR_NOT_WITNESSED');

    down = false;                                                          // AH-3
    const cp5 = await checkpoint(api);
    const ex = exported();
    expect(ex.map((a) => a.checkpoint.payload.checkpointId)).toEqual([cp1, ...held, cp5].map((c) => c.payload.checkpointId));
    for (const a of ex) expect(a.cosignatures).toHaveLength(1);
    // every cosignature verifies under the trusted witness key: the boot check below requires >= 1 verified per anchor
    expect(events.some((e) => e.t === 'AUDIT_ANCHOR_BACKLOG_EXPORTED' && e.d.exported === 4)).toBe(true);
    const after = await boot(api);
    expect(after).toMatchObject({ ok: true, r: { checked: true, anchors: 5 } });
  });

  test('AH-4 a cosignature that does not verify under the trusted keys does not count', async () => {
    const { LocalFileWitness } = require('../../anchoring/witness');
    const other = new LocalFileWitness({ witnessId: 'pilot-witness', keyPath: path.join(dir, 'w2', 'key.json'), logPath: path.join(dir, 'w2', 'log.jsonl') });
    const api = anchoringApi({ trustOverride: { keys: [other.publicKeyRecord()] } });   // trust set names a different key
    await checkpoint(api);
    expect(exported()).toHaveLength(0);
    expect(events.some((e) => e.t === 'AUDIT_ANCHOR_HELD')).toBe(true);
    expect(events.some((e) => e.t === 'AUDIT_ANCHOR_WITNESS_FAILED' && e.d.code === 'WITNESS_COSIGNATURE_UNVERIFIED')).toBe(true);
  });
});
