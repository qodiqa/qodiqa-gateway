'use strict';

/**
 * — evidence generation and verification FAIL CLOSED when the audit history cannot
 * be read. Acceptance criteria..F-5:
 * Real audit-log (file mode, 20-entry window), 1,500 valid chained entries, the real evidence router.
 *
 *   FC-1  every endpoint × every history read (chain walk, artifact lookup, replay lineage) failing → HTTP 503
 *         AUDIT_HISTORY_UNAVAILABLE, never 200 / 404 / "CLEAN", no internal error text, one ERROR
 *         EVIDENCE_HISTORY_UNAVAILABLE naming the failing read
 *   FC-2  a readable chain that does NOT verify still yields the explicit verification result (valid:false, COMPROMISED)
 *   FC-3  with nothing failing the endpoints answer as before (200, chain valid over every entry)
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const request = require('supertest');
const eb = require('../../../core/audit/entryBuilder');

const N = 1500;
let dir; let file; let ids; let lines; let a; let app; let events = [];

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-aut12-'));
  file = path.join(dir, 'audit.log');
  ids = []; lines = []; let prev = 'GENESIS';
  for (let i = 0; i < N; i++) {
    const id = crypto.randomUUID(); ids.push(id);
    const e = eb.buildEntry(eb.normalizeFields({ artifactId: id, inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: eb.EMPTY_OUTPUT_HASH,
      signature: 's'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true, tenantId: 't' }), prev);
    lines.push(JSON.stringify(e)); prev = e.hash;
  }
  fs.writeFileSync(file, lines.join('\n') + '\n');
  process.env.QODIQA_AUDIT_LOG = file;
  process.env.QODIQA_AUDIT_WINDOW_SIZE = '20';
  jest.resetModules();
  const logger = require('../../../../services/logger');
  const realEmit = logger.emit;
  jest.spyOn(logger, 'emit').mockImplementation((level, type, data) => { events.push({ level, type, data }); return realEmit(level, type, data); });
  a = require('../../../core/audit/audit-log');
  const createEvidenceRouter = require('../evidence');
  app = express();
  app.use((req, res, next) => { req.requestId = 'fc-req'; res.locals.requestId = req.requestId; next(); });
  app.use('/evidence', createEvidenceRouter({ _getPolicies: () => [] }));
});
afterAll(() => {
  delete process.env.QODIQA_AUDIT_LOG; delete process.env.QODIQA_AUDIT_WINDOW_SIZE;
  jest.restoreAllMocks();
  jest.resetModules();
  fs.rmSync(dir, { recursive: true, force: true });
});
beforeEach(() => { events = []; });
afterEach(() => { for (const k of ['forEachChainEntry', 'getArtifactById', 'getReplayLineage']) if (a[k].mockRestore) a[k].mockRestore(); });

const ENDPOINTS = (id) => [
  ['package', `/evidence/package/${id}`],
  ['package/json', `/evidence/package/${id}/json`],
  ['package/pdf', `/evidence/package/${id}/pdf`],
  ['bundle', `/evidence/package/${id}/bundle`],
  ['verify', `/evidence/package/${id}/verify`],
  ['audit (filtered)', `/evidence/package/${id}/audit`],
  ['audit (unfiltered, streamed)', `/evidence/package/${id}/audit?filtered=false`],
];
// which reads each endpoint performs (the export only walks the chain)
const READS = { 'chain walk': 'forEachChainEntry', 'artifact lookup': 'getArtifactById', 'replay lineage': 'getReplayLineage' };
const usesRead = (name, read) => read === 'chain walk' || !name.startsWith('audit');

describe('FC-1 every endpoint × every failing history read → 503 AUDIT_HISTORY_UNAVAILABLE', () => {
  for (const [read, fn] of Object.entries(READS)) {
    for (const [name, url] of ENDPOINTS('ID')) {
      if (!usesRead(name, read)) continue;
      test(`${name} with a failing ${read}`, async () => {
        jest.spyOn(a, fn).mockImplementation(async () => { throw new Error('EIO: disk gone (internal detail)'); });
        const r = await request(app).get(url.replace('ID', ids[700]));
        expect(r.status).toBe(503);
        expect(r.body.status).toBe('error');
        expect(r.body.error.code).toBe('AUDIT_HISTORY_UNAVAILABLE');
        expect(r.text).not.toContain('disk gone');
        expect(r.text).not.toMatch(/"valid":true|CLEAN|ARTIFACT_NOT_FOUND/);
        const logged = events.filter((e) => e.type === 'EVIDENCE_HISTORY_UNAVAILABLE');
        expect(logged).toHaveLength(1);
        expect(logged[0].level).toBe('ERROR');
        expect(logged[0].data.read).toBe(read);
      });
    }
  }
});

test('FC-2 a readable chain that does not verify still returns the explicit verification result', async () => {
  const t = JSON.parse(lines[900]); t.canonical = t.canonical.replace('"decision":"ALLOW"', '"decision":"BLOCK"');
  const tampered = lines.slice(); tampered[900] = JSON.stringify(t);
  fs.writeFileSync(file, tampered.join('\n') + '\n');
  try {
    const v = await request(app).get(`/evidence/package/${ids[100]}/verify`);
    expect(v.status).toBe(200);
    expect(v.body.data.verifications.chain).toMatchObject({ status: 'INVALID', valid: false, tamperingDetected: true, entriesVerified: 900 });
    expect(v.body.data.overallStatus).toBe('COMPROMISED');
    const pkg = await request(app).get(`/evidence/package/${ids[100]}`);
    expect(pkg.status).toBe(200);
    expect(pkg.body.data.sections.audit.chainIntegrity).toMatchObject({ valid: false, tamperingDetected: true });
  } finally {
    fs.writeFileSync(file, lines.join('\n') + '\n');
  }
});

test('FC-3 with nothing failing, the endpoints answer as before', async () => {
  const v = await request(app).get(`/evidence/package/${ids[100]}/verify`);
  expect(v.status).toBe(200);
  expect(v.body.data.verifications.chain).toMatchObject({ status: 'VALID', entriesVerified: N });
  expect((await request(app).get(`/evidence/package/${ids[100]}/audit`)).status).toBe(200);
  expect(events.filter((e) => e.type === 'EVIDENCE_HISTORY_UNAVAILABLE')).toHaveLength(0);
});
