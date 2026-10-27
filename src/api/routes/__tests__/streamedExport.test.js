'use strict';

/**
 * — GET /evidence/package/:id/audit?filtered=false is streamed (the whole history, never
 * materialised). The response must be what success(res, exportAuditChain(id, false)) produced before.
 * Real audit-log (file mode, 20-entry window) over 2,500 valid chained entries → three pages.
 *
 *   RS-1  byte-identical body to JSON.stringify of the previous envelope (same key order, same entries, same meta),
 *         JSON content type, the API CSP header the res.json hook used to add
 * RS-2 a failure before the first byte → 503 AUDIT_HISTORY_UNAVAILABLE
 *   RS-3  a failure after the first page was sent → the connection is aborted: the client never receives a well-formed
 *         body presenting a partial chain
 *   RS-4  the filtered export (default) is unchanged and still 404s for an unknown artifact
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const express = require('express');
const request = require('supertest');
const eb = require('../../../core/audit/entryBuilder');

const N = 2500;
let dir; let ids; let a; let app;

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-aut11-rs-'));
  const file = path.join(dir, 'audit.log');
  ids = []; const lines = []; let prev = 'GENESIS';
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
  a = require('../../../core/audit/audit-log');
  const createEvidenceRouter = require('../evidence');
  app = express();
  app.use((req, res, next) => { req.requestId = 'rs-req'; res.locals.requestId = req.requestId; next(); });
  app.use('/evidence', createEvidenceRouter({ _getPolicies: () => [] }));
});
afterAll(() => {
  delete process.env.QODIQA_AUDIT_LOG; delete process.env.QODIQA_AUDIT_WINDOW_SIZE;
  jest.resetModules();
  fs.rmSync(dir, { recursive: true, force: true });
});
afterEach(() => jest.restoreAllMocks());

test('RS-1 byte-identical to the previous success() envelope, with the JSON type and the API CSP', async () => {
  const id = ids[3];
  const r = await request(app).get(`/evidence/package/${id}/audit?filtered=false`);
  expect(r.status).toBe(200);
  expect(r.headers['content-type']).toBe('application/json; charset=utf-8');
  expect(r.headers['content-security-policy']).toBe(require('../../../infra/security/csp').API_CSP);
  const body = JSON.parse(r.text);
  expect(Object.keys(body)).toEqual(['status', 'timestamp', 'requestId', 'data']);
  expect(Object.keys(body.data)).toEqual(['entries', 'meta']);
  const chain = await a.getAuditChain();
  const previous = {
    status: 'success', timestamp: body.timestamp, requestId: 'rs-req',
    data: { entries: chain, meta: { artifactId: id, filtered: false, totalChain: N, exportedCount: N, exportedAt: body.data.meta.exportedAt,
      chainIntegrity: { valid: true, tamperingDetected: false, entriesVerified: N } } },
  };
  expect(r.text).toBe(JSON.stringify(previous));
});

test('RS-2 a failure before the first byte → 503 AUDIT_HISTORY_UNAVAILABLE', async () => {
  jest.spyOn(a, 'forEachChainEntry').mockImplementation(async () => { throw new Error('disk gone'); });
  const r = await request(app).get(`/evidence/package/${ids[3]}/audit?filtered=false`);
  expect(r.status).toBe(503);
  const body = JSON.parse(r.text);
  expect(body.status).toBe('error');
  expect(body.error.code).toBe('AUDIT_HISTORY_UNAVAILABLE');
  expect(r.text).not.toContain('disk gone');
});

test('RS-3 a failure after the first page → aborted, never a well-formed partial body', async () => {
  const real = a.forEachChainEntry;
  jest.spyOn(a, 'forEachChainEntry').mockImplementation(async (visit, opts) => {
    let pages = 0;
    return real(visit, { ...opts, afterPage: async () => { await opts.afterPage(); if (++pages === 1) throw new Error('disk gone mid-stream'); } });
  });
  const server = app.listen(0);
  try {
    const { port } = server.address();
    const outcome = await new Promise((resolve) => {
      const req = http.get(`http://127.0.0.1:${port}/evidence/package/${ids[3]}/audit?filtered=false`, (res) => {
        let text = ''; res.setEncoding('utf8');
        res.on('data', (c) => { text += c; });
        res.on('end', () => resolve({ ended: true, text }));
        res.on('error', (e) => resolve({ aborted: true, error: e.message, text }));
        res.on('aborted', () => resolve({ aborted: true, text }));
      });
      req.on('error', (e) => resolve({ aborted: true, error: e.message, text: '' }));
    });
    let wellFormed = true;
    try { JSON.parse(outcome.text); } catch { wellFormed = false; }
    expect(wellFormed).toBe(false);
    expect(outcome.text.startsWith('{"status":"success"')).toBe(true);   // the first page was sent …
    expect(outcome.text).not.toContain('"meta"');                       // … and no meta claiming a complete chain
  } finally {
    server.close();
  }
});

test('RS-4 the filtered export is unchanged (and still 404s for an unknown artifact)', async () => {
  const r = await request(app).get(`/evidence/package/${ids[1001]}/audit`);
  expect(r.status).toBe(200);
  expect(r.body.data.entries).toHaveLength(1);
  expect(r.body.data.meta).toMatchObject({ filtered: true, totalChain: N, exportedCount: 1, chainIntegrity: { valid: true, entriesVerified: N } });
  const miss = await request(app).get(`/evidence/package/${crypto.randomUUID()}/audit`);
  expect(miss.status).toBe(404);
});
