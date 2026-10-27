'use strict';

/**
 * COMMIT of a non-streamed request on the real routes (real /sign, real /ai/chat, real audit log).
 *
 * CE-00 audit schema v8 off (the default): no COMMIT is written
 *   CE-01  a delivered response: DECISION, then COMMIT RESPONSE_DELIVERED / COMPLETE; bytesDelivered = the UTF-8 bytes of `response`, outputHash = the
 *          DECISION's; the chain verifies and the lifecycle walk finds no orphan
 *   CE-02  a multi-byte answer is counted in UTF-8 bytes, not characters
 *   CE-04  the client closes the connection before the answer is written: COMMIT RESPONSE_FAILED / CLIENT_DISCONNECTED, 0 bytes, the hash of nothing
 *   CE-06  a BLOCK writes no COMMIT
 */

jest.mock('../../../core/dsr/subjectPseudonym', () => require('../../../../test/helpers/subjectPseudonymMock'));
jest.mock('../../../core/consent', () => ({ verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }) }));

const http = require('http');
const request = require('supertest');
const express = require('express');
const { PROVIDER_FIXTURE_KEYS } = require('../../../../test/helpers/providerFixtureKeys');
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');

const { apiKey: SIGN_KEY } = provisionTestSigningIdentity({ tenantId: 'default' });

let app; let audit; let eb; let lifecycle; let providerText = 'ok'; let providerGate = null;
const SAVED_V8 = process.env.QODIQA_AUDIT_SCHEMA_V8;

beforeAll(() => {
  jest.resetModules();
  for (const k of ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY', 'MISTRAL_API_KEY', 'LLAMA_BASE_URL', 'LOCAL_BASE_URL']) delete process.env[k];
  process.env.OPENAI_API_KEY = PROVIDER_FIXTURE_KEYS.openai;
  process.env.QODIQA_CLIENT_ID = 'default';
  delete process.env.QODIQA_AUDIT_SCHEMA_V8;
  process.env.IDEMPOTENCY_ENABLED = 'false';   // the idempotency store would reach for a Redis this test does not provide
  audit = require('../../../core/audit/audit-log');
  eb = require('../../../core/audit/entryBuilder');
  lifecycle = require('../../../core/audit/v7Lifecycle');
  const createSignRouter = require('../sign');
  const createAiChatRouter = require('../aiChat');
  const requestId = require('../../../../middleware/requestId');
  const attachClientIp = require('../../../../middleware/clientIp');
  const { validateAndPrepare } = require('../../../../services/policy/loader');
  const { createStore } = require('../../../../services/policy/store');
  const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
  const policies = validateAndPrepare({ policies: [{ id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }] });
  app = express();
  app.use(requestId); app.use(attachClientIp);
  app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }));
  app.use('/sign', createSignRouter(() => policies));
  app.use('/ai/chat', createAiChatRouter({
    _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _getPolicies: () => policies, _policyStore: createStore(),
    _providerFn: async () => { if (providerGate) await providerGate; return { output: providerText }; },
  }));
});
afterAll(() => { delete process.env.IDEMPOTENCY_ENABLED; if (SAVED_V8 === undefined) delete process.env.QODIQA_AUDIT_SCHEMA_V8; else process.env.QODIQA_AUDIT_SCHEMA_V8 = SAVED_V8; });
beforeEach(() => { providerText = 'ok'; providerGate = null; });
const v8 = (on) => { if (on) process.env.QODIQA_AUDIT_SCHEMA_V8 = 'true'; else delete process.env.QODIQA_AUDIT_SCHEMA_V8; };

const BODY = { prompt: 'hello', model: 'gpt-4o' };
const signed = async () => (await request(app).post('/sign').set('Authorization', `Bearer ${SIGN_KEY}`).send({ request: { method: 'POST', path: '/ai/chat', body: BODY } })).body.artifact;
const header = (a) => Buffer.from(JSON.stringify(a)).toString('base64');
const chat = (a, headers = {}) => { let r = request(app).post('/ai/chat').set('Content-Type', 'application/json').set('x-qodiqa-artifact', header(a)); for (const [k, v] of Object.entries(headers)) r = r.set(k, v); return r.send(JSON.stringify(BODY)); };
const chainNow = async () => audit.getAuditChain();
const entriesOf = async (rid) => (await chainNow()).filter((e) => e.requestId === rid || (typeof e.artifactId === 'string' && e.artifactId.startsWith(rid)));
async function commitOf(rid) {
  for (let i = 0; i < 80; i++) {
    const e = (await chainNow()).find((x) => x.artifactId === `${rid}:commit`);
    if (e) return e;
    await new Promise((r) => setTimeout(r, 25));
  }
  return null;
}
const walk = async () => {
  const t = lifecycle.createLifecycleTracker({ lifecycleComplete: false, nowMs: Date.now() });
  const failures = [];
  for (const e of await chainNow()) { const f = t.step(e); if (f) failures.push(f); }
  return { failures, warnings: t.finish() };
};

describe('COMMIT after a non-streamed response', () => {
  test('CE-00 with audit schema v8 off (the default) nothing is written and every entry is v7', async () => {
    v8(false);
    const r = await chat(await signed());
    expect(r.status).toBe(200);
    await new Promise((res) => setTimeout(res, 150));
    expect((await chainNow()).some((e) => e.artifactId === `${r.body.artifactId}:commit`)).toBe(false);
    expect((await entriesOf(r.body.artifactId)).every((e) => e.schemaVersion === 7)).toBe(true);
  });

  test('CE-01 DECISION then COMMIT RESPONSE_DELIVERED / COMPLETE with the exact bytes and hash; the chain and the lifecycle walk are clean', async () => {
    v8(true);
    providerText = 'a plain answer';
    const r = await chat(await signed());
    expect(r.status).toBe(200);
    expect(r.body.decision).toBe('EXECUTE');
    const rid = r.body.artifactId;
    const commit = await commitOf(rid);
    expect(commit).toBeTruthy();
    const dec = (await entriesOf(rid)).find((e) => e.entryType === 'DECISION');
    expect(commit).toMatchObject({
      schemaVersion: 8, entryType: 'COMMIT', stage: 'COMMIT', decision: 'ALLOW', reason: 'RESPONSE_DELIVERED', completionStatus: 'COMPLETE',
      bytesDelivered: Buffer.byteLength(r.body.response, 'utf8'), outputHash: dec.outputHash, requestId: rid, signature: dec.signature,
    });
    const chain = await chainNow();
    expect(chain.findIndex((e) => e.hash === commit.hash)).toBeGreaterThan(chain.findIndex((e) => e.hash === dec.hash));
    expect(audit.verifyAuditChainDetailed(chain, 'GENESIS').valid).toBe(true);
    const w = await walk();
    expect(w.failures).toEqual([]);
    expect(JSON.stringify(w.warnings)).not.toMatch(/COMMIT_WITHOUT_DECISION|ORPHAN_DECISION/);
  });

  test('CE-02 a multi-byte answer is counted in UTF-8 bytes', async () => {
    v8(true);
    providerText = 'Sunny é 😀 – 日本語';
    const r = await chat(await signed());
    const commit = await commitOf(r.body.artifactId);
    expect(r.body.response).toBe(providerText);
    expect(commit.bytesDelivered).toBe(Buffer.byteLength(providerText, 'utf8'));
    expect(commit.bytesDelivered).toBeGreaterThan(providerText.length);
    expect(commit.outputHash).toBe(eb.outputHashOf(providerText));
  });

  test('CE-04 the client closes the connection before the answer is written: RESPONSE_FAILED / CLIENT_DISCONNECTED, 0 bytes', async () => {
    v8(true);
    let release; providerGate = new Promise((res) => { release = res; });
    const a = await signed();
    const server = http.createServer(app);
    await new Promise((res) => server.listen(0, '127.0.0.1', res));
    const { port } = server.address();
    const rid = a.payload.requestId;
    const reqObj = http.request({ host: '127.0.0.1', port, path: '/ai/chat', method: 'POST', headers: { 'content-type': 'application/json', 'x-qodiqa-artifact': header(a) } });
    reqObj.on('error', () => {});
    reqObj.end(JSON.stringify(BODY));
    await new Promise((res) => setTimeout(res, 250));           // the request is inside the provider call
    reqObj.destroy();
    await new Promise((res) => setTimeout(res, 150));
    release();
    const commit = await commitOf(rid);
    await new Promise((res) => server.close(res));
    expect(commit).toBeTruthy();
    expect(commit).toMatchObject({ reason: 'RESPONSE_FAILED', completionStatus: 'CLIENT_DISCONNECTED', bytesDelivered: 0, outputHash: eb.EMPTY_OUTPUT_HASH });
  });

  test('CE-06 a BLOCK writes no COMMIT', async () => {
    v8(true);
    const r = await request(app).post('/ai/chat').set('Content-Type', 'application/json').send(JSON.stringify(BODY));
    expect(r.body.decision).toBe('BLOCK');
    await new Promise((res) => setTimeout(res, 100));
    expect((await chainNow()).filter((e) => e.entryType === 'COMMIT' && e.requestId === r.body.requestId)).toHaveLength(0);
  });
});
