'use strict';

/**
 * protocol V2 end to end on the real routes - /sign issues a V2 artifact (V2-FREEZE 3-4), /ai/chat verifies it
 * (version negotiation, claims, V2 request binding, model pin, output cap). Flags: QODIQA_PROTOCOL_V2_ISSUE / _ACCEPT / _MIN_VERSION.
 */

jest.mock('../../../core/dsr/subjectPseudonym', () => require('../../../../test/helpers/subjectPseudonymMock'));
jest.mock('../../../core/consent', () => ({ verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }) }));

const request = require('supertest');
const express = require('express');
const { PROVIDER_FIXTURE_KEYS } = require('../../../../test/helpers/providerFixtureKeys');
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');

const { apiKey: SIGN_KEY } = provisionTestSigningIdentity({ tenantId: 'default' });

let app; let calls;
const FLAGS = ['QODIQA_PROTOCOL_V2_ISSUE', 'QODIQA_PROTOCOL_V2_ACCEPT', 'QODIQA_PROTOCOL_MIN_VERSION'];

beforeAll(() => {
  jest.resetModules();
  for (const k of ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY', 'MISTRAL_API_KEY', 'LLAMA_BASE_URL', 'LOCAL_BASE_URL']) delete process.env[k];
  process.env.OPENAI_API_KEY = PROVIDER_FIXTURE_KEYS.openai;
  process.env.QODIQA_CLIENT_ID = 'default';
  const createSignRouter = require('../sign');
  const createAiChatRouter = require('../aiChat');
  const requestId = require('../../../../middleware/requestId');
  const attachClientIp = require('../../../../middleware/clientIp');
  const { validateAndPrepare } = require('../../../../services/policy/loader');
  const { createStore } = require('../../../../services/policy/store');
  const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
  const policies = validateAndPrepare({ policies: [{ id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }] });
  calls = [];
  app = express();
  app.use(requestId); app.use(attachClientIp);
  app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }));
  app.use('/sign', createSignRouter(() => policies));
  app.use('/ai/chat', createAiChatRouter({
    _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _getPolicies: () => policies, _policyStore: createStore(),
    _providerFn: async (provider, body) => { calls.push({ provider, body }); return { output: 'ok' }; },
  }));
});
beforeEach(() => { calls.length = 0; for (const f of FLAGS) delete process.env[f]; });
afterEach(() => { for (const f of FLAGS) delete process.env[f]; });
const v2On = () => { process.env.QODIQA_PROTOCOL_V2_ISSUE = 'true'; process.env.QODIQA_PROTOCOL_V2_ACCEPT = 'true'; };

const BODY = { prompt: 'hello', model: 'gpt-4o' };
const sign = (over = {}) => request(app).post('/sign').set('Authorization', `Bearer ${SIGN_KEY}`).send({
  request: { method: 'POST', path: '/ai/chat', body: BODY, ...(over.request || {}) },
  ...(over.v2 === undefined ? { v2: { bind: { headers: [] } } } : (over.v2 === null ? {} : { v2: over.v2 })),
  ...(over.payload ? { payload: over.payload } : {}),
});
const header = (artifact) => Buffer.from(JSON.stringify(artifact)).toString('base64');
const chat = (artifact, { target = '/ai/chat', body = JSON.stringify(BODY), headers = {} } = {}) => {
  let r = request(app).post(target).set('Content-Type', 'application/json').set('x-qodiqa-artifact', header(artifact));
  for (const [k, v] of Object.entries(headers)) r = r.set(k, v);
  return r.send(body);
};

describe('issuance (/sign)', () => {
  test('F4-E2E-01 without the issue flag a v2 block is UNSUPPORTED_PROTOCOL_VERSION', async () => {
    const r = await sign();
    expect(r.status).toBe(400);
    expect(r.body.reason).toBe('UNSUPPORTED_PROTOCOL_VERSION');
  });

  test('F4-E2E-02 with the flag the artifact carries exactly one reserved block and the V1 identity claims', async () => {
    v2On();
    const r = await sign({ v2: { bind: { headers: ['x-trace'] }, limits: { maxTokens: 64 } }, payload: { claims: { team: 'a' } } });
    expect(r.status).toBe(200);
    const p = r.body.artifact.payload;
    expect(Object.keys(p).sort()).toEqual(['callerContext', 'claims', 'policyHash', 'provider', 'qodiqa', 'requestHash', 'requestId', 'tenantId']);
    expect(p.qodiqa).toEqual({ v: 2, kind: 'request', bind: { headers: ['x-trace'] }, model: 'gpt-4o', limits: { maxTokens: 64 } });
    expect(r.body.meta.protocolVersion).toBe(2);
  });

  test.each([
    ['qodiqa', 'RESERVED_CLAIM'], [' Qodiqa', 'RESERVED_CLAIM'], ['QODIQA ', 'RESERVED_CLAIM'],
  ])('F4-E2E-03 a caller payload key %j is refused with %s on V1 and V2', async (key) => {
    for (const v2 of [null, { bind: { headers: [] } }]) {
      v2On();
      const r = await sign({ v2, payload: { [key]: { v: 2 } } });
      expect(r.status).toBe(400);
      expect(r.body.reason).toBe('RESERVED_CLAIM');
    }
  });

  test('F4-E2E-04 caller data of a V2 request: only provider and claims; query with raw + or ; is QUERY_NOT_BINDABLE with a message', async () => {
    v2On();
    expect((await sign({ payload: { other: 1 } })).body.reason).toBe('INVALID_REQUEST');
    const r = await sign({ request: { query: 'a=b+c' } });
    expect(r.status).toBe(400);
    expect(r.body.reason).toBe('QUERY_NOT_BINDABLE');
    expect((await sign({ request: { query: 'a=1;b=2' } })).body.reason).toBe('QUERY_NOT_BINDABLE');
    expect((await sign({ request: { query: 'a=b%2Bc' } })).status).toBe(200);
  });

  test('F4-E2E-05 bad v2 blocks: unknown fields, forbidden bound headers, maxCostMicros (not enforceable yet), query/headers without v2', async () => {
    v2On();
    for (const v2 of [{ bind: { headers: ['authorization'] } }, { bind: { headers: ['Accept'] } }, { bind: { headers: [] }, extra: 1 }, { bind: { headers: [] }, limits: { maxCostMicros: 5 } }, { bind: { headers: [] }, limits: { maxTokens: 0 } }, { bind: {} }, { bind: { headers: [] }, crit: [] }, { bind: { headers: [] }, crit: ['v'] }]) {
      expect({ v2, status: (await sign({ v2 })).status }).toEqual({ v2, status: 400 });
    }
    const r = await sign({ v2: null, request: { query: 'a=1' } });
    expect(r.status).toBe(400);
  });
});

describe('verification (/ai/chat)', () => {
  test('F4-E2E-06 a V2 artifact bound to query and a header executes; the provider receives the signed output cap', async () => {
    v2On();
    const s = await sign({ request: { query: 'b=2&a=1', headers: { 'x-trace': 'abc' } }, v2: { bind: { headers: ['x-trace'] }, limits: { maxTokens: 32 } } });
    expect(s.status).toBe(200);
    const r = await chat(s.body.artifact, { target: '/ai/chat?a=1&b=2', headers: { 'x-trace': 'abc' } });
    expect(r.body.decision).toBe('EXECUTE');
    expect(calls).toHaveLength(1);
    expect(calls[0].body.maxTokens).toBe(32);
  });

  test('F4-E2E-07 every single-component change breaks the binding (constant REQUEST_MISMATCH, empty details)', async () => {
    v2On();
    const mk = () => sign({ request: { query: 'a=1', headers: { 'x-trace': 'abc' } }, v2: { bind: { headers: ['x-trace'] } } });
    const cases = [
      { target: '/ai/chat?a=2', headers: { 'x-trace': 'abc' } },
      { target: '/ai/chat', headers: { 'x-trace': 'abc' } },
      { target: '/ai/chat?a=1', headers: { 'x-trace': 'abd' } },
      { target: '/ai/chat?a=1', headers: {} },
      { target: '/ai/chat?a=1', headers: { 'x-trace': 'abc' }, body: JSON.stringify({ ...BODY, prompt: 'other' }) },
      { target: '/ai/chat?a=1', headers: { 'x-trace': 'abc' }, body: '{"prompt":"hello","prompt":"hello","model":"gpt-4o"}' },
      { target: '/ai/chat?a=1&a=1', headers: { 'x-trace': 'abc' } },
      { target: '/ai/chat?a=1;b=2', headers: { 'x-trace': 'abc' } },
    ];
    for (const c of cases) {
      const s = await mk();
      const r = await chat(s.body.artifact, c);
      expect({ c, reason: r.body.reason, details: r.body.details }).toEqual({ c, reason: 'REQUEST_MISMATCH', details: {} });
    }
    expect(calls).toHaveLength(0);
  });

  test('F4-E2E-08 version gates: accept flag off, tenant/env minimum, unknown version, unknown critical claim, wrong kind', async () => {
    v2On();
    const v1 = await sign({ v2: null });                                          // a V1 artifact (no v2 block)
    const s = await sign();
    process.env.QODIQA_PROTOCOL_V2_ACCEPT = 'false';
    expect((await chat(s.body.artifact)).body.reason).toBe('UNSUPPORTED_PROTOCOL_VERSION');
    v2On();
    process.env.QODIQA_PROTOCOL_MIN_VERSION = '2';
    expect((await chat(v1.body.artifact)).body.reason).toBe('PROTOCOL_VERSION_TOO_LOW');
    const s2 = await sign();
    expect((await chat(s2.body.artifact)).body.decision).toBe('EXECUTE');          // V2 still passes at minimum 2
    expect(calls).toHaveLength(1);
  });

  test('F4-E2E-09 the V1 path is unchanged: a V1 artifact still executes with the flags off', async () => {
    const v1 = await sign({ v2: null });
    expect(v1.status).toBe(200);
    expect(v1.body.artifact.payload.qodiqa).toBeUndefined();
    const r = await chat(v1.body.artifact);
    expect(r.body.decision).toBe('EXECUTE');
    expect(calls[0].body.maxTokens).toBeUndefined();
  });

  test('F4-E2E-10 a model pin: the artifact authorizes the model named at signing', async () => {
    v2On();
    const s = await sign({ v2: { bind: { headers: [] }, model: 'gpt-4o' } });
    expect(s.body.artifact.payload.qodiqa.model).toBe('gpt-4o');
    expect((await sign({ v2: { bind: { headers: [] }, model: 'other' } })).status).toBe(400);   // conflicts with request.body.model
  });
});

describe('tenant minimum protocol version', () => {
  test('F4-E2E-11 a tenant with minProtocolVersion 2 refuses V1 artifacts and still accepts V2', async () => {
    v2On();
    const { updateTenant, getTenant } = require('../../../core/tenancy/tenantRegistry');
    expect(getTenant('default').minProtocolVersion || 1).toBe(1);
    const v1 = await sign({ v2: null });
    const v2 = await sign();
    await updateTenant('default', { minProtocolVersion: 2 });
    try {
      expect(getTenant('default').minProtocolVersion).toBe(2);
      expect((await chat(v1.body.artifact)).body.reason).toBe('PROTOCOL_VERSION_TOO_LOW');
      expect((await chat(v2.body.artifact)).body.decision).toBe('EXECUTE');
      await expect((async () => updateTenant('default', { minProtocolVersion: 3 }))()).rejects.toThrow(/INVALID_MIN_PROTOCOL_VERSION/);
    } finally { await updateTenant('default', { minProtocolVersion: 1 }); }
  });
});
