'use strict';

/**
 * TQ-05 — /ai/chat signing-identity scope and
 * provider-failover authorization.
 *
 * Mutation testing showed both controls effectively unasserted: the SCOPE-stage refusals, and the failover authorizer
 * (_makeFailoverAuthorizer) that decides whether a configured failover target may execute for THIS caller, which had
 * no coverage at all — the injectable _providerFn never receives it. Here the real router runs with the real
 * validation, policy and audit chain; only the provider execution module (to capture the authorizer the router hands
 * it) and the signing-identity store are stubbed. Deterministic: no timing.
 *
 *   SF-01 a revoked / disabled / deleted signing identity is refused at SCOPE before any provider call, bound evidence
 *   SF-02 an identity whose provider scope excludes the signed provider is refused (SCOPE_PROVIDER_DENIED)
 *   SF-03 a stale control plane fails closed with its own code, before any provider call
 *   SF-04 failover authorizer: an in-scope, enabled, permitted target passes the same consent/policy check
 *   SF-05 failover authorizer refusals: out of scope, revoked meanwhile, disabled, missing SIGN_ARTIFACT, identity store
 *         error (with and without a code), and a target the consent policy refuses
 *   SF-06 failover authorizer: an artifact with no caller identity can never fail over (NO_CALLER_IDENTITY)
 */

process.env.AI_CHAT_TIMEOUT_MS = '5000';

// Entries that carry a caller identity need the subject pseudonym (PostgreSQL in production); the shared test double
// other aiChat suites use stands in for it here.
jest.mock('../../../core/dsr/subjectPseudonym', () => require('../../../../test/helpers/subjectPseudonymMock'));
const mockConsentVerify = jest.fn();
jest.mock('../../../core/consent', () => ({ verify: (...a) => mockConsentVerify(...a) }));
jest.mock('../../../core/semantic/embeddingGate', () => ({ checkText: jest.fn().mockResolvedValue({ blocks: false }) }));
const mockGetIdentity = jest.fn();
jest.mock('../../../core/signing/signingIdentityStore', () => {
  const actual = jest.requireActual('../../../core/signing/signingIdentityStore');
  return { ...actual, getSigningIdentity: (...a) => mockGetIdentity(...a) };
});
const mockExec = jest.fn();
jest.mock('../../../../services/execution', () => {
  const actual = jest.requireActual('../../../../services/execution');
  return { ...actual, executeProviderCall: (...a) => mockExec(...a) };
});

const express   = require('express');
const supertest = require('supertest');

const createAiChatRouter     = require('../aiChat');
const attachClientIp         = require('../../../../middleware/clientIp');
const { signBoundArtifact }  = require('../../../validation/signBoundArtifact');
const { getActiveKey }       = require('../../../../services/artifact/keyStore');
const { resetStats }         = require('../../../../services/execution-guard');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const { createStore }        = require('../../../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
const { getModernChain, drainPendingWrites } = require('../../../core/audit/audit-log');

jest.setTimeout(30_000);

const CHAT_PATH = '/ai/chat';
const CHAT_BODY = { prompt: 'Hello, world!', model: 'gpt-4' };
const CALLER = { callerId: 'sid-tq05-1', callerName: 'tq05', environment: 'test', credentialType: 'signing_identity' };
const POLICIES = validateAndPrepare({ policies: [{
  id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true },
}] });
let KEY;
const ident = (over = {}) => ({ id: CALLER.callerId, enabled: true, revoked: false, permissions: ['SIGN_ARTIFACT'], allowedProviders: ['openai', 'anthropic'], ...over });

function buildArtifact({ caller = CALLER } = {}) {
  const now = Date.now();
  return signBoundArtifact({ method: 'POST', path: CHAT_PATH, body: CHAT_BODY },
    { payload: { provider: 'openai', ...(caller ? { callerContext: caller } : {}) }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer);
}
function makeApp() {
  const app = express();
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({
    _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(),
    _getPolicies: () => POLICIES, _policyStore: createStore(),
  }));
  return app;
}
const post = (app, artifact) => supertest(app).post('/ai/chat')
  .set('x-qodiqa-artifact', Buffer.from(JSON.stringify(artifact)).toString('base64')).send(CHAT_BODY);
async function entryFor(artifact, before) {
  for (let i = 0; i < 200; i++) {
    await drainPendingWrites();
    const mine = (await getModernChain()).slice(before).filter((e) => e.artifactId === artifact.payload.requestId);
    if (mine.length) return mine[mine.length - 1];
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error('no audit entry');
}
// Runs one request whose (stubbed) provider execution calls the authorizer the router hands it with `target`, after
// `beforeAuthorize` (e.g. a revocation that lands mid-request). Returns the authorizer's verdict.
async function authorizeVia(target, { beforeAuthorize, artifact = buildArtifact() } = {}) {
  let verdict;
  mockExec.mockImplementationOnce(async (_provider, _body, _ctx, traceMeta) => {
    if (beforeAuthorize) beforeAuthorize();
    verdict = await traceMeta.authorizeFailover(target);
    return { output: 'ok' };
  });
  const res = await post(makeApp(), artifact);
  await drainPendingWrites();
  return { verdict, res };
}

beforeAll(() => { KEY = getActiveKey('default'); });
beforeEach(() => {
  resetStats();
  mockConsentVerify.mockReset();
  mockConsentVerify.mockResolvedValue({ pass: true, reason: 'ACTIVE' });
  mockGetIdentity.mockReset();
  mockGetIdentity.mockImplementation(() => ident());
  mockExec.mockReset();
  mockExec.mockImplementation(async () => ({ output: 'ok' }));
});

describe('SCOPE stage (TQ-05)', () => {
  test.each([
    ['revoked', () => ident({ revoked: true })],
    ['disabled', () => ident({ enabled: false })],
    ['deleted', () => null],
  ])('SF-01 a %s signing identity is refused at SCOPE before any provider call, with bound evidence', async (_n, impl) => {
    mockGetIdentity.mockImplementation(impl);
    const a = buildArtifact();
    const before = (await getModernChain()).length;
    const res = await post(makeApp(), a);
    expect(res.body).toMatchObject({ decision: 'BLOCK', reason: 'SIGNING_IDENTITY_REVOKED' });
    expect(mockExec).not.toHaveBeenCalled();
    const e = await entryFor(a, before);
    expect(e.decision).toBe('BLOCK');
    expect(e.executionContext).toMatchObject({ stage: 'SCOPE', reason: 'SIGNING_IDENTITY_REVOKED' });
    expect(e.inputHash).toBe(a.payload.requestHash);
    expect(e.requestHash).toBe(a.payload.requestHash);
    expect(e.signature).toBe(a.signature);
    // the caller is recorded pseudonymised in the chain, never as the raw identity id
    expect(e.callerContext.callerId).toMatch(/^ap1:[0-9a-f]{64}$/);
    expect(JSON.stringify(e)).not.toContain(CALLER.callerId);
  });

  test('SF-02 an identity scoped away from the signed provider is refused (SCOPE_PROVIDER_DENIED), bound evidence', async () => {
    mockGetIdentity.mockImplementation(() => ident({ allowedProviders: ['anthropic'] }));
    const a = buildArtifact();
    const before = (await getModernChain()).length;
    const res = await post(makeApp(), a);
    expect(res.body).toMatchObject({ decision: 'BLOCK', reason: 'SCOPE_PROVIDER_DENIED' });
    expect(mockExec).not.toHaveBeenCalled();
    const e = await entryFor(a, before);
    expect(e.executionContext).toMatchObject({ stage: 'SCOPE', reason: 'SCOPE_PROVIDER_DENIED' });
    expect(e.inputHash).toBe(a.payload.requestHash);
    expect(e.signature).toBe(a.signature);
  });

  test('SF-02b an identity with no provider scope list is not restricted by it', async () => {
    mockGetIdentity.mockImplementation(() => ident({ allowedProviders: undefined }));
    const res = await post(makeApp(), buildArtifact());
    expect(res.body.decision).toBe('EXECUTE');
  });

  test('SF-03 a stale control plane fails closed with its own code before any provider call', async () => {
    mockGetIdentity.mockImplementation(() => { throw Object.assign(new Error('stale'), { name: 'ControlPlaneError', code: 'CONTROL_PLANE_STALE' }); });
    const res = await post(makeApp(), buildArtifact());
    expect(res.body).toMatchObject({ decision: 'BLOCK', reason: 'CONTROL_PLANE_STALE' });
    expect(mockExec).not.toHaveBeenCalled();
  });
});

describe('provider failover authorization (TQ-05)', () => {
  test('SF-04 an enabled, permitted, in-scope target that passes consent/policy is authorized', async () => {
    const { verdict, res } = await authorizeVia('anthropic');
    expect(verdict).toEqual({ ok: true });
    expect(res.body.decision).toBe('EXECUTE');
    // the target was checked with the SAME consent policy, as the target (REQUIRE_CONSENT reads payload.provider)
    expect(mockConsentVerify.mock.calls.map(([q]) => q.action)).toEqual(['openai', 'anthropic']);
  });

  test.each([
    ['out of the identity\'s provider scope', 'mistral', null, 'SCOPE_PROVIDER_DENIED'],
    ['identity revoked mid-request', 'anthropic', () => mockGetIdentity.mockImplementation(() => ident({ revoked: true })), 'SIGNING_IDENTITY_REVOKED'],
    ['identity disabled mid-request', 'anthropic', () => mockGetIdentity.mockImplementation(() => ident({ enabled: false })), 'SIGNING_IDENTITY_REVOKED'],
    ['identity deleted mid-request', 'anthropic', () => mockGetIdentity.mockImplementation(() => null), 'SIGNING_IDENTITY_REVOKED'],
    ['identity lost SIGN_ARTIFACT', 'anthropic', () => mockGetIdentity.mockImplementation(() => ident({ permissions: ['VIEW_AUDIT'] })), 'IDENTITY_PERMISSION_DENIED'],
    ['identity has no permission list', 'anthropic', () => mockGetIdentity.mockImplementation(() => ident({ permissions: undefined })), 'IDENTITY_PERMISSION_DENIED'],
    ['identity store error with a code', 'anthropic', () => mockGetIdentity.mockImplementation(() => { throw Object.assign(new Error('x'), { code: 'CONTROL_PLANE_STALE' }); }), 'CONTROL_PLANE_STALE'],
    ['identity store error without a code', 'anthropic', () => mockGetIdentity.mockImplementation(() => { throw new Error('x'); }), 'IDENTITY_UNAVAILABLE'],
  ])('SF-05 failover refused: %s', async (_n, target, beforeAuthorize, reason) => {
    const { verdict } = await authorizeVia(target, { beforeAuthorize });
    expect(verdict).toEqual({ ok: false, reason });
  });

  test('SF-05b failover refused when the consent policy refuses the TARGET provider (checked as the target)', async () => {
    // consent is verified per action = provider: granted for the signed provider, revoked for the failover target
    mockConsentVerify.mockImplementation(async ({ action }) => (action === 'anthropic'
      ? { pass: false, reason: 'CONSENT_REVOKED' } : { pass: true, reason: 'ACTIVE' }));
    const { verdict } = await authorizeVia('anthropic');
    expect(verdict).toEqual({ ok: false, reason: 'CONSENT_REVOKED' });
    expect(mockConsentVerify.mock.calls.map(([q]) => q.action)).toEqual(['openai', 'anthropic']);
  });

  test('SF-06 an artifact with no caller identity can never fail over', async () => {
    const { verdict } = await authorizeVia('anthropic', { artifact: buildArtifact({ caller: null }) });
    expect(verdict).toEqual({ ok: false, reason: 'NO_CALLER_IDENTITY' });
  });
});
