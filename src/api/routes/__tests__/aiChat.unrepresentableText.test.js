'use strict';

/**
 * / F6-N2 — /ai/chat end-to-end against the REAL audit log
 * (per-file temp log from test/support/jest.setup.js); the transparency registrar is mocked only to observe leaves, and the subject-
 * pseudonym module is the explicit test-only stand-in (no database here) so its calls can be counted.
 *
 *   N2-01  a request-derived value carrying U+0000 (signed callerContext.callerName) → 422 AUDIT_UNREPRESENTABLE_TEXT,
 *          provider NEVER called, NOTHING persisted: no audit entry, no transparency leaf, no pseudonym lookup/key
 *   N2-02  the same with a lone surrogate
 *   N2-03  a provider-returned value (model) carrying U+0000 after the INTENT → the lifecycle is CLOSED by a BLOCK
 *          DECISION without the provider values (reason AUDIT_UNREPRESENTABLE_TEXT, executingProvider set); no ALLOW,
 *          content not delivered, 422; the chain verifies with no ORPHAN_INTENT warning
 *   N2-04  a provider error whose code carries a lone surrogate → BLOCK DECISION reason AUDIT_UNREPRESENTABLE_TEXT, the
 *          lifecycle is closed (no orphan), chain valid
 *   N2-05  ordinary Unicode (Romanian, CJK, emoji = paired surrogates, TAB) in the same positions is NOT refused: EXECUTE
 */

jest.mock('../../../core/consent', () => ({ verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }) }));
jest.mock('../../../core/dsr/subjectPseudonym', () => require('../../../../test/helpers/subjectPseudonymMock'));
const mockLeaves = [];
jest.mock('../../../core/transparency/registrar', () => ({
  register: async (r) => { mockLeaves.push(r); return { transparencyId: 't-' + mockLeaves.length, entryHash: 'e'.repeat(64), signature: 's', keyId: 'tr-default:key_v1', persisted: true }; },
}));

const express   = require('express');
const supertest = require('supertest');
const createAiChatRouter    = require('../aiChat');
const attachClientIp        = require('../../../../middleware/clientIp');
const { signBoundArtifact } = require('../../../validation/signBoundArtifact');
const { getActiveKey }      = require('../../../../services/artifact/keyStore');
const { resetStats }        = require('../../../../services/execution-guard');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const { createStore }        = require('../../../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
const audit = require('../../../core/audit/audit-log');
const { pseudonymFor } = require('../../../core/dsr/subjectPseudonym');

let KEY;
let IDENTITY;   // a live signing identity: the signed callerContext.callerId must resolve to one
let providerCalls = 0;
let providerImpl = null;
beforeAll(() => { KEY = getActiveKey('default'); IDENTITY = require('../../../../test/helpers/signingIdentity').provisionTestSigningIdentity().identityId; });
beforeEach(() => { resetStats(); providerCalls = 0; providerImpl = null; mockLeaves.length = 0; pseudonymFor.mockClear(); });

const BODY = { prompt: 'Hello, world!', model: 'gpt-4' };
const POLICIES = validateAndPrepare({ policies: [{ id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }] });
function makeApp() {
  const app = express(); app.use(attachClientIp); app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({ _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _getPolicies: () => POLICIES, _policyStore: createStore(),
    _providerFn: async () => { providerCalls++; return providerImpl ? providerImpl() : { output: 'fine output' }; } }));
  return app;
}
function artifact(callerContext) {
  const now = Date.now();
  return signBoundArtifact({ method: 'POST', path: '/ai/chat', body: BODY },
    { payload: { provider: 'openai', ...(callerContext ? { callerContext } : {}) }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer);
}
const post = (a) => supertest(makeApp()).post('/ai/chat').set('x-qodiqa-artifact', Buffer.from(JSON.stringify(a)).toString('base64')).send(BODY);
const chainLen = async () => (await audit.getModernChain()).length;

describe('F6-N2 — refuse unrepresentable text at write time, never a partial lifecycle', () => {
  for (const [id, bad] of [['N2-01', 'ci\u0000runner'], ['N2-02', 'ci\ud800runner']]) {
    test(`${id} request-derived ${JSON.stringify(bad)} → 422, provider never called, nothing persisted`, async () => {
      const before = await chainLen();
      const res = await post(artifact({ callerId: IDENTITY, callerName: bad, environment: 'test' }));
      expect(res.status).toBe(422);
      expect(res.body).toMatchObject({ decision: 'BLOCK', reason: 'AUDIT_UNREPRESENTABLE_TEXT' });
      expect(providerCalls).toBe(0);
      expect(await chainLen()).toBe(before);        // no INTENT, no BLOCK — nothing at all
      expect(mockLeaves).toHaveLength(0);           // no transparency leaf
      expect(pseudonymFor).not.toHaveBeenCalled();  // refused before the pseudonym key lookup / creation
    });
  }

  test('N2-03 provider-returned model with U+0000 after the INTENT → closing BLOCK without it, no ALLOW, nothing delivered', async () => {
    providerImpl = () => ({ output: 'SECRET-OUTPUT', model: 'gpt-4\u0000x', executionMetadata: { responseId: 'resp-ok' } });
    const before = await chainLen();
    const res = await post(artifact());
    expect(res.status).toBe(422);
    expect(res.body.reason).toBe('AUDIT_UNREPRESENTABLE_TEXT');
    expect(JSON.stringify(res.body)).not.toContain('SECRET-OUTPUT');
    expect(providerCalls).toBe(1);
    const chain = await audit.getModernChain();
    const added = chain.slice(before);
    expect(added.map((e) => [e.entryType, e.decision, e.stage, e.reason])).toEqual([
      ['INTENT', 'ALLOW', 'PROVIDER_DISPATCH', null],
      ['DECISION', 'BLOCK', 'PROVIDER_EXECUTION', 'AUDIT_UNREPRESENTABLE_TEXT'],
    ]);
    expect(added[1]).toMatchObject({ executingProvider: 'openai', model: null, responseId: null, requestId: added[0].requestId });
    expect(JSON.stringify(added)).not.toMatch(/\u0000/);
    const walk = audit.verifyAuditChainDetailed(chain, 'GENESIS');
    expect(walk).toMatchObject({ valid: true, lifecycleComplete: true });
    expect(walk.warnings.map((w) => w.code)).not.toContain('ORPHAN_INTENT');
    expect(mockLeaves.map((l) => l.payload.entryType || l.payload.decision)).toEqual(['INTENT', 'BLOCK']);
  });

  test('N2-04 provider error code with a lone surrogate → closing BLOCK reason AUDIT_UNREPRESENTABLE_TEXT, no orphan', async () => {
    providerImpl = () => { throw Object.assign(new Error('boom'), { code: 'PROVIDER_\ud800X' }); };
    const before = await chainLen();
    const res = await post(artifact());
    expect(res.status).not.toBe(200);
    const added = (await audit.getModernChain()).slice(before);
    expect(added.map((e) => [e.entryType, e.decision, e.reason])).toEqual([['INTENT', 'ALLOW', null], ['DECISION', 'BLOCK', 'AUDIT_UNREPRESENTABLE_TEXT']]);
    expect(added[1].executingProvider).toBe('openai');
    const walk = audit.verifyAuditChainDetailed(await audit.getModernChain(), 'GENESIS');
    expect(walk.valid).toBe(true);
    expect(walk.warnings.map((w) => w.code)).not.toContain('ORPHAN_INTENT');
  });

  test('N2-05 ordinary Unicode (Romanian, CJK, emoji, TAB) is not refused', async () => {
    providerImpl = () => ({ output: 'ok', model: 'model-Ș-漢-😀', executionMetadata: { responseId: 'r-é\t1' } });
    const before = await chainLen();
    const res = await post(artifact({ callerId: IDENTITY, callerName: 'Ștefan 漢字 😀\tci', environment: 'test' }));
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('EXECUTE');
    const added = (await audit.getModernChain()).slice(before);
    expect(added.map((e) => e.entryType)).toEqual(['INTENT', 'DECISION']);
    expect(added[1]).toMatchObject({ model: 'model-Ș-漢-😀', responseId: 'r-é\t1' });
    expect(added[1].callerContext.callerName).toBe('Ștefan 漢字 😀\tci');
  });
});
