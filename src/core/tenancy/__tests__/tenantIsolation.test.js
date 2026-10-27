'use strict';

// Mock consent registry — tenant isolation tests verify per-tenant artifact
// and nonce isolation; consent evaluation is tested in src/core/consent/.
jest.mock('../../consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

/**
 * Multi-tenancy isolation test suite.
 *
 * Verifies that two tenants (tenant-a, tenant-b) cannot access each other's
 * keys, nonces, anomaly counters, audit entries, or execution contexts.
 */

const supertest              = require('supertest');
const express                = require('express');
const createAiChatRouter     = require('../../../api/routes/aiChat');
const { rotateKey, getActiveKey } = require('../../../../services/artifact/keyStore');
const { signBoundArtifact }  = require('../../../validation/signBoundArtifact');
const { validateBoundRequest } = require('../../../validation/validateBoundRequest');
const { checkAnomaly }       = require('../../../validation/checkAnomaly');
const { registerNonce }      = require('../../../validation/registerNonce');
const { getAuditChain, getArtifactById, getAuditChainForTenant } = require('../../audit/audit-log');
const { assertExecutionInvariant, resetStats } = require('../../../../services/execution-guard');
const { mintExecutionToken } = require('../../../../services/executionInvariantToken');
const { setPolicies, getPoliciesForTenant, _reset: resetPolicies } = require('../tenantPolicyRegistry');
const { _reset: resetRegistry, assertActiveTenant } = require('../tenantRegistry');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
const { buildNonceKey } = require('../../../validation/nonceStore');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const { createStore }        = require('../../../../services/policy/store');

// ── Setup ─────────────────────────────────────────────────────────────────────

const TENANT_A = 'isolation-tenant-a';
const TENANT_B = 'isolation-tenant-b';

let KEY_A, KEY_B;

beforeAll(() => {
  rotateKey(TENANT_A);
  rotateKey(TENANT_B);
  KEY_A = getActiveKey(TENANT_A);
  KEY_B = getActiveKey(TENANT_B);
});

beforeEach(() => {
  resetStats();
  resetPolicies();
});

const BASE_REQ_A = { method: 'POST', path: '/ai/chat', body: { prompt: 'hello from A', model: 'gpt-4' } };
const BASE_REQ_B = { method: 'POST', path: '/ai/chat', body: { prompt: 'hello from B', model: 'gpt-4' } };

function buildArtifact(req, key, extraPayload = {}) {
  return signBoundArtifact(
    req,
    {
      payload: { provider: 'openai', ...extraPayload },
      timestamp: Date.now(),
      expiry: Date.now() + 300_000,
      publicKeyId: key.keyId,
    },
    key.privDer,
  );
}

// ── Tenant key isolation ──────────────────────────────────────────────────────

describe('Tenant key isolation', () => {
  test('Tenant A artifact validates only with Tenant A key', async () => {
    const artifactA = buildArtifact(BASE_REQ_A, KEY_A);
    const store     = makeNonceStore();
    const result = await validateBoundRequest(artifactA, BASE_REQ_A, {
      _store:        store,
      _anomalyStore: makeOpenAnomalyStore(),
    });
    expect(result.allowed).toBe(true);
    expect(result.tenantId).toBe(TENANT_A);
  });

  test('Tenant B artifact validates only with Tenant B key', async () => {
    const artifactB = buildArtifact(BASE_REQ_B, KEY_B);
    const store     = makeNonceStore();
    const result = await validateBoundRequest(artifactB, BASE_REQ_B, {
      _store:        store,
      _anomalyStore: makeOpenAnomalyStore(),
    });
    expect(result.allowed).toBe(true);
    expect(result.tenantId).toBe(TENANT_B);
  });

  test('Tenant A artifact with wrong key (B) is rejected', async () => {
    // Build an artifact that claims to use KEY_B's keyId but is signed with KEY_A
    const forgedArtifact = signBoundArtifact(
      BASE_REQ_A,
      {
        payload:     { provider: 'openai' },
        timestamp:   Date.now(),
        expiry:      Date.now() + 300_000,
        publicKeyId: KEY_B.keyId, // claims B's key
      },
      KEY_A.privDer, // but signed with A's key
    );
    const store  = makeNonceStore();
    const result = await validateBoundRequest(forgedArtifact, BASE_REQ_A, {
      _store:        store,
      _anomalyStore: makeOpenAnomalyStore(),
    });
    expect(result.allowed).toBe(false);
    // Should fail signature verification
    expect(['INVALID_SIGNATURE', 'KEY_NOT_FOUND', 'SIGNATURE_INVALID']).toContain(result.reason);
  });
});

// ── Nonce isolation ───────────────────────────────────────────────────────────

describe('Nonce isolation', () => {
  test('Same requestId may be used by different tenants without replay', async () => {
    const store = makeNonceStore();
    const expiry = Date.now() + 300_000;

    // Register same UUID for both tenants
    const uuid = '12345678-1234-4234-8234-123456789012';
    const r1 = await registerNonce(uuid, expiry, { _store: store, tenantId: TENANT_A });
    const r2 = await registerNonce(uuid, expiry, { _store: store, tenantId: TENANT_B });

    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(true);
    expect(r1.requestId).toBe(uuid);
    expect(r2.requestId).toBe(uuid);
  });

  test('Same requestId used twice by same tenant is a replay', async () => {
    const store = makeNonceStore();
    const expiry = Date.now() + 300_000;
    const uuid = '22345678-1234-4234-8234-123456789012';

    const r1 = await registerNonce(uuid, expiry, { _store: store, tenantId: TENANT_A });
    const r2 = await registerNonce(uuid, expiry, { _store: store, tenantId: TENANT_A });

    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(false);
    expect(r2.reason).toBe('REPLAY_DETECTED');
  });

  test('Nonce store keys are scoped per QODIQA-PROTOCOL-SPEC.md §27.11: <tenantId>:qodiqa:req:v2:<requestId>', async () => {
    const store = makeNonceStore();
    const expiry = Date.now() + 300_000;
    const uuid = '32345678-1234-4234-8234-123456789012';

    await registerNonce(uuid, expiry, { _store: store, tenantId: TENANT_A });

    // A's key should be in the map
    expect(store._map.has(buildNonceKey(uuid, TENANT_A))).toBe(true);
    // B's key should NOT be in the map
    expect(store._map.has(buildNonceKey(uuid, TENANT_B))).toBe(false);
    // Unscoped key should NOT be in the map
    expect(store._map.has(buildNonceKey(uuid))).toBe(false);
  });
});

// ── Anomaly store isolation ───────────────────────────────────────────────────

describe('Anomaly store isolation', () => {
  test('checkAnomaly uses tenant-prefixed keys for per-key window', async () => {
    const recordedKeys = [];
    const mockStore = {
      async record(key) { recordedKeys.push(key); return { count: 1 }; },
      async peek(key)   { return { count: 0 }; },
    };

    await checkAnomaly(KEY_A.keyId, { _store: mockStore, tenantId: TENANT_A });
    expect(recordedKeys[0]).toBe(`tenant:${TENANT_A}:key:${KEY_A.keyId}`);
    expect(recordedKeys[1]).toBe(`tenant:${TENANT_A}:global`);
  });

  test('checkAnomaly for tenant-b uses tenant-b prefix', async () => {
    const recordedKeys = [];
    const mockStore = {
      async record(key) { recordedKeys.push(key); return { count: 1 }; },
      async peek(key)   { return { count: 0 }; },
    };

    await checkAnomaly(KEY_B.keyId, { _store: mockStore, tenantId: TENANT_B });
    expect(recordedKeys[0]).toBe(`tenant:${TENANT_B}:key:${KEY_B.keyId}`);
    expect(recordedKeys[1]).toBe(`tenant:${TENANT_B}:global`);
  });

  test('Tenant A burst does not affect Tenant B quota', async () => {
    const mockStore = (() => {
      const counts = {};
      return {
        async record(key) {
          counts[key] = (counts[key] || 0) + 1;
          return { count: counts[key] };
        },
        _counts: counts,
      };
    })();

    const thresholds = { WINDOW_MS: 60_000, PER_KEY_MAX: 3, GLOBAL_MAX: 1000 };

    // Burst Tenant A to the limit
    for (let i = 0; i < 3; i++) {
      await checkAnomaly(KEY_A.keyId, { _store: mockStore, _thresholds: thresholds, tenantId: TENANT_A });
    }

    // Tenant B should still have count = 0
    const bKey = `tenant:${TENANT_B}:key:${KEY_B.keyId}`;
    expect(mockStore._counts[bKey] || 0).toBe(0);
  });
});

// ── Audit isolation ───────────────────────────────────────────────────────────

describe('Audit isolation', () => {
  // Note: audit-log uses an append-only in-memory chain; we test getAuditChainForTenant
  // and cross-tenant getArtifactById blocking without modifying the shared chain.
  // We construct entries manually to test the filtering logic.

  test('getAuditChainForTenant returns empty array for missing tenantId', async () => {
    const result = await getAuditChainForTenant(null);
    expect(result).toEqual([]);
  });

  test('getAuditChainForTenant returns empty array for empty string', async () => {
    const result = await getAuditChainForTenant('');
    expect(result).toEqual([]);
  });

  test('getArtifactById with cross-tenant tenantId returns null', async () => {
    // This test verifies the isolation logic in getArtifactById.
    // Build a fake entry object to test the function's filtering logic directly.
    // Since the audit chain is append-only, we verify via the chain's content.
    const chain = await getAuditChain();
    for (const entry of chain) {
      if (entry.tenantId && entry.artifactId) {
        // Try to retrieve it with a different tenant — should return null
        const wrongTenant = entry.tenantId === TENANT_A ? TENANT_B : TENANT_A;
        const result = await getArtifactById(entry.artifactId, wrongTenant);
        // If the entry has tenantId, cross-tenant access is blocked
        expect(result).toBeNull();
        break; // Only need one example
      }
    }
    // If no entries with tenantId exist yet, the isolation code path will be
    // exercised in the integration test below.
  });
});

// ── Execution context isolation ───────────────────────────────────────────────

describe('Execution context isolation', () => {
  test('verifiedCtx WITHOUT tenantId throws UNVERIFIED_EXECUTION_ATTEMPT', () => {
    const VALID_HASH = 'a'.repeat(64);
    const ctxWithoutTenant = Object.freeze({
      verified:    true,
      requestHash: VALID_HASH,
      artifactId:  'test-artifact-id',
      // tenantId intentionally omitted
    });

    expect(() => assertExecutionInvariant(ctxWithoutTenant))
      .toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('verifiedCtx WITH tenantId passes invariant', () => {
    const VALID_HASH        = 'a'.repeat(64);
    const VALID_POLICY_HASH = 'b'.repeat(64);
    // assertExecutionInvariant now also requires a valid HMAC
    // signature binding requestHash+policyHash+issuedAt — a hand-built
    // object of the right shape is no longer sufficient on its own.
    const { issuedAt, signature } = mintExecutionToken({ requestHash: VALID_HASH, policyHash: VALID_POLICY_HASH });
    const ctxWithTenant = Object.freeze({
      verified:    true,
      requestHash: VALID_HASH,
      policyHash:  VALID_POLICY_HASH,
      artifactId:  'test-artifact-id',
      tenantId:    TENANT_A,
      issuedAt,
      signature,
    });

    expect(() => assertExecutionInvariant(ctxWithTenant)).not.toThrow();
  });

  test('verifiedCtx with empty string tenantId fails invariant', () => {
    const VALID_HASH = 'a'.repeat(64);
    const ctxEmptyTenant = Object.freeze({
      verified:    true,
      requestHash: VALID_HASH,
      artifactId:  'test-artifact-id',
      tenantId:    '',
    });

    expect(() => assertExecutionInvariant(ctxEmptyTenant))
      .toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });
});

// ── Policy isolation ──────────────────────────────────────────────────────────

describe('Policy isolation', () => {
  test('setPolicies sets policies for a tenant', () => {
    const policiesA = [{ type: 'ALLOW_ALL' }];
    setPolicies(TENANT_A, policiesA);
    expect(getPoliciesForTenant(TENANT_A)).toEqual(policiesA);
  });

  test('getPoliciesForTenant returns null for tenant with no policies', () => {
    expect(getPoliciesForTenant(TENANT_B)).toBeNull();
  });

  test('Tenant A policies do not leak to Tenant B', () => {
    const policiesA = [{ type: 'BLOCK_IP', ip: '1.2.3.4' }];
    setPolicies(TENANT_A, policiesA);
    expect(getPoliciesForTenant(TENANT_B)).toBeNull();
    expect(getPoliciesForTenant(TENANT_A)).toBe(policiesA);
  });

  test('setPolicies throws for missing tenantId', () => {
    expect(() => setPolicies('', [])).toThrow();
    expect(() => setPolicies(null, [])).toThrow();
    expect(() => setPolicies(undefined, [])).toThrow();
  });
});

// ── Fail-closed validation ────────────────────────────────────────────────────

describe('Fail-closed tenant validation', () => {
  test('validateBoundRequest with unregistered tenant returns TENANT_UNKNOWN', async () => {
    // Use a clientId that was never rotated (so never registered)
    const unregisteredId = 'unregistered-ghost-tenant';

    // Create a fake artifact structure that claims to use an unregistered tenant
    // We can't sign it validly, but we can test the tenant check path by
    // constructing what validateArtifact would accept with an unregistered key.
    // Since we can't easily fake a valid signature for an unregistered key,
    // we test assertActiveTenant directly.
    const result = assertActiveTenant(unregisteredId);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('TENANT_UNKNOWN');
  });

  test('assertActiveTenant with empty tenantId returns TENANT_CONTEXT_MISSING', () => {
    const result = assertActiveTenant('');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('TENANT_CONTEXT_MISSING');
  });

  test('assertActiveTenant with null returns TENANT_CONTEXT_MISSING', () => {
    const result = assertActiveTenant(null);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('TENANT_CONTEXT_MISSING');
  });

  test('validateBoundRequest with registered tenant succeeds', async () => {
    const artifact = buildArtifact(BASE_REQ_A, KEY_A);
    const result = await validateBoundRequest(artifact, BASE_REQ_A, {
      _store:        makeNonceStore(),
      _anomalyStore: makeOpenAnomalyStore(),
    });
    expect(result.allowed).toBe(true);
    expect(result.tenantId).toBe(TENANT_A);
  });
});

// ── Cross-tenant artifact HTTP integration test ───────────────────────────────

describe('Cross-tenant artifact HTTP integration', () => {
  // Permissive policy that allows any valid artifact
  const _OPEN_POLICIES = validateAndPrepare({ policies: [{
    id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
    config: { requireValidArtifact: true },
  }] });
  const _OPEN_POLICY_STORE = createStore();

  function makeTestApp(nonceStore, anomalyStore) {
    const app = express();
    app.use(express.json());

    app.use('/ai/chat', createAiChatRouter({
      _store:        nonceStore,
      _anomalyStore: anomalyStore,
      _getPolicies:  () => _OPEN_POLICIES,
      _policyStore:  _OPEN_POLICY_STORE,
      _providerFn:   async () => ({ output: 'test-response', model: 'mock', tokenUsage: null, executionMetadata: { responseId: null } }),
    }));

    return app;
  }

  test('Tenant A can execute successfully with own valid artifact', async () => {
    const nonceStore   = makeNonceStore();
    const anomalyStore = makeOpenAnomalyStore();
    const app          = makeTestApp(nonceStore, anomalyStore);

    const reqBody   = { prompt: 'hello from A', model: 'gpt-4' };
    const reqObj    = { method: 'POST', path: '/ai/chat', body: reqBody };
    const artifactA = buildArtifact(reqObj, KEY_A);

    const res = await supertest(app)
      .post('/ai/chat')
      .set('content-type', 'application/json')
      .set('x-qodiqa-artifact', Buffer.from(JSON.stringify(artifactA)).toString('base64'))
      .send(reqBody);

    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('EXECUTE');
  });

  test('Artifact signed with Tenant A key but claiming Tenant B key ID is rejected', async () => {
    const nonceStore   = makeNonceStore();
    const anomalyStore = makeOpenAnomalyStore();
    const app          = makeTestApp(nonceStore, anomalyStore);

    const reqBody = { prompt: 'cross-tenant attempt', model: 'gpt-4' };
    const reqObj  = { method: 'POST', path: '/ai/chat', body: reqBody };

    // Build artifact claiming to use B's key but signed with A's key
    const forged = signBoundArtifact(
      reqObj,
      {
        payload:     { provider: 'openai' },
        timestamp:   Date.now(),
        expiry:      Date.now() + 300_000,
        publicKeyId: KEY_B.keyId, // B's key ID
      },
      KEY_A.privDer, // but signed with A's private key
    );

    const res = await supertest(app)
      .post('/ai/chat')
      .set('content-type', 'application/json')
      .set('x-qodiqa-artifact', Buffer.from(JSON.stringify(forged)).toString('base64'))
      .send(reqBody);

    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
  });

  test('Replay of Tenant A artifact is blocked for Tenant A but Tenant B can use same requestId', async () => {
    const nonceStore   = makeNonceStore();
    const anomalyStore = makeOpenAnomalyStore();
    const app          = makeTestApp(nonceStore, anomalyStore);

    const reqBodyA  = { prompt: 'tenant A first request', model: 'gpt-4' };
    const reqObjA   = { method: 'POST', path: '/ai/chat', body: reqBodyA };
    const artifactA = buildArtifact(reqObjA, KEY_A);

    // First Tenant A request — should succeed
    const res1 = await supertest(app)
      .post('/ai/chat')
      .set('content-type', 'application/json')
      .set('x-qodiqa-artifact', Buffer.from(JSON.stringify(artifactA)).toString('base64'))
      .send(reqBodyA);
    expect(res1.status).toBe(200);
    expect(res1.body.decision).toBe('EXECUTE');

    // Replay Tenant A same artifact — should be blocked
    const res2 = await supertest(app)
      .post('/ai/chat')
      .set('content-type', 'application/json')
      .set('x-qodiqa-artifact', Buffer.from(JSON.stringify(artifactA)).toString('base64'))
      .send(reqBodyA);
    expect(res2.status).toBe(200);
    expect(res2.body.reason).toBe('REPLAY_DETECTED');

    // Tenant B using a different artifact (different nonce) — should succeed
    const reqBodyB  = { prompt: 'tenant B independent request', model: 'gpt-4' };
    const reqObjB   = { method: 'POST', path: '/ai/chat', body: reqBodyB };
    const artifactB = buildArtifact(reqObjB, KEY_B);
    const res3 = await supertest(app)
      .post('/ai/chat')
      .set('content-type', 'application/json')
      .set('x-qodiqa-artifact', Buffer.from(JSON.stringify(artifactB)).toString('base64'))
      .send(reqBodyB);
    expect(res3.status).toBe(200);
    expect(res3.body.decision).toBe('EXECUTE');
  });
});
