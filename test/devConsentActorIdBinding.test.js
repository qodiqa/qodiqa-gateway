'use strict';

/**
 * remediation — regression test for the dev-bootstrap consent
 * actor_id mismatch (Session 3, disclosed but not filed; confirmed
 * live and fixed while validating docs/guides/quickstart.md's own Path A).
 *
 * Root cause: scripts/lib/devConsent.js's auto-grant used to bind consent
 * to the tenant's artifact-signing KEY id (services/artifact/keyManager.js's
 * getSigningKey(clientId).keyId, format "<clientId>:key_v<N>"), but
 * services/policy/evaluators/requireConsent.js's real,
 * caller-binding verification looks up by the signing IDENTITY's own id
 * (context.callerId, which src/api/routes/sign.js populates from
 * identity.id — a distinct UUID from a distinct store) — every real signed
 * artifact carries callerContext, so the auto-granted record never actually
 * matched a real request's own consent lookup.
 *
 * This test proves the wiring directly (mocked stores, no real Postgres —
 * the real end-to-end proof is the genuine fresh-clone docs/guides/quickstart.md
 * validation run): provisionDevConsent()
 * must grant against the signing identity's own `id`, never the signing
 * key's `keyId`, and the two must be different values for this test to mean
 * anything (a real signing identity's id is always a UUID, the key's keyId
 * is always "<clientId>:key_v<N>" — structurally distinct by construction,
 * not just different by coincidence in this fixture).
 */

// devConsent.js's own dependency graph reaches real infrastructure at three
// points that must ALL be mocked, never just the ones this test cares about
// — an incomplete mock here would let a Jest run reach a real, ambient
// Postgres connection using whatever QODIQA_PG_TEST_USER/PASSWORD happen to
// be sitting in .env, exactly the un-isolated-write hazard CLAUDE.md's
// note exists to prevent:
//   1. `pg`'s Pool (ensureDatabaseExists() constructs one directly)
//   2. src/infra/postgres/migrate.js's runMigrations() (a *separate* lazy
//      require from src/infra/postgres/pool.js — mocking one does not mock
//      the other)
//   3. src/infra/postgres/pool.js itself (initialize()/isEnabled())
// Mocking bootstrapIsolationGuard is not required for safety (it only
// asserts, never connects) but is included so a real per-boot database name
// is never even computed.
jest.mock('pg', () => ({
  Pool: jest.fn(() => ({
    query: jest.fn().mockResolvedValue({ rows: [{ '?column?': 1 }] }), // ensureDatabaseExists: db already exists
    end:   jest.fn().mockResolvedValue(undefined),
  })),
}));
jest.mock('../src/infra/postgres/migrate', () => ({
  runMigrations: jest.fn().mockResolvedValue({ applied: [], skipped: 0 }),
}));
jest.mock('../src/infra/postgres/pool', () => ({
  initialize: jest.fn(),
  isEnabled:  jest.fn(() => true),
}));
jest.mock('../scripts/lib/bootstrapIsolationGuard', () => ({
  assertBootstrapDatabaseIsolated: jest.fn(),
}));
jest.mock('../src/core/signing/signingIdentityStore', () => ({
  listSigningIdentities: jest.fn(),
}));
jest.mock('../src/core/consent', () => ({
  grant: jest.fn().mockResolvedValue({ id: 'consent-record-1' }),
}));

const { listSigningIdentities } = require('../src/core/signing/signingIdentityStore');
const consent = require('../src/core/consent');
const { provisionDevConsent } = require('../scripts/lib/devConsent');

const ORIGINAL_ENV = { ...process.env };

beforeEach(() => {
  jest.clearAllMocks();
  process.env = { ...ORIGINAL_ENV };
  process.env.QODIQA_PG_ENABLED = 'true';
  process.env.QODIQA_PG_DATABASE = 'qodiqa_test_actor_id_binding_fixture'; // never falsy — keeps ensureDatabaseExists/migrate on the mocked, explicit-database branch, not the real-Pool-construction generated-name branch
  process.env.QODIQA_PG_TEST_USER = 'mock-user';
  process.env.OPENAI_API_KEY = 'sk-test';
  delete process.env.ANTHROPIC_API_KEY;
  delete process.env.GEMINI_API_KEY;
  delete process.env.MISTRAL_API_KEY;
  delete process.env.LLAMA_BASE_URL;
  delete process.env.LOCAL_BASE_URL;

  // Real-shaped values: a UUID (signing identity id) vs. a "<clientId>:key_v<N>"
  // string (signing key id) — structurally distinct, matching production.
  listSigningIdentities.mockReturnValue([
    { id: '9c3f2b1a-1111-4a5b-8c6d-000000000001', tenantId: 'test-client', name: 'test-client-dev', createdBy: 'DEV_BOOTSTRAP' },
    { id: '9c3f2b1a-2222-4a5b-8c6d-000000000002', tenantId: 'other-tenant', name: 'other-tenant-dev', createdBy: 'DEV_BOOTSTRAP' },
  ]);
});

afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
});

describe('dev-bootstrap consent grants against the real signing-identity id', () => {
  test('grants actor_id = the signing identity\'s own id, not a "<clientId>:key_v<N>" key id', async () => {
    const result = await provisionDevConsent({ clientId: 'test-client', log: () => {}, warn: () => {} });

    expect(consent.grant).toHaveBeenCalledTimes(1);
    const grantArg = consent.grant.mock.calls[0][0];

    expect(grantArg.actor_id).toBe('9c3f2b1a-1111-4a5b-8c6d-000000000001'); // the identity's own id
    expect(grantArg.actor_id).not.toMatch(/^test-client:key_v\d+$/);        // never the old, wrong key-id format
    expect(grantArg.tenant_id).toBe('test-client');
    expect(result.granted).toEqual(['openai']);

    // Only this tenant's own identity is ever considered, even with another
    // tenant's identity present in the same (isolated, per-boot) store.
    expect(grantArg.actor_id).not.toBe('9c3f2b1a-2222-4a5b-8c6d-000000000002');
  });

  test('skips gracefully (no grant attempted) when no dev-bootstrap identity exists for this tenant', async () => {
    listSigningIdentities.mockReturnValue([]); // simulates a boot sequence bug/ordering error

    const warnings = [];
    const result = await provisionDevConsent({ clientId: 'test-client', log: () => {}, warn: (m) => warnings.push(m) });

    expect(consent.grant).not.toHaveBeenCalled();
    expect(result).toEqual({ attempted: true, granted: [] });
    expect(warnings.some((w) => w.includes('No dev-bootstrap signing identity found'))).toBe(true);
  });
});
