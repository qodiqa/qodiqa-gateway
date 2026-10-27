'use strict';

/**
 * deterministic proof that pinning READ COMMITTED closes the
 * concurrent-mutation race, run against the real, unmodified ConsentStore
 *.
 *
 * The bug: pool.js's REPEATABLE READ default meant a transaction's
 * `SELECT ... FOR UPDATE` (or INSERT ... ON CONFLICT DO UPDATE, which locks
 * its conflict-target row the same way) raised SQLSTATE 40001 — surfaced by
 * the route layer as a generic HTTP 500 with no retry — whenever it woke up
 * from waiting on a row a concurrent transaction had just committed. Nothing
 * ever retried, so the loser's operation simply failed outright: in the
 * live campaign, 3 of 12 racing revokes failed this way and left the
 * consent record wrongly ACTIVE.
 *
 * Determinism strategy: the fake pool in fakePgRaceHarness.js has no real
 * I/O — every `await` resolves on the current microtask queue with nothing
 * pending — so `Promise.all([opA(), opB()])` deterministically has opA reach
 * its row lock first (JS evaluates array elements left-to-right, and the
 * synchronous prefix of each async call chain — down to the lock-queue
 * mutation itself — runs before the engine ever suspends to let opB start).
 * Reordering which call is listed first in `Promise.all` is therefore a
 * reliable, non-flaky way to force each interleaving, not a race against the
 * clock.
 */

const { makeFakePgPool } = require('../fakePgRaceHarness');

function makeRow(overrides = {}) {
  return {
    id:              'race-row-1',
    actor_id:        'ai-agent-001',
    action:          'Facial Recognition',
    tenant_id:       null,
    state:           'ACTIVE',
    scope:           null,
    required_scope:  null,
    granted_by:      'admin',
    granted_via:     'API',
    grant_reference: null,
    granted_at:      new Date('2026-01-01T00:00:00Z'),
    expires_at:      null,
    duration_days:   null,
    subject_name:    null,
    action_display:  null,
    policy_reference: null,
    tags:            [],
    metadata:        {},
    record_hash:     null,
    revoked_at:       null, revoked_by: null, revocation_reason: null,
    suspended_at:     null, suspended_by: null, suspension_reason: null, suspended_until: null,
    ...overrides,
  };
}

// ── Harness self-test: proves the fake pool models the real bug faithfully ──
// Not through ConsentStore — a synthetic two-transaction race issued
// directly against the fake pool, documenting exactly why the READ
// COMMITTED pin (not some other fix) is what closes.

describe('fakePgRaceHarness — isolation-level fidelity (self-test, documents the mechanism)', () => {
  test('REPEATABLE READ: the loser of a same-row race gets SQLSTATE 40001', async () => {
    const pool = makeFakePgPool();
    pool.seed('r1', makeRow());

    async function txn(label) {
      return pool.withTransaction(async (tx) => {
        await tx.query('SELECT * FROM consent_records WHERE id = $1 FOR UPDATE', ['r1']);
        await tx.query('UPDATE consent_records SET state = $1 WHERE id = $2', [label, 'r1']);
      }, { isolationLevel: 'REPEATABLE READ' });
    }

    const results = await Promise.allSettled([txn('WINNER'), txn('LOSER')]);
    const statuses = results.map((r) => r.status);
    expect(statuses).toContain('rejected');
    const rejected = results.find((r) => r.status === 'rejected');
    expect(rejected.reason.code).toBe('40001');
  });

  test('READ COMMITTED: the identical race never raises 40001 — both transactions complete', async () => {
    const pool = makeFakePgPool();
    pool.seed('r1', makeRow());

    async function txn(label) {
      return pool.withTransaction(async (tx) => {
        await tx.query('SELECT * FROM consent_records WHERE id = $1 FOR UPDATE', ['r1']);
        await tx.query('UPDATE consent_records SET state = $1 WHERE id = $2', [label, 'r1']);
      }, { isolationLevel: 'READ COMMITTED' });
    }

    const results = await Promise.allSettled([txn('FIRST'), txn('SECOND')]);
    expect(results.every((r) => r.status === 'fulfilled')).toBe(true);
    // The second writer's UPDATE is what's left standing — no error, no lost commit.
    expect(pool.getRow('r1').state).toBe('SECOND');
  });
});

// ── Through the real ConsentStore, now pinned to READ COMMITTED ─────────────

describe('ConsentStore — race regression (real create()/revoke()/suspend(), fake pool)', () => {
  let store;
  let pool;

  beforeEach(() => {
    jest.resetModules();
    pool = makeFakePgPool();
    jest.doMock('../../../infra/postgres/pool', () => pool);
    jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));
    store = require('../ConsentStore');
  });

  afterEach(() => jest.resetModules());

  // Case #10 — concurrent grant (re-create) + revoke of the same active key.
  describe('Case #10 — concurrent create() (re-grant) + revoke()', () => {
    test('revoke wins the lock first: commits REVOKED; the losing re-grant is rejected with a clean 400-mappable error, never 40001', async () => {
      pool.seed('race-row-1', makeRow());

      const [revokeResult, createResult] = await Promise.allSettled([
        store.revoke({ id: 'race-row-1', revoked_by: 'admin' }),
        store.create({ actor_id: 'ai-agent-001', action: 'Facial Recognition', granted_by: 'admin' }),
      ]);

      expect(revokeResult.status).toBe('fulfilled');
      expect(revokeResult.value.state).toBe('REVOKED');

      expect(createResult.status).toBe('rejected');
      expect(createResult.reason.code).not.toBe('40001');
      expect(createResult.reason.message).toMatch(/terminal state REVOKED/);

      // The revoke's write is never silently undone by the losing re-grant.
      expect(pool.getRow('race-row-1').state).toBe('REVOKED');
    });

    test('re-grant wins the lock first: revoke still completes normally against the fresh row, never 40001, consent never left wrongly ACTIVE', async () => {
      pool.seed('race-row-1', makeRow());

      const [createResult, revokeResult] = await Promise.allSettled([
        store.create({ actor_id: 'ai-agent-001', action: 'Facial Recognition', granted_by: 'admin' }),
        store.revoke({ id: 'race-row-1', revoked_by: 'admin' }),
      ]);

      expect(createResult.status).toBe('fulfilled');
      expect(revokeResult.status).toBe('fulfilled');
      expect(revokeResult.value.state).toBe('REVOKED');
      expect(revokeResult.reason).toBeUndefined();

      // The exact failure mode this closes: a losing revoke leaving
      // consent live. Here revoke is never the loser — under READ COMMITTED
      // it always sees the fresh row and completes.
      expect(pool.getRow('race-row-1').state).toBe('REVOKED');
    });
  });

  // Case #12 Part A2 — concurrent suspend + suspend from ACTIVE (a genuine
  // write/write race, unlike SUSPENDED->SUSPENDED which is rejected on
  // transition validity before any UPDATE is attempted).
  describe('Case #12 Part A2 — concurrent suspend() + suspend() from ACTIVE', () => {
    test('exactly one suspend wins; the other is rejected on transition validity (400-mappable), never 40001; final state is SUSPENDED', async () => {
      pool.seed('race-row-1', makeRow());

      const results = await Promise.allSettled([
        store.suspend({ id: 'race-row-1', suspended_by: 'admin-a' }),
        store.suspend({ id: 'race-row-1', suspended_by: 'admin-b' }),
      ]);

      const fulfilled = results.filter((r) => r.status === 'fulfilled');
      const rejected  = results.filter((r) => r.status === 'rejected');

      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      expect(fulfilled[0].value.state).toBe('SUSPENDED');

      expect(rejected[0].reason.code).not.toBe('40001');
      expect(rejected[0].reason.message).toMatch(/Invalid transition: SUSPENDED → SUSPENDED/);

      expect(pool.getRow('race-row-1').state).toBe('SUSPENDED');
    });
  });

  // Case #14 (A.14.reframe) — concurrent create() (grant) against a row
  // already in a terminal state, exercising the fix's WHERE guard under
  // race rather than single-threaded.
  describe('Case #14 (A.14.reframe) — concurrent create() against a terminal-state row', () => {
    test('both racing grants are rejected on the terminal-state guard, never 40001; the row is never reactivated', async () => {
      pool.seed('race-row-1', makeRow({ state: 'REVOKED', revoked_at: new Date(), revoked_by: 'admin' }));

      const results = await Promise.allSettled([
        store.create({ actor_id: 'ai-agent-001', action: 'Facial Recognition', granted_by: 'admin-a' }),
        store.create({ actor_id: 'ai-agent-001', action: 'Facial Recognition', granted_by: 'admin-b' }),
      ]);

      expect(results.every((r) => r.status === 'rejected')).toBe(true);
      for (const r of results) {
        expect(r.reason.code).not.toBe('40001');
        expect(r.reason.message).toMatch(/terminal state REVOKED/);
      }

      expect(pool.getRow('race-row-1').state).toBe('REVOKED');
    });
  });
});
