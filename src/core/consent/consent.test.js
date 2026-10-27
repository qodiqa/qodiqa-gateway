'use strict';

/**
 * Runtime Consent Registry — test suite
 *
 * Covers:
 *   1.  ConsentStateModel   — state machine, transitions, effectiveState
 *   2.  ConsentStore        — CRUD operations (mocked pool)
 *   3.  ConsentCache        — get/set/invalidate (mocked Redis)
 *   4.  ConsentVerifier     — hot-path verification logic
 *   5.  ConsentRegistry     — service orchestration
 *   6.  requireConsent      — policy evaluator (async, fail-closed)
 *   7.  Consent API routes  — input validation and HTTP responses
 *   8.  Security controls   — fail-closed, terminal state immutability
 *   9.  State machine edge cases
 */

// ── Shared helpers ────────────────────────────────────────────────────────────

function makeRecord(overrides = {}) {
  return {
    id:              'aaaaaaaa-0000-4000-8000-000000000001',
    actor_id:        'ai-agent-001',
    action:          'Facial Recognition',
    state:           'ACTIVE',
    scope:           'biometric',
    tenant_id:       null,
    required_scope:  null,
    granted_at:      new Date('2026-01-01T00:00:00Z'),
    granted_by:      'admin',
    expires_at:      null,
    suspended_until: null,
    version:         1,
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. ConsentStateModel
// ═══════════════════════════════════════════════════════════════════════════════

describe('ConsentStateModel', () => {
  const {
    STATE, isValidTransition, isTerminal, isValid, effectiveState, isActiveNow,
  } = require('./ConsentStateModel');

  describe('STATE constants', () => {
    test('exports all five states', () => {
      expect(STATE.PENDING).toBe('PENDING');
      expect(STATE.ACTIVE).toBe('ACTIVE');
      expect(STATE.REVOKED).toBe('REVOKED');
      expect(STATE.EXPIRED).toBe('EXPIRED');
      expect(STATE.SUSPENDED).toBe('SUSPENDED');
    });
  });

  describe('isValidTransition()', () => {
    test('PENDING → ACTIVE is valid',     () => expect(isValidTransition('PENDING',   'ACTIVE')).toBe(true));
    test('PENDING → REVOKED is valid',    () => expect(isValidTransition('PENDING',   'REVOKED')).toBe(true));
    test('ACTIVE → REVOKED is valid',     () => expect(isValidTransition('ACTIVE',    'REVOKED')).toBe(true));
    test('ACTIVE → EXPIRED is valid',     () => expect(isValidTransition('ACTIVE',    'EXPIRED')).toBe(true));
    test('ACTIVE → SUSPENDED is valid',   () => expect(isValidTransition('ACTIVE',    'SUSPENDED')).toBe(true));
    test('SUSPENDED → ACTIVE is valid',   () => expect(isValidTransition('SUSPENDED', 'ACTIVE')).toBe(true));
    test('SUSPENDED → REVOKED is valid',  () => expect(isValidTransition('SUSPENDED', 'REVOKED')).toBe(true));
    test('REVOKED → ACTIVE is invalid',   () => expect(isValidTransition('REVOKED',   'ACTIVE')).toBe(false));
    test('EXPIRED → ACTIVE is invalid',   () => expect(isValidTransition('EXPIRED',   'ACTIVE')).toBe(false));
    test('ACTIVE → PENDING is invalid',   () => expect(isValidTransition('ACTIVE',    'PENDING')).toBe(false));
    test('unknown state returns false',   () => expect(isValidTransition('UNKNOWN',   'ACTIVE')).toBe(false));
  });

  describe('isTerminal()', () => {
    test('REVOKED is terminal',       () => expect(isTerminal('REVOKED')).toBe(true));
    test('EXPIRED is terminal',       () => expect(isTerminal('EXPIRED')).toBe(true));
    test('ACTIVE is not terminal',    () => expect(isTerminal('ACTIVE')).toBe(false));
    test('PENDING is not terminal',   () => expect(isTerminal('PENDING')).toBe(false));
    test('SUSPENDED is not terminal', () => expect(isTerminal('SUSPENDED')).toBe(false));
  });

  describe('isValid()', () => {
    test('recognises all five states', () => {
      for (const s of ['PENDING', 'ACTIVE', 'REVOKED', 'EXPIRED', 'SUSPENDED']) {
        expect(isValid(s)).toBe(true);
      }
    });
    test('rejects unknown state', () => expect(isValid('UNKNOWN')).toBe(false));
  });

  describe('effectiveState()', () => {
    const past   = new Date(Date.now() - 1000);
    const future = new Date(Date.now() + 86_400_000);

    test('ACTIVE with no expiry → ACTIVE',                () => expect(effectiveState(makeRecord())).toBe('ACTIVE'));
    test('ACTIVE with future expiry → ACTIVE',            () => expect(effectiveState(makeRecord({ expires_at: future }))).toBe('ACTIVE'));
    test('ACTIVE with past expiry → EXPIRED',             () => expect(effectiveState(makeRecord({ expires_at: past }))).toBe('EXPIRED'));

    // (#18) case #8a, live-witnessed 2026-08-11: expires_at <= now is
    // an INCLUSIVE boundary — the exact instant of expiry must already read
    // as EXPIRED, not the instant after. The two tests above only cover
    // "clearly future" and "clearly past"; this is the boundary itself.
    test('ACTIVE with expires_at exactly equal to now → EXPIRED (inclusive boundary)', () => {
      const boundary = new Date('2026-08-11T13:22:19.000Z');
      expect(effectiveState(makeRecord({ expires_at: boundary }), boundary)).toBe('EXPIRED');
    });
    test('SUSPENDED with future suspended_until → SUSPENDED', () =>
      expect(effectiveState(makeRecord({ state: 'SUSPENDED', suspended_until: future }))).toBe('SUSPENDED'));
    test('SUSPENDED with past suspended_until → ACTIVE',  () =>
      expect(effectiveState(makeRecord({ state: 'SUSPENDED', suspended_until: past }))).toBe('ACTIVE'));
    test('REVOKED stays REVOKED',                         () =>
      expect(effectiveState(makeRecord({ state: 'REVOKED' }))).toBe('REVOKED'));
  });

  describe('isActiveNow()', () => {
    test('ACTIVE record with no expiry → true',              () => expect(isActiveNow(makeRecord())).toBe(true));
    test('ACTIVE record with past expiry → false',           () =>
      expect(isActiveNow(makeRecord({ expires_at: new Date(Date.now() - 1) }))).toBe(false));
    test('REVOKED record → false',                           () =>
      expect(isActiveNow(makeRecord({ state: 'REVOKED' }))).toBe(false));
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 2. ConsentStore (mocked pool)
// ═══════════════════════════════════════════════════════════════════════════════

describe('ConsentStore', () => {
  let store;
  let mockTx;
  let pool;

  beforeEach(() => {
    jest.resetModules();
    mockTx = { query: jest.fn() };
    pool = {
      isEnabled:             jest.fn().mockReturnValue(true),
      isHealthy:             jest.fn().mockReturnValue(true),
      query:                 jest.fn(),
      withTransaction:       jest.fn(async (fn) => fn(mockTx)),
      withTenantTransaction: jest.fn(async (_tenantId, fn) => fn(mockTx)),
    };
    jest.doMock('../../infra/postgres/pool', () => pool);
    jest.doMock('../../../services/logger',  () => ({ emit: jest.fn() }));
    store = require('./ConsentStore');
  });

  afterEach(() => jest.resetModules());

  describe('create()', () => {
    test('inserts record and appends audit event', async () => {
      const row = makeRecord({ id: 'test-uuid-1' });
      mockTx.query
        .mockResolvedValueOnce({ rows: [row] })  // INSERT
        .mockResolvedValueOnce({ rows: [] })      // UPDATE hash
        .mockResolvedValueOnce({ rows: [] });     // audit INSERT

      const result = await store.create({
        actor_id: 'ai-agent-001', action: 'Facial Recognition', granted_by: 'admin',
      });

      expect(result.actor_id).toBe('ai-agent-001');
      expect(mockTx.query).toHaveBeenCalledTimes(3);
    });

    //a plain
    // ON CONFLICT (actor_id, action, tenant_id) never fires for a NULL
    // tenant_id (SQL NULL-distinctness), so a platform-level re-grant always
    // fell through to a second INSERT instead of upserting the existing row
    // — the terminal-state guard below never ran. Locks in that the INSERT
    // targets migration 046's COALESCE(tenant_id, '') expression index
    // instead, which does treat NULL as a self-equal value.
    test('INSERT targets the COALESCE(tenant_id, \'\') conflict expression, not the raw column', async () => {
      const row = makeRecord({ id: 'test-uuid-1' });
      mockTx.query
        .mockResolvedValueOnce({ rows: [row] })
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [] });

      await store.create({ actor_id: 'ai-agent-001', action: 'Facial Recognition', granted_by: 'admin' });

      const insertSql = mockTx.query.mock.calls[0][0];
      expect(insertSql).toMatch(/ON CONFLICT \(actor_id, action, \(COALESCE\(tenant_id, ''\)\)\)/);
    });

    test('throws when actor_id missing',   async () =>
      expect(store.create({ action: 'X', granted_by: 'Y' })).rejects.toThrow('required'));
    test('throws when action missing',     async () =>
      expect(store.create({ actor_id: 'X', granted_by: 'Y' })).rejects.toThrow('required'));
    test('throws when granted_by missing', async () =>
      expect(store.create({ actor_id: 'X', action: 'Y' })).rejects.toThrow('required'));

    test('rejects reactivation when existing record is REVOKED', async () => {
      mockTx.query
        .mockResolvedValueOnce({ rows: [] })                     // INSERT ... WHERE guard blocks the upsert
        .mockResolvedValueOnce({ rows: [{ state: 'REVOKED' }] }); // fetch existing state for the error

      await expect(store.create({
        actor_id: 'ai-agent-001', action: 'Facial Recognition', granted_by: 'admin',
      })).rejects.toThrow('terminal state REVOKED');

      expect(mockTx.query).toHaveBeenCalledTimes(2);
    });

    // (#18) case #9, live-witnessed 2026-08-11: a re-grant attempt
    // against a REVOKED record must not just throw — it must also emit
    // WARN CONSENT_REACTIVATION_BLOCKED, the operator-facing signal the live
    // witness confirmed fires. The two tests above only assert the thrown
    // error; this one is the regression test for the WARN side-effect itself.
    test('emits WARN CONSENT_REACTIVATION_BLOCKED when reactivation is blocked', async () => {
      mockTx.query
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [{ state: 'REVOKED' }] });

      await expect(store.create({
        actor_id: 'ai-agent-001', action: 'Facial Recognition', granted_by: 'admin',
      })).rejects.toThrow('terminal state REVOKED');

      const { emit } = require('../../../services/logger');
      expect(emit).toHaveBeenCalledWith('WARN', 'CONSENT_REACTIVATION_BLOCKED', expect.objectContaining({
        actorId: 'ai-agent-001', action: 'Facial Recognition', state: 'REVOKED',
      }));
    });

    test('rejects reactivation when existing record is EXPIRED', async () => {
      mockTx.query
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [{ state: 'EXPIRED' }] });

      await expect(store.create({
        actor_id: 'ai-agent-001', action: 'Facial Recognition', granted_by: 'admin',
      })).rejects.toThrow('terminal state EXPIRED');
    });

    test('allows re-grant when existing record is SUSPENDED (non-terminal)', async () => {
      const row = makeRecord({ id: 'test-uuid-2', state: 'ACTIVE' });
      mockTx.query
        .mockResolvedValueOnce({ rows: [row] })  // INSERT ... WHERE guard allows the upsert
        .mockResolvedValueOnce({ rows: [] })      // UPDATE hash
        .mockResolvedValueOnce({ rows: [] });     // audit INSERT

      const result = await store.create({
        actor_id: 'ai-agent-001', action: 'Facial Recognition', granted_by: 'admin',
      });

      expect(result.state).toBe('ACTIVE');
      expect(mockTx.query).toHaveBeenCalledTimes(3);
    });
  });

  describe('revoke()', () => {
    test('rejects revocation of already-REVOKED record', async () => {
      mockTx.query.mockResolvedValueOnce({ rows: [makeRecord({ state: 'REVOKED' })] });
      await expect(store.revoke({ id: 'x', revoked_by: 'admin' })).rejects.toThrow('terminal state');
    });

    test('rejects revocation of EXPIRED record', async () => {
      mockTx.query.mockResolvedValueOnce({ rows: [makeRecord({ state: 'EXPIRED' })] });
      await expect(store.revoke({ id: 'x', revoked_by: 'admin' })).rejects.toThrow('terminal state');
    });

    test('throws when record not found', async () => {
      mockTx.query.mockResolvedValueOnce({ rows: [] });
      await expect(store.revoke({ id: 'missing', revoked_by: 'admin' })).rejects.toThrow('not found');
    });

    test('revokes ACTIVE record and returns REVOKED row', async () => {
      const row     = makeRecord();
      const revoked = makeRecord({ state: 'REVOKED' });
      mockTx.query
        .mockResolvedValueOnce({ rows: [row] })      // SELECT FOR UPDATE
        .mockResolvedValueOnce({ rows: [revoked] })  // UPDATE
        .mockResolvedValueOnce({ rows: [] });         // audit INSERT
      const result = await store.revoke({ id: row.id, revoked_by: 'admin' });
      expect(result.state).toBe('REVOKED');
    });
  });

  describe('markExpired()', () => {
    test('persists ACTIVE -> EXPIRED with an audit entry when the row is due', async () => {
      const row = makeRecord({ expires_at: new Date(Date.now() - 1000) });
      mockTx.query
        .mockResolvedValueOnce({ rows: [row] })                              // SELECT FOR UPDATE
        .mockResolvedValueOnce({ rows: [{ ...row, state: 'EXPIRED' }] })     // UPDATE
        .mockResolvedValueOnce({ rows: [] });                                // audit INSERT
      const out = await store.markExpired({ id: row.id });
      expect(out.state).toBe('EXPIRED');
      expect(mockTx.query.mock.calls[1][0]).toMatch(/expires_at <= NOW\(\)/);
      expect(mockTx.query.mock.calls[2][1]).toContain('CONSENT_EXPIRED');
    });
    test('returns null and writes nothing for a non-ACTIVE record', async () => {
      mockTx.query.mockResolvedValueOnce({ rows: [makeRecord({ state: 'REVOKED' })] });
      expect(await store.markExpired({ id: 'x' })).toBeNull();
      expect(mockTx.query).toHaveBeenCalledTimes(1);
    });
    test('returns null when the guarded UPDATE matches nothing (not yet due)', async () => {
      mockTx.query.mockResolvedValueOnce({ rows: [makeRecord()] }).mockResolvedValueOnce({ rows: [] });
      expect(await store.markExpired({ id: 'x' })).toBeNull();
      expect(mockTx.query).toHaveBeenCalledTimes(2);
    });
  });

  describe('findByKey()', () => {
    test('returns null when not found', async () => {
      pool.query.mockResolvedValueOnce({ rows: [] });
      expect(await store.findByKey('unknown', 'action')).toBeNull();
    });
    test('returns record when found', async () => {
      const row = makeRecord();
      pool.query.mockResolvedValueOnce({ rows: [row] });
      expect((await store.findByKey('ai-agent-001', 'Facial Recognition')).id).toBe(row.id);
    });

    // Code-hygiene batch, 2026-08-14: the query's LIMIT 1 was previously
    // unordered — non-deterministic among any future duplicate rows. `id` is
    // a random UUID (not time-ordered), so created_at is the only column
    // that actually orders by recency.
    test('platform-level lookup (no tenant_id) orders by created_at DESC before LIMIT 1', async () => {
      pool.query.mockResolvedValueOnce({ rows: [makeRecord()] });
      await store.findByKey('ai-agent-001', 'Facial Recognition');
      const sql = pool.query.mock.calls[0][0];
      expect(sql).toMatch(/ORDER BY created_at DESC\s+LIMIT 1/);
    });

    test('tenant-scoped lookup (tenant_id supplied) also orders by created_at DESC before LIMIT 1', async () => {
      mockTx.query.mockResolvedValueOnce({ rows: [makeRecord({ tenant_id: 'tenant-a' })] });
      await store.findByKey('ai-agent-001', 'Facial Recognition', 'tenant-a');
      const sql = mockTx.query.mock.calls[0][0];
      expect(sql).toMatch(/ORDER BY created_at DESC\s+LIMIT 1/);
    });
  });

  describe('list()', () => {
    test('returns records and total', async () => {
      pool.query
        .mockResolvedValueOnce({ rows: [makeRecord()] })
        .mockResolvedValueOnce({ rows: [{ total: '1' }] });
      const { records, total } = await store.list({ actor_id: 'ai-agent-001' });
      expect(records).toHaveLength(1);
      expect(total).toBe(1);
    });

    test('caps limit at 200', async () => {
      pool.query
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [{ total: '0' }] });
      await store.list({ limit: 9999 });
      expect(pool.query.mock.calls[0][0]).toMatch(/LIMIT/);
    });
  });

  // ── GDPR DSR extensions: rectify / anonymize / pseudonymizeActor ────

  describe('rectify()', () => {
    test('updates allow-listed fields and appends CONSENT_RECTIFIED audit entry', async () => {
      const before = makeRecord({ subject_name: 'Old Name', metadata: { a: 1 } });
      const after  = makeRecord({ subject_name: 'New Name', metadata: { a: 1 } });
      mockTx.query
        .mockResolvedValueOnce({ rows: [before] })  // SELECT FOR UPDATE
        .mockResolvedValueOnce({ rows: [after] })   // UPDATE
        .mockResolvedValueOnce({ rows: [] });        // audit INSERT

      const result = await store.rectify({
        id: before.id, fields: { subject_name: 'New Name' }, rectified_by: 'compliance-1',
      });

      expect(result.record.subject_name).toBe('New Name');
      expect(result.before.subject_name).toBe('Old Name');
      expect(result.after.subject_name).toBe('New Name');
      expect(mockTx.query).toHaveBeenCalledTimes(3);
      expect(mockTx.query.mock.calls[2][0]).toMatch(/consent_audit_log/);
      expect(mockTx.query.mock.calls[2][1]).toContain('CONSENT_RECTIFIED');
    });

    test('rejects a field not on the allow-list', async () => {
      await expect(store.rectify({
        id: 'x', fields: { actor_id: 'someone-else' }, rectified_by: 'compliance-1',
      })).rejects.toThrow('fields must include at least one of');
    });

    test('throws when record not found', async () => {
      mockTx.query.mockResolvedValueOnce({ rows: [] });
      await expect(store.rectify({
        id: 'missing', fields: { subject_name: 'X' }, rectified_by: 'compliance-1',
      })).rejects.toThrow('not found');
    });

    test('throws when rectified_by missing', async () => {
      await expect(store.rectify({ id: 'x', fields: { subject_name: 'X' } }))
        .rejects.toThrow('rectified_by is required');
    });
  });

  describe('anonymize()', () => {
    test('scrubs subject_name/metadata/tags and forces ACTIVE to REVOKED', async () => {
      const active    = makeRecord({ state: 'ACTIVE', subject_name: 'Jane', metadata: { x: 1 }, tags: ['a'] });
      const anonymized = makeRecord({ state: 'REVOKED', subject_name: null, metadata: {}, tags: [] });
      mockTx.query
        .mockResolvedValueOnce({ rows: [active] })      // SELECT FOR UPDATE
        .mockResolvedValueOnce({ rows: [anonymized] })  // UPDATE
        .mockResolvedValueOnce({ rows: [] });            // audit INSERT

      const result = await store.anonymize({ id: active.id, erased_by: 'compliance-1', request_id: 'req-1' });

      expect(result.state).toBe('REVOKED');
      expect(result.subject_name).toBeNull();
      expect(mockTx.query.mock.calls[2][1]).toContain('CONSENT_ERASED');
    });

    test('leaves an already-EXPIRED record in EXPIRED state (no invalid transition attempted)', async () => {
      const expired = makeRecord({ state: 'EXPIRED' });
      mockTx.query
        .mockResolvedValueOnce({ rows: [expired] })
        .mockResolvedValueOnce({ rows: [makeRecord({ state: 'EXPIRED', subject_name: null })] })
        .mockResolvedValueOnce({ rows: [] });

      const result = await store.anonymize({ id: expired.id, erased_by: 'compliance-1' });
      expect(result.state).toBe('EXPIRED');
      // UPDATE ... SET state = $1 ... — $1 must be 'EXPIRED', proving no REVOKED transition was forced.
      expect(mockTx.query.mock.calls[1][1][0]).toBe('EXPIRED');
    });

    test('is idempotent: erasing an already-erased (REVOKED, scrubbed) record re-applies cleanly', async () => {
      const already = makeRecord({ state: 'REVOKED', subject_name: null, metadata: {}, tags: [] });
      mockTx.query
        .mockResolvedValueOnce({ rows: [already] })
        .mockResolvedValueOnce({ rows: [already] })
        .mockResolvedValueOnce({ rows: [] });

      await expect(store.anonymize({ id: already.id, erased_by: 'compliance-1' })).resolves.toMatchObject({
        state: 'REVOKED', subject_name: null,
      });
    });

    test('throws when record not found', async () => {
      mockTx.query.mockResolvedValueOnce({ rows: [] });
      await expect(store.anonymize({ id: 'missing', erased_by: 'compliance-1' })).rejects.toThrow('not found');
    });
  });

  describe('pseudonymizeActor()', () => {
    test('updates actor_id on consent_records only (never touches consent_audit_log)', async () => {
      mockTx.query.mockResolvedValueOnce({ rows: [{ id: 'rec-1' }, { id: 'rec-2' }], rowCount: 2 });

      const result = await store.pseudonymizeActor({ actor_id: 'ai-agent-001', pseudonym: 'dsr-pseudo:abc123' });

      expect(result.recordsUpdated).toBe(2);
      expect(mockTx.query).toHaveBeenCalledTimes(1);
      expect(mockTx.query.mock.calls[0][0]).toMatch(/UPDATE consent_records/);
      expect(mockTx.query.mock.calls[0][0]).not.toMatch(/consent_audit_log/);
    });

    test('throws when pseudonym missing', async () => {
      await expect(store.pseudonymizeActor({ actor_id: 'x' })).rejects.toThrow('pseudonym is required');
    });
  });

  // ── every mutation path pinned to READ COMMITTED ───────────────────────
  // Case #10/#12: under pool.js's REPEATABLE
  // READ default, concurrent writes to the same consent row raised SQLSTATE
  // 40001, surfaced as an undifferentiated HTTP 500 with no retry — a losing
  // revoke() could leave consent wrongly ACTIVE. Each of these six mutation
  // paths is a single-row check-then-act transaction (or, for create(), a
  // single-statement upsert) that never needs cross-statement snapshot
  // consistency with a different row, so it is explicitly pinned to READ
  // COMMITTED — under which 40001 cannot occur at all — rather than left on
  // the shared default. This is a drift guard: if a future refactor drops the
  // explicit isolationLevel override on any of these six call sites, it
  // silently reverts to REPEATABLE READ and reopens on that path; these
  // tests fail loudly instead. Same convention as's AlertStore fix.
  describe('isolation level pinned to READ COMMITTED', () => {
    test('create() pins READ COMMITTED on the platform-level (withTransaction) path', async () => {
      const row = makeRecord({ id: 'test-uuid-1' });
      mockTx.query
        .mockResolvedValueOnce({ rows: [row] })
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [] });

      await store.create({ actor_id: 'ai-agent-001', action: 'Facial Recognition', granted_by: 'admin' });

      expect(pool.withTransaction).toHaveBeenCalledWith(
        expect.any(Function), { isolationLevel: 'READ COMMITTED' },
      );
    });

    test('create() pins READ COMMITTED on the tenant-scoped (withTenantTransaction) path', async () => {
      const row = makeRecord({ id: 'test-uuid-1', tenant_id: 'tenant-a' });
      mockTx.query
        .mockResolvedValueOnce({ rows: [row] })
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [] });

      await store.create({
        actor_id: 'ai-agent-001', action: 'Facial Recognition', granted_by: 'admin', tenant_id: 'tenant-a',
      });

      expect(pool.withTenantTransaction).toHaveBeenCalledWith(
        'tenant-a', expect.any(Function), { isolationLevel: 'READ COMMITTED' },
      );
    });

    test('revoke() pins READ COMMITTED', async () => {
      const row     = makeRecord();
      const revoked = makeRecord({ state: 'REVOKED' });
      mockTx.query
        .mockResolvedValueOnce({ rows: [row] })
        .mockResolvedValueOnce({ rows: [revoked] })
        .mockResolvedValueOnce({ rows: [] });

      await store.revoke({ id: row.id, revoked_by: 'admin' });

      expect(pool.withTransaction).toHaveBeenCalledWith(
        expect.any(Function), { isolationLevel: 'READ COMMITTED' },
      );
    });

    test('suspend() pins READ COMMITTED', async () => {
      const row      = makeRecord({ state: 'ACTIVE' });
      const suspended = makeRecord({ state: 'SUSPENDED' });
      mockTx.query
        .mockResolvedValueOnce({ rows: [row] })
        .mockResolvedValueOnce({ rows: [suspended] })
        .mockResolvedValueOnce({ rows: [] });

      await store.suspend({ id: row.id, suspended_by: 'admin' });

      expect(pool.withTransaction).toHaveBeenCalledWith(
        expect.any(Function), { isolationLevel: 'READ COMMITTED' },
      );
    });

    test('resume() pins READ COMMITTED', async () => {
      const row     = makeRecord({ state: 'SUSPENDED' });
      const resumed = makeRecord({ state: 'ACTIVE' });
      mockTx.query
        .mockResolvedValueOnce({ rows: [row] })
        .mockResolvedValueOnce({ rows: [resumed] })
        .mockResolvedValueOnce({ rows: [] });

      await store.resume({ id: row.id, resumed_by: 'admin' });

      expect(pool.withTransaction).toHaveBeenCalledWith(
        expect.any(Function), { isolationLevel: 'READ COMMITTED' },
      );
    });

    test('rectify() pins READ COMMITTED', async () => {
      const before = makeRecord({ subject_name: 'Old Name' });
      const after  = makeRecord({ subject_name: 'New Name' });
      mockTx.query
        .mockResolvedValueOnce({ rows: [before] })
        .mockResolvedValueOnce({ rows: [after] })
        .mockResolvedValueOnce({ rows: [] });

      await store.rectify({ id: before.id, fields: { subject_name: 'New Name' }, rectified_by: 'compliance-1' });

      expect(pool.withTransaction).toHaveBeenCalledWith(
        expect.any(Function), { isolationLevel: 'READ COMMITTED' },
      );
    });

    test('anonymize() pins READ COMMITTED', async () => {
      const active     = makeRecord({ state: 'ACTIVE' });
      const anonymized = makeRecord({ state: 'REVOKED', subject_name: null, metadata: {}, tags: [] });
      mockTx.query
        .mockResolvedValueOnce({ rows: [active] })
        .mockResolvedValueOnce({ rows: [anonymized] })
        .mockResolvedValueOnce({ rows: [] });

      await store.anonymize({ id: active.id, erased_by: 'compliance-1' });

      expect(pool.withTransaction).toHaveBeenCalledWith(
        expect.any(Function), { isolationLevel: 'READ COMMITTED' },
      );
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 3. ConsentCache (mocked Redis)
// ═══════════════════════════════════════════════════════════════════════════════

describe('ConsentCache', () => {
  let cache;
  let mockClient;

  beforeEach(() => {
    jest.resetModules();
    mockClient = {
      get:        jest.fn().mockResolvedValue(null),
      set:        jest.fn().mockResolvedValue('OK'),
      del:        jest.fn().mockResolvedValue(1),
      eval:       jest.fn().mockResolvedValue(1),
      scan:       jest.fn().mockResolvedValue({ cursor: 0, keys: [] }),
      connect:    jest.fn().mockResolvedValue(undefined),
      disconnect: jest.fn().mockResolvedValue(undefined),
      ping:       jest.fn().mockResolvedValue('PONG'),
      on:         jest.fn((event, cb) => { if (event === 'ready') cb(); }),
    };
    jest.doMock('redis', () => ({ createClient: jest.fn(() => mockClient) }));
    jest.doMock('../../infra/redis/clientConfig', () => ({
      buildClientOptions: jest.fn(() => ({})),
      isAuthError:        jest.fn(() => false),
      isTlsError:         jest.fn(() => false),
    }));
    jest.doMock('../../../services/logger', () => ({ emit: jest.fn() }));
    cache = require('./ConsentCache');
  });

  afterEach(() => jest.resetModules());

  test('get() returns null on cache miss', async () => {
    mockClient.get.mockResolvedValue(null);
    expect(await cache.get('actor', 'action')).toBeNull();
  });

  test('get() returns parsed object on cache hit', async () => {
    // entries are keyring-sealed and bound to their key.
    mockClient.get.mockResolvedValue(cache._seal(cache._cacheKey('actor', 'action'),
      { pass: true, reason: 'CONSENT_VERIFIED', requiredScope: null, cacheExpiresAt: Date.now() + 60000 }));
    const result = await cache.get('actor', 'action');
    expect(result.pass).toBe(true);
  });

  describe('signed, scope-bound entries', () => {
    // read the metrics instance from the SAME module registry the cache was loaded into (beforeEach resets modules)
    const failures = () => [...require('../../observability/metrics').consentCacheIntegrityFailuresTotal._values.values()].reduce((a, v) => a + v, 0);
    const good = (over = {}) => ({ pass: true, reason: 'CONSENT_VERIFIED', requiredScope: null, cacheExpiresAt: Date.now() + 60000, ...over });

    test('a round trip through set() and get() is a hit', async () => {
      await cache.set('actor', 'action', 't1', { pass: true, reason: 'CONSENT_VERIFIED' }, null, { requiredScope: 'biometric' });
      const [key, raw] = mockClient.set.mock.calls.at(-1);
      expect(key).toBe(cache._cacheKey('actor', 'action', 't1'));
      mockClient.get.mockResolvedValue(raw);
      expect(await cache.get('actor', 'action', 't1', { requiredScope: 'biometric' })).toMatchObject({ pass: true });
    });

    test('an unsigned (plain JSON) ALLOW written directly to Redis is a MISS and is counted', async () => {
      const before = failures();
      mockClient.get.mockResolvedValue(JSON.stringify({ pass: true, reason: 'CONSENT_VERIFIED' }));
      expect(await cache.get('actor', 'action')).toBeNull();
      expect(failures()).toBe(before + 1);
    });

    test('a tampered payload (DENY flipped to ALLOW) is a MISS and is counted', async () => {
      const key = cache._cacheKey('actor', 'action');
      const outer = JSON.parse(cache._seal(key, good({ pass: false, reason: 'CONSENT_NOT_FOUND' })));
      const before = failures();
      mockClient.get.mockResolvedValue(JSON.stringify({ ...outer, p: outer.p.replace('"pass":false', '"pass":true') }));
      expect(await cache.get('actor', 'action')).toBeNull();
      expect(failures()).toBe(before + 1);
    });

    test('a validly signed entry replayed under another key (other tenant) is a MISS', async () => {
      mockClient.get.mockResolvedValue(cache._seal(cache._cacheKey('actor', 'action', 'tenant-a'), good()));
      expect(await cache.get('actor', 'action', 'tenant-b')).toBeNull();
    });

    test('NF-1: an entry cached for one required scope is a MISS for a different required scope', async () => {
      const key = cache._cacheKey('actor', 'action');
      mockClient.get.mockResolvedValue(cache._seal(key, good({ requiredScope: 'basic' })));
      expect(await cache.get('actor', 'action', null, { requiredScope: 'biometric' })).toBeNull();
      mockClient.get.mockResolvedValue(cache._seal(key, good({ requiredScope: 'basic' })));
      expect(await cache.get('actor', 'action', null, { requiredScope: 'basic' })).toMatchObject({ pass: true });
    });

    test('a signed entry past its signed cacheExpiresAt is a MISS (bounds replay of a legitimately signed entry)', async () => {
      mockClient.get.mockResolvedValue(cache._seal(cache._cacheKey('actor', 'action'), good({ cacheExpiresAt: Date.now() - 1 })));
      expect(await cache.get('actor', 'action')).toBeNull();
    });
  });

  test('get() returns null on JSON parse error (corrupt entry)', async () => {
    mockClient.get.mockResolvedValue('NOT JSON {{{');
    expect(await cache.get('actor', 'action')).toBeNull();
  });

  test('set() calls Redis SET with EX TTL', async () => {
    await cache.set('actor', 'action', null, { pass: true });
    expect(mockClient.set).toHaveBeenCalledWith(
      expect.stringContaining('qodiqa:consent:actor:action:'),
      expect.any(String),
      expect.objectContaining({ EX: expect.any(Number) }),
    );
  });

  test('positive result uses longer TTL than negative result', async () => {
    await cache.set('actor', 'action', null, { pass: false });
    const negTTL = mockClient.set.mock.calls[0][2].EX;
    mockClient.set.mockClear();
    await cache.set('actor', 'action', null, { pass: true });
    const posTTL = mockClient.set.mock.calls[0][2].EX;
    expect(posTTL).toBeGreaterThan(negTTL);
  });

  // ── cache TTL capped to the record's own expiry/suspend boundary ──
  // Case #8b/#13: a cache entry written just
  // before expires_at (or suspended_until) previously kept serving its now-
  // stale result for the rest of the default TTL window, because the
  // cache-hit fast path never re-checks effectiveState(). These lock in that
  // set() now clamps the TTL to the boundary instead.

  test('ALLOW result with expiresAt sooner than TTL_POSITIVE_S is capped to the boundary', async () => {
    const expiresAt = new Date(Date.now() + 5_000); // 5s out, well under the 60s default
    await cache.set('actor', 'action', null, { pass: true, expiresAt });
    const ttl = mockClient.set.mock.calls[0][2].EX;
    expect(ttl).toBeGreaterThanOrEqual(1);
    expect(ttl).toBeLessThanOrEqual(6);
  });

  test('ALLOW result with expiresAt far in the future keeps the default TTL_POSITIVE_S', async () => {
    const expiresAt = new Date(Date.now() + 3_600_000); // 1h out
    await cache.set('actor', 'action', null, { pass: true, expiresAt });
    expect(mockClient.set.mock.calls[0][2].EX).toBe(60);
  });

  test('ALLOW result with no expiresAt (never expires) keeps the default TTL_POSITIVE_S', async () => {
    await cache.set('actor', 'action', null, { pass: true, expiresAt: null });
    expect(mockClient.set.mock.calls[0][2].EX).toBe(60);
  });

  test('a boundary already at/past now floors the TTL at 1 second, never 0 or negative', async () => {
    const expiresAt = new Date(Date.now() - 1_000); // already past
    await cache.set('actor', 'action', null, { pass: true, expiresAt });
    expect(mockClient.set.mock.calls[0][2].EX).toBe(1);
  });

  test('CONSENT_SUSPENDED result with suspendedUntil sooner than TTL_NEGATIVE_S is capped to the boundary', async () => {
    const suspendedUntil = new Date(Date.now() + 3_000); // 3s out, under the 10s default
    await cache.set('actor', 'action', null, { pass: false, reason: 'CONSENT_SUSPENDED', suspendedUntil });
    const ttl = mockClient.set.mock.calls[0][2].EX;
    expect(ttl).toBeGreaterThanOrEqual(1);
    expect(ttl).toBeLessThanOrEqual(4);
  });

  test('other DENY reasons (no suspendedUntil semantics) keep the default TTL_NEGATIVE_S', async () => {
    await cache.set('actor', 'action', null, { pass: false, reason: 'CONSENT_REVOKED' });
    expect(mockClient.set.mock.calls[0][2].EX).toBe(10);
  });

  test('the clamped TTL is also used on the CAS/EVAL path (version provided)', async () => {
    const expiresAt = new Date(Date.now() + 5_000);
    await cache.set('actor', 'action', null, { pass: true, expiresAt }, 3);
    const args = mockClient.eval.mock.calls[0][1].arguments;
    expect(Number(args[2])).toBeGreaterThanOrEqual(1);
    expect(Number(args[2])).toBeLessThanOrEqual(6);
  });

  // ── the clamp rounds DOWN, never up, past its own boundary ────
  // Case #11 phase D: Math.ceil rounded a
  // non-whole-second remainder UP, so the Redis key's own TTL systematically
  // outlived expires_at/suspended_until by up to ~999ms (witnessed 32-131ms
  // via direct PTTL reads) — pins that the clamp now rounds down instead.
  // Date.now() is stubbed so the boundary's exact remainder is deterministic,
  // not dependent on how much wall-clock time this test itself takes to run.

  test('a non-whole-second remainder rounds DOWN (floor), not up (ceil)', async () => {
    const nowSpy = jest.spyOn(Date, 'now').mockReturnValue(1_000_000_000_000);
    try {
      const expiresAt = new Date(1_000_000_000_000 + 5_900); // 5.9s remaining
      await cache.set('actor', 'action', null, { pass: true, expiresAt });
      // Math.ceil(5.9) would give 6 (outliving the boundary); Math.floor(5.9) gives 5.
      expect(mockClient.set.mock.calls[0][2].EX).toBe(5);
    } finally {
      nowSpy.mockRestore();
    }
  });

  test('a whole-second remainder is unaffected by the rounding direction', async () => {
    const nowSpy = jest.spyOn(Date, 'now').mockReturnValue(1_000_000_000_000);
    try {
      const expiresAt = new Date(1_000_000_000_000 + 5_000); // exactly 5s remaining
      await cache.set('actor', 'action', null, { pass: true, expiresAt });
      expect(mockClient.set.mock.calls[0][2].EX).toBe(5);
    } finally {
      nowSpy.mockRestore();
    }
  });

  test('the same floor rounding applies to the negative (SUSPENDED) TTL path', async () => {
    const nowSpy = jest.spyOn(Date, 'now').mockReturnValue(1_000_000_000_000);
    try {
      const suspendedUntil = new Date(1_000_000_000_000 + 3_900); // 3.9s remaining
      await cache.set('actor', 'action', null, { pass: false, reason: 'CONSENT_SUSPENDED', suspendedUntil });
      expect(mockClient.set.mock.calls[0][2].EX).toBe(3);
    } finally {
      nowSpy.mockRestore();
    }
  });

  test('invalidate() calls Redis DEL', async () => {
    await cache.invalidate('actor', 'action');
    expect(mockClient.del).toHaveBeenCalled();
  });

  test('get() returns null when Redis throws (fail-safe, not fail-closed)', async () => {
    mockClient.get.mockRejectedValue(new Error('CONN_RESET'));
    expect(await cache.get('actor', 'action')).toBeNull();
  });

  test('set() does not throw when Redis unavailable', async () => {
    mockClient.set.mockRejectedValue(new Error('CONN_RESET'));
    await expect(cache.set('actor', 'action', null, { pass: true })).resolves.not.toThrow();
  });

  // ── version-guarded writes ─────────────────────────────────────

  test('set() with a numeric version uses EVAL (CAS), not plain SET', async () => {
    await cache.set('actor', 'action', null, { pass: true }, 3);
    expect(mockClient.eval).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        keys:      [expect.stringContaining('qodiqa:consent:actor:action:')],
        arguments: [expect.any(String), '3', expect.any(String)],
      }),
    );
    expect(mockClient.set).not.toHaveBeenCalled();
  });

  test('set() without a version falls back to plain SET (e.g. CONSENT_NOT_FOUND has no record)', async () => {
    await cache.set('actor', 'action', null, { pass: false });
    expect(mockClient.set).toHaveBeenCalled();
    expect(mockClient.eval).not.toHaveBeenCalled();
  });

  test('invalidate() with a numeric version writes a version-stamped tombstone via EVAL, not DEL', async () => {
    await cache.invalidate('actor', 'action', null, 5);
    expect(mockClient.eval).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ arguments: [expect.any(String), '5', expect.any(String)] }),
    );
    // the tombstone itself is sealed; its outer version drives the Lua CAS.
    const sealed = mockClient.eval.mock.calls[0][1].arguments[0];
    expect(JSON.parse(sealed).version).toBe(5);
    expect(cache._open(cache._cacheKey('actor', 'action'), sealed)).toMatchObject({ tombstone: true, version: 5 });
    expect(mockClient.del).not.toHaveBeenCalled();
  });

  test('invalidate() without a version falls back to plain DEL (legacy/actor-bulk callers)', async () => {
    await cache.invalidate('actor', 'action');
    expect(mockClient.del).toHaveBeenCalled();
    expect(mockClient.eval).not.toHaveBeenCalled();
  });

  test('invalidate() does not throw when EVAL rejects (Redis unavailable/timeout during invalidation)', async () => {
    mockClient.eval.mockRejectedValue(new Error('ETIMEDOUT'));
    await expect(cache.invalidate('actor', 'action', null, 5)).resolves.not.toThrow();
  });

  test('set() does not throw when EVAL rejects (Redis unavailable/timeout during write)', async () => {
    mockClient.eval.mockRejectedValue(new Error('ETIMEDOUT'));
    await expect(cache.set('actor', 'action', null, { pass: true }, 3)).resolves.not.toThrow();
  });

  test('get() treats a tombstone entry as a cache miss', async () => {
    mockClient.get.mockResolvedValue(JSON.stringify({ tombstone: true, version: 5 }));
    expect(await cache.get('actor', 'action')).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 3b. ConsentCache — optimistic concurrency (real CAS semantics)
// ═══════════════════════════════════════════════════════════════════════════════
//
// The tests above only prove ConsentCache *invokes* EVAL correctly; they
// don't exercise the Lua script's actual compare-and-set decision (mocked
// Redis has no Lua interpreter). This fakeRedis reimplements the exact same
// GET → decode → compare `version` → conditional SET algorithm the
// production _CAS_SCRIPT runs atomically in real Redis, so these tests
// verify the real race the finding describes is actually closed — not just
// that the right client method was called.

function makeFakeRedis() {
  const store = new Map(); // key -> { value: string, expiresAt: number }

  function liveGet(key) {
    const entry = store.get(key);
    if (!entry) return null;
    if (entry.expiresAt !== null && entry.expiresAt <= Date.now()) { store.delete(key); return null; }
    return entry.value;
  }

  return {
    get:  jest.fn(async (key) => liveGet(key)),
    set:  jest.fn(async (key, value, opts) => {
      const ttlMs = opts?.EX ? opts.EX * 1000 : null;
      store.set(key, { value, expiresAt: ttlMs ? Date.now() + ttlMs : null });
      return 'OK';
    }),
    del:  jest.fn(async (key) => { const had = store.has(key); store.delete(key); return had ? 1 : 0; }),
    eval: jest.fn(async (_script, { keys, arguments: args }) => {
      const [key] = keys;
      const [payload, versionStr, ttlStr] = args;
      const newVersion = Number(versionStr);
      const current = liveGet(key);
      if (current) {
        const decoded = JSON.parse(current);
        if (decoded.version !== undefined && decoded.version !== null && Number(decoded.version) > newVersion) {
          return 0; // reject — a newer entry is already cached
        }
      }
      store.set(key, { value: payload, expiresAt: Date.now() + Number(ttlStr) * 1000 });
      return 1;
    }),
    scan:       jest.fn().mockResolvedValue({ cursor: 0, keys: [] }),
    connect:    jest.fn().mockResolvedValue(undefined),
    disconnect: jest.fn().mockResolvedValue(undefined),
    ping:       jest.fn().mockResolvedValue('PONG'),
    on:         jest.fn((event, cb) => { if (event === 'ready') cb(); }),
    _store: store,
  };
}

describe('ConsentCache — optimistic concurrency (simulated CAS)', () => {
  let cache;
  let fakeRedis;

  beforeEach(() => {
    jest.resetModules();
    fakeRedis = makeFakeRedis();
    jest.doMock('redis', () => ({ createClient: jest.fn(() => fakeRedis) }));
    jest.doMock('../../infra/redis/clientConfig', () => ({
      buildClientOptions: jest.fn(() => ({})),
      isAuthError:        jest.fn(() => false),
      isTlsError:         jest.fn(() => false),
    }));
    jest.doMock('../../../services/logger', () => ({ emit: jest.fn() }));
    cache = require('./ConsentCache');
  });

  afterEach(() => jest.resetModules());

  test('reproduces the stale-write-after-invalidate race and shows it is rejected', async () => {
    // t0: a verify() call reads the DB and gets an ACTIVE record at version 1.
    const staleAllow = { pass: true, reason: 'CONSENT_VERIFIED', state: 'ACTIVE' };

    // t1: concurrently, an admin revokes — DB commits, local cache is
    // invalidated with the record's NEW version (2). This lands BEFORE the
    // stale writer's set() call below, exactly like the real race.
    await cache.invalidate('actor1', 'run', null, 2);

    // t2: the in-flight verify() call from t0 finally calls set() with the
    // OLD version (1) it read before the revoke happened.
    await cache.set('actor1', 'run', null, staleAllow, 1);

    // The stale ALLOW must NOT win — the tombstone (version 2) must still be
    // in effect, so a subsequent read must be a cache miss (forcing a fresh
    // DB lookup), never a resurrected ALLOW.
    expect(await cache.get('actor1', 'run', null)).toBeNull();
  });

  test('without a version, the same stale write WOULD have resurrected a stale ALLOW (regression baseline)', async () => {
    // This documents the pre-CONSENT-3 behavior for contrast: an unversioned
    // invalidate() + unversioned set() in the same order resurrects the
    // stale positive result, because a bare DEL then SET has no memory of
    // "something newer already happened here".
    const staleAllow = { pass: true, reason: 'CONSENT_VERIFIED', state: 'ACTIVE' };
    await cache.invalidate('actor1', 'run'); // plain DEL, no version
    await cache.set('actor1', 'run', null, staleAllow); // plain SET, no version
    expect((await cache.get('actor1', 'run', null))?.pass).toBe(true);
  });

  test('in-order writes (no race) still cache normally', async () => {
    const allow = { pass: true, reason: 'CONSENT_VERIFIED', state: 'ACTIVE' };
    await cache.set('actor1', 'run', null, allow, 1);
    const cached = await cache.get('actor1', 'run', null);
    expect(cached.pass).toBe(true);
  });

  test('repeated revoke operations are idempotent — later tombstone always wins', async () => {
    await cache.invalidate('actor1', 'run', null, 2);
    await cache.invalidate('actor1', 'run', null, 3);
    // A late writer from before the FIRST revoke still can't resurrect ALLOW.
    await cache.set('actor1', 'run', null, { pass: true }, 1);
    expect(await cache.get('actor1', 'run', null)).toBeNull();
  });

  test('a fresh grant after a revoke is cacheable again (higher version wins)', async () => {
    await cache.invalidate('actor1', 'run', null, 2); // revoke
    const allow = { pass: true, reason: 'CONSENT_VERIFIED', state: 'ACTIVE' };
    await cache.set('actor1', 'run', null, allow, 3); // re-grant, newer version
    expect((await cache.get('actor1', 'run', null))?.pass).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 4. ConsentVerifier
// ═══════════════════════════════════════════════════════════════════════════════

describe('ConsentVerifier', () => {
  let verifier;
  let mockCache;
  let mockStore;
  let mockPool;

  beforeEach(() => {
    jest.resetModules();
    mockCache = {
      get:        jest.fn().mockResolvedValue(null),
      set:        jest.fn().mockResolvedValue(undefined),
      invalidate: jest.fn(),
    };
    mockStore = {
      findByKey:       jest.fn().mockResolvedValue(null),
      logVerification: jest.fn().mockResolvedValue(undefined),
    };
    mockPool = { isEnabled: jest.fn().mockReturnValue(true) };

    jest.doMock('./ConsentCache',  () => mockCache);
    jest.doMock('./ConsentStore',  () => mockStore);
    jest.doMock('../../infra/postgres/pool', () => mockPool);
    jest.doMock('../../../services/logger',  () => ({ emit: jest.fn() }));
    verifier = require('./ConsentVerifier');
  });

  afterEach(() => jest.resetModules());

  test('returns CONSENT_NOT_FOUND when no DB record', async () => {
    const r = await verifier.verify({ actor_id: 'agent', action: 'action' });
    expect(r.pass).toBe(false);
    expect(r.reason).toBe('CONSENT_NOT_FOUND');
  });

  test('returns CONSENT_VERIFIED for ACTIVE record with no expiry', async () => {
    mockStore.findByKey.mockResolvedValue(makeRecord());
    const r = await verifier.verify({ actor_id: 'ai-agent-001', action: 'Facial Recognition' });
    expect(r.pass).toBe(true);
    expect(r.reason).toBe('CONSENT_VERIFIED');
  });

  // FINDING-REVOCATION-SUBSCRIBER-LIVELOCK follow-on: pg returns
  // timestamp/timestamptz columns (created_at/granted_at/expires_at) as
  // native Date instances, not strings. consentProvenance is hash-protected
  // (stableStringify, TRACE-2/aiChat.js's mandatory ALLOW-stage audit
  // write) and stableStringify deliberately throws on any non-plain-object
  // value including Date (QODIQA-PROTOCOL-SPEC.md §6.1 — no relaxation of
  // that contract here). Reproduced live: a real granted consent record
  // reaching /ai/chat's ALLOW path threw
  // "stableStringify: cannot serialize a non-plain-object value (Date)"
  // during the mandatory audit write, turning a would-be EXECUTE into a 503
  //.
  test('consentProvenance never carries a raw Date — every pg timestamp field is stableStringify-safe', async () => {
    const stableStringify = require('../../utils/stableStringify');
    mockStore.findByKey.mockResolvedValue(makeRecord({
      created_at: new Date('2026-01-01T00:00:00Z'),
      granted_at: new Date('2026-01-02T00:00:00Z'),
      expires_at: new Date('2099-01-01T00:00:00Z'),
    }));
    const r = await verifier.verify({ actor_id: 'ai-agent-001', action: 'Facial Recognition' });
    expect(r.pass).toBe(true);

    expect(r.consentProvenance).not.toBeNull();
    expect(r.consentProvenance.consentCreatedAt).toBe('2026-01-01T00:00:00.000Z');
    expect(r.consentProvenance.consentApprovedAt).toBe('2026-01-02T00:00:00.000Z');
    expect(r.consentProvenance.expiresAt).toBe('2099-01-01T00:00:00.000Z');
    expect(r.consentProvenance.consentCreatedAt).not.toBeInstanceOf(Date);
    expect(r.consentProvenance.consentApprovedAt).not.toBeInstanceOf(Date);
    expect(r.consentProvenance.expiresAt).not.toBeInstanceOf(Date);

    // The real failure mode: this must not throw.
    expect(() => stableStringify(r.consentProvenance)).not.toThrow();
  });

  test('returns CONSENT_EXPIRED for ACTIVE record with past expires_at', async () => {
    mockStore.findByKey.mockResolvedValue(makeRecord({ expires_at: new Date(Date.now() - 1000) }));
    const r = await verifier.verify({ actor_id: 'agent', action: 'action' });
    expect(r.pass).toBe(false);
    expect(r.reason).toBe('CONSENT_EXPIRED');
  });

  test('persists EXPIRED for an ACTIVE record past expires_at, once, and not for other states', async () => {
    mockStore.markExpired = jest.fn().mockResolvedValue({});
    mockStore.findByKey.mockResolvedValue(makeRecord({ expires_at: new Date(Date.now() - 1000) }));
    await verifier.verify({ actor_id: 'agent', action: 'action' });
    await new Promise((r) => setImmediate(r));
    expect(mockStore.markExpired).toHaveBeenCalledTimes(1);
    expect(mockStore.markExpired.mock.calls[0][0].id).toBeDefined();
    mockStore.markExpired.mockClear();
    mockStore.findByKey.mockResolvedValue(makeRecord({ state: 'REVOKED' }));
    await verifier.verify({ actor_id: 'agent', action: 'action' });
    await new Promise((r) => setImmediate(r));
    expect(mockStore.markExpired).not.toHaveBeenCalled();
  });

  test('a failing expiry persist never changes the verification answer', async () => {
    mockStore.markExpired = jest.fn().mockRejectedValue(new Error('db down'));
    mockStore.findByKey.mockResolvedValue(makeRecord({ expires_at: new Date(Date.now() - 1000) }));
    const r = await verifier.verify({ actor_id: 'agent', action: 'action' });
    expect(r.reason).toBe('CONSENT_EXPIRED');
  });

  test('returns CONSENT_REVOKED for REVOKED record', async () => {
    mockStore.findByKey.mockResolvedValue(makeRecord({ state: 'REVOKED' }));
    const r = await verifier.verify({ actor_id: 'agent', action: 'action' });
    expect(r.pass).toBe(false);
    expect(r.reason).toBe('CONSENT_REVOKED');
  });

  test('returns CONSENT_SUSPENDED for SUSPENDED record with future suspended_until', async () => {
    mockStore.findByKey.mockResolvedValue(
      makeRecord({ state: 'SUSPENDED', suspended_until: new Date(Date.now() + 60_000) }),
    );
    const r = await verifier.verify({ actor_id: 'agent', action: 'action' });
    expect(r.pass).toBe(false);
    expect(r.reason).toBe('CONSENT_SUSPENDED');
  });

  test('auto-resumes SUSPENDED record whose suspended_until has passed', async () => {
    mockStore.findByKey.mockResolvedValue(
      makeRecord({ state: 'SUSPENDED', suspended_until: new Date(Date.now() - 1) }),
    );
    const r = await verifier.verify({ actor_id: 'agent', action: 'action' });
    expect(r.pass).toBe(true);
  });

  test('returns CONSENT_SCOPE_MISMATCH when required_scope does not match', async () => {
    mockStore.findByKey.mockResolvedValue(makeRecord({ scope: 'basic' }));
    const r = await verifier.verify({ actor_id: 'agent', action: 'action', required_scope: 'biometric' });
    expect(r.pass).toBe(false);
    expect(r.reason).toBe('CONSENT_SCOPE_MISMATCH');
  });

  test('scope match passes when scopes align', async () => {
    mockStore.findByKey.mockResolvedValue(makeRecord({ scope: 'biometric' }));
    const r = await verifier.verify({ actor_id: 'agent', action: 'action', required_scope: 'biometric' });
    expect(r.pass).toBe(true);
  });

  test('cache hit is returned without DB query', async () => {
    mockCache.get.mockResolvedValue({ pass: true, reason: 'CONSENT_VERIFIED', cached: true });
    const r = await verifier.verify({ actor_id: 'agent', action: 'action' });
    expect(r.cached).toBe(true);
    expect(mockStore.findByKey).not.toHaveBeenCalled();
  });

  test('returns CONSENT_STORE_UNAVAILABLE when DB not enabled', async () => {
    mockPool.isEnabled.mockReturnValue(false);
    const r = await verifier.verify({ actor_id: 'agent', action: 'action' });
    expect(r.pass).toBe(false);
    expect(r.reason).toBe('CONSENT_STORE_UNAVAILABLE');
  });

  test('returns CONSENT_STORE_ERROR when DB throws', async () => {
    mockStore.findByKey.mockRejectedValue(new Error('connection timeout'));
    const r = await verifier.verify({ actor_id: 'agent', action: 'action' });
    expect(r.pass).toBe(false);
    expect(r.reason).toBe('CONSENT_STORE_ERROR');
  });

  test('returns CONSENT_INVALID_INPUT when actor_id is empty', async () => {
    const r = await verifier.verify({ actor_id: '', action: 'action' });
    expect(r.pass).toBe(false);
    expect(r.reason).toBe('CONSENT_INVALID_INPUT');
  });

  test('returns CONSENT_INVALID_INPUT when action is empty', async () => {
    const r = await verifier.verify({ actor_id: 'agent', action: '' });
    expect(r.pass).toBe(false);
    expect(r.reason).toBe('CONSENT_INVALID_INPUT');
  });

  test('caches positive result after DB hit, CAS-guarded with the record version', async () => {
    mockStore.findByKey.mockResolvedValue(makeRecord({ version: 7 }));
    await verifier.verify({ actor_id: 'agent', action: 'action' });
    expect(mockCache.set).toHaveBeenCalledWith('agent', 'action', null, expect.objectContaining({ pass: true }), 7, { requiredScope: null });
  });

  test('caches negative result (NOT_FOUND) after DB miss', async () => {
    await verifier.verify({ actor_id: 'agent', action: 'action' });
    expect(mockCache.set).toHaveBeenCalledWith('agent', 'action', null, expect.objectContaining({ pass: false }), null, { requiredScope: null });
  });

  test('never throws — always returns a result object', async () => {
    mockStore.findByKey.mockRejectedValue(new Error('catastrophic'));
    const r = await verifier.verify({ actor_id: 'agent', action: 'action' });
    expect(r).toHaveProperty('pass');
    expect(r).toHaveProperty('reason');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 5. ConsentRegistry
// ═══════════════════════════════════════════════════════════════════════════════

describe('ConsentRegistry', () => {
  let registry;
  let mockStore;
  let mockCache;
  let mockVerifier;
  let mockPool;

  beforeEach(() => {
    jest.resetModules();
    mockStore = {
      create:          jest.fn().mockResolvedValue(makeRecord()),
      revoke:          jest.fn().mockResolvedValue(makeRecord({ state: 'REVOKED' })),
      suspend:         jest.fn().mockResolvedValue(makeRecord({ state: 'SUSPENDED' })),
      resume:          jest.fn().mockResolvedValue(makeRecord()),
      findByKey:       jest.fn().mockResolvedValue(null),
      findById:        jest.fn().mockResolvedValue(null),
      list:            jest.fn().mockResolvedValue({ records: [], total: 0 }),
      getAuditLog:     jest.fn().mockResolvedValue([]),
      logVerification: jest.fn().mockResolvedValue(undefined),
    };
    mockCache = {
      invalidate:      jest.fn().mockResolvedValue(undefined),
      invalidateActor: jest.fn().mockResolvedValue(undefined),
      isReady:         jest.fn().mockReturnValue(true),
    };
    mockVerifier = {
      verify: jest.fn().mockResolvedValue({ pass: true, reason: 'CONSENT_VERIFIED' }),
    };
    mockPool = {
      isEnabled: jest.fn().mockReturnValue(true),
      isHealthy: jest.fn().mockReturnValue(true),
    };

    jest.doMock('./ConsentStore',           () => mockStore);
    jest.doMock('./ConsentCache',           () => mockCache);
    jest.doMock('./ConsentVerifier',        () => mockVerifier);
    jest.doMock('../../infra/postgres/pool',() => mockPool);
    jest.doMock('../../../services/logger', () => ({ emit: jest.fn() }));

    registry = require('./ConsentRegistry');
  });

  afterEach(() => jest.resetModules());

  test('grant() calls store.create and invalidates cache', async () => {
    await registry.grant({ actor_id: 'a', action: 'b', granted_by: 'admin' });
    expect(mockStore.create).toHaveBeenCalled();
    expect(mockCache.invalidate).toHaveBeenCalled();
  });

  test('revoke() calls store.revoke and invalidates cache', async () => {
    await registry.revoke({ id: 'uuid', revoked_by: 'admin' });
    expect(mockStore.revoke).toHaveBeenCalled();
    expect(mockCache.invalidate).toHaveBeenCalled();
  });

  test('suspend() calls store.suspend and invalidates cache', async () => {
    await registry.suspend({ id: 'uuid', suspended_by: 'admin' });
    expect(mockStore.suspend).toHaveBeenCalled();
    expect(mockCache.invalidate).toHaveBeenCalled();
  });

  test('resume() calls store.resume and invalidates cache', async () => {
    await registry.resume({ id: 'uuid', resumed_by: 'admin' });
    expect(mockStore.resume).toHaveBeenCalled();
    expect(mockCache.invalidate).toHaveBeenCalled();
  });

  test('verify() delegates to ConsentVerifier', async () => {
    const result = await registry.verify({ actor_id: 'a', action: 'b' });
    expect(mockVerifier.verify).toHaveBeenCalled();
    expect(result.pass).toBe(true);
  });

  test('revokeAll() revokes active and pending records, skips terminal ones', async () => {
    const r1 = makeRecord({ id: 'id-1', state: 'ACTIVE' });
    const r2 = makeRecord({ id: 'id-2', state: 'PENDING' });
    const r3 = makeRecord({ id: 'id-3', state: 'REVOKED' });
    const r4 = makeRecord({ id: 'id-4', state: 'EXPIRED' });
    mockStore.list.mockResolvedValue({ records: [r1, r2, r3, r4], total: 4 });

    const { count } = await registry.revokeAll('ai-agent-001', 'admin', undefined, { tenantIds: [] }); // platform scope only; tenant scopes: ConsentRegistry.revokeAll.test.js (audit 3.2)
    expect(count).toBe(2);
    expect(mockStore.revoke).toHaveBeenCalledTimes(2);
    expect(mockCache.invalidateActor).toHaveBeenCalledWith('ai-agent-001');
  });

  test('revokeAll() calls invalidateActor even if all records are terminal', async () => {
    mockStore.list.mockResolvedValue({
      records: [makeRecord({ state: 'REVOKED' }), makeRecord({ state: 'EXPIRED' })],
      total: 2,
    });
    const { count } = await registry.revokeAll('actor', 'admin', undefined, { tenantIds: [] });
    expect(count).toBe(0);
    expect(mockCache.invalidateActor).toHaveBeenCalled();
  });

  test('health() returns all three status fields', () => {
    const h = registry.health();
    expect(h).toHaveProperty('pgEnabled');
    expect(h).toHaveProperty('pgHealthy');
    expect(h).toHaveProperty('cacheReady');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 6. requireConsent evaluator
// ═══════════════════════════════════════════════════════════════════════════════

describe('requireConsent evaluator', () => {
  let evaluator;
  let mockRegistry;

  beforeEach(() => {
    jest.resetModules();
    mockRegistry = { verify: jest.fn().mockResolvedValue({ pass: true, reason: 'CONSENT_VERIFIED' }) };
    // requireConsent uses a lazy _registry() call that requires src/core/consent
    // We mock it at the path the evaluator will resolve from services/policy/evaluators/
    jest.doMock('../../../src/core/consent', () => mockRegistry);
    evaluator = require('../../../services/policy/evaluators/requireConsent');
  });

  afterEach(() => jest.resetModules());

  describe('validate()', () => {
    test('throws when requireValidArtifact is not true', () =>
      expect(() => evaluator.validate({ requireValidArtifact: false })).toThrow());
    test('passes when requireValidArtifact is true', () =>
      expect(() => evaluator.validate({ requireValidArtifact: true })).not.toThrow());
  });

  describe('evaluate()', () => {
    const config = { requireValidArtifact: true };

    const validCtx = {
      userId:   'ai-agent-001',
      action:   'Facial Recognition',
      artifact: { valid: true, payload: { userId: 'ai-agent-001', provider: 'Facial Recognition' } },
    };

    test('returns pass:false CONSENT_MISSING when artifact.valid is false', async () => {
      const r = await evaluator.evaluate({ ...validCtx, artifact: { valid: false } }, config);
      expect(r.pass).toBe(false);
      expect(r.reason).toBe('CONSENT_MISSING');
    });

    test('returns pass:false when artifact is absent', async () => {
      const r = await evaluator.evaluate({ userId: 'x', action: 'y' }, config);
      expect(r.pass).toBe(false);
      expect(r.reason).toBe('CONSENT_MISSING');
    });

    test('returns CONSENT_CONTEXT_INCOMPLETE when actor_id cannot be derived', async () => {
      const r = await evaluator.evaluate({ artifact: { valid: true, payload: {} } }, config);
      expect(r.pass).toBe(false);
      expect(r.reason).toBe('CONSENT_CONTEXT_INCOMPLETE');
    });

    test('calls registry.verify with actor_id and action', async () => {
      await evaluator.evaluate(validCtx, config);
      expect(mockRegistry.verify).toHaveBeenCalledWith(
        expect.objectContaining({ actor_id: 'ai-agent-001', action: 'Facial Recognition' }),
      );
    });

    test('returns pass:true when registry returns CONSENT_VERIFIED', async () => {
      const r = await evaluator.evaluate(validCtx, config);
      expect(r.pass).toBe(true);
    });

    test('propagates denial reason from registry', async () => {
      mockRegistry.verify.mockResolvedValue({ pass: false, reason: 'CONSENT_REVOKED' });
      const r = await evaluator.evaluate(validCtx, config);
      expect(r.pass).toBe(false);
      expect(r.reason).toBe('CONSENT_REVOKED');
    });

    test('returns CONSENT_EVALUATION_ERROR when registry throws', async () => {
      mockRegistry.verify.mockRejectedValue(new Error('unexpected'));
      const r = await evaluator.evaluate(validCtx, config);
      expect(r.pass).toBe(false);
      expect(r.reason).toBe('CONSENT_EVALUATION_ERROR');
    });

    test('evaluate() returns a Promise (is async)', () => {
      const rv = evaluator.evaluate(validCtx, config);
      expect(rv).toBeInstanceOf(Promise);
    });

    test('requiredScope from config is forwarded to registry.verify', async () => {
      const cfgWithScope = { ...config, requiredScope: 'biometric' };
      await evaluator.evaluate(validCtx, cfgWithScope);
      expect(mockRegistry.verify).toHaveBeenCalledWith(
        expect.objectContaining({ required_scope: 'biometric' }),
      );
    });
  });
});


// ═══════════════════════════════════════════════════════════════════════════════
// 7. Consent API routes — input validation
// ═══════════════════════════════════════════════════════════════════════════════

describe('Consent API routes — input validation', () => {
  let createConsentRouter;
  let mockRegistry;
  let mockEmit;
  let request;

  beforeEach(() => {
    jest.resetModules();
    mockRegistry = {
      grant:      jest.fn().mockResolvedValue(makeRecord()),
      revoke:     jest.fn().mockResolvedValue(makeRecord({ state: 'REVOKED' })),
      suspend:    jest.fn().mockResolvedValue(makeRecord({ state: 'SUSPENDED' })),
      resume:     jest.fn().mockResolvedValue(makeRecord()),
      verify:     jest.fn().mockResolvedValue({ pass: true, reason: 'CONSENT_VERIFIED' }),
      list:       jest.fn().mockResolvedValue({ records: [], total: 0 }),
      getById:    jest.fn().mockResolvedValue(null),
      getAuditLog:jest.fn().mockResolvedValue([]),
      revokeAll:  jest.fn().mockResolvedValue({ count: 0 }),
      health:     jest.fn().mockReturnValue({ pgEnabled: true, pgHealthy: true, cacheReady: true }),
    };
    mockEmit = jest.fn();

    jest.doMock('../../core/consent',       () => mockRegistry);
    jest.doMock('../../../services/logger', () => ({ emit: mockEmit }));

    ({ createConsentRouter } = require('../../api/routes/consent'));

    const express = require('express');
    const app = express();
    app.use(express.json());
    app.use('/consent', createConsentRouter());
    request = require('supertest')(app);
  });

  afterEach(() => jest.resetModules());

  describe('GET /consent/health', () => {
    test('returns 200 with health fields', async () => {
      const res = await request.get('/consent/health');
      expect(res.status).toBe(200);
      expect(res.body.data.pgEnabled).toBe(true);
    });
  });

  describe('POST /consent (grant) — lawful basis and purpose', () => {
    const base = { actorId: 'agent', action: 'Facial Recognition', grantedBy: 'admin' };
    function withStore(special) {
      jest.resetModules();
      jest.doMock('../../core/consent',       () => mockRegistry);
      jest.doMock('../../../services/logger', () => ({ emit: mockEmit }));
      jest.doMock('../../core/consent/ConsentStore', () => ({ isSpecialCategoryScope: jest.fn().mockResolvedValue(special) }));
      const { createConsentRouter: mk } = require('../../api/routes/consent');
      const app = require('express')();
      app.use(require('express').json());
      app.use('/consent', mk());
      return require('supertest')(app);
    }

    test('400 without lawfulBasis, and 400 without purpose', async () => {
      expect((await request.post('/consent').send({ ...base, purpose: 'p' })).status).toBe(400);
      expect((await request.post('/consent').send({ ...base, lawfulBasis: 'consent' })).status).toBe(400);
      expect(mockRegistry.grant).not.toHaveBeenCalled();
    });

    test('the basis, purpose, purposeCode and Art. 9 condition reach the store', async () => {
      const res = await request.post('/consent').send({
        ...base, lawfulBasis: 'legitimate_interests', purpose: 'Fraud prevention', purposeCode: 'fraud.prevention',
      });
      expect(res.status).toBe(201);
      expect(mockRegistry.grant).toHaveBeenCalledWith(expect.objectContaining({
        lawful_basis: 'legitimate_interests', purpose: 'Fraud prevention', purpose_code: 'fraud.prevention', special_category_condition: null,
      }));
    });

    test('a special-category scope without specialCategoryCondition → 400 SPECIAL_CATEGORY_CONDITION_REQUIRED', async () => {
      const req = withStore(true);
      const res = await req.post('/consent').send({ ...base, scope: 'biometric', lawfulBasis: 'consent', purpose: 'Door entry' });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('SPECIAL_CATEGORY_CONDITION_REQUIRED');
      expect(mockRegistry.grant).not.toHaveBeenCalled();
    });

    test('a special-category scope WITH the Art. 9(2) condition is granted', async () => {
      const req = withStore(true);
      const res = await req.post('/consent').send({
        ...base, scope: 'biometric', lawfulBasis: 'consent', purpose: 'Door entry', specialCategoryCondition: 'art9_2_a',
      });
      expect(res.status).toBe(201);
      expect(mockRegistry.grant).toHaveBeenCalledWith(expect.objectContaining({ special_category_condition: 'art9_2_a' }));
    });
  });

  describe('POST /consent (grant)', () => {
    test('400 when actor_id missing',    async () => {
      const res = await request.post('/consent').send({ action: 'Facial Recognition', granted_by: 'admin' });
      expect(res.status).toBe(400);
    });
    test('400 when action missing',      async () => {
      const res = await request.post('/consent').send({ actor_id: 'agent', granted_by: 'admin' });
      expect(res.status).toBe(400);
    });
    test('400 when expires_at is past', async () => {
      const res = await request.post('/consent').send({
        actor_id: 'agent', action: 'action', granted_by: 'admin',
        expires_at: new Date(Date.now() - 1000).toISOString(),
      });
      expect(res.status).toBe(400);
    });
    test('400 when scope contains invalid chars', async () => {
      const res = await request.post('/consent').send({
        actor_id: 'agent', action: 'action', granted_by: 'admin', scope: '<script>',
      });
      expect(res.status).toBe(400);
    });
    test('201 with valid grant payload', async () => {
      const res = await request.post('/consent').send({
        actor_id: 'agent', action: 'Facial Recognition', granted_by: 'admin',
        lawfulBasis: 'consent', purpose: 'Identity check at door entry', // (D8-A)
      });
      expect(res.status).toBe(201);
      expect(res.body.status).toBe('success');
      expect(res.body.data.record).toBeDefined();
    });

    // OPS-04: consent.js used to construct expires_at as a JS Date object
    // (both the client-supplied-expiresAt branch and the computed-from-
    // durationDays branch), which stableStringify() rejects when the audit
    // log tries to checksum it — a 500 on every grant that supplied an
    // expiry. The fix normalizes both branches to a canonical ISO-UTC
    // string. These four tests lock all four combinations (durationDays x
    // expiresAt, snake_case x camelCase) — each must succeed and must pass
    // registry.grant() a plain string, never a Date instance.
    describe('OPS-04: expires_at is always a canonical ISO-UTC string, never a Date', () => {
      test('camelCase expiresAt (non-canonical client input) is normalized to canonical ISO-UTC', async () => {
        const res = await request.post('/consent').send({
          actorId: 'agent', action: 'local', grantedBy: 'admin', lawfulBasis: 'consent', purpose: 'p',
          expiresAt: '2027-06-15', // bare date — parseable but not canonical UTC
        });
        expect(res.status).toBe(201);
        const passed = mockRegistry.grant.mock.calls[0][0].expires_at;
        expect(typeof passed).toBe('string');
        expect(passed).not.toBeInstanceOf(Date);
        // Proves normalization, not passthrough: the canonical form differs
        // from the raw client bytes ("2027-06-15" alone is not ISO-8601 with
        // a time/offset component).
        expect(passed).toBe(new Date('2027-06-15').toISOString());
      });

      test('camelCase durationDays computes a canonical ISO-UTC string, never a Date', async () => {
        const before = Date.now();
        const res = await request.post('/consent').send({
          actorId: 'agent', action: 'local', grantedBy: 'admin', durationDays: 7, lawfulBasis: 'consent', purpose: 'p',
        });
        expect(res.status).toBe(201);
        const passed = mockRegistry.grant.mock.calls[0][0].expires_at;
        expect(typeof passed).toBe('string');
        expect(passed).not.toBeInstanceOf(Date);
        const passedMs = new Date(passed).getTime();
        expect(passedMs).toBeGreaterThanOrEqual(before + 7 * 86_400_000 - 5000);
        expect(passedMs).toBeLessThanOrEqual(Date.now() + 7 * 86_400_000 + 5000);
      });

      test('snake_case expires_at is normalized to canonical ISO-UTC and warns CONSENT_LEGACY_FIELD_CASING_USED', async () => {
        const res = await request.post('/consent').send({
          actor_id: 'agent', action: 'local', granted_by: 'admin', lawful_basis: 'consent', purpose: 'p',
          expires_at: '2027-06-15',
        });
        expect(res.status).toBe(201);
        const passed = mockRegistry.grant.mock.calls[0][0].expires_at;
        expect(typeof passed).toBe('string');
        expect(passed).toBe(new Date('2027-06-15').toISOString());
        expect(mockEmit).toHaveBeenCalledWith('WARN', 'CONSENT_LEGACY_FIELD_CASING_USED',
          expect.objectContaining({ legacyFieldsUsed: expect.arrayContaining(['expires_at']) }));
      });

      test('snake_case duration_days computes a canonical ISO-UTC string and warns CONSENT_LEGACY_FIELD_CASING_USED', async () => {
        const before = Date.now();
        const res = await request.post('/consent').send({
          actor_id: 'agent', action: 'local', granted_by: 'admin', duration_days: 7, lawful_basis: 'consent', purpose: 'p',
        });
        expect(res.status).toBe(201);
        const passed = mockRegistry.grant.mock.calls[0][0].expires_at;
        expect(typeof passed).toBe('string');
        const passedMs = new Date(passed).getTime();
        expect(passedMs).toBeGreaterThanOrEqual(before + 7 * 86_400_000 - 5000);
        expect(mockEmit).toHaveBeenCalledWith('WARN', 'CONSENT_LEGACY_FIELD_CASING_USED',
          expect.objectContaining({ legacyFieldsUsed: expect.arrayContaining(['duration_days']) }));
      });
    });
  });

  describe('GET /consent (list)', () => {
    test('200 returns records and total', async () => {
      const res = await request.get('/consent');
      expect(res.status).toBe(200);
      expect(res.body.data).toHaveProperty('total');
    });
    test('400 on invalid state filter', async () => {
      const res = await request.get('/consent?state=INVALID');
      expect(res.status).toBe(400);
    });
    test('accepts valid state filter', async () => {
      mockRegistry.list.mockResolvedValue({ records: [makeRecord()], total: 1 });
      const res = await request.get('/consent?state=ACTIVE');
      expect(res.status).toBe(200);
    });
  });

  describe('GET /consent/:id', () => {
    test('400 on non-UUID id',        async () => expect((await request.get('/consent/not-a-uuid')).status).toBe(400));
    test('404 when record not found', async () =>
      expect((await request.get('/consent/aaaaaaaa-0000-4000-8000-000000000001')).status).toBe(404));
    test('200 when record found', async () => {
      mockRegistry.getById.mockResolvedValue(makeRecord());
      const res = await request.get('/consent/aaaaaaaa-0000-4000-8000-000000000001');
      expect(res.status).toBe(200);
      expect(res.body.data.record.actor_id).toBe('ai-agent-001');
    });
  });

  describe('POST /consent/:id/revoke', () => {
    test('400 on non-UUID id', async () =>
      expect((await request.post('/consent/bad-id/revoke').send({ revoked_by: 'admin' })).status).toBe(400));
    test('200 on valid revoke', async () => {
      const res = await request.post('/consent/aaaaaaaa-0000-4000-8000-000000000001/revoke')
        .send({ revoked_by: 'admin' });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
    });

    // any PostgreSQL serialization conflict (40001) or deadlock
    // (40P01) that still reaches this route is mapped to a distinguishable,
    // client-retryable 409 — never the generic, indistinguishable-from-a-
    // real-fault 500 seen in live testing. ConsentStore's own READ COMMITTED pin means
    // this branch should not fire for this route in practice; it is a
    // defense-in-depth guard for any path this remediation didn't trace.
    test('a residual 40001 from the registry is mapped to 409 CONCURRENT_MODIFICATION, not 500', async () => {
      const err = new Error('could not serialize access due to concurrent update');
      err.code = '40001';
      mockRegistry.revoke.mockRejectedValueOnce(err);

      const res = await request.post('/consent/aaaaaaaa-0000-4000-8000-000000000001/revoke')
        .send({ revoked_by: 'admin' });

      expect(res.status).toBe(409);
      expect(res.body.error.code).toBe('CONCURRENT_MODIFICATION');
    });

    test('a residual 40P01 deadlock is likewise mapped to 409, not 500', async () => {
      const err = new Error('deadlock detected');
      err.code = '40P01';
      mockRegistry.revoke.mockRejectedValueOnce(err);

      const res = await request.post('/consent/aaaaaaaa-0000-4000-8000-000000000001/revoke')
        .send({ revoked_by: 'admin' });

      expect(res.status).toBe(409);
      expect(res.body.error.code).toBe('CONCURRENT_MODIFICATION');
    });

    test('an unrelated DB error (no retryable code) still maps to a generic 500', async () => {
      mockRegistry.revoke.mockRejectedValueOnce(new Error('connection terminated unexpectedly'));

      const res = await request.post('/consent/aaaaaaaa-0000-4000-8000-000000000001/revoke')
        .send({ revoked_by: 'admin' });

      expect(res.status).toBe(500);
      expect(res.body.error.code).toBe('INTERNAL_ERROR');
    });
  });

  describe('POST /consent/:id/suspend', () => {
    test('400 on non-UUID id', async () =>
      expect((await request.post('/consent/bad/suspend').send({})).status).toBe(400));
    test('400 on invalid suspended_until', async () => {
      const res = await request.post('/consent/aaaaaaaa-0000-4000-8000-000000000001/suspend')
        .send({ suspended_by: 'admin', suspended_until: 'not-a-date' });
      expect(res.status).toBe(400);
    });
    test('200 on valid suspend', async () => {
      const res = await request.post('/consent/aaaaaaaa-0000-4000-8000-000000000001/suspend')
        .send({ suspended_by: 'admin' });
      expect(res.status).toBe(200);
    });

    // OPS-04: same Date-serialization defect as grant's expires_at (see
    // that describe block above) — consent.js used to construct
    // suspended_until as a JS Date object, which stableStringify() rejects
    // when the audit log checksums suspend()'s { suspension_reason,
    // suspended_until } detail.
    test('OPS-04: suspendedUntil is normalized to a canonical ISO-UTC string, never a Date', async () => {
      const res = await request.post('/consent/aaaaaaaa-0000-4000-8000-000000000001/suspend')
        .send({ suspended_by: 'admin', suspended_until: '2027-06-15' });
      expect(res.status).toBe(200);
      const passed = mockRegistry.suspend.mock.calls[0][0].suspended_until;
      expect(typeof passed).toBe('string');
      expect(passed).not.toBeInstanceOf(Date);
      expect(passed).toBe(new Date('2027-06-15').toISOString());
    });

    test('OPS-04: suspendedUntil omitted stays null — unchanged behavior', async () => {
      const res = await request.post('/consent/aaaaaaaa-0000-4000-8000-000000000001/suspend')
        .send({ suspended_by: 'admin' });
      expect(res.status).toBe(200);
      expect(mockRegistry.suspend.mock.calls[0][0].suspended_until).toBeNull();
    });
  });

  describe('POST /consent/:id/resume', () => {
    test('200 on valid resume', async () => {
      mockRegistry.resume.mockResolvedValue(makeRecord());
      const res = await request.post('/consent/aaaaaaaa-0000-4000-8000-000000000001/resume')
        .send({ resumed_by: 'admin' });
      expect(res.status).toBe(200);
    });
  });

  describe('POST /consent/actor/:actorId/revoke', () => {
    test('400 on invalid actorId', async () =>
      expect((await request.post('/consent/actor/<script>/revoke')).status).toBe(400));
    test('200 with revoked count', async () => {
      mockRegistry.revokeAll.mockResolvedValue({ count: 3 });
      const res = await request.post('/consent/actor/ai-agent-001/revoke');
      expect(res.status).toBe(200);
      expect(res.body.data.count).toBe(3);
    });
    test('does not set deprecation headers and does not warn (current, non-legacy path)', async () => {
      const res = await request.post('/consent/actor/ai-agent-001/revoke');
      expect(res.headers.deprecation).toBeUndefined();
      expect(res.headers.sunset).toBeUndefined();
      expect(mockEmit).not.toHaveBeenCalledWith('WARN', 'CONSENT_DELETE_ACTOR_DEPRECATED_USED', expect.anything());
    });
  });

  describe('DELETE /consent/actor/:actorId', () => {
    test('400 on invalid actorId', async () =>
      expect((await request.delete('/consent/actor/<script>')).status).toBe(400));
    test('200 with revoked count — still functions identically to the new route', async () => {
      mockRegistry.revokeAll.mockResolvedValue({ count: 3 });
      const res = await request.delete('/consent/actor/ai-agent-001');
      expect(res.status).toBe(200);
      expect(res.body.data.count).toBe(3);
      expect(mockRegistry.revokeAll).toHaveBeenCalledWith('ai-agent-001', expect.any(String), expect.any(String));
    });
    test('returns Deprecation, Sunset, and Link headers pointing at the successor endpoint', async () => {
      const res = await request.delete('/consent/actor/ai-agent-001');
      expect(res.headers.deprecation).toBe('true');
      expect(res.headers.sunset).toBeTruthy();
      expect(res.headers.link).toContain('/consent/actor/ai-agent-001/revoke');
      expect(res.headers.link).toContain('rel="successor-version"');
    });
    test('emits a CONSENT_DELETE_ACTOR_DEPRECATED_USED warning on every call', async () => {
      await request.delete('/consent/actor/ai-agent-001');
      expect(mockEmit).toHaveBeenCalledWith(
        'WARN',
        'CONSENT_DELETE_ACTOR_DEPRECATED_USED',
        expect.objectContaining({ actorId: 'ai-agent-001' }),
      );
    });
    test('does not delete or erase any record — only revokes (state transition)', async () => {
      mockRegistry.revokeAll.mockResolvedValue({ count: 1 });
      const res = await request.delete('/consent/actor/ai-agent-001');
      expect(res.status).toBe(200);
      // The legacy route calls the exact same registry.revokeAll() used by the
      // new endpoint — never a delete/erase primitive. registry has no such
      // method in this mock at all, so calling it would throw.
      expect(mockRegistry.revokeAll).toHaveBeenCalled();
    });
  });

  describe('POST /consent/verify', () => {
    test('400 when actor_id missing', async () => {
      const res = await request.post('/consent/verify').send({ action: 'action' });
      expect(res.status).toBe(400);
    });
    test('400 when action missing', async () => {
      const res = await request.post('/consent/verify').send({ actor_id: 'agent' });
      expect(res.status).toBe(400);
    });
    test('400 on SQL injection attempt in actor_id', async () => {
      const res = await request.post('/consent/verify').send({ actor_id: "'; DROP TABLE --", action: 'X' });
      expect(res.status).toBe(400);
    });
    test('200 when consent verified', async () => {
      const res = await request.post('/consent/verify').send({ actor_id: 'agent', action: 'Facial Recognition' });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data.pass).toBe(true);
    });
    test('403 when consent denied', async () => {
      mockRegistry.verify.mockResolvedValue({ pass: false, reason: 'CONSENT_REVOKED' });
      const res = await request.post('/consent/verify').send({ actor_id: 'agent', action: 'action' });
      expect(res.status).toBe(403);
      expect(res.body.status).toBe('error');
      expect(res.body.error.details.pass).toBe(false);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 8. Security controls
// ═══════════════════════════════════════════════════════════════════════════════

describe('Security controls', () => {
  const sm = require('./ConsentStateModel');

  test('unknown state through effectiveState does not yield ACTIVE', () => {
    const result = sm.effectiveState({ state: 'UNKNOWN', expires_at: null, suspended_until: null });
    expect(result).not.toBe(sm.STATE.ACTIVE);
  });

  test('REVOKED cannot transition to any non-terminal state', () => {
    for (const target of ['ACTIVE', 'PENDING', 'SUSPENDED', 'EXPIRED']) {
      expect(sm.isValidTransition('REVOKED', target)).toBe(false);
    }
  });

  test('EXPIRED cannot transition to any state', () => {
    for (const target of ['ACTIVE', 'PENDING', 'SUSPENDED', 'REVOKED']) {
      expect(sm.isValidTransition('EXPIRED', target)).toBe(false);
    }
  });

  test('ACTIVE cannot jump directly to PENDING (no backward transitions)', () => {
    expect(sm.isValidTransition('ACTIVE', 'PENDING')).toBe(false);
  });

  test('isTerminal guards all terminal states', () => {
    expect(sm.isTerminal('REVOKED')).toBe(true);
    expect(sm.isTerminal('EXPIRED')).toBe(true);
    expect(sm.isTerminal('ACTIVE')).toBe(false);
    expect(sm.isTerminal('PENDING')).toBe(false);
    expect(sm.isTerminal('SUSPENDED')).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 9. State machine edge cases
// ═══════════════════════════════════════════════════════════════════════════════

describe('State machine edge cases', () => {
  const { effectiveState, STATE } = require('./ConsentStateModel');

  test('PENDING record is not treated as ACTIVE', () => {
    expect(effectiveState(makeRecord({ state: STATE.PENDING }))).toBe(STATE.PENDING);
  });

  test('SUSPENDED auto-resumes at exact suspended_until boundary', () => {
    const now = new Date();
    const record = makeRecord({ state: STATE.SUSPENDED, suspended_until: new Date(now.getTime()) });
    expect(effectiveState(record, now)).toBe(STATE.ACTIVE);
  });

  test('ACTIVE expires at exact expires_at boundary', () => {
    const now = new Date();
    const record = makeRecord({ state: STATE.ACTIVE, expires_at: new Date(now.getTime()) });
    expect(effectiveState(record, now)).toBe(STATE.EXPIRED);
  });

  test('null expires_at on ACTIVE is indefinite consent', () => {
    expect(effectiveState(makeRecord({ expires_at: null }))).toBe(STATE.ACTIVE);
  });

  test('null suspended_until on SUSPENDED means indefinite suspension', () => {
    expect(effectiveState(makeRecord({ state: STATE.SUSPENDED, suspended_until: null }))).toBe(STATE.SUSPENDED);
  });

  test('effectiveState is pure — does not mutate the record', () => {
    const record = makeRecord({ expires_at: new Date(Date.now() - 1000) });
    const originalState = record.state;
    effectiveState(record);
    expect(record.state).toBe(originalState);
  });
});
