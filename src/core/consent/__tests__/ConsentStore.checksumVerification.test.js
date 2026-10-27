'use strict';

/**
 * ConsentStore — consent audit checksum bidirectional verification (TRACE-3).
 *
 * Previously the consent_audit_log.checksum column was written on every
 * insert and never read back or compared against anything — it provided no
 * runtime integrity. This file covers the fix: verifyAuditChecksum()
 * recomputes the checksum from a row's own fields and compares it,
 * getAuditLog() annotates every returned row with the result, and
 * verifyConsentAuditIntegrity() scans for mismatches.
 *
 * Also covers the real bug this fix uncovered: the original formula used
 * plain JSON.stringify(detail), but `detail` is stored in a JSONB column —
 * and PostgreSQL's jsonb type does NOT preserve original key insertion
 * order (empirically verified: it re-emits keys in an internal order,
 * observed as ascending key length). A checksum computed from
 * JSON.stringify(detail) at write time could never be reproduced from the
 * same row read back later for a multi-key `detail` object whose authored
 * order wasn't already length-ascending (e.g. suspend()'s
 * `{ suspension_reason, suspended_until }`) — a false tamper signal on
 * every legitimate row of that shape. The fix uses stableStringify
 * (lexicographic key sort, order-independent) instead.
 */

describe('ConsentStore — consent audit checksum verification (TRACE-3)', () => {
  let store;
  let pool;

  beforeEach(() => {
    jest.resetModules();
    pool = {
      query:                 jest.fn(),
      isEnabled:             jest.fn(() => true),
      withTransaction:       jest.fn(async (fn) => fn({ query: jest.fn() })),
      withTenantTransaction: jest.fn(async (_tenantId, fn) => fn({ query: jest.fn() })),
    };
    jest.doMock('../../../infra/postgres/pool', () => pool);
    jest.doMock('../../../infra/postgres/rolePools', () => require('../../../../test/helpers/rolePoolsDelegate')(pool)); //
    jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));
    store = require('../ConsentStore');
  });

  afterEach(() => jest.resetModules());

  test('CKV-01 verifyAuditChecksum() passes for a row whose checksum matches the recomputed formula', () => {
    const row = {
      consent_id: 'c-1', event_type: 'CONSENT_GRANTED', actor: 'admin-1',
      detail: { scope: 'read', expires_at: '2027-01-01', granted_via: 'API' },
    };
    // Compute the expected checksum exactly as _auditChecksum() would, via
    // the store's own exported helper for construction (no separate formula).
    const written = store.verifyAuditChecksum({ ...row, checksum: 'placeholder' });
    row.checksum = written.expected;
    expect(store.verifyAuditChecksum(row).valid).toBe(true);
  });

  test('CKV-02 verifyAuditChecksum() fails when a checksum-covered field is mutated', () => {
    const row = { consent_id: 'c-1', event_type: 'CONSENT_GRANTED', actor: 'admin-1', detail: { scope: 'read' } };
    row.checksum = store.verifyAuditChecksum({ ...row, checksum: 'x' }).expected;

    const tampered = { ...row, actor: 'attacker' };
    expect(store.verifyAuditChecksum(tampered).valid).toBe(false);
  });

  test('CKV-03 verifyAuditChecksum() still PASSES when a NON-covered field is mutated — documents the real coverage boundary', () => {
    const row = {
      consent_id: 'c-1', event_type: 'CONSENT_GRANTED', actor: 'admin-1',
      detail: { scope: 'read' }, denial_reason: null, tenant_id: 'tenant-A',
    };
    row.checksum = store.verifyAuditChecksum({ ...row, checksum: 'x' }).expected;

    // denial_reason/tenant_id are persisted columns but NOT part of the
    // checksum formula (consent_id|event_type|actor|detail only) — mutating
    // them must not flip a genuine row to "invalid".
    const tampered = { ...row, denial_reason: 'SOMETHING_ELSE', tenant_id: 'tenant-B' };
    expect(store.verifyAuditChecksum(tampered).valid).toBe(true);
  });

  test('CKV-04 verifyAuditChecksum() is order-independent for `detail` — survives a simulated JSONB key-reorder round-trip', () => {
    // Mirrors ConsentStore.js's own documented finding: PostgreSQL jsonb
    // re-emits object keys in its own internal order (observed: ascending
    // key length) on every read, not the original insertion order used at
    // write time (e.g. suspend()'s { suspension_reason, suspended_until }).
    const original = {
      consent_id: 'c-1', event_type: 'CONSENT_SUSPENDED', actor: 'admin-1',
      detail: { suspension_reason: 'fraud_review', suspended_until: '2027-01-01' },
    };
    const checksum = store.verifyAuditChecksum({ ...original, checksum: 'x' }).expected;

    // Simulate the JSONB round-trip: same content, keys re-emitted in a
    // different order (as PostgreSQL would after storing/reading it back).
    const roundTripped = {
      ...original, checksum,
      detail: { suspended_until: '2027-01-01', suspension_reason: 'fraud_review' },
    };
    expect(store.verifyAuditChecksum(roundTripped).valid).toBe(true);
  });

  test('CKV-05 verifyAuditChecksum() reports invalid for a missing/empty checksum without throwing', () => {
    expect(store.verifyAuditChecksum(null).valid).toBe(false);
    expect(store.verifyAuditChecksum({ consent_id: 'c-1' }).valid).toBe(false);
  });

  test('CKV-06 getAuditLog() annotates every row with checksumValid', async () => {
    const goodRow = { id: 1, consent_id: 'c-1', event_type: 'CONSENT_GRANTED', actor: 'admin-1', detail: {} };
    goodRow.checksum = store.verifyAuditChecksum({ ...goodRow, checksum: 'x' }).expected;
    const badRow = { id: 2, consent_id: 'c-2', event_type: 'CONSENT_GRANTED', actor: 'admin-1', detail: {}, checksum: 'deadbeef'.repeat(8) };

    pool.query.mockResolvedValueOnce({ rows: [goodRow, badRow] });

    const rows = await store.getAuditLog({ consent_id: 'c-1' });
    expect(rows[0].checksumValid).toBe(true);
    expect(rows[1].checksumValid).toBe(false);
  });

  test('CKV-07 verifyConsentAuditIntegrity() scans rows and reports only mismatches', async () => {
    const goodRow = { id: 1, consent_id: 'c-1', event_type: 'CONSENT_GRANTED', actor: 'admin-1', detail: {}, event_ts: '2026-01-01T00:00:00.000Z' };
    goodRow.checksum = store.verifyAuditChecksum({ ...goodRow, checksum: 'x' }).expected;
    const badRow = { id: 2, consent_id: 'c-2', event_type: 'CONSENT_REVOKED', actor: 'admin-1', detail: {}, checksum: 'deadbeef'.repeat(8), event_ts: '2026-01-02T00:00:00.000Z' };

    pool.query.mockResolvedValueOnce({ rows: [goodRow, badRow] });

    const result = await store.verifyConsentAuditIntegrity({ limit: 100 });
    expect(result.scanned).toBe(2);
    expect(result.mismatches).toHaveLength(1);
    expect(result.mismatches[0]).toMatchObject({ id: 2, consentId: 'c-2', eventType: 'CONSENT_REVOKED' });
  });

  test('CKV-08 verifyConsentAuditIntegrity() is a no-op when Postgres is disabled', async () => {
    pool.isEnabled.mockReturnValue(false);
    const result = await store.verifyConsentAuditIntegrity({});
    expect(result).toEqual({ scanned: 0, mismatches: [] });
    expect(pool.query).not.toHaveBeenCalled();
  });

  // OPS-04: end-to-end regression lock for the Date-serialization bug (see
  // src/api/routes/consent.js's OPS-04 fix comments). create()/suspend()
  // themselves never constructed the Date — the route did — but this proves
  // the full write path (INSERT, record_hash UPDATE, _appendAudit's
  // stableStringify-checksummed audit row) genuinely completes without
  // throwing when handed the post-fix shape: a plain ISO-UTC string.
  test('AUDIT-LOCK-01 create() with a string expires_at appends a valid audit entry without throwing', async () => {
    const txQuery = jest.fn()
      .mockResolvedValueOnce({ rows: [{ id: 'rec-1', actor_id: 'agent', action: 'local', state: 'ACTIVE' }] }) // INSERT consent_records RETURNING *
      .mockResolvedValueOnce({ rows: [] }) // UPDATE ... SET record_hash
      .mockResolvedValueOnce({ rows: [] }); // INSERT consent_audit_log
    pool.withTransaction.mockImplementation(async (fn) => fn({ query: txQuery }));

    await expect(store.create({
      actor_id: 'agent', action: 'local', granted_by: 'admin',
      expires_at: '2027-01-01T00:00:00.000Z',
    })).resolves.toMatchObject({ id: 'rec-1' });

    expect(txQuery).toHaveBeenCalledTimes(3);
    expect(txQuery.mock.calls[2][0]).toMatch(/INSERT INTO consent_audit_log/);
  });

  test('AUDIT-LOCK-02 suspend() with a string suspended_until appends a valid audit entry without throwing', async () => {
    const existing = { id: 'rec-1', actor_id: 'agent', action: 'local', state: 'ACTIVE' };
    const txQuery = jest.fn()
      .mockResolvedValueOnce({ rows: [existing] }) // SELECT ... FOR UPDATE
      .mockResolvedValueOnce({ rows: [{ ...existing, state: 'SUSPENDED' }] }) // UPDATE ... RETURNING *
      .mockResolvedValueOnce({ rows: [] }); // INSERT consent_audit_log
    pool.withTransaction.mockImplementation(async (fn) => fn({ query: txQuery }));

    await expect(store.suspend({
      id: 'rec-1', suspended_by: 'admin',
      suspended_until: '2027-01-01T00:00:00.000Z',
    })).resolves.toMatchObject({ state: 'SUSPENDED' });

    expect(txQuery).toHaveBeenCalledTimes(3);
    expect(txQuery.mock.calls[2][0]).toMatch(/INSERT INTO consent_audit_log/);
  });
});
