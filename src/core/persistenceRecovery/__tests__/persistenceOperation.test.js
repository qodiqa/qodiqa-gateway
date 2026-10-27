'use strict';

/**
 * isPersistenceFailure() classification — Component #13
 *
 * pool.js's circuit breaker throws a synthetic error (code
 * 'PG_CIRCUIT_OPEN') when it fast-fails without ever contacting PostgreSQL.
 * That code matched none of isPersistenceFailure()'s classification rules —
 * not a real PG SQLSTATE, not a Node network code, not any of the message
 * heuristics — so it fell through to `return false`, meaning
 * pg-audit-backend.js's persistEntry() treated a textbook-transient
 * condition (the breaker is deliberately pausing, will self-clear) exactly
 * like a permanent data/logic error and never enqueued it for retry. The
 * write was silently and permanently dropped from the PostgreSQL mirror.
 *
 * POC-01…03  PG_CIRCUIT_OPEN is now classified retryable
 * POC-04…07  Pre-existing classification is unchanged (no regression)
 *
 * pool.js's real, non-synthetic
 * pool-exhaustion error — pg-pool's own 'timeout exceeded when trying to
 * connect' (no .code at all, thrown before Postgres ever parses anything) —
 * matched none of the message heuristics above either, so the identical
 * silent-drop consequence PG_CIRCUIT_OPEN caused for recurred through a
 * genuinely different, real trigger's own fix never touched. Root cause:
 * two independently-maintained message lists (this file's, and
 * pgCircuitBreaker.js's own) that happened to disagree on this exact string.
 * Fixed by converging both onto one canonical, exported
 * CODELESS_CONNECTION_MESSAGES set (this file, Core) that
 * pgCircuitBreaker.js (Infrastructure) now imports instead of duplicating.
 *
 * POC-08…11  Every message in CODELESS_CONNECTION_MESSAGES is retryable
 * POC-12     The set contains exactly the four known-transient messages
 * POC-13     A genuine codeless caller/data-bug message is still NOT
 *            retryable — the counter-example found during this remediation's
 *            own diagnosis pass (node_modules/pg/lib/utils.js's circular-
 *            reference error) that ruled out a blanket "codeless == retryable"
 *            policy.
 */

const {
  isPersistenceFailure,
  RETRYABLE_SYNTHETIC_CODES,
  CODELESS_CONNECTION_MESSAGES,
} = require('../persistenceOperation');

describe('isPersistenceFailure — Layer 1: PG_CIRCUIT_OPEN classification', () => {
  test('POC-01: an error with code PG_CIRCUIT_OPEN is classified retryable', () => {
    const err = Object.assign(
      new Error('PostgreSQL circuit breaker is OPEN — fast-failing without contacting the database'),
      { code: 'PG_CIRCUIT_OPEN' },
    );
    expect(isPersistenceFailure(err)).toBe(true);
  });

  // added AUDIT_MIRROR_PARENT_MISSING (a mirror row waiting for its
  // parent — pg-audit-backend.js insertMirrorRow). The set is still pinned
  // exactly, so any further addition must be deliberate.
  test('POC-02: RETRYABLE_SYNTHETIC_CODES contains exactly PG_CIRCUIT_OPEN and AUDIT_MIRROR_PARENT_MISSING', () => {
    expect([...RETRYABLE_SYNTHETIC_CODES].sort()).toEqual(['AUDIT_MIRROR_PARENT_MISSING', 'PG_CIRCUIT_OPEN']);
  });

  test('POC-02b: AUDIT_MIRROR_PARENT_MISSING is classified retryable', () => {
    expect(isPersistenceFailure(Object.assign(new Error('parent missing'), { code: 'AUDIT_MIRROR_PARENT_MISSING' }))).toBe(true);
  });

  test('POC-03: the classification is case-sensitive-safe — lowercase code still matches (code is uppercased internally)', () => {
    const err = Object.assign(new Error('circuit open'), { code: 'pg_circuit_open' });
    expect(isPersistenceFailure(err)).toBe(true);
  });
});

describe('isPersistenceFailure — pre-existing classification unchanged (no regression)', () => {
  test('POC-04: a real non-retryable PG error (23505 unique violation) is still not retryable', () => {
    const err = Object.assign(new Error('duplicate key value violates unique constraint'), { code: '23505' });
    expect(isPersistenceFailure(err)).toBe(false);
  });

  test('POC-05: a real retryable PG connection-class error (08006) is still retryable', () => {
    const err = Object.assign(new Error('connection failure'), { code: '08006' });
    expect(isPersistenceFailure(err)).toBe(true);
  });

  test('POC-06: a Node network-layer error (ECONNREFUSED) is still retryable', () => {
    const err = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
    expect(isPersistenceFailure(err)).toBe(true);
  });

  test('POC-07: an unrelated unknown code still falls through to non-retryable', () => {
    const err = Object.assign(new Error('something else entirely'), { code: 'SOME_OTHER_CODE' });
    expect(isPersistenceFailure(err)).toBe(false);
  });
});

describe('isPersistenceFailure — canonical codeless-connection-message set', () => {
  test('POC-08: pg-pool pool-exhaustion is classified retryable', () => {
    const err = new Error('timeout exceeded when trying to connect');
    expect(isPersistenceFailure(err)).toBe(true);
  });

  test('POC-09: pg-pool new-client-handshake timeout is classified retryable', () => {
    const err = new Error('Connection terminated due to connection timeout');
    expect(isPersistenceFailure(err)).toBe(true);
  });

  test('POC-10: a client already in a connection-error state is classified retryable', () => {
    const err = new Error('Client has encountered a connection error and is not queryable');
    expect(isPersistenceFailure(err)).toBe(true);
  });

  test('POC-11: a closed client rejecting further queries is classified retryable', () => {
    const err = new Error('Client was closed and is not queryable');
    expect(isPersistenceFailure(err)).toBe(true);
  });

  test('POC-12: CODELESS_CONNECTION_MESSAGES contains exactly the four known-transient messages', () => {
    expect(CODELESS_CONNECTION_MESSAGES.size).toBe(4);
    expect(CODELESS_CONNECTION_MESSAGES.has('timeout exceeded when trying to connect')).toBe(true);
    expect(CODELESS_CONNECTION_MESSAGES.has('Connection terminated due to connection timeout')).toBe(true);
    expect(CODELESS_CONNECTION_MESSAGES.has('Client has encountered a connection error and is not queryable')).toBe(true);
    expect(CODELESS_CONNECTION_MESSAGES.has('Client was closed and is not queryable')).toBe(true);
  });

  test('POC-13: a genuine codeless caller/data-bug message (pg\'s own circular-reference error) stays non-retryable — rules out a blanket "codeless == retryable" policy', () => {
    const err = new Error('circular reference detected while preparing "[object Object]" for query');
    expect(isPersistenceFailure(err)).toBe(false);
  });
});
