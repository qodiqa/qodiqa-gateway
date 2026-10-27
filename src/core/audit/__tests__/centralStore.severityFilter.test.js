'use strict';

/**
 * regression — centralStore.ingest() must drop severities the
 * platform_audit_events CHECK constraint cannot accept, before any database
 * work.
 *
 * logger.js:180 forwards EVERY emit() here fire-and-forget, DEBUG included, and
 * migration 003's platform_audit_events_severity_chk admits only five levels.
 * Every DEBUG event therefore cost a PostgreSQL round-trip on an INSERT that
 * failed with SQLSTATE 23514 — and there is exactly one DEBUG emit site in the
 * non-test codebase, ConsentVerifier.js's CONSENT_CACHE_HIT, which sits on the
 * hottest path in the system.
 *
 * These assertions pin the DROP, not merely the absence of a crash: the failing
 * inserts were already being swallowed by ingest()'s own catch, so "no error"
 * was true before the fix too. What changed is that no query is issued at all.
 */

const path = require('path');

const POOL_PATH = path.resolve(__dirname, '..', '..', '..', 'infra', 'postgres', 'pool');
const STORE_PATH = path.resolve(__dirname, '..', 'centralStore.js');

describe('centralStore.ingest() — severity filter', () => {
  let store, pool;

  beforeEach(() => {
    jest.resetModules();
    jest.doMock(POOL_PATH, () => ({
      isEnabled: jest.fn(() => true),
      query: jest.fn(async () => ({ rows: [], rowCount: 0 })),
    }));
    pool = require(POOL_PATH);
    store = require(STORE_PATH);
  });

  afterEach(() => {
    jest.dontMock(POOL_PATH);
    jest.resetModules();
  });

  it('issues no query at all for a DEBUG event', async () => {
    await store.ingest('DEBUG', 'CONSENT_CACHE_HIT', {
      actorId: 'a', action: 'openai', tenantId: 't',
    });
    await store.flush(); // (step 5): rows are written by the batched flush
    expect(pool.query).not.toHaveBeenCalled();
  });

  it.each(['FATAL', 'CRITICAL', 'ERROR', 'WARN', 'INFO'])(
    'still ingests %s — the five severities the CHECK constraint admits',
    async (level) => {
      await store.ingest(level, 'SOME_EVENT', { requestId: 'r1' });
      await store.flush(); // (step 5): rows are written by the batched flush
      expect(pool.query).toHaveBeenCalledTimes(1);
      // The severity actually bound to the INSERT must be the level passed in,
      // not a coerced or defaulted one.
      const params = pool.query.mock.calls[0][1];
      expect(params).toContain(level);
    },
  );

  it('drops any severity outside the constraint, not just DEBUG', async () => {
    // TRACE/VERBOSE do not exist in this codebase today, but the filter is a
    // set-membership test rather than a DEBUG special-case, so a future level
    // added to logger.js cannot silently reintroduce failing inserts.
    for (const level of ['TRACE', 'VERBOSE', 'debug', '', null, undefined]) {
      await store.ingest(level, 'SOME_EVENT', {});
      await store.flush(); // (step 5): rows are written by the batched flush
    }
    expect(pool.query).not.toHaveBeenCalled();
  });

  it('exports the exact severity set the write path uses', () => {
    // Asserting against the store's own exported constant rather than a literal
    // copy keeps this test from drifting away from the code it guards.
    expect([...store.INGESTIBLE_SEVERITIES].sort())
      .toEqual(['CRITICAL', 'ERROR', 'FATAL', 'INFO', 'WARN']);
    expect(store.INGESTIBLE_SEVERITIES.has('DEBUG')).toBe(false);
  });

  it('drops DEBUG before the pgPool.isEnabled() short-circuit is the only guard', async () => {
    // Ordering check: with PG enabled (mocked true above) the DEBUG path must
    // still issue nothing — i.e. the filter is a real guard, not something that
    // only appears to work because PG happened to be disabled.
    expect(pool.isEnabled()).toBe(true);
    await store.ingest('DEBUG', 'CONSENT_CACHE_HIT', {});
    await store.flush(); // (step 5): rows are written by the batched flush
    expect(pool.query).not.toHaveBeenCalled();
  });
});
