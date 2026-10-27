'use strict';

/**
 * deterministic proof that the reader/writer race is real and is
 * fixed, run against the actual production call chain (ConsentVerifier +
 * ConsentRegistry), not a reconstruction of it.
 *
 * The race: a verify() call suffers a cache miss and reads the DB while a
 * concurrent revoke() commits and invalidates. Awaiting the invalidate() call
 * (which the code already did, before and) does not help,
 * because the DB read is sandwiched between the revoke's invalidate() and the
 * reader's own late cache.set() — two independent client-side Redis calls
 * with no ordering relationship to each other.
 *
 * Determinism strategy: instead of real timers/sleeps (which only produce a
 * *probabilistic* reproduction, and would make this test flaky), the DB read
 * is held open with a manually-resolved ("deferred") promise. The test
 * explicitly drives the exact interleaving — read starts, full revoke()
 * completes, THEN the stale read resolves — so the race is reproduced on
 * every run, not just "usually." A bounded `waitUntil` poll (via
 * `setImmediate`, not `setTimeout`+delay) confirms the read has genuinely
 * reached the DB call before the "concurrent" revoke proceeds, without
 * hardcoding a fragile microtask-hop count that would break if an unrelated
 * internal `await` were added or removed.
 *
 * Same harness, same fake Redis, same interleaving — the ONLY variable
 * swapped between the two describe blocks below is which ConsentCache
 * implementation ConsentVerifier/ConsentRegistry are wired to:
 *   - ConsentCache.preCONSENT3.snapshot.js — the verbatim pre-fix file
 *     (see that file's header for provenance).
 *   - ConsentCache.js — the real, current, fixed file.
 * That isolation is what makes this a proof the CODE CHANGE is what closes
 * the race, not an artifact of the test harness itself.
 */

function makeDeferred() {
  let resolve;
  const promise = new Promise((res) => { resolve = res; });
  return { promise, resolve };
}

async function waitUntil(conditionFn, { timeoutMs = 2000 } = {}) {
  const start = Date.now();
  while (!conditionFn()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error('waitUntil: condition never became true');
    }
    await new Promise((r) => setImmediate(r));
  }
}

// Backs the mocked `redis` package with a real in-memory GET/SET/DEL/EVAL
// store, so both the old (no-EVAL) and new (CAS-via-EVAL) ConsentCache
// exercise genuine cache semantics rather than jest.fn() stubs that only
// record calls. EVAL implements the exact same algorithm as production's
// _CAS_SCRIPT so the "new" scenario is a faithful, not simulated, run.
function makeFakeRedis() {
  const store = new Map();

  function liveGet(key) {
    const entry = store.get(key);
    if (!entry) return null;
    if (entry.expiresAt !== null && entry.expiresAt <= Date.now()) { store.delete(key); return null; }
    return entry.value;
  }

  return {
    get: jest.fn(async (key) => liveGet(key)),
    set: jest.fn(async (key, value, opts) => {
      const ttlMs = opts?.EX ? opts.EX * 1000 : null;
      store.set(key, { value, expiresAt: ttlMs ? Date.now() + ttlMs : null });
      return 'OK';
    }),
    del: jest.fn(async (key) => { const had = store.has(key); store.delete(key); return had ? 1 : 0; }),
    eval: jest.fn(async (_script, { keys, arguments: args }) => {
      const [key] = keys;
      const [payload, versionStr, ttlStr] = args;
      const newVersion = Number(versionStr);
      const current = liveGet(key);
      if (current) {
        const decoded = JSON.parse(current);
        if (decoded.version !== undefined && decoded.version !== null && Number(decoded.version) > newVersion) {
          return 0;
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
  };
}

const STALE_RECORD = Object.freeze({
  id:              'rec-1',
  actor_id:        'agent',
  action:          'run',
  tenant_id:       null,
  state:           'ACTIVE',
  scope:           null,
  required_scope:  null,
  granted_at:      new Date('2026-01-01T00:00:00Z'),
  granted_by:      'admin',
  expires_at:      null,
  suspended_until: null,
  version:         1, // the version the in-flight read captured, BEFORE the revoke
});

function makeRevokedReturn() {
  return { ...STALE_RECORD, state: 'REVOKED', revoked_at: new Date(), revoked_by: 'admin', revocation_reason: 'TEST', version: 2 };
}

/**
 * Sets up real ConsentVerifier + ConsentRegistry wired to `cacheSpecifier`
 * (a module specifier resolved relative to THIS test file — same directory
 * as both target modules, so the resolution is identical either way).
 * Everything else (DB store, pool, pub/sub) is mocked to isolate the cache
 * layer as the only thing under test.
 *
 * `cacheSpecifier` of `null` means "use the real, current ConsentCache".
 * This ALWAYS calls `jest.doMock('./ConsentCache', ...)`, in both branches —
 * two things make that necessary, not optional:
 *   1. A factory whose own body calls `require('./ConsentCache')` recurses
 *      into the mock currently being constructed and blows the call stack,
 *      so the "real" branch must use `jest.requireActual` instead, which
 *      deliberately bypasses the mock registry.
 *   2. `jest.doMock(...)` registrations are NOT cleared by
 *      `jest.resetModules()` — they persist for the rest of the test file.
 *      Skipping the call on the "real" branch after an earlier test already
 *      registered the OLD-snapshot mock for `'./ConsentCache'` would leave
 *      that stale registration active, silently making the "fixed" test
 *      exercise the pre-fix code too. This bit exactly this test during
 *      development — see the explicit override here as the fix.
 */
function setup(cacheSpecifier) {
  jest.resetModules();

  const fakeRedis = makeFakeRedis();
  jest.doMock('redis', () => ({ createClient: jest.fn(() => fakeRedis) }));
  jest.doMock('../../infra/redis/clientConfig', () => ({
    buildClientOptions: jest.fn(() => ({})),
    isAuthError:        jest.fn(() => false),
    isTlsError:         jest.fn(() => false),
  }));
  jest.doMock('../../../services/logger', () => ({ emit: jest.fn() }));
  jest.doMock('../../infra/postgres/pool', () => ({
    isEnabled: jest.fn(() => true),
    isHealthy: jest.fn(() => true),
  }));

  const mockStore = {
    findByKey:       jest.fn(),
    revoke:          jest.fn(),
    logVerification: jest.fn().mockResolvedValue(undefined),
  };
  jest.doMock('./ConsentStore', () => mockStore);
  jest.doMock('./revocation/RevocationPublisher', () => ({
    publish: jest.fn().mockResolvedValue(true), isReady: jest.fn(() => true), disconnect: jest.fn(),
  }));
  // Subscriber "not yet started" bypasses the (separate, already-correct)
  // fail-closed gate so this test isolates the cache-write race specifically.
  jest.doMock('./revocation/RevocationSubscriber', () => ({
    isStarted: jest.fn(() => false), isReady: jest.fn(() => false), start: jest.fn(), stop: jest.fn(),
  }));

  jest.doMock('./ConsentCache', () => (
    cacheSpecifier ? require(cacheSpecifier) : jest.requireActual('./ConsentCache')
  ));

  const ConsentVerifier = require('./ConsentVerifier');
  const ConsentRegistry = require('./ConsentRegistry');
  const cache           = require('./ConsentCache');

  return { ConsentVerifier, ConsentRegistry, cache, mockStore };
}

/**
 * Runs the deterministic race and returns what ended up cached afterward.
 * Shared by both scenarios below — the only difference between calls is
 * which `deps` (old vs. new ConsentCache) were constructed by setup().
 */
async function runRace(deps) {
  const { ConsentVerifier, ConsentRegistry, cache, mockStore } = deps;

  // Warm up the (fake) Redis connection before the timed race starts. The
  // managed Redis client connects asynchronously in the background on its
  // first use; without this, the race's own first cache operation could
  // itself race the client's OWN internal "not ready yet" bootstrap window
  // and silently no-op — a test-harness artifact, not the thing under test.
  // Production servers connect to Redis at startup, long before traffic
  // arrives, so forcing "already connected" here before the interleaving
  // begins matches reality rather than cheating the test.
  await cache.get('__warmup__', '__warmup__', null);
  await waitUntil(() => cache.isReady());

  const deferred = makeDeferred();
  mockStore.findByKey.mockReturnValue(deferred.promise);
  mockStore.revoke.mockResolvedValue(makeRevokedReturn());

  // t0: an incoming request suffers a cache miss and starts reading the DB.
  const verifyPromise = ConsentVerifier.verify({ actor_id: 'agent', action: 'run' });

  // Deterministically wait until that read has genuinely reached the DB
  // call (not a fixed sleep — a bounded poll on an observable fact).
  await waitUntil(() => mockStore.findByKey.mock.calls.length > 0);

  // t1: "concurrently" — a full, completed revoke() runs to completion
  // while the read from t0 is still pending. This is the realistic
  // interleaving describes: the writer finishes first.
  await ConsentRegistry.revoke({ id: 'rec-1', revoked_by: 'admin' });

  // t2: the stale read from t0 finally resolves with the pre-revocation
  // ACTIVE record it captured before the revoke happened.
  deferred.resolve(STALE_RECORD);
  const verifyResult = await verifyPromise;

  // The in-flight request itself correctly reflects the data it read at
  // t0 — that part is expected and is not the bug being tested.
  expect(verifyResult.pass).toBe(true);

  // The bug is whether the LATE write behind that request poisoned the
  // cache for every SUBSEQUENT, independent request.
  return cache.get('agent', 'run', null);
}

describe('deterministic race regression', () => {
  test('OLD ConsentCache (pre-fix): concurrent revoke racing a slow DB read resurrects a stale cached ALLOW', async () => {
    const deps = setup('./ConsentCache.preCONSENT3.snapshot');
    const cachedAfterRace = await runRace(deps);

    // THE BUG, confirmed: despite the revoke() having fully completed (DB
    // committed, invalidate() awaited) before the stale read resolved, the
    // cache now holds a positive ALLOW for a consent that is REVOKED in the
    // DB. Every request for the next TTL_POSITIVE_S (60s default) would be
    // wrongly authorized.
    expect(cachedAfterRace).not.toBeNull();
    expect(cachedAfterRace.pass).toBe(true);
    expect(cachedAfterRace.state).toBe('ACTIVE');
  });

  test('NEW ConsentCache (fixed): the identical interleaving never resurrects a stale ALLOW', async () => {
    const deps = setup(null);
    const cachedAfterRace = await runRace(deps);

    // THE FIX, confirmed: the exact same interleaving — same DB mock, same
    // fake Redis, same deferred-promise control — now leaves the cache in a
    // safe miss state. The next request is forced back to the DB, which
    // will correctly return REVOKED. No window, however small, exists where
    // a stale ALLOW is observable from the cache.
    expect(cachedAfterRace).toBeNull();
  });

  test('NEW ConsentCache: a follow-up request after the race correctly sees the revocation (end-to-end self-heal)', async () => {
    const deps = setup(null);
    const { ConsentVerifier, mockStore } = deps;

    await runRace(deps);

    // A brand new incoming request, after the race: cache is a guaranteed
    // miss (proven above), so this must fall through to the DB — which by
    // now reflects the revocation.
    mockStore.findByKey.mockReturnValue(Promise.resolve(makeRevokedReturn()));
    const secondResult = await ConsentVerifier.verify({ actor_id: 'agent', action: 'run' });

    expect(secondResult.pass).toBe(false);
    expect(secondResult.reason).toBe('CONSENT_REVOKED');
  });
});
