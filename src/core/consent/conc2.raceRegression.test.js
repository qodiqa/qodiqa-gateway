'use strict';

/**
 * deterministic proof that the READ-side replica-lag race is real
 * and is fixed, run against the actual production call chain
 * (ConsentRegistry.revoke() + ConsentVerifier.verify()), through the real,
 * unmodified src/infra/redis/managedClient.js — only the `redis` package's
 * createSentinel() is faked, so the routing decision under test
 * (replicaPoolSize / forceMasterReads) exercises the REAL production code
 * path, not a reconstruction of it.
 *
 * The race: closed the WRITE-side race (a stale set() from an
 * in-flight DB read can never resurrect an ALLOW once a newer tombstone
 * exists — see consent3.raceRegression.test.js). That fix adds zero
 * protection on the READ side. In a Sentinel deployment with
 * REDIS_SENTINEL_USE_REPLICAS=true, plain GET is a Redis-classified
 * read-only command and node-redis transparently routes it to a replica,
 * round-robin (see managedClient.js's module header and
 * @redis/client/dist/lib/sentinel/index.js's `_execute(isReadonly, fn)`).
 * revoke()'s tombstone write (EVAL — not read-only) always lands on master;
 * master-to-replica replication is asynchronous and unbounded, so a
 * verify() call immediately after a *fully completed* revoke() can still be
 * served by a replica that hasn't replicated the tombstone yet —
 * resurrecting the pre-revocation ALLOW with a full, unexpired TTL, even
 * though the caller who ran revoke() already awaited it to completion.
 *
 * Determinism strategy: no real Redis, no timers, no probabilistic
 * reproduction. A fake Sentinel-mode Redis backend keeps two separate
 * in-memory stores (master/replica); a write lands on master immediately and
 * is only copied to the replica when the test explicitly calls
 * `replicateNow()`. The tests below never call it after a revoke — "the
 * replica has not caught up yet" is a fact under direct test control, not a
 * race against the clock. Every command's master-vs-replica routing mirrors
 * the real @redis/client decision (`command.IS_READ_ONLY` combined with
 * `replicaPoolSize > 0`, confirmed against the installed `redis` package's
 * own command definitions before writing this fake), so the only thing that
 * can make the "fixed" tests pass is whether `forceMasterReads` actually
 * reaches `createSentinel()` as `replicaPoolSize: 0` — i.e. the real fix in
 * managedClient.js + ConsentCache.js, not an artifact of this harness.
 *
 * Same harness, same fake Sentinel backend, same "replication never
 * happens" — the ONLY variable swapped between test cases is which
 * ConsentCache implementation ConsentVerifier/ConsentRegistry are wired to:
 *   - ConsentCache.preCONC2.snapshot.js — the verbatim pre-fix file (never
 *     passes forceMasterReads to createManagedRedisClient()).
 *   - ConsentCache.js — the real, current, fixed file.
 */

async function waitUntil(conditionFn, { timeoutMs = 2000 } = {}) {
  const start = Date.now();
  while (!conditionFn()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error('waitUntil: condition never became true');
    }
    await new Promise((r) => setImmediate(r));
  }
}

// ── Fake Sentinel-mode Redis backend ─────────────────────────────────────────
//
// Reproduces exactly the piece of @redis/client's real routing logic this
// fix depends on: a command classified read-only is served by the replica
// pool when replicaPoolSize > 0, and by master otherwise (see
// sentinel/index.js's `_execute`). GET is read-only; EVAL/SET/DEL are not
// (verified directly against the installed `redis` package's command
// definitions — GET.IS_READ_ONLY===true, EVAL.IS_READ_ONLY===false,
// DEL.IS_READ_ONLY===false — before writing this fake). Master and replica
// are separate Maps; every write lands on master immediately and is queued
// for replica application — the replica only "catches up" when the test
// calls `replicateNow()`.
function makeFakeSentinelBackend() {
  const master  = new Map();
  const replica = new Map();
  let pending = [];

  function replicateNow() {
    for (const apply of pending) apply();
    pending = [];
  }

  function writeThrough(mutate) {
    mutate(master);
    pending.push(() => mutate(replica));
  }

  function liveGet(store, key) {
    const entry = store.get(key);
    if (!entry) return null;
    if (entry.expiresAt !== null && entry.expiresAt <= Date.now()) { store.delete(key); return null; }
    return entry.value;
  }

  // Called once per createManagedRedisClient() -> createSentinel()
  // invocation, with the REAL options managedClient.js computed — including
  // replicaPoolSize, which is exactly what forceMasterReads controls.
  function build(options) {
    const useReplicas = (options.replicaPoolSize ?? 0) > 0;
    const readStore   = useReplicas ? replica : master;

    return {
      isOpen:  true,
      isReady: true,
      connect:    jest.fn(async function () { return this; }),
      disconnect: jest.fn().mockResolvedValue(undefined),
      on: jest.fn(),
      getMasterNode:   jest.fn(() => ({ host: 'master1', port: 6379 })),
      getReplicaNodes: jest.fn(() => new Map()),

      get: jest.fn(async (key) => liveGet(readStore, key)),

      set: jest.fn(async (key, value, opts) => {
        const ttlMs = opts?.EX ? opts.EX * 1000 : null;
        writeThrough((store) => store.set(key, { value, expiresAt: ttlMs ? Date.now() + ttlMs : null }));
        return 'OK';
      }),

      del: jest.fn(async (key) => {
        writeThrough((store) => store.delete(key));
        return 1;
      }),

      // Faithful reimplementation of production's _CAS_SCRIPT
      // (ConsentCache.js). EVAL is not a read-only command, so — exactly
      // like real Redis Lua scripting — it always checks and lands on
      // master, regardless of replicaPoolSize.
      eval: jest.fn(async (_script, { keys, arguments: args }) => {
        const [key] = keys;
        const [payload, versionStr, ttlStr] = args;
        const newVersion = Number(versionStr);
        const current = liveGet(master, key);
        if (current) {
          const decoded = JSON.parse(current);
          if (decoded.version !== undefined && decoded.version !== null && Number(decoded.version) > newVersion) {
            return 0;
          }
        }
        writeThrough((store) => store.set(key, { value: payload, expiresAt: Date.now() + Number(ttlStr) * 1000 }));
        return 1;
      }),

      scan: jest.fn().mockResolvedValue({ cursor: 0, keys: [] }),
    };
  }

  return { build, replicateNow, master, replica };
}

const ORIGINAL_ENV = { ...process.env };
afterAll(() => { process.env = ORIGINAL_ENV; });

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
  version:         1,
});

function makeRevokedReturn(overrides = {}) {
  return {
    ...STALE_RECORD,
    ...overrides,
    state:             'REVOKED',
    revoked_at:        new Date(),
    revoked_by:        'admin',
    revocation_reason: 'TEST',
    version:           overrides.version ?? 2,
  };
}

/**
 * Wires real ConsentVerifier + ConsentRegistry to `cacheSpecifier` against a
 * fake Sentinel-mode Redis (REDIS_MODE=sentinel,
 * REDIS_SENTINEL_USE_REPLICAS=true), through the real, unmodified
 * managedClient.js. Everything else (DB store, pool, pub/sub) is mocked to
 * isolate cache read-routing as the only thing under test — same isolation
 * strategy as consent3.raceRegression.test.js.
 *
 * `cacheSpecifier` of `null` means "use the real, current ConsentCache".
 * jest.doMock('./ConsentCache', ...) is ALWAYS called, for the same two
 * reasons documented in consent3.raceRegression.test.js: a factory that
 * itself requires './ConsentCache' would recurse into its own mock, and
 * jest.doMock registrations are not cleared by jest.resetModules() — the
 * "real" branch must re-register on every call or a stale OLD-snapshot
 * registration from an earlier test would silently persist.
 */
function setup(cacheSpecifier) {
  jest.resetModules();

  process.env.REDIS_MODE                 = 'sentinel';
  process.env.REDIS_SENTINEL_HOSTS       = 'sentinel1:26379';
  process.env.REDIS_SENTINEL_MASTER_NAME = 'mymaster';
  process.env.REDIS_SENTINEL_USE_REPLICAS = 'true';

  const backend = makeFakeSentinelBackend();
  const createSentinel = jest.fn((options) => backend.build(options));

  jest.doMock('redis', () => ({
    createClient:  jest.fn(),
    createSentinel,
    createCluster: jest.fn(),
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
  // Subscriber "not yet started" bypasses the separate, already-correct
  // fail-closed gate so this test isolates the cache read-routing race.
  jest.doMock('./revocation/RevocationSubscriber', () => ({
    isStarted: jest.fn(() => false), isReady: jest.fn(() => false), start: jest.fn(), stop: jest.fn(),
  }));

  jest.doMock('./ConsentCache', () => (
    cacheSpecifier ? require(cacheSpecifier) : jest.requireActual('./ConsentCache')
  ));

  const ConsentVerifier = require('./ConsentVerifier');
  const ConsentRegistry = require('./ConsentRegistry');
  const cache           = require('./ConsentCache');

  return { ConsentVerifier, ConsentRegistry, cache, mockStore, backend, createSentinel };
}

/**
 * Common scenario: a prior successful verify() cached ACTIVE (already fully
 * replicated — normal steady state), then a revoke() runs to FULL
 * completion (DB commit + CAS-guarded tombstone write, fully awaited), and
 * ONLY THEN does an independent verify() call run. replicateNow() is
 * deliberately never called again after the baseline — the replica is left
 * permanently stale for the rest of the scenario.
 */
async function runPostRevokeVerify(deps, { keyActor = 'agent', keyAction = 'run', recordId = 'rec-1' } = {}) {
  const { ConsentVerifier, ConsentRegistry, cache, mockStore, backend } = deps;

  await cache.get('__warmup__', '__warmup__', null);
  await waitUntil(() => cache.isReady());

  await cache.set(keyActor, keyAction, null, {
    pass: true, reason: 'CONSENT_VERIFIED', consentId: recordId, state: 'ACTIVE', cached: true,
  }, 1);
  backend.replicateNow();

  mockStore.revoke.mockResolvedValue(makeRevokedReturn({ id: recordId, actor_id: keyActor, action: keyAction }));
  mockStore.findByKey.mockResolvedValue(makeRevokedReturn({ id: recordId, actor_id: keyActor, action: keyAction }));

  await ConsentRegistry.revoke({ id: recordId, revoked_by: 'admin' });

  return ConsentVerifier.verify({ actor_id: keyActor, action: keyAction });
}

describe('deterministic replica-lag race regression', () => {
  test('OLD ConsentCache (pre-fix): a revocation fully completed on master is invisible to a GET served from a lagging replica', async () => {
    const deps = setup('./ConsentCache.preCONC2.snapshot');
    const result = await runPostRevokeVerify(deps);

    // THE BUG, confirmed: revoke() fully resolved (DB committed, CAS tombstone
    // written and awaited) before verify() ran — yet verify()'s GET was
    // routed to a replica that never received that tombstone, so it served
    // the stale, pre-revocation cached ALLOW as if nothing had happened. The
    // DB was never even consulted.
    expect(result.pass).toBe(true);
    expect(result.state).toBe('ACTIVE');
    expect(deps.mockStore.findByKey).not.toHaveBeenCalled();
  });

  test('NEW ConsentCache (fixed): the identical scenario, with replication never triggered, is never observed as stale', async () => {
    const deps = setup(null);
    const result = await runPostRevokeVerify(deps);

    // THE FIX, confirmed: forceMasterReads makes the GET target master
    // unconditionally — it sees the tombstone (a guaranteed miss), falls
    // through to the DB, and correctly reflects the revocation. This holds
    // with the replica left PERMANENTLY stale — the result never depended
    // on replication catching up, only on where the read was routed.
    expect(result.pass).toBe(false);
    expect(result.reason).toBe('CONSENT_REVOKED');
    expect(deps.mockStore.findByKey).toHaveBeenCalledTimes(1);
  });

  test('Requirement 1/2 — revocation followed immediately by concurrent authorization requests cannot return stale authorization', async () => {
    const deps = setup(null);
    const { ConsentVerifier, ConsentRegistry, cache, mockStore, backend } = deps;

    await cache.get('__warmup__', '__warmup__', null);
    await waitUntil(() => cache.isReady());
    await cache.set('agent', 'run', null, { pass: true, reason: 'CONSENT_VERIFIED', consentId: 'rec-1', state: 'ACTIVE', cached: true }, 1);
    backend.replicateNow();

    mockStore.revoke.mockResolvedValue(makeRevokedReturn());
    mockStore.findByKey.mockResolvedValue(makeRevokedReturn());

    await ConsentRegistry.revoke({ id: 'rec-1', revoked_by: 'admin' });

    // Every verify() call is dispatched before any of them is awaited —
    // genuine concurrent overlap, not N sequential round-trips — and the
    // replica is never allowed to catch up during this window.
    const N = 25;
    const results = await Promise.all(
      Array.from({ length: N }, () => ConsentVerifier.verify({ actor_id: 'agent', action: 'run' })),
    );

    expect(results).toHaveLength(N);
    for (const r of results) {
      expect(r.pass).toBe(false);
      expect(r.reason).toBe('CONSENT_REVOKED');
    }
  });

  test('Requirement 3 — multiple simultaneous revocations remain deterministic: concurrently revoking two independent keys never cross-contaminates cached state', async () => {
    const deps = setup(null);
    const { ConsentVerifier, ConsentRegistry, cache, mockStore, backend } = deps;

    await cache.get('__warmup__', '__warmup__', null);
    await waitUntil(() => cache.isReady());

    await cache.set('agent-a', 'run', null, { pass: true, reason: 'CONSENT_VERIFIED', consentId: 'rec-a', state: 'ACTIVE', cached: true }, 1);
    await cache.set('agent-b', 'run', null, { pass: true, reason: 'CONSENT_VERIFIED', consentId: 'rec-b', state: 'ACTIVE', cached: true }, 1);
    backend.replicateNow();

    mockStore.revoke.mockImplementation(async ({ id }) => (
      id === 'rec-a'
        ? makeRevokedReturn({ id: 'rec-a', actor_id: 'agent-a', action: 'run' })
        : makeRevokedReturn({ id: 'rec-b', actor_id: 'agent-b', action: 'run' })
    ));
    mockStore.findByKey.mockImplementation(async (actor_id) => (
      actor_id === 'agent-a'
        ? makeRevokedReturn({ id: 'rec-a', actor_id: 'agent-a', action: 'run' })
        : makeRevokedReturn({ id: 'rec-b', actor_id: 'agent-b', action: 'run' })
    ));

    // Both revocations run concurrently, not sequentially.
    await Promise.all([
      ConsentRegistry.revoke({ id: 'rec-a', revoked_by: 'admin' }),
      ConsentRegistry.revoke({ id: 'rec-b', revoked_by: 'admin' }),
    ]);

    const [resultA, resultB] = await Promise.all([
      ConsentVerifier.verify({ actor_id: 'agent-a', action: 'run' }),
      ConsentVerifier.verify({ actor_id: 'agent-b', action: 'run' }),
    ]);
    expect(resultA.pass).toBe(false);
    expect(resultA.reason).toBe('CONSENT_REVOKED');
    expect(resultB.pass).toBe(false);
    expect(resultB.reason).toBe('CONSENT_REVOKED');

    // Determinism, not "usually correct": re-running observes the same
    // outcome, not a coin flip.
    const rerun = await Promise.all([
      ConsentVerifier.verify({ actor_id: 'agent-a', action: 'run' }),
      ConsentVerifier.verify({ actor_id: 'agent-b', action: 'run' }),
    ]);
    expect(rerun[0].pass).toBe(false);
    expect(rerun[1].pass).toBe(false);
  });

  test('Requirement 5 — existing consent behavior is unchanged for non-concurrent scenarios (no revoke involved)', async () => {
    const deps = setup(null);
    const { ConsentVerifier, cache, mockStore } = deps;

    await cache.get('__warmup__', '__warmup__', null);
    await waitUntil(() => cache.isReady());

    // Plain cache miss -> DB ACTIVE -> ALLOW -> cached. No revoke anywhere
    // in this test — proves forceMasterReads doesn't change ordinary
    // (non-racing) behavior: master is a perfectly normal read target when
    // there is no replica involved in the decision at all.
    mockStore.findByKey.mockResolvedValueOnce({ ...STALE_RECORD, version: 1 });
    const first = await ConsentVerifier.verify({ actor_id: 'agent', action: 'run' });
    expect(first.pass).toBe(true);
    expect(first.state).toBe('ACTIVE');

    const second = await ConsentVerifier.verify({ actor_id: 'agent', action: 'run' });
    expect(second.pass).toBe(true);
    expect(second.cached).toBe(true);
    expect(mockStore.findByKey).toHaveBeenCalledTimes(1); // second call was a cache hit
  });

  test('NEW ConsentCache: a follow-up request after the race correctly sees the revocation (end-to-end self-heal)', async () => {
    const deps = setup(null);
    await runPostRevokeVerify(deps);

    deps.mockStore.findByKey.mockResolvedValue(makeRevokedReturn());
    const followUp = await deps.ConsentVerifier.verify({ actor_id: 'agent', action: 'run' });

    expect(followUp.pass).toBe(false);
    expect(followUp.reason).toBe('CONSENT_REVOKED');
  });
});
