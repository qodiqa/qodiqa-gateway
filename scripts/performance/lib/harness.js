'use strict';

/**
 * shared performance-test harness.
 *
 * Builds a REAL, listening HTTP server mounting the actual
 * createAiChatRouter() — the same router factory server.js and
 * aiChat.test.js use — with the real crypto/signing, real (auto-discovered)
 * semantic engine, and the real non-semantic policy engine. The only
 * pluggable piece is the provider function, so the same harness can measure
 * "QODIQA's own overhead" (instant mock provider) or real end-to-end
 * latency including a real provider (see providerBenchmark.js).
 *
 * This is deliberately built the same way the project's own test suite
 * builds its router instances — not a new
 * architecture, just a lean host app for benchmarking purposes, using
 * REAL Redis-backed nonce/anomaly stores (not the in-memory test doubles)
 * so load numbers include real Redis round-trips.
 */

require('./setupEnv');

const express = require('express');
const crypto = require('crypto');

const createAiChatRouter = require('../../../src/api/routes/aiChat');
const attachClientIp = require('../../../middleware/clientIp');
const { signBoundArtifact } = require('../../../src/validation/signBoundArtifact');
const { getActiveKey } = require('../../../services/artifact/keyStore');
const { validateAndPrepare } = require('../../../services/policy/loader');
const rateLimitStoreModule = require('../../../services/policy/store');
const { createStore, createRedisStore, initialize: initRateLimitStore } = rateLimitStoreModule;
const nonceStore = require('../../../src/validation/nonceStore');
const anomalyStore = require('../../../src/validation/anomalyStore');
const consent = require('../../../src/core/consent');
const pgPool = require('../../../src/infra/postgres/pool');
const embeddingClassifier = require('../../../src/core/semantic/embeddingSimilarity');
const {
  resolveTestRedisUrl, createAdminClient, writeSentinel, guardedFlush, finalCleanup,
} = require('./redisTestDb');
const { tryRealConsent, provisionIdentityPool } = require('./identities');

const CHAT_PATH = '/ai/chat';
const DEFAULT_ACTION = 'perf-mock';
const DEFAULT_ACTOR_KEY = 'default';

/** Instant, allocation-light mock provider — isolates QODIQA's own overhead. */
function instantMockProvider() {
  return Promise.resolve({ output: 'ok', executionMetadata: { responseId: 'perf-mock' }, model: 'mock', tokenUsage: { total: 1 } });
}

/**
 * @param {object} opts
 * @param {Function} [opts.providerFn]   — defaults to instantMockProvider
 * @param {string}   [opts.action]       — artifact.payload.provider value (also the consent "action")
 * @param {boolean}  [opts.useRealStores]— use real Redis nonce/anomaly stores (default true; Redis was confirmed reachable)
 * @returns {Promise<{ app, server, url, KEY, buildArtifact, toHeader, close }>}
 */
async function buildHarness(opts = {}) {
  const providerFn = opts.providerFn || instantMockProvider;
  const action = opts.action || DEFAULT_ACTION;
  const useRealStores = opts.useRealStores !== false;

  // Item 24 amendment 1 — dedicated, disposable Redis DB (index 1). Must
  // happen before ANY store's first connect: nonceStore/anomalyStore/the
  // rate-limit policy store all resolve REDIS_URL lazily at first call, not
  // at require time (see redisTestDb.js for the confirmation this actually
  // propagates through buildClientOptions()). Gated on useRealStores since
  // the in-memory-only path (useRealStores:false, e.g. the cluster-mode
  // signer instance) never touches Redis at all.
  let redisAdmin = null;
  if (useRealStores) {
    resolveTestRedisUrl();
    redisAdmin = await createAdminClient();
    await writeSentinel(redisAdmin);
  }

  // Item 24 — real-consent bug fix: nothing in this harness ever called
  // pool.js's initialize() before this. Every consent.grant()/verify() call
  // (both this single-'default'-identity path and provisionIdentityPool()'s
  // pool path below) threw 'PG pool not initialized' immediately, was
  // silently caught by tryRealConsent(), and fell back to the stub — this
  // is why every historical consentMode reading from this harness (incl.
  // items 16/17's own 8 committed result files) showed stubbed-fast-path,
  // independent of setupEnv.js's PG-disable guard. Confirmed by direct
  // reproduction (uncaught throw, same stack) before this fix was written.
  // Safe to call unconditionally — pool.js's own initialize() already
  // no-ops with a WARN when QODIQA_PG_ENABLED !== 'true'.
  pgPool.initialize();

  // harness fix — mirrors server/startup.js's own boot-time embedding-
  // classifier warm-up (its "-1.25. Embedding-similarity classifier boot"
  // step, which blocks real server start until embeddingClassifier.init()
  // resolves READY). This harness never called init() at all: classify()
  // fails closed with EMBEDDING_CLASSIFIER_NOT_READY when called before
  // init() completes (documented in embeddingSimilarity/index.js's own
  // init() docstring — "classify() fails closed on its own if called
  // beforehand, but that is a safety net, not the intended call pattern"),
  // so every request through this harness was measuring the fail-closed
  // SEMANTIC_INSPECTION_UNAVAILABLE path, never real embedding/FT-2/FT-3
  // inference — regardless of QODIQA_SEM_FT3_ENABLED's value. Confirmed by
  // direct reproduction (embeddingSimilarity.classify() called standalone
  // returned engineStatus UNAVAILABLE / failureReason
  // EMBEDDING_CLASSIFIER_NOT_READY in 1ms — far too fast for real ONNX
  // inference) before this fix was written. Does not change embedding
  // classifier or gate behavior — only makes this harness reach the same
  // boot state real production traffic is guaranteed to run against.
  const _embeddingStatus = await embeddingClassifier.init();
  if (_embeddingStatus.status !== 'READY') {
    throw new Error(
      `embedding classifier failed to reach READY before harness start: status=${_embeddingStatus.status} error=${_embeddingStatus.error}`,
    );
  }

  const KEY = getActiveKey(DEFAULT_ACTOR_KEY);
  const tenantId = DEFAULT_ACTOR_KEY;

  let consentMode = 'none';
  const realConsentOk = await tryRealConsent(KEY.keyId, action, tenantId);
  if (realConsentOk) {
    consentMode = 'real-postgres';
  } else {
    // Fall back to the same fast-path stub the project's own Jest suite uses
    // (: jest.mock('././core/consent', ...)).
    // Plain property mutation on the shared module-export object — works
    // identically outside Jest since consent.verify is looked up fresh via
    // _registry().verify at each call (services/policy/evaluators/requireConsent.js).
    consent.verify = async () => ({ pass: true, reason: 'ACTIVE' });
    consentMode = 'stubbed-fast-path';
  }

  let store = nonceStore;
  let anomaly = anomalyStore;
  let storeMode = 'redis';
  if (useRealStores) {
    try {
      await nonceStore.initialize();
      await anomalyStore.initialize();
    } catch (err) {
      storeMode = 'in-memory-fallback';
      const { makeNonceStore, makeOpenAnomalyStore } = require('../../../src/testing/stores');
      store = makeNonceStore();
      anomaly = makeOpenAnomalyStore();
    }
  } else {
    storeMode = 'in-memory';
    const { makeNonceStore, makeOpenAnomalyStore } = require('../../../src/testing/stores');
    store = makeNonceStore();
    anomaly = makeOpenAnomalyStore();
  }

  // Item 16: opt-in only, default OFF, byte-identical to the pre-existing
  // behavior above when unset. The harness has never exercised RATE_LIMIT
  // policies or the real Redis-backed policy store before this flag existed
  // — every prior loadTest.js RPS number (incl. the ~40-56 RPS Program 5
  // baseline) was measured with ZERO rate-limit Redis round trips on this
  // path. See ITEM-16-REMEDIATION-REPORT.md §"measurement gap" for why that
  // matters for interpreting before/after numbers.
  const withRateLimitPolicies = opts.withRateLimitPolicies === true;

  // Item 24 amendment 2 — RATE_LIMIT policies bucket by signing-key identity
  // (checkPolicy.js: userId = publicKeyId). Running them against the single
  // 'default' identity above reproduces exactly the item-17-documented
  // budget-exhaustion confound (ITEM-17-REMEDIATION-REPORT.md §7). Coupled
  // to this flag by design (approved decision — a behavior change from the
  // item-16/17 "byte-identical when unset" discipline, recorded here): the
  // flag is harness-internal, so preventing the broken single-identity
  // configuration by construction outweighs preserving withRateLimitPolicies'
  // previously-shipped single-identity behavior. When the flag is off, none
  // of this runs — the identity/consent code above this block is untouched.
  let identityPool = null;
  let activeIdentityCount = 1;
  let poolConsentMode = null;
  let poolStubbedCount = 0;
  if (withRateLimitPolicies) {
    const poolSize = Math.max(1, opts.identityPoolSize || 1);
    const provisioned = await provisionIdentityPool(poolSize, action);
    identityPool = provisioned.identities;
    activeIdentityCount = poolSize;
    poolConsentMode = provisioned.consentMode;
    poolStubbedCount = provisioned.stubbedCount;
  }

  // Item 17: opt-in only, default OFF, byte-identical to the pre-existing
  // behavior above when unset. Below (line ~160), `store`/`anomaly` are
  // passed to createAiChatRouter() as EXPLICIT `_store`/`_anomalyStore`
  // values — even in the useRealStores=true case, where they're just
  // references to the real nonceStore/anomalyStore singleton modules. That
  // matters because validateBoundRequest.js's combined-Lua routing (item 17)
  // only activates when BOTH are `undefined` (letting it `require()` those
  // same singletons itself) — an explicitly-passed reference, even to the
  // identical module, keeps it on the sequential path. So without this flag,
  // every historical /ai/chat RPS number on this harness — including item
  // 16's own before/after numbers — was measured on the sequential
  // registerNonce()+checkAnomaly() path, never the combined one. When this
  // flag is set (and real Redis stores are actually in play), `_store`/
  // `_anomalyStore` are omitted from the router options entirely, so
  // validateBoundRequest falls through to its own default — the same
  // already-initialized singletons — which is exactly what makes the
  // combined path activate. Requires storeMode === 'redis' (in-memory
  // fallback/test doubles don't implement registerAndCheckAnomaly()).
  const useCombinedNonceAnomaly = opts.useCombinedNonceAnomaly === true;

  const rateLimitPolicyDefs = withRateLimitPolicies ? [
    // Mirrors policies.json's POL-004/POL-NEW exactly (same maxRequests/
    // windowSeconds/keyBy) — the two genuinely-consecutive RATE_LIMIT
    // policies item 16's combined-Lua batching targets.
    { id: 'POL-004', type: 'RATE_LIMIT', priority: 40, enabled: true,
      config: { windowSeconds: 60, maxRequests: 100, keyBy: 'userId' } },
    { id: 'POL-NEW', type: 'RATE_LIMIT', priority: 50, enabled: true,
      config: { windowSeconds: 30, maxRequests: 50, keyBy: 'userId' } },
  ] : [];

  const policies = validateAndPrepare({ policies: [
    { id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
      config: { requireValidArtifact: true } },
    ...rateLimitPolicyDefs,
  ] });

  let policyStore;
  if (withRateLimitPolicies) {
    await initRateLimitStore();
    policyStore = createRedisStore();
  } else {
    policyStore = createStore();
  }

  const app = express();
  app.use(attachClientIp);
  app.use(express.json({ limit: '2mb' }));
  // Anomaly thresholds: real production defaults unless explicitly raised.
  // Raising them is ONLY appropriate for load/stress/concurrency testing,
  // where the goal is to measure the server's raw processing capacity, not
  // its per-identity abuse-detection ceiling (see checkAnomaly.js's
  // documented single-identity SIGNATURE_BURST/global RATE_BURST limits,
  // which a synthetic load generator hammering with one signing key WILL
  // legitimately trip — that is correct, working security behavior, not a
  // load-test bug; see loadTest.js's --realistic-identity-limits flag for a
  // dedicated measurement of that ceiling).
  const thresholds = opts.thresholds || undefined; // undefined = real production defaults

  const combinedNonceAnomalyActive = useCombinedNonceAnomaly && storeMode === 'redis';

  app.use(CHAT_PATH, createAiChatRouter({
    // Omitting _store/_anomalyStore (rather than passing the real store
    // refs) is what lets validateBoundRequest's own default resolve them —
    // required for the item-17 combined-Lua path to activate. See the
    // useCombinedNonceAnomaly comment above.
    ...(combinedNonceAnomalyActive ? {} : { _store: store, _anomalyStore: anomaly }),
    _providerFn: providerFn,
    _getPolicies: () => policies,
    _policyStore: policyStore,
    _thresholds: thresholds,
  }));
  app.use((_req, res) => res.status(404).json({ error: 'NOT_FOUND' }));

  const listenPort = opts.port || 0;
  const server = await new Promise((resolve, reject) => {
    const s = app.listen(listenPort, '127.0.0.1', (err) => (err ? reject(err) : resolve(s)));
  });
  const { port } = server.address();
  const url = `http://127.0.0.1:${port}${CHAT_PATH}`;

  function freshEnvelope(payload = {}, identity = KEY) {
    const now = Date.now();
    return { payload, timestamp: now, expiry: now + 300_000, publicKeyId: identity.keyId };
  }

  function buildArtifact(reqBody, extraPayload = {}, identity = KEY) {
    const req = { method: 'POST', path: CHAT_PATH, body: reqBody };
    return signBoundArtifact(req, freshEnvelope({ provider: action, ...extraPayload }, identity), identity.privDer);
  }

  function toHeader(artifact) {
    return Buffer.from(JSON.stringify(artifact)).toString('base64');
  }

  // Item 24 amendment 2 — round-robins across the provisioned identity pool
  // (a no-op, always KEY, when identityPool is null — i.e. whenever
  // withRateLimitPolicies is off). activeIdentityCount lets a per-level
  // runner shrink the round-robin range for lower-RPS levels without
  // re-provisioning key material (see setActiveIdentityCount below).
  let _rrCounter = 0;
  function _nextIdentity() {
    if (!identityPool || identityPool.length === 0) return KEY;
    const n = Math.max(1, Math.min(activeIdentityCount, identityPool.length));
    const identity = identityPool[_rrCounter % n].KEY;
    _rrCounter++;
    return identity;
  }

  /**
   * Restrict makeRequest()'s round-robin to the first `n` provisioned
   * identities (clamped to [1, pool size]) — used to size the identity
   * count to the current level's target RPS (amendment 2's
   * N >= ceil(targetRps / 1.5) sizing) without re-provisioning. No-op when
   * no pool was provisioned (withRateLimitPolicies off).
   */
  function setActiveIdentityCount(n) {
    if (!identityPool) return;
    activeIdentityCount = Math.max(1, Math.min(n, identityPool.length));
  }

  // Item 24 mandatory addition — verify that policy DEFINITIONS (as opposed
  // to their Redis-side counters) survive a guardedFlush. Confirmed by
  // reading services/policy/store.js: createRedisStore() only ever
  // GET/INCR/EXPIRE/EVALs `ratelimit:v1:*` counter keys — policy id/type/
  // windowSeconds/maxRequests/keyBy are never written to Redis at all; they
  // live purely in this closure's `policies` array (built once by
  // validateAndPrepare() above, before any request is ever sent). A FLUSHDB
  // on the test DB cannot delete them by construction. This assertion is a
  // fail-hard safety net anyway, per instruction, in case that ever changes.
  function assertRateLimitPoliciesResolvable() {
    if (!withRateLimitPolicies) return;
    const has004 = policies.some((p) => p.id === 'POL-004' && p.enabled);
    const hasNew = policies.some((p) => p.id === 'POL-NEW' && p.enabled);
    if (!has004 || !hasNew) {
      throw new Error(
        'assertRateLimitPoliciesResolvable: POL-004/POL-NEW not resolvable — refusing to continue the run.',
      );
    }
  }

  /**
   * Build a ready-to-send { body, headers } pair for a fresh unique request.
   * `extra` fields (e.g. { stream: true }) are merged in BEFORE signing, so
   * the artifact's requestHash binds the actual body sent — mutating body
   * after this call breaks REQUEST_MISMATCH binding by design (that check
   * is the security control working correctly, not a bug to work around).
   */
  function makeRequest(promptOverride, extra = {}) {
    const body = { prompt: promptOverride || `benchmark prompt ${crypto.randomUUID()}`, model: 'bench', ...extra };
    const artifact = buildArtifact(body, {}, _nextIdentity());
    return { body, headers: { 'x-qodiqa-artifact': toHeader(artifact), 'content-type': 'application/json' } };
  }

  async function close() {
    await new Promise((resolve) => server.close(resolve));
    if (redisAdmin) await redisAdmin.quit();
  }

  // Item 24 — aggregate consent-path reporting (amendment 4): when the
  // identity pool is active, its own aggregate (which real traffic actually
  // used) supersedes the unused single-'default'-identity probe above.
  const effectiveConsentMode = identityPool ? poolConsentMode : consentMode;

  return {
    app, server, url, port, KEY, action, tenantId, consentMode: effectiveConsentMode, storeMode,
    combinedNonceAnomaly: combinedNonceAnomalyActive, buildArtifact, toHeader, makeRequest, close,
    identityPoolSize: identityPool ? identityPool.length : 1,
    identityPoolStubbedCount: poolStubbedCount,
    setActiveIdentityCount,
    assertRateLimitPoliciesResolvable,
    redisAdmin,
    guardedFlush: redisAdmin ? () => guardedFlush(redisAdmin) : null,
    finalCleanup: redisAdmin ? () => finalCleanup(redisAdmin) : null,
  };
}

module.exports = { buildHarness, instantMockProvider, CHAT_PATH };
