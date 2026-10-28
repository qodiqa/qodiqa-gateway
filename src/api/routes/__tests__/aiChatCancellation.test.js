'use strict';

/**
 * Finding 32 (2.3) remediation — non-streaming route-level timeout cancellation.
 *
 * Before this fix, the non-streaming /ai/chat timeout only raced the client
 * response against a timer: when the timer won, the underlying
 * _enforceAndExecute() promise (and the outbound provider call inside it) was
 * simply abandoned, not cancelled — it kept running, could still consume
 * provider quota, and could still write a misleading ALLOW/EXECUTE audit
 * entry for a response the client never received.
 *
 * This suite proves, through the real HTTP route (not a unit stub):
 *   1. A timed-out request gets 504 REQUEST_TIMEOUT promptly, without waiting
 *      for the slow provider call to finish.
 *   2. The AbortSignal reaches the injected provider function (the same
 *      choke point real provider adapters are wired to — see
 *      services/providers/__tests__/cancellation.test.js for adapter-level
 *      coverage).
 *   3. The persisted audit entry for a cancelled execution is BLOCK with a
 *      CANCELLED completion status — never ALLOW — even when the "provider"
 *      technically returns a value after the signal has already aborted
 *      (the late-completion guard).
 *   4. No second HTTP response is ever attempted and no unhandled promise
 *      rejection occurs.
 *   5. Concurrent, independent timeouts each get their own correct audit
 *      record.
 *   6. Normal (non-timed-out) requests are completely unaffected — control
 *      case proving no regression to the happy path.
 */

// AI_CHAT_TIMEOUT_MS is read once at module load — must be set before the
// first require of aiChat.js (or anything that transitively requires it).
// The budget covers the whole request, not only the provider call: artifact
// signature check, policy evaluation and the audit write all run inside it. At
// 200 ms a loaded two-core CI runner could spend the budget before a 20 ms
// provider answered, and the control case then got 504 instead of 200. 1000 ms
// leaves the fast path about a second of headroom; the delays of the slow
// providers below are several multiples of it, so the timeout cases still
// time out deterministically. What each test asserts is unchanged.
process.env.AI_CHAT_TIMEOUT_MS = '1000';

jest.mock('../../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

// Real (unmocked) here would pull in the real ONNX embedding classifier —
// this suite proves timeout/cancellation orchestration, not semantic-layer
// correctness or speed (D6 latency and embeddingGate's own suites own
// that). Mocked for the same isolation reason core/consent is mocked
// above. Always resolves ALLOW (blocks: false), matching this file's own
// benign "Hello, world!" CHAT_BODY's real production outcome — aiChat.js's
// _runSemanticCheck() only reads embeddingResult.blocks when it's true, so
// a minimal {blocks: false} is a faithful stand-in, not a partial mock.
jest.mock('../../../core/semantic/embeddingGate', () => ({
  checkText: jest.fn().mockResolvedValue({ blocks: false }),
}));

const express   = require('express');
const supertest = require('supertest');

const createAiChatRouter     = require('../aiChat');
const attachClientIp         = require('../../../../middleware/clientIp');
const { signBoundArtifact }  = require('../../../validation/signBoundArtifact');
const { getActiveKey }       = require('../../../../services/artifact/keyStore');
const { resetStats }         = require('../../../../services/execution-guard');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const { createStore }        = require('../../../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
const { getModernChain, drainPendingWrites } = require('../../../core/audit/audit-log');
const metrics                = require('../../../observability/metrics');

let KEY;
beforeAll(async () => {
  KEY = getActiveKey('default');
  // Warm up lazy one-time initialization (key material, crypto engine, etc.)
  // that the first request through this router pays for — without this, the
  // very first timing-sensitive assertion below would be measuring startup
  // cost rather than the timeout/cancellation behavior under test.
  const warmupApp = makeApp({ providerFn: () => Promise.resolve({ output: MOCK_RESPONSE }) });
  await post(warmupApp, buildArtifact());
  await post(warmupApp, buildArtifact());
  await drainPendingWrites();
}, 20_000);
beforeEach(() => resetStats());

const CHAT_PATH = '/ai/chat';
const CHAT_BODY = { prompt: 'Hello, world!', model: 'gpt-4' };
const MOCK_RESPONSE = 'Mock AI response';

function freshEnvelope(payload = {}) {
  const now = Date.now();
  return { payload, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId };
}
function buildArtifact(reqBody = CHAT_BODY, extraPayload = {}) {
  const req = { method: 'POST', path: CHAT_PATH, body: reqBody };
  return signBoundArtifact(req, freshEnvelope({ provider: 'openai', ...extraPayload }), KEY.privDer);
}
function toHeader(artifact) {
  return Buffer.from(JSON.stringify(artifact)).toString('base64');
}

const _DEFAULT_POLICIES = validateAndPrepare({ policies: [{
  id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
  config: { requireValidArtifact: true },
}] });
const _DEFAULT_POLICY_STORE = createStore();

function makeApp({ providerFn } = {}) {
  const app = express();
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({
    _store:        makeNonceStore(),
    _anomalyStore: makeOpenAnomalyStore(),
    _providerFn:   providerFn,
    _getPolicies:  () => _DEFAULT_POLICIES,
    _policyStore:  _DEFAULT_POLICY_STORE,
  }));
  app.use((_req, res) => res.status(404).json({ error: 'NOT_FOUND' }));
  return app;
}

async function post(app, artifact, body = CHAT_BODY) {
  return supertest(app)
    .post('/ai/chat')
    .set('x-qodiqa-artifact', toHeader(artifact))
    .send(body);
}

// ── awaited conditions instead of fixed sleeps ──────
// The tests used to sleep(300/600/1000) and hope the background continuation
// (still running after the 504 was sent) had written its audit entry by then;
// under parallel load 600ms was not always enough. Every test now waits for the
// actual events instead:
//   - providersSettled(): every provider call started so far has settled
//     (resolved, rejected on abort, or completed late);
//   - waitForChainLength(n): audit writes drained and the chain holds >= n
//     entries (bounded — fails with a clear message, never hangs);
//   - abortFired(signal): the AbortSignal has actually fired.
// Each test drains its own background work before returning, so no entry from
// one test can land during the next — "the newest N entries" is exact.
const _providerCalls = new Set();
function trackProviderCall(promise) {
  _providerCalls.add(promise);
  promise.then(() => _providerCalls.delete(promise), () => _providerCalls.delete(promise));
  return promise;
}
async function providersSettled() {
  while (_providerCalls.size) await Promise.allSettled([..._providerCalls]);
}
async function chainLength() {
  return (await getModernChain()).length;
}
async function waitForChainLength(n, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    await drainPendingWrites();
    const chain = await getModernChain();
    if (chain.length >= n) return chain;
    if (Date.now() > deadline) {
      throw new Error(`audit chain did not reach ${n} entries within ${timeoutMs}ms (has ${chain.length})`);
    }
    await new Promise(resolve => setImmediate(resolve));
  }
}
// Schema v7: every dispatched
// execution writes an INTENT lifecycle entry (fixed decision "ALLOW", artifactId suffixed ":intent", stage
// PROVIDER_DISPATCH) BEFORE its DECISION entry. waitForChainLength(n0 + 1) was therefore satisfied by the INTENT
// alone: when the asynchronous cancellation BLOCK had not landed yet, "the newest entry" was the INTENT and a correct
// run failed with decision ALLOW, and a late BLOCK could fall into the
// next test's window. The tests now wait for, and read, the DECISION entries themselves.
const isLifecycle = (e) => /:(intent|stream_opened)$/.test(String(e.artifactId));
function decisionsSince(chain, n0) { return chain.slice(n0).filter((e) => !isLifecycle(e)); }
async function waitForDecisions(n0, k = 1, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    await drainPendingWrites();
    const chain = await getModernChain();
    if (decisionsSince(chain, n0).length >= k) return chain;
    if (Date.now() > deadline) {
      throw new Error(`audit chain did not gain ${k} DECISION entries within ${timeoutMs}ms (has ${decisionsSince(chain, n0).length})`);
    }
    await new Promise((resolve) => setImmediate(resolve));
  }
}

function abortFired(signal) {
  return signal.aborted ? Promise.resolve() : new Promise(resolve => signal.addEventListener('abort', resolve, { once: true }));
}
// Lets a pending 'unhandledRejection' be emitted: Node reports it once the
// microtask queue has drained, i.e. before the next macrotask turn.
function nextMacrotask() {
  return new Promise(resolve => setImmediate(resolve));
}

// A well-behaved provider stand-in: honors the AbortSignal exactly like the
// real adapters now do (services/providers/{openai,anthropic,...}.js) —
// rejects with PROVIDER_CANCELLED as soon as the signal fires, instead of
// running to completion.
function makeAbortAwareProvider(delayMs, onSignal) {
  return (_provider, _body, _ctx, signal) => {
    if (onSignal) onSignal(signal);
    return trackProviderCall(new Promise((resolve, reject) => {
      const timer = setTimeout(() => resolve({ output: MOCK_RESPONSE }), delayMs);
      if (signal) {
        signal.addEventListener('abort', () => {
          clearTimeout(timer);
          const err = new Error('PROVIDER_CANCELLED');
          err.code  = 'PROVIDER_CANCELLED';
          reject(err);
        }, { once: true });
      }
    }));
  };
}

// An adversarial/non-compliant provider stand-in: ignores the AbortSignal
// entirely and resolves successfully once its delay elapses regardless —
// exercises the late-completion guard in _enforceAndExecute.
function makeAbortIgnoringProvider(delayMs) {
  return () => trackProviderCall(new Promise(resolve => {
    setTimeout(() => resolve({ output: MOCK_RESPONSE }), delayMs);
  }));
}

function findEntryFor(chain, artifactId) {
  return [...chain].reverse().find(e => e.artifactId === artifactId);
}

// ═════════════════════════════════════════════════════════════════════════════
// Control case — no regression to the happy path
// ═════════════════════════════════════════════════════════════════════════════

describe('control case — provider well within the timeout budget', () => {
  test('fast provider still returns 200 EXECUTE with the response body', async () => {
    const app      = makeApp({ providerFn: makeAbortAwareProvider(20) });
    const artifact = buildArtifact();
    const n0       = await chainLength();
    const res      = await post(app, artifact);

    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('EXECUTE');
    expect(res.body.response).toBe(MOCK_RESPONSE);
    await providersSettled();
    await waitForDecisions(n0);
  });

  test('the audit entry for a fast request is ALLOW, not CANCELLED', async () => {
    const app      = makeApp({ providerFn: makeAbortAwareProvider(20) });
    const artifact = buildArtifact();
    const n0       = await chainLength();
    const res      = await post(app, artifact);

    await providersSettled();
    const entry = findEntryFor(await waitForDecisions(n0), res.body.artifactId);
    expect(entry.decision).toBe('ALLOW');
    expect(entry.executionContext.completionStatus).not.toBe('CANCELLED');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Timeout cancels the in-flight provider call
// ═════════════════════════════════════════════════════════════════════════════

describe('timeout cancels in-flight provider work', () => {
  test('client receives 504 REQUEST_TIMEOUT promptly — does not wait for the slow provider', async () => {
    const app      = makeApp({ providerFn: makeAbortAwareProvider(4000) });
    const artifact = buildArtifact();
    const n0       = await chainLength();

    const startedAt = Date.now();
    const res       = await post(app, artifact);
    const elapsedMs = Date.now() - startedAt;

    expect(res.status).toBe(504);
    expect(res.body.reason).toBe('REQUEST_TIMEOUT');
    // Well under the provider's 4000ms delay — proves the client isn't held
    // hostage by the abandoned/still-running provider call. Generous margin
    // to stay deterministic under parallel-worker CPU contention.
    expect(elapsedMs).toBeLessThan(3000);   // the provider takes 4000 ms; the timeout (1000 ms) must end the request well before that
    // Drain this request's background continuation before the next test.
    await providersSettled();
    await waitForDecisions(n0);
  });

  test('the AbortSignal reaches the provider dispatch point', async () => {
    let capturedSignal = null;
    const app      = makeApp({
      providerFn: makeAbortAwareProvider(4000, (signal) => { capturedSignal = signal; }),
    });
    const artifact = buildArtifact();
    const n0       = await chainLength();

    await post(app, artifact);

    expect(capturedSignal).toBeInstanceOf(AbortSignal);
    // Wait for the abort itself rather than a fixed delay.
    await abortFired(capturedSignal);
    expect(capturedSignal.aborted).toBe(true);
    await providersSettled();
    await waitForDecisions(n0);
  });

  test('audit entry is BLOCK/CANCELLED, never ALLOW, for a cancelled execution', async () => {
    const app      = makeApp({ providerFn: makeAbortAwareProvider(4000) });
    const artifact = buildArtifact();
    const n0       = await chainLength();

    const res = await post(app, artifact);
    expect(res.status).toBe(504);

    // The background continuation (still running after the client response
    // was sent) reacts to the abort and writes its entry: wait for exactly that.
    await providersSettled();
    const chain = await waitForDecisions(n0);
    // requestId isn't in the 504 body (BLOCK before requestId is known to the
    // caller) — locate this request's DECISION entry and confirm its shape.
    const added = chain.slice(n0);
    const [entry, ...extraDecisions] = decisionsSince(chain, n0);
    expect(extraDecisions).toEqual([]);
    // v7 composition: exactly one INTENT for this request, written before dispatch, then the DECISION.
    const intents = added.filter(isLifecycle);
    expect(intents).toHaveLength(1);
    expect(intents[0].artifactId).toBe(`${entry.artifactId}:intent`);
    expect(intents[0].decision).toBe('ALLOW'); // fixed by schema (R-8): a lifecycle marker, not an authorization
    expect(intents[0].executionContext.stage).toBe('PROVIDER_DISPATCH');
    expect(added.indexOf(intents[0])).toBeLessThan(added.indexOf(entry));
    expect(entry.decision).toBe('BLOCK');
    expect(entry.executionContext.completionStatus).toBe('CANCELLED');
    expect(entry.executionContext.stage).toBe('PROVIDER_EXECUTION_CANCELLED');
    expect(['REQUEST_TIMEOUT', 'PROVIDER_CANCELLED']).toContain(entry.executionContext.reason);

    // No entry for this artifactId is ever ALLOW.
    const allowEntry = chain.find(e => e.artifactId === entry.artifactId && e.decision === 'ALLOW');
    expect(allowEntry).toBeUndefined();
  });

  test('providerExecutionCancelledTotal is incremented on cancellation', async () => {
    const before = [...metrics.providerExecutionCancelledTotal._values.values()].reduce((a, b) => a + b, 0);

    const app      = makeApp({ providerFn: makeAbortAwareProvider(4000) });
    const n0       = await chainLength();
    await post(app, buildArtifact());
    await providersSettled();
    await waitForDecisions(n0);

    const after = [...metrics.providerExecutionCancelledTotal._values.values()].reduce((a, b) => a + b, 0);
    expect(after).toBeGreaterThan(before);
  });

  test('no unhandled promise rejection occurs when the abandoned execution later rejects', async () => {
    const unhandled = [];
    const onUnhandled = (reason) => unhandled.push(reason);
    process.on('unhandledRejection', onUnhandled);

    try {
      const app = makeApp({ providerFn: makeAbortAwareProvider(4000) });
      const n0  = await chainLength();
      await post(app, buildArtifact());
      // The abandoned execution rejects on abort; wait for that rejection and
      // its audit write, then one macrotask so any unhandled rejection is emitted.
      await providersSettled();
      await waitForDecisions(n0);
      await nextMacrotask();
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }

    expect(unhandled).toHaveLength(0);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Late-completion guard — provider ignores the AbortSignal
// ═════════════════════════════════════════════════════════════════════════════

describe('late-completion guard — non-compliant provider ignores the signal', () => {
  test('a provider that resolves successfully after the timeout is still recorded as CANCELLED, not ALLOW', async () => {
    const app      = makeApp({ providerFn: makeAbortIgnoringProvider(2500) });
    const artifact = buildArtifact();
    const n0       = await chainLength();

    const res = await post(app, artifact);
    expect(res.status).toBe(504);

    // Wait for the provider's "late success" itself to land (it ignores the
    // signal and resolves after 700ms), then for every audit write it caused —
    // so a wrongly-recorded late ALLOW would be visible below.
    await providersSettled();
    await waitForDecisions(n0);
    await nextMacrotask();
    await drainPendingWrites();

    const chain = await getModernChain();
    const decisions = decisionsSince(chain, n0);
    expect(decisions).toHaveLength(1); // a wrongly-recorded late ALLOW would be a SECOND decision for this request
    const entry = decisions[0];
    expect(entry.decision).toBe('BLOCK');
    expect(entry.executionContext.completionStatus).toBe('CANCELLED');
    expect(entry.executionContext.reason).toBe('REQUEST_TIMEOUT');

    const allowEntry = chain.find(e => e.artifactId === entry.artifactId && e.decision === 'ALLOW');
    expect(allowEntry).toBeUndefined();
  });
});

// — the timeout-during-output-check case lives in
// aiChatArch03LateTimeout.test.js: it needs a wider budget than this file's to be deterministic under load.

// ═════════════════════════════════════════════════════════════════════════════
// Concurrency
// ═════════════════════════════════════════════════════════════════════════════

describe('concurrent cancelled requests', () => {
  test('multiple simultaneous timeouts each get their own correct audit record', async () => {
    const app = makeApp({ providerFn: makeAbortAwareProvider(4000) });
    const n0  = await chainLength();

    const responses = await Promise.all(
      [0, 1, 2].map(() => post(app, buildArtifact())),
    );
    responses.forEach(res => expect(res.status).toBe(504));

    await providersSettled();
    const chain = await waitForDecisions(n0, 3);
    const recent = decisionsSince(chain, n0);
    expect(recent).toHaveLength(3);
    expect(chain.slice(n0).filter(isLifecycle).map((e) => e.artifactId).sort()).toEqual(recent.map((e) => `${e.artifactId}:intent`).sort());
    recent.forEach(entry => {
      expect(entry.decision).toBe('BLOCK');
      expect(entry.executionContext.completionStatus).toBe('CANCELLED');
    });
    // Each cancelled execution got a distinct artifactId — no cross-contamination.
    expect(new Set(recent.map(e => e.artifactId)).size).toBe(3);
  });
});
