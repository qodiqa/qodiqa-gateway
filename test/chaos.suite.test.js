'use strict';

/**
 * Chaos Engineering Tests
 *
 * Proves that the QODIQA enforcement pipeline maintains fail-closed guarantees
 * under injected infrastructure failures:
 *
 *   CHAOS-01  Redis nonce store down        → always blocked, never throws
 *   CHAOS-02  Redis anomaly store down      → always blocked, never throws
 *   CHAOS-03  Network partition (both down) → blocked, fail-closed
 *   CHAOS-04  Redis nonce store latency     → still returns correct result
 *   CHAOS-05  Redis nonce store timeout     → request fails-closed
 *   CHAOS-06  Clock skew (negative)         → FUTURE_TIMESTAMP blocks
 *   CHAOS-07  Memory pressure               → pipeline does not crash
 *   CHAOS-08  Burst failures mid-stream     → all post-failure requests blocked
 *   CHAOS-09  Store recovery               → fresh store resumes allowed
 *   CHAOS-10  Anomaly store latency        → still returns correct result
 *
 * All faults are injected via the failure injection framework.
 * No real Redis or PG infrastructure is required.
 */

// Mock consent so policy evaluation doesn't need live infrastructure
jest.mock('../src/core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

const { validateBoundRequest } = require('../src/validation/validateBoundRequest');
const { signBoundArtifact }    = require('../src/validation/signBoundArtifact');
const { getActiveKey, rotateKey } = require('../services/artifact/keyStore');

const {
  makeNonceStore,
  makeOpenAnomalyStore,
  makeCountingAnomalyStore,
} = require('../src/testing/stores');

const {
  redisDownNonceStore,
  redisLatencyNonceStore,
  redisTimeoutNonceStore,
  redisDownAnomalyStore,
  redisLatencyAnomalyStore,
  networkPartition,
  withMemoryPressure,
  injectClockSkew,
  FaultInjector,
} = require('../src/testing/failureInjection');

// ── Fixtures ──────────────────────────────────────────────────────────────────

let KEY;
beforeAll(() => {
  try   { KEY = getActiveKey('default'); }
  catch { rotateKey('default'); KEY = getActiveKey('default'); }
});

const BASE_REQUEST = { method: 'POST', path: '/ai/chat', body: { prompt: 'hello', model: 'gpt-4' } };

function freshArtifact(reqOverrides = {}, envelopeOverrides = {}) {
  const now = Date.now();
  const envelope = {
    payload:     { provider: 'openai' },
    timestamp:   now,
    expiry:      now + 300_000,
    publicKeyId: KEY.keyId,
    ...envelopeOverrides,
  };
  const request = { ...BASE_REQUEST, ...reqOverrides };
  return signBoundArtifact(request, envelope, KEY.privDer);
}

function freshRequest(overrides = {}) {
  return { ...BASE_REQUEST, ...overrides };
}

// Validate a single fresh artifact+request pair with injected stores
async function validate(artifact, request, storeOpts = {}) {
  return validateBoundRequest(artifact, request, {
    _store:        storeOpts.nonceStore,
    _anomalyStore: storeOpts.anomalyStore,
    _thresholds:   storeOpts.thresholds,
    _clock:        storeOpts.clock,
  });
}

// ── CHAOS-01: Redis nonce store down ─────────────────────────────────────────

describe('CHAOS-01 Redis nonce store down — fail-closed, never throws', () => {

  test('CHAOS-01a  single request → { allowed: false }', async () => {
    const artifact = freshArtifact();
    const result = await validate(artifact, BASE_REQUEST, {
      nonceStore:   redisDownNonceStore(),
      anomalyStore: makeOpenAnomalyStore(),
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('NONCE_STORE_ERROR');
  });

  test('CHAOS-01b  10 consecutive requests → all blocked, none throw', async () => {
    const brokenStore = redisDownNonceStore();
    const anomalyStore = makeOpenAnomalyStore();

    for (let i = 0; i < 10; i++) {
      const artifact = freshArtifact();
      await expect(
        validate(artifact, BASE_REQUEST, { nonceStore: brokenStore, anomalyStore })
      ).resolves.toMatchObject({ allowed: false, reason: 'NONCE_STORE_ERROR' });
    }
  });

  test('CHAOS-01c  result is a plain object (does not throw)', async () => {
    const artifact = freshArtifact();
    const result = await validate(artifact, BASE_REQUEST, {
      nonceStore:   redisDownNonceStore(),
      anomalyStore: makeOpenAnomalyStore(),
    });
    expect(result).toBeDefined();
    expect(result.allowed).toBe(false);
  });
});

// ── CHAOS-02: Redis anomaly store down ───────────────────────────────────────

describe('CHAOS-02 Redis anomaly store down — fail-closed, never throws', () => {

  test('CHAOS-02a  single request → { allowed: false }', async () => {
    const artifact = freshArtifact();
    const result = await validate(artifact, BASE_REQUEST, {
      nonceStore:   makeNonceStore(),
      anomalyStore: redisDownAnomalyStore(),
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('ANOMALY_DETECTED');
  });

  test('CHAOS-02b  10 consecutive requests (fresh nonces) → all blocked', async () => {
    const anomalyStore = redisDownAnomalyStore();

    for (let i = 0; i < 10; i++) {
      const artifact = freshArtifact();
      const result = await validate(artifact, BASE_REQUEST, {
        nonceStore:   makeNonceStore(), // fresh nonce store per request (no replay)
        anomalyStore,
      });
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('ANOMALY_DETECTED');
    }
  });

  test('CHAOS-02c  anomaly block details include STORE_ERROR type', async () => {
    const artifact = freshArtifact();
    const result = await validate(artifact, BASE_REQUEST, {
      nonceStore:   makeNonceStore(),
      anomalyStore: redisDownAnomalyStore(),
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('ANOMALY_DETECTED');
    expect(result.details).toBeDefined();
    expect(result.details.type).toBe('STORE_ERROR');
  });
});

// ── CHAOS-03: Network partition (both stores down) ────────────────────────────

describe('CHAOS-03 Network partition — both stores down, fail-closed', () => {

  test('CHAOS-03a  networkPartition() stores → request blocked', async () => {
    const { nonceStore, anomalyStore } = networkPartition();
    const artifact = freshArtifact();
    const result = await validate(artifact, BASE_REQUEST, { nonceStore, anomalyStore });
    expect(result.allowed).toBe(false);
  });

  test('CHAOS-03b  network partition blocks at nonce step (first failure wins)', async () => {
    const { nonceStore, anomalyStore } = networkPartition();
    const artifact = freshArtifact();
    const result = await validate(artifact, BASE_REQUEST, { nonceStore, anomalyStore });
    // Nonce store is checked before anomaly — expect nonce error
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('NONCE_STORE_ERROR');
  });

  test('CHAOS-03c  5 requests under partition → all blocked', async () => {
    for (let i = 0; i < 5; i++) {
      const { nonceStore, anomalyStore } = networkPartition();
      const artifact = freshArtifact();
      const result = await validate(artifact, BASE_REQUEST, { nonceStore, anomalyStore });
      expect(result.allowed).toBe(false);
    }
  });
});

// ── CHAOS-04: Redis nonce store latency ──────────────────────────────────────

describe('CHAOS-04 Redis nonce store with 50ms latency — correct result, just slower', () => {

  test('CHAOS-04a  latency store returns { allowed: true } for valid request', async () => {
    const realStore    = makeNonceStore();
    const latentStore  = redisLatencyNonceStore(realStore, 50);
    const anomalyStore = makeOpenAnomalyStore();

    const artifact = freshArtifact();
    const start    = Date.now();
    const result   = await validate(artifact, BASE_REQUEST, {
      nonceStore:   latentStore,
      anomalyStore,
    });
    const elapsed = Date.now() - start;

    expect(result.allowed).toBe(true);
    expect(elapsed).toBeGreaterThanOrEqual(45); // tolerant of timer jitter
  });

  test('CHAOS-04b  replay still detected through latent store', async () => {
    const realStore    = makeNonceStore();
    const latentStore  = redisLatencyNonceStore(realStore, 50);
    const anomalyStore = makeOpenAnomalyStore();

    const artifact = freshArtifact();
    const r1 = await validate(artifact, BASE_REQUEST, { nonceStore: latentStore, anomalyStore });
    expect(r1.allowed).toBe(true);

    const r2 = await validate(artifact, BASE_REQUEST, { nonceStore: latentStore, anomalyStore });
    expect(r2.allowed).toBe(false);
    expect(r2.reason).toBe('REPLAY_DETECTED');
  });
});

// ── CHAOS-05: Redis nonce store timeout ──────────────────────────────────────

describe('CHAOS-05 Redis nonce store timeout — fails-closed', () => {

  // Shorter hangMs than the test timeout so the test completes
  const HANG_MS = 200;

  test('CHAOS-05a  timeout store → { allowed: false, reason: NONCE_STORE_ERROR }', async () => {
    const realStore     = makeNonceStore();
    const timeoutStore  = redisTimeoutNonceStore(realStore, HANG_MS);
    const anomalyStore  = makeOpenAnomalyStore();

    const artifact = freshArtifact();
    const result   = await validate(artifact, BASE_REQUEST, {
      nonceStore:   timeoutStore,
      anomalyStore,
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('NONCE_STORE_ERROR');
  }, 5_000);

  test('CHAOS-05b  timeout store does not throw — result is a plain object', async () => {
    const timeoutStore = redisTimeoutNonceStore(makeNonceStore(), HANG_MS);
    const artifact     = freshArtifact();

    const result = await validate(artifact, BASE_REQUEST, {
      nonceStore:   timeoutStore,
      anomalyStore: makeOpenAnomalyStore(),
    });
    expect(result).toBeDefined();
    expect(result.allowed).toBe(false);
  }, 5_000);
});

// ── CHAOS-06: Clock skew ──────────────────────────────────────────────────────

describe('CHAOS-06 Clock skew — negative skew makes artifact appear from the future', () => {

  afterEach(() => {
    // Safety restore in case a test fails mid-way
    Date.now = Date.now.bind(Date);
  });

  test('CHAOS-06a  negative skew shifts clock back → artifact timestamp in future → blocked', async () => {
    // Negative skew: Date.now() returns a value in the past relative to the artifact's timestamp.
    // The artifact is signed with the real clock; then we shift the clock back 1 hour.
    // From the shifted clock's perspective, the artifact's timestamp is in the future.
    const faults = new FaultInjector();

    const artifact = freshArtifact(); // signed at "real now"
    faults.clockSkew(-3_600_000);     // shift clock 1 hour into the past

    try {
      const result = await validate(artifact, BASE_REQUEST, {
        nonceStore:   makeNonceStore(),
        anomalyStore: makeOpenAnomalyStore(),
        clock:        Date.now,       // uses the skewed Date.now
      });
      // The artifact's timestamp is in the future relative to the shifted clock → blocked
      expect(result.allowed).toBe(false);
    } finally {
      faults.restore();
    }
  });

  test('CHAOS-06b  restore() resets clock; subsequent requests use real time', async () => {
    const faults   = new FaultInjector();
    const realNow  = Date.now();

    faults.clockSkew(-3_600_000);
    const skewedNow = Date.now();
    faults.restore();
    const restoredNow = Date.now();

    // After restore, Date.now() should be close to the real time
    expect(Math.abs(restoredNow - realNow)).toBeLessThan(500);
    // During skew, clock was in the past
    expect(skewedNow).toBeLessThan(realNow);
  });

  test('CHAOS-06c  large positive skew makes artifact appear expired → blocked', async () => {
    // With a very large positive skew, Date.now() is far in the future,
    // so the artifact's expiry has already passed from the clock's perspective.
    const faults = new FaultInjector();

    const artifact = freshArtifact(); // expiry = now + 300s
    faults.clockSkew(+600_000);       // shift clock 10 minutes into the future

    try {
      const result = await validate(artifact, BASE_REQUEST, {
        nonceStore:   makeNonceStore(),
        anomalyStore: makeOpenAnomalyStore(),
        clock:        Date.now,
      });
      // Clock is 10 min ahead; artifact expiry was only 5 min out → expired
      expect(result.allowed).toBe(false);
    } finally {
      faults.restore();
    }
  });
});

// ── CHAOS-07: Memory pressure ─────────────────────────────────────────────────

describe('CHAOS-07 Memory pressure — pipeline does not crash', () => {

  test('CHAOS-07a  50 MB pressure around nonce store ops → no crash, result returned', async () => {
    const realStore = makeNonceStore();

    // Wrap the register method with memory pressure
    const pressuredStore = {
      register:     withMemoryPressure((...a) => realStore.register(...a),     50_000_000),
      isRegistered: withMemoryPressure((...a) => realStore.isRegistered(...a), 50_000_000),
    };

    const artifact = freshArtifact();
    const result = await validate(artifact, BASE_REQUEST, {
      nonceStore:   pressuredStore,
      anomalyStore: makeOpenAnomalyStore(),
    });

    expect(result).toBeDefined();
    expect(typeof result.allowed).toBe('boolean');
  });

  test('CHAOS-07b  memory pressure with valid artifact → still returns { allowed: true }', async () => {
    const realStore = makeNonceStore();
    const pressuredStore = {
      register:     withMemoryPressure((...a) => realStore.register(...a),     50_000_000),
      isRegistered: withMemoryPressure((...a) => realStore.isRegistered(...a), 50_000_000),
    };

    const artifact = freshArtifact();
    const result   = await validate(artifact, BASE_REQUEST, {
      nonceStore:   pressuredStore,
      anomalyStore: makeOpenAnomalyStore(),
    });
    expect(result.allowed).toBe(true);
  });

  test('CHAOS-07c  5 requests under memory pressure → consistent results', async () => {
    for (let i = 0; i < 5; i++) {
      const realStore = makeNonceStore();
      const pressuredStore = {
        register:     withMemoryPressure((...a) => realStore.register(...a),     50_000_000),
        isRegistered: withMemoryPressure((...a) => realStore.isRegistered(...a), 50_000_000),
      };

      const artifact = freshArtifact();
      const result   = await validate(artifact, BASE_REQUEST, {
        nonceStore:   pressuredStore,
        anomalyStore: makeOpenAnomalyStore(),
      });
      expect(result.allowed).toBe(true);
    }
  });
});

// ── CHAOS-08: Burst of failures mid-stream ────────────────────────────────────

describe('CHAOS-08 Burst of failures mid-stream — first 5 succeed, then store goes down', () => {

  test('CHAOS-08a  5 success then store fails → all subsequent blocked', async () => {
    const realStore    = makeNonceStore();
    const anomalyStore = makeOpenAnomalyStore();

    // First 5 requests with a healthy store
    for (let i = 0; i < 5; i++) {
      const artifact = freshArtifact();
      const result   = await validate(artifact, BASE_REQUEST, {
        nonceStore:   realStore,
        anomalyStore,
      });
      expect(result.allowed).toBe(true);
    }

    // Switch to broken store (simulates mid-stream failure)
    const brokenStore = redisDownNonceStore();

    for (let i = 0; i < 5; i++) {
      const artifact = freshArtifact();
      const result   = await validate(artifact, BASE_REQUEST, {
        nonceStore:   brokenStore,
        anomalyStore,
      });
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('NONCE_STORE_ERROR');
    }
  });

  test('CHAOS-08b  mid-stream failure count matches expected blocked count', async () => {
    const realStore    = makeNonceStore();
    const anomalyStore = makeOpenAnomalyStore();
    const brokenStore  = redisDownNonceStore();

    let successCount = 0;
    let failCount    = 0;

    // 5 healthy
    for (let i = 0; i < 5; i++) {
      const artifact = freshArtifact();
      const result   = await validate(artifact, BASE_REQUEST, { nonceStore: realStore, anomalyStore });
      if (result.allowed) successCount++;
    }

    // 5 broken
    for (let i = 0; i < 5; i++) {
      const artifact = freshArtifact();
      const result   = await validate(artifact, BASE_REQUEST, { nonceStore: brokenStore, anomalyStore });
      if (!result.allowed) failCount++;
    }

    expect(successCount).toBe(5);
    expect(failCount).toBe(5);
  });
});

// ── CHAOS-09: Store recovery ──────────────────────────────────────────────────

describe('CHAOS-09 Store recovery — store down then fresh store → requests allowed', () => {

  test('CHAOS-09a  store goes down, then recovered, requests succeed again', async () => {
    const anomalyStore = makeOpenAnomalyStore();

    // healthy
    const healthyStore = makeNonceStore();
    const art1 = freshArtifact();
    const r1 = await validate(art1, BASE_REQUEST, { nonceStore: healthyStore, anomalyStore });
    expect(r1.allowed).toBe(true);

    // store fails
    const brokenStore = redisDownNonceStore();
    const art2 = freshArtifact();
    const r2 = await validate(art2, BASE_REQUEST, { nonceStore: brokenStore, anomalyStore });
    expect(r2.allowed).toBe(false);
    expect(r2.reason).toBe('NONCE_STORE_ERROR');

    // new store injected (recovery) — fresh store knows nothing of previous nonces
    const recoveredStore = makeNonceStore();
    const art3 = freshArtifact();
    const r3 = await validate(art3, BASE_REQUEST, { nonceStore: recoveredStore, anomalyStore });
    expect(r3.allowed).toBe(true);
  });

  test('CHAOS-09b  repeated down/up cycles all resolve correctly', async () => {
    const anomalyStore = makeOpenAnomalyStore();

    for (let cycle = 0; cycle < 3; cycle++) {
      // Up
      const store = makeNonceStore();
      const artUp = freshArtifact();
      const rUp   = await validate(artUp, BASE_REQUEST, { nonceStore: store, anomalyStore });
      expect(rUp.allowed).toBe(true);

      // Down
      const broken = redisDownNonceStore();
      const artDown = freshArtifact();
      const rDown   = await validate(artDown, BASE_REQUEST, { nonceStore: broken, anomalyStore });
      expect(rDown.allowed).toBe(false);
    }
  });
});

// ── CHAOS-10: Anomaly store latency ──────────────────────────────────────────

describe('CHAOS-10 Anomaly store with 50ms latency — correct result, just slower', () => {

  test('CHAOS-10a  latent anomaly store → { allowed: true } for valid request', async () => {
    const realAnomaly   = makeOpenAnomalyStore();
    const latentAnomaly = redisLatencyAnomalyStore(realAnomaly, 50);

    const artifact = freshArtifact();
    const start    = Date.now();
    const result   = await validate(artifact, BASE_REQUEST, {
      nonceStore:   makeNonceStore(),
      anomalyStore: latentAnomaly,
    });
    const elapsed = Date.now() - start;

    expect(result.allowed).toBe(true);
    expect(elapsed).toBeGreaterThanOrEqual(45);
  });

  test('CHAOS-10b  latent anomaly store still forwards calls to underlying store', async () => {
    // Build a manual latency wrapper that correctly forwards all arguments.
    // This tests that the latency layer does not suppress or alter results.
    const calls = [];
    const spyStore = {
      async record(...args) { calls.push({ method: 'record', args }); return { count: 1 }; },
      async peek(...args)   { calls.push({ method: 'peek',   args }); return { count: 1 }; },
    };
    const latentAnomaly = redisLatencyAnomalyStore(spyStore, 50);

    const artifact = freshArtifact();
    const result   = await validate(artifact, BASE_REQUEST, {
      nonceStore:   makeNonceStore(),
      anomalyStore: latentAnomaly,
    });

    // The anomaly check makes exactly 2 record() calls (per-key + global)
    const recordCalls = calls.filter(c => c.method === 'record');
    expect(recordCalls.length).toBe(2);
    // Result should be allowed (counts are 1 which is below defaults)
    expect(result.allowed).toBe(true);
  });

  test('CHAOS-10c  5 sequential requests with 50ms latency anomaly store → all succeed', async () => {
    const realAnomaly   = makeOpenAnomalyStore();
    const latentAnomaly = redisLatencyAnomalyStore(realAnomaly, 50);

    for (let i = 0; i < 5; i++) {
      const artifact = freshArtifact();
      const result   = await validate(artifact, BASE_REQUEST, {
        nonceStore:   makeNonceStore(),
        anomalyStore: latentAnomaly,
      });
      expect(result.allowed).toBe(true);
    }
  });
});
