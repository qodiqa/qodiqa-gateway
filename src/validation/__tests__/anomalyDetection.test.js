'use strict';

/**
 * Anomaly detection test suite — QODIQA V2
 *
 * Tests the sliding-window rate enforcement layer:
 *   SIGNATURE_BURST — per-publicKeyId request rate
 *   RATE_BURST      — global request rate
 *
 * The anomaly store is injected via _anomalyStore / _store in every test —
 * no Redis required.  The in-memory test store uses timestamp arrays that
 * correctly model a true sliding window (not a tumbling window).
 *
 * Test categories:
 *   1.  Signature burst — per-key window
 *   2.  Rate burst — global window
 *   3.  Boundary conditions (exactly at threshold vs. one over)
 *   4.  Parallel flood (Promise.all concurrency)
 *   5.  Reset resistance (time advancement clears old events)
 *   6.  Store failure (fail-closed)
 *   7.  checkAnomaly — input validation
 *   8.  validateBoundRequest — full pipeline with anomaly step
 */

const { checkAnomaly, DEFAULT_THRESHOLDS } = require('../checkAnomaly');
const { validateBoundRequest }             = require('../validateBoundRequest');
const { signBoundArtifact }                = require('../signBoundArtifact');
const { getActiveKey }                     = require('../../../services/artifact/keyStore');

// ── In-memory test store ──────────────────────────────────────────────────────

/**
 * True sliding-window store backed by timestamp arrays.
 * Faithfully models anomalyStore.js Redis sorted-set behavior:
 *   • record() evicts events older than the window then appends the new one
 *   • count is the number of events remaining in the window after eviction
 *   • Two callers sharing the same store instance share the same windows
 */
function makeTestAnomalyStore() {
  const windows = new Map(); // key → [timestamp, ...]
  return {
    async record(key, nowMs, windowMs) {
      const existing = windows.get(key) || [];
      const fresh    = existing.filter(t => t > nowMs - windowMs);
      fresh.push(nowMs);
      windows.set(key, fresh);
      return { count: fresh.length };
    },
    _windows: windows,
    _reset(key) { windows.delete(key); },
    _resetAll() { windows.clear(); },
  };
}

/**
 * Store that always throws — models Redis unavailability.
 */
function makeBrokenStore() {
  return {
    async record() { throw new Error('ECONREFUSED: anomaly store unreachable'); },
  };
}

/**
 * Store that throws only for global key.
 */
function makePartiallyBrokenStore() {
  const windows = new Map();
  return {
    async record(key, nowMs, windowMs) {
      if (key === 'global') throw new Error('ETIMEDOUT: global store failed');
      const existing = windows.get(key) || [];
      const fresh    = existing.filter(t => t > nowMs - windowMs);
      fresh.push(nowMs);
      windows.set(key, fresh);
      return { count: fresh.length };
    },
  };
}

// ── Shared fixtures ───────────────────────────────────────────────────────────

let KEY;

beforeAll(() => {
  KEY = getActiveKey('default');
});

function freshEnvelope(payload = {}) {
  const now = Date.now();
  return {
    payload,
    timestamp:   now,
    expiry:      now + 300_000,
    publicKeyId: KEY.keyId,
  };
}

function buildBound(request, extraPayload = {}) {
  return signBoundArtifact(request, freshEnvelope(extraPayload), KEY.privDer);
}

const BASE_REQ = { method: 'POST', path: '/api/run', body: { q: 1 } };

// Tight thresholds for fast tests
const T = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 5, GLOBAL_MAX: 10 });

// ── 1. Signature burst — per-key ──────────────────────────────────────────────

describe('anomaly detection — SIGNATURE_BURST (per-key)', () => {

  test('BURST-01  requests within threshold are allowed', async () => {
    const store = makeTestAnomalyStore();
    for (let i = 0; i < T.PER_KEY_MAX; i++) {
      const result = await checkAnomaly('keyA', { _store: store, _thresholds: T });
      expect(result.block).toBe(false);
    }
  });

  test('BURST-02  one request over threshold is blocked as SIGNATURE_BURST', async () => {
    const store = makeTestAnomalyStore();
    for (let i = 0; i < T.PER_KEY_MAX; i++) {
      await checkAnomaly('keyA', { _store: store, _thresholds: T });
    }
    const result = await checkAnomaly('keyA', { _store: store, _thresholds: T });
    expect(result.block).toBe(true);
    expect(result.reason).toBe('ANOMALY_DETECTED');
    expect(result.type).toBe('SIGNATURE_BURST');
  });

  test('BURST-03  burst on keyA does not affect keyB', async () => {
    const store = makeTestAnomalyStore();
    // Saturate keyA
    for (let i = 0; i <= T.PER_KEY_MAX; i++) {
      await checkAnomaly('keyA', { _store: store, _thresholds: T });
    }
    // keyB should still be clear (global not yet saturated in this scenario)
    // Note: keyB also increments global; as long as global < GLOBAL_MAX, keyB passes
    const result = await checkAnomaly('keyB', { _store: store, _thresholds: T });
    // keyA used PER_KEY_MAX+1 = 6 events, keyB used 1; global = 7 < 10
    expect(result.block).toBe(false);
  });

  test('BURST-04  each key tracks its own independent window', async () => {
    const store  = makeTestAnomalyStore();
    // GLOBAL_MAX must exceed total events across all keys to avoid triggering RATE_BURST.
    // 3 keys × (PER_KEY_MAX + 1 blocking call) = 3 × 6 = 18 → use 1_000.
    const thresh = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 5, GLOBAL_MAX: 1_000 });
    const keys   = ['k1', 'k2', 'k3'];
    for (const k of keys) {
      for (let i = 0; i < thresh.PER_KEY_MAX; i++) {
        const r = await checkAnomaly(k, { _store: store, _thresholds: thresh });
        expect(r.block).toBe(false);
      }
    }
    // Each key at exactly PER_KEY_MAX; next call to each should block
    for (const k of keys) {
      const r = await checkAnomaly(k, { _store: store, _thresholds: thresh });
      expect(r.block).toBe(true);
      expect(r.type).toBe('SIGNATURE_BURST');
    }
  });

});

// ── 2. Rate burst — global ────────────────────────────────────────────────────

describe('anomaly detection — RATE_BURST (global)', () => {

  test('GLOBAL-01  global burst blocks even a fresh key', async () => {
    const store       = makeTestAnomalyStore();
    const bigThresh   = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 1_000, GLOBAL_MAX: 5 });
    // Send 5 requests across 5 different keys (per-key never bursts)
    for (let i = 0; i < bigThresh.GLOBAL_MAX; i++) {
      const r = await checkAnomaly(`key${i}`, { _store: store, _thresholds: bigThresh });
      expect(r.block).toBe(false);
    }
    // Next request on a brand-new key — global window is full
    const result = await checkAnomaly('keyNew', { _store: store, _thresholds: bigThresh });
    expect(result.block).toBe(true);
    expect(result.reason).toBe('ANOMALY_DETECTED');
    expect(result.type).toBe('RATE_BURST');
  });

  test('GLOBAL-02  SIGNATURE_BURST takes precedence over RATE_BURST when both would trigger', async () => {
    const store  = makeTestAnomalyStore();
    const thresh = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 2, GLOBAL_MAX: 2 });
    // Use keyA 2 times (fills per-key AND global)
    for (let i = 0; i < thresh.PER_KEY_MAX; i++) {
      await checkAnomaly('keyA', { _store: store, _thresholds: thresh });
    }
    // Third call on keyA — per-key check runs first
    const result = await checkAnomaly('keyA', { _store: store, _thresholds: thresh });
    expect(result.block).toBe(true);
    expect(result.type).toBe('SIGNATURE_BURST');
  });

  test('GLOBAL-03  global counter increments regardless of which key triggers', async () => {
    const store  = makeTestAnomalyStore();
    const thresh = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 1_000, GLOBAL_MAX: 3 });
    await checkAnomaly('k1', { _store: store, _thresholds: thresh });
    await checkAnomaly('k2', { _store: store, _thresholds: thresh });
    await checkAnomaly('k3', { _store: store, _thresholds: thresh });
    const result = await checkAnomaly('k4', { _store: store, _thresholds: thresh });
    expect(result.block).toBe(true);
    expect(result.type).toBe('RATE_BURST');
  });

});

// ── 3. Boundary conditions ─────────────────────────────────────────────────────

describe('anomaly detection — boundary conditions', () => {

  test('BOUND-01  exactly at PER_KEY_MAX is allowed; one over is blocked', async () => {
    const store = makeTestAnomalyStore();
    const thresh = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 3, GLOBAL_MAX: 1_000 });

    for (let i = 0; i < thresh.PER_KEY_MAX; i++) {
      const r = await checkAnomaly('k', { _store: store, _thresholds: thresh });
      expect(r.block).toBe(false);
    }
    const r = await checkAnomaly('k', { _store: store, _thresholds: thresh });
    expect(r.block).toBe(true);
    expect(r.type).toBe('SIGNATURE_BURST');
  });

  test('BOUND-02  exactly at GLOBAL_MAX is allowed; one over is blocked', async () => {
    const store  = makeTestAnomalyStore();
    const thresh = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 1_000, GLOBAL_MAX: 4 });

    for (let i = 0; i < thresh.GLOBAL_MAX; i++) {
      const r = await checkAnomaly(`k${i}`, { _store: store, _thresholds: thresh });
      expect(r.block).toBe(false);
    }
    const r = await checkAnomaly('kOver', { _store: store, _thresholds: thresh });
    expect(r.block).toBe(true);
    expect(r.type).toBe('RATE_BURST');
  });

  test('BOUND-03  events outside the window do not count (sliding, not tumbling)', async () => {
    const store  = makeTestAnomalyStore();
    const thresh = Object.freeze({ WINDOW_MS: 1_000, PER_KEY_MAX: 3, GLOBAL_MAX: 1_000 });
    const t0     = Date.now();

    // Send 3 events in the "past" (2 seconds ago — outside 1s window)
    for (let i = 0; i < thresh.PER_KEY_MAX; i++) {
      await store.record('key:myKey', t0 - 2_000, thresh.WINDOW_MS);
      await store.record('global',   t0 - 2_000, thresh.WINDOW_MS);
    }

    // Current-time request should see an empty window
    const result = await checkAnomaly('myKey', {
      _store:      store,
      _clock:      () => t0,
      _thresholds: thresh,
    });
    expect(result.block).toBe(false);
  });

  test('BOUND-04  events at window edge (exactly at cutoff) are evicted', async () => {
    const store  = makeTestAnomalyStore();
    const thresh = Object.freeze({ WINDOW_MS: 1_000, PER_KEY_MAX: 2, GLOBAL_MAX: 1_000 });
    const t0     = 1_000_000;

    // Place events at exactly the cutoff boundary (t = t0 - windowMs)
    // The sliding window evicts events where t <= cutoff (t <= t0 - windowMs)
    // Event at t0 - windowMs is at the boundary — it should be evicted
    await store.record('key:myKey', t0 - thresh.WINDOW_MS, thresh.WINDOW_MS);
    await store.record('global',   t0 - thresh.WINDOW_MS, thresh.WINDOW_MS);

    // Two more within window
    await store.record('key:myKey', t0 - 100, thresh.WINDOW_MS);
    await store.record('global',   t0 - 100, thresh.WINDOW_MS);

    // Now at t0 — the boundary event is gone, window has 1 event + the new one = 2
    const result = await checkAnomaly('myKey', {
      _store:      store,
      _clock:      () => t0,
      _thresholds: thresh,
    });
    expect(result.block).toBe(false);
  });

  test('BOUND-05  threshold of 1 — second request always blocks', async () => {
    const store  = makeTestAnomalyStore();
    const thresh = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 1, GLOBAL_MAX: 1_000 });
    const r1 = await checkAnomaly('k', { _store: store, _thresholds: thresh });
    expect(r1.block).toBe(false);
    const r2 = await checkAnomaly('k', { _store: store, _thresholds: thresh });
    expect(r2.block).toBe(true);
    expect(r2.type).toBe('SIGNATURE_BURST');
  });

});

// ── 4. Parallel flood ─────────────────────────────────────────────────────────

describe('anomaly detection — parallel flood', () => {

  test('PARA-01  100 concurrent requests on one key — exactly PER_KEY_MAX pass', async () => {
    const store  = makeTestAnomalyStore();
    const thresh = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 10, GLOBAL_MAX: 1_000 });
    const now    = Date.now();

    const results = await Promise.all(
      Array.from({ length: 100 }, () =>
        checkAnomaly('floodKey', { _store: store, _clock: () => now, _thresholds: thresh }),
      ),
    );

    const allowed = results.filter(r => !r.block).length;
    const blocked = results.filter(r =>  r.block && r.type === 'SIGNATURE_BURST').length;

    // Exactly PER_KEY_MAX allowed; the rest blocked as SIGNATURE_BURST
    expect(allowed).toBe(thresh.PER_KEY_MAX);
    expect(blocked).toBe(100 - thresh.PER_KEY_MAX);
  });

  test('PARA-02  concurrent requests across keys respect global window', async () => {
    const store  = makeTestAnomalyStore();
    const thresh = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 1_000, GLOBAL_MAX: 20 });
    const now    = Date.now();

    // 50 requests spread across 5 keys (10 per key — stays under PER_KEY_MAX)
    const results = await Promise.all(
      Array.from({ length: 50 }, (_, i) =>
        checkAnomaly(`key${i % 5}`, { _store: store, _clock: () => now, _thresholds: thresh }),
      ),
    );

    const allowed = results.filter(r => !r.block).length;
    const blocked = results.filter(r =>  r.block && r.type === 'RATE_BURST').length;

    expect(allowed).toBe(thresh.GLOBAL_MAX);
    expect(blocked).toBe(50 - thresh.GLOBAL_MAX);
  });

  test('PARA-03  no double-counting — exactly one allowed per threshold slot', async () => {
    const store  = makeTestAnomalyStore();
    const thresh = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 5, GLOBAL_MAX: 1_000 });
    const now    = Date.now();

    // 5 concurrent requests to the same key at the same timestamp
    const results = await Promise.all(
      Array.from({ length: 5 }, () =>
        checkAnomaly('k', { _store: store, _clock: () => now, _thresholds: thresh }),
      ),
    );

    // All 5 should be allowed (count goes 1→2→3→4→5, never exceeds 5)
    expect(results.every(r => !r.block)).toBe(true);

    // Sixth request should be blocked
    const sixth = await checkAnomaly('k', { _store: store, _clock: () => now, _thresholds: thresh });
    expect(sixth.block).toBe(true);
    expect(sixth.type).toBe('SIGNATURE_BURST');
  });

});

// ── 5. Reset resistance (sliding window eviction) ─────────────────────────────

describe('anomaly detection — reset resistance', () => {

  test('RESET-01  window advances — old events expire and key is no longer blocked', async () => {
    const store  = makeTestAnomalyStore();
    const thresh = Object.freeze({ WINDOW_MS: 1_000, PER_KEY_MAX: 3, GLOBAL_MAX: 1_000 });
    const t0     = 1_000_000;

    // Fill the window
    for (let i = 0; i < thresh.PER_KEY_MAX; i++) {
      await checkAnomaly('k', { _store: store, _clock: () => t0, _thresholds: thresh });
    }
    // Blocked at t0
    const blocked = await checkAnomaly('k', { _store: store, _clock: () => t0, _thresholds: thresh });
    expect(blocked.block).toBe(true);

    // Advance time past the window
    const t1 = t0 + thresh.WINDOW_MS + 1;
    const clear = await checkAnomaly('k', { _store: store, _clock: () => t1, _thresholds: thresh });
    expect(clear.block).toBe(false);
  });

  test('RESET-02  partial window advance — only expired events are evicted', async () => {
    const store  = makeTestAnomalyStore();
    const thresh = Object.freeze({ WINDOW_MS: 1_000, PER_KEY_MAX: 3, GLOBAL_MAX: 1_000 });
    const t0     = 2_000_000;

    // 2 events at t0 (will still be in window at t0+500)
    await checkAnomaly('k', { _store: store, _clock: () => t0,       _thresholds: thresh });
    await checkAnomaly('k', { _store: store, _clock: () => t0,       _thresholds: thresh });
    // 2 events at t0-900 (will be evicted at t0+500 since 900+500=1400 > 1000)
    await store.record('key:k', t0 - 900, thresh.WINDOW_MS);
    await store.record('global', t0 - 900, thresh.WINDOW_MS);
    await store.record('key:k', t0 - 900, thresh.WINDOW_MS);
    await store.record('global', t0 - 900, thresh.WINDOW_MS);

    // At t0+500: old events are evicted; window contains only the 2 from t0
    const t1     = t0 + 500;
    const result = await checkAnomaly('k', { _store: store, _clock: () => t1, _thresholds: thresh });
    // 2 surviving + 1 new = 3 ≤ PER_KEY_MAX(3) → allowed
    expect(result.block).toBe(false);
  });

  test('RESET-03  attacker cannot reset the counter by waiting less than the window', async () => {
    const store  = makeTestAnomalyStore();
    const thresh = Object.freeze({ WINDOW_MS: 1_000, PER_KEY_MAX: 3, GLOBAL_MAX: 1_000 });
    const t0     = 3_000_000;

    // Fill window at t0
    for (let i = 0; i < thresh.PER_KEY_MAX; i++) {
      await checkAnomaly('k', { _store: store, _clock: () => t0, _thresholds: thresh });
    }
    // Wait 500ms (half the window) — old events still present
    const t1     = t0 + 500;
    const result = await checkAnomaly('k', { _store: store, _clock: () => t1, _thresholds: thresh });
    expect(result.block).toBe(true);
    expect(result.type).toBe('SIGNATURE_BURST');
  });

  test('RESET-04  global window resets correctly after all events expire', async () => {
    const store  = makeTestAnomalyStore();
    const thresh = Object.freeze({ WINDOW_MS: 1_000, PER_KEY_MAX: 1_000, GLOBAL_MAX: 3 });
    const t0     = 4_000_000;

    // Fill global window
    for (let i = 0; i < thresh.GLOBAL_MAX; i++) {
      await checkAnomaly(`k${i}`, { _store: store, _clock: () => t0, _thresholds: thresh });
    }
    const blocked = await checkAnomaly('kNew', { _store: store, _clock: () => t0, _thresholds: thresh });
    expect(blocked.block).toBe(true);
    expect(blocked.type).toBe('RATE_BURST');

    // Advance past window
    const t1    = t0 + thresh.WINDOW_MS + 1;
    const clear = await checkAnomaly('kNew', { _store: store, _clock: () => t1, _thresholds: thresh });
    expect(clear.block).toBe(false);
  });

});

// ── 6. Store failure (fail-closed) ────────────────────────────────────────────

describe('anomaly detection — store failure (fail-closed)', () => {

  test('FAIL-01  store throws → block with type STORE_ERROR', async () => {
    const store  = makeBrokenStore();
    const result = await checkAnomaly('k', { _store: store, _thresholds: T });
    expect(result.block).toBe(true);
    expect(result.reason).toBe('ANOMALY_DETECTED');
    expect(result.type).toBe('STORE_ERROR');
    expect(result.error).toMatch(/ECONREFUSED/);
  });

  test('FAIL-02  global store error after per-key succeeds → fail-closed', async () => {
    const store  = makePartiallyBrokenStore();
    const result = await checkAnomaly('k', { _store: store, _thresholds: T });
    expect(result.block).toBe(true);
    expect(result.type).toBe('STORE_ERROR');
  });

  test('FAIL-03  unavailable store never returns allowed', async () => {
    const store   = makeBrokenStore();
    const results = await Promise.all(
      Array.from({ length: 20 }, () => checkAnomaly('k', { _store: store, _thresholds: T })),
    );
    expect(results.every(r => r.block)).toBe(true);
  });

});

// ── 7. checkAnomaly — input validation ────────────────────────────────────────

describe('checkAnomaly — input validation', () => {

  test('INPUT-01  empty publicKeyId → blocked as STORE_ERROR', async () => {
    const store  = makeTestAnomalyStore();
    const result = await checkAnomaly('', { _store: store, _thresholds: T });
    expect(result.block).toBe(true);
    expect(result.type).toBe('STORE_ERROR');
  });

  test('INPUT-02  non-string publicKeyId → blocked as STORE_ERROR', async () => {
    const store  = makeTestAnomalyStore();
    const result = await checkAnomaly(null, { _store: store, _thresholds: T });
    expect(result.block).toBe(true);
    expect(result.type).toBe('STORE_ERROR');
  });

  test('INPUT-03  numeric publicKeyId → blocked as STORE_ERROR', async () => {
    const store  = makeTestAnomalyStore();
    const result = await checkAnomaly(123, { _store: store, _thresholds: T });
    expect(result.block).toBe(true);
    expect(result.type).toBe('STORE_ERROR');
  });

  test('INPUT-04  valid publicKeyId with default thresholds → block or allow (no throw)', async () => {
    const store = makeTestAnomalyStore();
    const result = await checkAnomaly('validKeyId', { _store: store });
    expect(typeof result.block).toBe('boolean');
  });

});

// ── 8. validateBoundRequest — full pipeline with anomaly step ─────────────────

describe('validateBoundRequest — anomaly detection integration', () => {

  function makeNonceStore() {
    const map = new Map();
    return {
      async register(requestId, expiryMs) {
        if (map.has(requestId)) return { registered: false };
        map.set(requestId, expiryMs);
        return { registered: true };
      },
    };
  }

  test('PIPE-01  valid request below threshold → allowed: true', async () => {
    const anomalyStore = makeTestAnomalyStore();
    const nonceStore   = makeNonceStore();
    const artifact     = buildBound(BASE_REQ);

    const result = await validateBoundRequest(artifact, BASE_REQ, {
      _store:        nonceStore,
      _anomalyStore: anomalyStore,
      _thresholds:   T,
    });
    expect(result.allowed).toBe(true);
    expect(result.publicKeyId).toBe(KEY.keyId);
  });

  test('PIPE-02  burst beyond per-key threshold → allowed: false, reason: ANOMALY_DETECTED', async () => {
    const anomalyStore = makeTestAnomalyStore();
    const thresh       = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 2, GLOBAL_MAX: 1_000 });

    // Pre-fill the per-key window using tenant-scoped key
    const tenantId = KEY.keyId.split(':')[0];
    const now = Date.now();
    for (let i = 0; i < thresh.PER_KEY_MAX; i++) {
      await anomalyStore.record(`tenant:${tenantId}:key:${KEY.keyId}`, now, thresh.WINDOW_MS);
    }

    const nonceStore = makeNonceStore();
    const artifact   = buildBound(BASE_REQ);

    const result = await validateBoundRequest(artifact, BASE_REQ, {
      _store:        nonceStore,
      _anomalyStore: anomalyStore,
      _thresholds:   thresh,
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('ANOMALY_DETECTED');
    expect(result.details.type).toBe('SIGNATURE_BURST');
  });

  test('PIPE-03  anomaly check runs AFTER nonce registration — nonce is already consumed on anomaly block', async () => {
    const anomalyStore = makeTestAnomalyStore();
    const nonceStore   = makeNonceStore();
    const thresh       = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 0, GLOBAL_MAX: 1_000 });
    const artifact     = buildBound(BASE_REQ);

    // PER_KEY_MAX=0 means first request is already over threshold
    const result = await validateBoundRequest(artifact, BASE_REQ, {
      _store:        nonceStore,
      _anomalyStore: anomalyStore,
      _thresholds:   thresh,
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('ANOMALY_DETECTED');

    // The requestId was registered before the anomaly check — it is now burned
    const replay = await validateBoundRequest(artifact, BASE_REQ, {
      _store:        nonceStore,
      _anomalyStore: anomalyStore,
      _thresholds:   thresh,
    });
    expect(replay.allowed).toBe(false);
    expect(replay.reason).toBe('REPLAY_DETECTED');
  });

  test('PIPE-04  failed binding check does NOT consume anomaly quota', async () => {
    const anomalyStore = makeTestAnomalyStore();
    const nonceStore   = makeNonceStore();
    const thresh       = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 1, GLOBAL_MAX: 1_000 });

    const artifact  = buildBound(BASE_REQ);
    const wrongReq  = { method: 'GET', path: '/other', body: {} };

    // Step 2 fails (request mismatch) — anomaly store should NOT be touched
    await validateBoundRequest(artifact, wrongReq, {
      _store:        nonceStore,
      _anomalyStore: anomalyStore,
      _thresholds:   thresh,
    });

    // Anomaly windows should be empty
    const keyWindow    = anomalyStore._windows.get(`key:${KEY.keyId}`);
    const globalWindow = anomalyStore._windows.get('global');
    expect(keyWindow).toBeUndefined();
    expect(globalWindow).toBeUndefined();
  });

  test('PIPE-05  failed signature check does NOT consume anomaly quota', async () => {
    const anomalyStore = makeTestAnomalyStore();
    const nonceStore   = makeNonceStore();

    // Pass garbage as artifact — step 1 fails immediately
    await validateBoundRequest({ not: 'valid' }, BASE_REQ, {
      _store:        nonceStore,
      _anomalyStore: anomalyStore,
      _thresholds:   T,
    });

    expect(anomalyStore._windows.size).toBe(0);
  });

  test('PIPE-06  anomaly store failure → ANOMALY_DETECTED, request blocked', async () => {
    const anomalyStore = makeBrokenStore();
    const nonceStore   = makeNonceStore();
    const artifact     = buildBound(BASE_REQ);

    const result = await validateBoundRequest(artifact, BASE_REQ, {
      _store:        nonceStore,
      _anomalyStore: anomalyStore,
      _thresholds:   T,
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('ANOMALY_DETECTED');
    expect(result.details.type).toBe('STORE_ERROR');
  });

  test('PIPE-07  sequential valid requests each get unique requestIds and all pass', async () => {
    const anomalyStore = makeTestAnomalyStore();
    const nonceStore   = makeNonceStore();
    const thresh       = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 10, GLOBAL_MAX: 100 });

    for (let i = 0; i < 5; i++) {
      const artifact = buildBound({ method: 'POST', path: '/api/run', body: { i } });
      const result   = await validateBoundRequest(artifact, { method: 'POST', path: '/api/run', body: { i } }, {
        _store:        nonceStore,
        _anomalyStore: anomalyStore,
        _thresholds:   thresh,
      });
      expect(result.allowed).toBe(true);
    }
  });

  test('PIPE-08  global burst blocks requests from multiple distinct keys', async () => {
    const anomalyStore = makeTestAnomalyStore();
    const thresh       = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 1_000, GLOBAL_MAX: 2 });
    const now          = Date.now();

    // Pre-fill global window using tenant-scoped key
    const tenantId = KEY.keyId.split(':')[0];
    for (let i = 0; i < thresh.GLOBAL_MAX; i++) {
      await anomalyStore.record(`tenant:${tenantId}:global`, now, thresh.WINDOW_MS);
    }

    const nonceStore = makeNonceStore();
    const artifact   = buildBound(BASE_REQ);

    const result = await validateBoundRequest(artifact, BASE_REQ, {
      _store:        nonceStore,
      _anomalyStore: anomalyStore,
      _thresholds:   thresh,
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('ANOMALY_DETECTED');
    expect(result.details.type).toBe('RATE_BURST');
  });

});

// ── 9. Item 17 pipelining lock-in — sequential path ───────────────────────────
//
// Written and confirmed passing against the unmodified sequential
// registerNonce() -> checkAnomaly() implementation BEFORE the combined-Lua
// path (item 17) existed. Kept byte-unchanged afterward — the _store/
// _anomalyStore overrides below always route validateBoundRequest through
// the sequential branch (see validateBoundRequest.js), so this suite proves
// the sequential path's semantics never drifted, independent of anything
// item 17 adds. Case (b) restates PIPE-03 under an item-17-traceable name;
// it is intentionally redundant with PIPE-03, not a replacement for it.

describe('validateBoundRequest — item 17 pipelining lock-in (sequential path)', () => {

  function makeNonceStore() {
    const map = new Map();
    return {
      async register(requestId, expiryMs) {
        if (map.has(requestId)) return { registered: false };
        map.set(requestId, expiryMs);
        return { registered: true };
      },
    };
  }

  test('ITEM17-A  replayed nonce -> rejected; anomaly state unaffected by the replay attempt', async () => {
    const anomalyStore = makeTestAnomalyStore();
    const nonceStore   = makeNonceStore();
    const artifact      = buildBound(BASE_REQ);
    const tenantId       = KEY.keyId.split(':')[0];
    const perKeyWindow    = `tenant:${tenantId}:key:${KEY.keyId}`;
    const globalWindow    = `tenant:${tenantId}:global`;

    const first = await validateBoundRequest(artifact, BASE_REQ, {
      _store: nonceStore, _anomalyStore: anomalyStore, _thresholds: T,
    });
    expect(first.allowed).toBe(true);

    const keyCountAfterFirst    = anomalyStore._windows.get(perKeyWindow).length;
    const globalCountAfterFirst = anomalyStore._windows.get(globalWindow).length;

    const replay = await validateBoundRequest(artifact, BASE_REQ, {
      _store: nonceStore, _anomalyStore: anomalyStore, _thresholds: T,
    });
    expect(replay.allowed).toBe(false);
    expect(replay.reason).toBe('REPLAY_DETECTED');

    // Nonce failure blocks before step 4 ever runs — anomaly windows must be
    // exactly as they were after the first (legitimate) request.
    expect(anomalyStore._windows.get(perKeyWindow).length).toBe(keyCountAfterFirst);
    expect(anomalyStore._windows.get(globalWindow).length).toBe(globalCountAfterFirst);
  });

  test('ITEM17-B  anomaly limit hit -> rejected; nonce stays registered (burned), matching PIPE-03', async () => {
    const anomalyStore = makeTestAnomalyStore();
    const nonceStore   = makeNonceStore();
    const thresh       = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 0, GLOBAL_MAX: 1_000 });
    const artifact      = buildBound(BASE_REQ);

    const blocked = await validateBoundRequest(artifact, BASE_REQ, {
      _store: nonceStore, _anomalyStore: anomalyStore, _thresholds: thresh,
    });
    expect(blocked.allowed).toBe(false);
    expect(blocked.reason).toBe('ANOMALY_DETECTED');

    // Nonce was registered in step 3 before the anomaly block in step 4 —
    // it stays burned; a second attempt with the same artifact is a replay,
    // never another chance at the anomaly check.
    const replay = await validateBoundRequest(artifact, BASE_REQ, {
      _store: nonceStore, _anomalyStore: anomalyStore, _thresholds: thresh,
    });
    expect(replay.allowed).toBe(false);
    expect(replay.reason).toBe('REPLAY_DETECTED');
  });

  test('ITEM17-C  both checks pass -> both are recorded (nonce burned, anomaly windows incremented)', async () => {
    const anomalyStore = makeTestAnomalyStore();
    const nonceStore   = makeNonceStore();
    const artifact      = buildBound(BASE_REQ);
    const tenantId       = KEY.keyId.split(':')[0];
    const perKeyWindow    = `tenant:${tenantId}:key:${KEY.keyId}`;
    const globalWindow    = `tenant:${tenantId}:global`;

    const result = await validateBoundRequest(artifact, BASE_REQ, {
      _store: nonceStore, _anomalyStore: anomalyStore, _thresholds: T,
    });
    expect(result.allowed).toBe(true);

    // Anomaly recorded — exactly one event in each window for this key.
    expect(anomalyStore._windows.get(perKeyWindow).length).toBe(1);
    expect(anomalyStore._windows.get(globalWindow).length).toBe(1);

    // Nonce recorded — replay with the same artifact is rejected.
    const replay = await validateBoundRequest(artifact, BASE_REQ, {
      _store: nonceStore, _anomalyStore: anomalyStore, _thresholds: T,
    });
    expect(replay.allowed).toBe(false);
    expect(replay.reason).toBe('REPLAY_DETECTED');
  });

});

// ── 10. Item 17 pipelining lock-in — combined path re-verification ───────────
//
// Same cases as the sequential-path suite above (§9), plus PIPE-03 itself,
// re-run through validateBoundRequest's _combined override (forces the
// combined-Lua branch — see validateBoundRequest.js). makeCombinedStore()
// is a faithful in-memory mirror of nonceStore.js's COMBINED_REGISTER_SCRIPT
// (SET-NX -> per-key slide -> global slide, same early-exit order), the
// same level of fidelity nonceStore.test.js's fake Redis .eval() uses.
// Written AFTER the combined path existed — these re-verify, they don't
// lock in the sequential implementation (§9 already does that).

describe('validateBoundRequest — item 17 pipelining lock-in (combined path re-verification)', () => {

  function makeCombinedStore() {
    const nonces = new Map();
    const windows = new Map();

    function slide(key, nowMs, windowMs) {
      const fresh = (windows.get(key) || []).filter(t => t > nowMs - windowMs);
      fresh.push(nowMs);
      windows.set(key, fresh);
      return fresh.length;
    }

    return {
      async registerAndCheckAnomaly(requestId, expiryMs, tenantId, { publicKeyId, nowMs, windowMs, perKeyMax, globalMax }) {
        if (nonces.has(requestId)) return { phase: 'REPLAY' };
        nonces.set(requestId, true);

        const prefix    = tenantId ? `tenant:${tenantId}:` : '';
        const perKeyKey = `${prefix}key:${publicKeyId}`;
        const globalKey = `${prefix}global`;

        const perKeyCount = slide(perKeyKey, nowMs, windowMs);
        if (perKeyCount > perKeyMax) return { phase: 'SIGNATURE_BURST', perKeyCount };

        const globalCount = slide(globalKey, nowMs, windowMs);
        if (globalCount > globalMax) return { phase: 'RATE_BURST', perKeyCount, globalCount };

        return { phase: 'ALLOWED', perKeyCount, globalCount };
      },
      _nonces:  nonces,
      _windows: windows,
    };
  }

  test('ITEM17-A (combined)  replayed nonce -> rejected; anomaly state unaffected by the replay attempt', async () => {
    const combined = makeCombinedStore();
    const artifact  = buildBound(BASE_REQ);
    const tenantId   = KEY.keyId.split(':')[0];
    const perKeyWindow = `tenant:${tenantId}:key:${KEY.keyId}`;

    const first = await validateBoundRequest(artifact, BASE_REQ, { _combined: combined, _thresholds: T });
    expect(first.allowed).toBe(true);
    const countAfterFirst = combined._windows.get(perKeyWindow).length;

    const replay = await validateBoundRequest(artifact, BASE_REQ, { _combined: combined, _thresholds: T });
    expect(replay.allowed).toBe(false);
    expect(replay.reason).toBe('REPLAY_DETECTED');
    expect(combined._windows.get(perKeyWindow).length).toBe(countAfterFirst);
  });

  test('ITEM17-B (combined)  anomaly limit hit -> rejected; nonce stays registered (burned) — restates PIPE-03', async () => {
    const combined = makeCombinedStore();
    const thresh    = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 0, GLOBAL_MAX: 1_000 });
    const artifact   = buildBound(BASE_REQ);

    const blocked = await validateBoundRequest(artifact, BASE_REQ, { _combined: combined, _thresholds: thresh });
    expect(blocked.allowed).toBe(false);
    expect(blocked.reason).toBe('ANOMALY_DETECTED');

    // PIPE-03's own assertion, re-run against the combined path: the nonce
    // registered inside the same EVAL that hit SIGNATURE_BURST stays burned.
    const replay = await validateBoundRequest(artifact, BASE_REQ, { _combined: combined, _thresholds: thresh });
    expect(replay.allowed).toBe(false);
    expect(replay.reason).toBe('REPLAY_DETECTED');
  });

  test('ITEM17-C (combined)  both checks pass -> both are recorded', async () => {
    const combined = makeCombinedStore();
    const artifact  = buildBound(BASE_REQ);
    const tenantId   = KEY.keyId.split(':')[0];
    const perKeyWindow = `tenant:${tenantId}:key:${KEY.keyId}`;
    const globalWindow = `tenant:${tenantId}:global`;

    const result = await validateBoundRequest(artifact, BASE_REQ, { _combined: combined, _thresholds: T });
    expect(result.allowed).toBe(true);
    expect(combined._windows.get(perKeyWindow).length).toBe(1);
    expect(combined._windows.get(globalWindow).length).toBe(1);

    const replay = await validateBoundRequest(artifact, BASE_REQ, { _combined: combined, _thresholds: T });
    expect(replay.allowed).toBe(false);
    expect(replay.reason).toBe('REPLAY_DETECTED');
  });

  test('PIPE-03 (combined)  anomaly check still only runs after nonce registration', async () => {
    const combined = makeCombinedStore();
    const thresh    = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 0, GLOBAL_MAX: 1_000 });
    const artifact   = buildBound(BASE_REQ);

    const result = await validateBoundRequest(artifact, BASE_REQ, { _combined: combined, _thresholds: thresh });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('ANOMALY_DETECTED');

    const replay = await validateBoundRequest(artifact, BASE_REQ, { _combined: combined, _thresholds: thresh });
    expect(replay.allowed).toBe(false);
    expect(replay.reason).toBe('REPLAY_DETECTED');
  });

});
