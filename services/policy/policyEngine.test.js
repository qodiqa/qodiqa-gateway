'use strict';

// Mock the consent registry so REQUIRE_CONSENT policy passes for valid artifacts
// without requiring a live Redis/PostgreSQL connection. These tests cover the
// policy ENGINE (rate limiting, IP blocking, time windows) — not the consent
// evaluator itself, which has dedicated tests in src/core/consent/.
jest.mock('../../src/core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

const { evaluate }          = require('./engine');
const { validateAndPrepare } = require('./loader');
const { createStore }        = require('./store');
const { computeRuleHash }    = require('../policyHash');

// ── Helpers ───────────────────────────────────────────────────────────────────

function policies(overrides = []) {
  return validateAndPrepare({ policies: [CONSENT_POLICY, ...overrides] });
}

function ctx(overrides = {}) {
  return {
    artifact:  { valid: true },
    userId:    'user-test',
    action:    'openai.chat.completions',
    ip:        '1.2.3.4',
    timestamp: WEEKDAY_NOON_UTC,
    ...overrides,
  };
}

// Monday 2025-01-06 12:00:00 UTC
const WEEKDAY_NOON_UTC = 1736164800;
// Saturday 2025-01-04 12:00:00 UTC
const WEEKEND_UTC      = 1735991800;

const CONSENT_POLICY = {
  id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
  config: { requireValidArtifact: true },
};

const BLOCK_IP_POLICY = {
  id: 'POL-BLOCK-IP', type: 'BLOCK_IP', priority: 20, enabled: true,
  config: { blocklist: ['5.5.5.5'], cidrs: ['192.168.0.0/16'] },
};

const TIME_POLICY = {
  id: 'POL-TIME', type: 'TIME_WINDOW', priority: 30, enabled: true,
  config: {
    allowedWindows: [
      { days: ['MON', 'TUE', 'WED', 'THU', 'FRI'], start: '09:00', end: '18:00' },
    ],
  },
};

const RATE_POLICY = (max = 3) => ({
  id: 'POL-RATE', type: 'RATE_LIMIT', priority: 40, enabled: true,
  config: { windowSeconds: 60, maxRequests: max, keyBy: 'userId' },
});

// Named/prioritised RATE_LIMIT policy — used to build two genuinely-
// consecutive RATE_LIMIT policies (nothing else enabled between them),
// mirroring the production policies.json shape (POL-004 + POL-NEW).
const namedRatePolicy = (id, priority, max) => ({
  id, type: 'RATE_LIMIT', priority, enabled: true,
  config: { windowSeconds: 60, maxRequests: max, keyBy: 'userId' },
});

// ── 1. Missing artifact ───────────────────────────────────────────────────────

describe('missing artifact', () => {
  const pol = policies();

  test('artifact.valid = false → BLOCK CONSENT_MISSING', async () => {
    const d = await evaluate(ctx({ artifact: { valid: false } }), pol, createStore());
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('CONSENT_MISSING');
    expect(d.policyId).toBe('POL-CONSENT');
  });

  test('artifact = null → BLOCK INVALID_CONTEXT (caught by context validator)', async () => {
    const d = await evaluate(ctx({ artifact: null }), pol, createStore());
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('INVALID_CONTEXT');
    expect(d.policyId).toBe('SYSTEM');
  });

  test('artifact omitted → BLOCK INVALID_CONTEXT (caught by context validator)', async () => {
    const { artifact, ...rest } = ctx();
    const d = await evaluate(rest, pol, createStore());
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('INVALID_CONTEXT');
    expect(d.policyId).toBe('SYSTEM');
  });
});

// ── 2. Invalid artifact ───────────────────────────────────────────────────────

describe('invalid artifact', () => {
  const pol = policies();

  test('artifact.valid = 0 (falsy) → BLOCK', async () => {
    const d = await evaluate(ctx({ artifact: { valid: 0 } }), pol, createStore());
    expect(d.decision).toBe('BLOCK');
    expect(d.policyId).toBe('POL-CONSENT');
  });

  test('artifact.valid = "true" (string, not boolean) → BLOCK', async () => {
    const d = await evaluate(ctx({ artifact: { valid: 'true' } }), pol, createStore());
    expect(d.decision).toBe('BLOCK');
  });

  test('empty artifact object {} → BLOCK', async () => {
    const d = await evaluate(ctx({ artifact: {} }), pol, createStore());
    expect(d.decision).toBe('BLOCK');
  });
});

// ── 3. Valid artifact with no blocking policy ─────────────────────────────────

describe('valid artifact', () => {
  test('valid artifact, no extra policies → EXECUTE', async () => {
    const pol = policies();
    const d   = await evaluate(ctx(), pol, createStore());
    expect(d.decision).toBe('EXECUTE');
    expect(d.reason).toBe('ALL_CHECKS_PASSED');
    expect(d.policyId).toBe('SYSTEM');
  });

  test('valid artifact with BLOCK_IP (non-matching IP) → EXECUTE', async () => {
    const pol = policies([BLOCK_IP_POLICY]);
    const d   = await evaluate(ctx({ ip: '8.8.8.8' }), pol, createStore());
    expect(d.decision).toBe('EXECUTE');
  });

  test('valid artifact with TIME_WINDOW (within window) → EXECUTE', async () => {
    const pol = policies([TIME_POLICY]);
    const d   = await evaluate(ctx({ timestamp: WEEKDAY_NOON_UTC }), pol, createStore());
    expect(d.decision).toBe('EXECUTE');
  });

  test('all policies enabled, nothing triggers → EXECUTE', async () => {
    const pol = policies([BLOCK_IP_POLICY, TIME_POLICY, RATE_POLICY(10)]);
    const d   = await evaluate(ctx({ timestamp: WEEKDAY_NOON_UTC }), pol, createStore());
    expect(d.decision).toBe('EXECUTE');
  });
});

// ── 4. Blocked IP ─────────────────────────────────────────────────────────────

describe('blocked IP', () => {
  const pol = policies([BLOCK_IP_POLICY]);

  test('exact match in blocklist → BLOCK IP_BLOCKED', async () => {
    const d = await evaluate(ctx({ ip: '5.5.5.5' }), pol, createStore());
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('IP_BLOCKED');
    expect(d.policyId).toBe('POL-BLOCK-IP');
  });

  test('IP within blocked CIDR 192.168.0.0/16 → BLOCK IP_BLOCKED', async () => {
    const d = await evaluate(ctx({ ip: '192.168.1.100' }), pol, createStore());
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('IP_BLOCKED');
  });

  test('boundary: first address in CIDR (192.168.0.0) → BLOCK', async () => {
    const d = await evaluate(ctx({ ip: '192.168.0.0' }), pol, createStore());
    expect(d.decision).toBe('BLOCK');
  });

  test('boundary: last address in CIDR (192.168.255.255) → BLOCK', async () => {
    const d = await evaluate(ctx({ ip: '192.168.255.255' }), pol, createStore());
    expect(d.decision).toBe('BLOCK');
  });

  test('just outside CIDR (192.169.0.0) → EXECUTE', async () => {
    const d = await evaluate(ctx({ ip: '192.169.0.0' }), pol, createStore());
    expect(d.decision).toBe('EXECUTE');
  });

  test('IP_BLOCKED fires before later policies (priority order)', async () => {
    const pol2 = policies([BLOCK_IP_POLICY, RATE_POLICY(1)]);
    const d    = await evaluate(ctx({ ip: '5.5.5.5' }), pol2, createStore());
    expect(d.decision).toBe('BLOCK');
    expect(d.policyId).toBe('POL-BLOCK-IP');
  });
});

// ── TRACE-4: per-rule deterministic policyRuleHash ────────────────────────────

describe('policyRuleHash (TRACE-4)', () => {
  test('BLOCK: policyRuleHash is present and matches the independently-recomputed hash of the deciding rule', async () => {
    const pol = policies([BLOCK_IP_POLICY]);
    const d   = await evaluate(ctx({ ip: '5.5.5.5' }), pol, createStore());
    expect(d.decision).toBe('BLOCK');
    expect(d.policyId).toBe('POL-BLOCK-IP');

    const decidingRule = pol.find(p => p.id === 'POL-BLOCK-IP');
    expect(d.policyRuleHash).toBe(computeRuleHash(decidingRule));
    expect(d.policyRuleHash).toMatch(/^[0-9a-f]{64}$/);
  });

  test('ALLOW: policyRuleHash is null — no single rule decides an ALLOW', async () => {
    const pol = policies([BLOCK_IP_POLICY, TIME_POLICY]);
    const d   = await evaluate(ctx({ ip: '8.8.8.8', timestamp: WEEKDAY_NOON_UTC }), pol, createStore());
    expect(d.decision).toBe('EXECUTE');
    expect(d.policyId).toBe('SYSTEM');
    expect(d.policyRuleHash).toBeNull();
  });

  test('evaluationPath carries a ruleHash for every rule actually evaluated, including passing ones', async () => {
    const pol = policies([BLOCK_IP_POLICY, TIME_POLICY]);
    const d   = await evaluate(ctx({ ip: '8.8.8.8', timestamp: WEEKDAY_NOON_UTC }), pol, createStore());
    expect(d.decision).toBe('EXECUTE');
    for (const step of d.evaluationPath) {
      expect(typeof step.ruleHash).toBe('string');
      expect(step.ruleHash).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  test('policyRuleHash changes when the deciding rule\'s config changes, but not when an unrelated rule changes', async () => {
    const polA = policies([BLOCK_IP_POLICY, RATE_POLICY(3)]);
    const dA   = await evaluate(ctx({ ip: '5.5.5.5' }), polA, createStore());

    // Unrelated rule (RATE_POLICY's maxRequests) changes — deciding rule
    // (BLOCK_IP) is identical — hash must be stable.
    const polB = policies([BLOCK_IP_POLICY, RATE_POLICY(99)]);
    const dB   = await evaluate(ctx({ ip: '5.5.5.5' }), polB, createStore());
    expect(dB.policyRuleHash).toBe(dA.policyRuleHash);

    // Deciding rule itself changes (different blocklist) — hash must differ.
    const changedBlockIp = { ...BLOCK_IP_POLICY, config: { blocklist: ['5.5.5.5', '6.6.6.6'], cidrs: ['192.168.0.0/16'] } };
    const polC = policies([changedBlockIp, RATE_POLICY(3)]);
    const dC   = await evaluate(ctx({ ip: '5.5.5.5' }), polC, createStore());
    expect(dC.policyRuleHash).not.toBe(dA.policyRuleHash);
  });
});

// ── 5. Time window violation ──────────────────────────────────────────────────

describe('time window', () => {
  const pol = policies([TIME_POLICY]);

  test('weekend → BLOCK OUTSIDE_TIME_WINDOW', async () => {
    const d = await evaluate(ctx({ timestamp: WEEKEND_UTC }), pol, createStore());
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('OUTSIDE_TIME_WINDOW');
    expect(d.policyId).toBe('POL-TIME');
  });

  test('weekday before window start (08:59 UTC) → BLOCK', async () => {
    // Monday 2025-01-06 08:59:00 UTC
    const d = await evaluate(ctx({ timestamp: 1736154000 - 60 }), pol, createStore());
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('OUTSIDE_TIME_WINDOW');
  });

  test('weekday after window end (18:00 UTC) → BLOCK', async () => {
    // Monday 2025-01-06 18:00:00 UTC  (window is < 18:00, so exactly 18:00 is outside)
    const d = await evaluate(ctx({ timestamp: 1736186400 }), pol, createStore());
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('OUTSIDE_TIME_WINDOW');
  });

  test('weekday within window (12:00 UTC) → EXECUTE', async () => {
    const d = await evaluate(ctx({ timestamp: WEEKDAY_NOON_UTC }), pol, createStore());
    expect(d.decision).toBe('EXECUTE');
  });

  test('missing timestamp → BLOCK TIMESTAMP_MISSING', async () => {
    const { timestamp, ...rest } = ctx();
    const d = await evaluate(rest, pol, createStore());
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('TIMESTAMP_MISSING');
  });

  test('uses context.timestamp not wall clock (frozen past timestamp is deterministic)', async () => {
    const past = 1700000000; // Sunday 2023-11-14 — always outside Mon-Fri window
    const d1   = await evaluate(ctx({ timestamp: past }), pol, createStore());
    const d2   = await evaluate(ctx({ timestamp: past }), pol, createStore());
    expect(d1.decision).toBe(d2.decision);
    expect(d1.reason).toBe(d2.reason);
  });
});

// ── 6. Rate limit ─────────────────────────────────────────────────────────────

describe('rate limit', () => {
  test('under limit → EXECUTE', async () => {
    const pol   = policies([RATE_POLICY(3)]);
    const store = createStore();
    const d     = await evaluate(ctx(), pol, store);
    expect(d.decision).toBe('EXECUTE');
  });

  test('exactly at limit → BLOCK RATE_LIMIT_EXCEEDED', async () => {
    const pol   = policies([RATE_POLICY(2)]);
    const store = createStore();
    await evaluate(ctx(), pol, store); // 1
    await evaluate(ctx(), pol, store); // 2
    const d = await evaluate(ctx(), pol, store); // 3 — over
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('RATE_LIMIT_EXCEEDED');
    expect(d.policyId).toBe('POL-RATE');
  });

  test('different users have independent counters', async () => {
    const pol    = policies([RATE_POLICY(1)]);
    const store  = createStore();
    await evaluate(ctx({ userId: 'user-a' }), pol, store); // user-a: 1/1
    const d1 = await evaluate(ctx({ userId: 'user-a' }), pol, store); // user-a: exceeded
    const d2 = await evaluate(ctx({ userId: 'user-b' }), pol, store); // user-b: 1/1
    expect(d1.decision).toBe('BLOCK');
    expect(d2.decision).toBe('EXECUTE');
  });

  test('DENY requests do not increment counter (failed gate = no cost)', async () => {
    const pol   = policies([RATE_POLICY(2)]);
    const store = createStore();
    await evaluate(ctx({ artifact: { valid: false } }), pol, store); // DENY — must not increment
    await evaluate(ctx(), pol, store); // 1
    await evaluate(ctx(), pol, store); // 2
    const d = await evaluate(ctx(), pol, store); // 3 — over only if DENY did not count
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('RATE_LIMIT_EXCEEDED');
  });

  test('max=1 allows exactly one request then blocks', async () => {
    const pol   = policies([RATE_POLICY(1)]);
    const store = createStore();
    expect((await evaluate(ctx(), pol, store)).decision).toBe('EXECUTE');
    expect((await evaluate(ctx(), pol, store)).decision).toBe('BLOCK');
  });

  test('rate limit keyed by ip', async () => {
    const ratByIp = {
      id: 'POL-RATE-IP', type: 'RATE_LIMIT', priority: 40, enabled: true,
      config: { windowSeconds: 60, maxRequests: 1, keyBy: 'ip' },
    };
    const pol   = policies([ratByIp]);
    const store = createStore();
    await evaluate(ctx({ ip: '1.1.1.1' }), pol, store);
    const blocked = await evaluate(ctx({ ip: '1.1.1.1' }), pol, store);
    const allowed = await evaluate(ctx({ ip: '2.2.2.2' }), pol, store);
    expect(blocked.decision).toBe('BLOCK');
    expect(allowed.decision).toBe('EXECUTE');
  });
});

// ── 6b. Rate limit — atomic admission & concurrency (RATE-1 regression) ───────
//
// Regression coverage for the check-then-act race: the engine used to read
// store.getCount() into a snapshot, evaluate against the snapshot, and only
// call store.increment() after the ENTIRE policy chain passed — two separate
// store round trips with an await boundary between them. Concurrent requests
// could all read the same pre-increment count, all pass, and all increment
// afterwards, admitting more than maxRequests. The fix collapses read +
// decide + increment into one atomic store.checkAndIncrement() call inside
// the evaluator, so there is no window where two callers can both observe
// "count is still under the limit".
describe('rate limit — atomic admission & concurrency', () => {
  test('below limit → EXECUTE', async () => {
    const pol   = policies([RATE_POLICY(5)]);
    const store = createStore();
    const d     = await evaluate(ctx(), pol, store);
    expect(d.decision).toBe('EXECUTE');
  });

  test('exactly at limit (Nth request, N = maxRequests) → EXECUTE', async () => {
    const pol   = policies([RATE_POLICY(3)]);
    const store = createStore();
    await evaluate(ctx(), pol, store); // 1
    await evaluate(ctx(), pol, store); // 2
    const d = await evaluate(ctx(), pol, store); // 3 — exactly at the limit, still allowed
    expect(d.decision).toBe('EXECUTE');
  });

  test('above limit (N+1th request) → BLOCK', async () => {
    const pol   = policies([RATE_POLICY(3)]);
    const store = createStore();
    await evaluate(ctx(), pol, store); // 1
    await evaluate(ctx(), pol, store); // 2
    await evaluate(ctx(), pol, store); // 3
    const d = await evaluate(ctx(), pol, store); // 4 — over
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('RATE_LIMIT_EXCEEDED');
  });

  test('window reset: counter starts fresh once windowSeconds has elapsed', () => {
    jest.useFakeTimers({ doNotFake: ['nextTick'] });
    try {
      jest.setSystemTime(0);
      const store = createStore();

      expect(store.checkAndIncrement('reset:key', 60, 2).allowed).toBe(true);  // 1/2
      expect(store.checkAndIncrement('reset:key', 60, 2).allowed).toBe(true);  // 2/2
      expect(store.checkAndIncrement('reset:key', 60, 2).allowed).toBe(false); // 3/2 — blocked

      // Advance past the 60s window
      jest.setSystemTime(61_000);

      const afterReset = store.checkAndIncrement('reset:key', 60, 2);
      expect(afterReset.allowed).toBe(true);
      expect(afterReset.count).toBe(1); // counter restarted, not carried over
    } finally {
      jest.useRealTimers();
    }
  });

  test('concurrent Promise.all burst: exactly maxRequests admitted, never more', async () => {
    const MAX  = 5;
    const pol  = policies([RATE_POLICY(MAX)]);
    const store = createStore();

    const results = await Promise.all(
      Array.from({ length: 20 }, () => evaluate(ctx(), pol, store))
    );

    const admitted = results.filter(r => r.decision === 'EXECUTE').length;
    const blocked  = results.filter(r => r.decision === 'BLOCK').length;
    expect(admitted).toBe(MAX);
    expect(blocked).toBe(20 - MAX);
  });

  test('concurrent burst with exactly one remaining slot: only one of many simultaneous requests is admitted', async () => {
    const MAX  = 3;
    const pol  = policies([RATE_POLICY(MAX)]);
    const store = createStore();

    // Consume MAX - 1 slots sequentially, leaving exactly one remaining.
    await evaluate(ctx(), pol, store);
    await evaluate(ctx(), pol, store);

    // 10 requests race for the single remaining slot.
    const results = await Promise.all(
      Array.from({ length: 10 }, () => evaluate(ctx(), pol, store))
    );

    const admitted = results.filter(r => r.decision === 'EXECUTE').length;
    expect(admitted).toBe(1);
  });

  test('concurrent burst with exactly two remaining slots: exactly two of many simultaneous requests are admitted', async () => {
    const MAX  = 5;
    const pol  = policies([RATE_POLICY(MAX)]);
    const store = createStore();

    // Consume MAX - 2 slots sequentially, leaving exactly two remaining.
    await evaluate(ctx(), pol, store);
    await evaluate(ctx(), pol, store);
    await evaluate(ctx(), pol, store);

    // 10 requests race for the two remaining slots.
    const results = await Promise.all(
      Array.from({ length: 10 }, () => evaluate(ctx(), pol, store))
    );

    const admitted = results.filter(r => r.decision === 'EXECUTE').length;
    expect(admitted).toBe(2);
  });

  test('concurrent bursts across independent keys never cross-contaminate counts', async () => {
    const pol   = policies([RATE_POLICY(2)]);
    const store = createStore();

    const [aResults, bResults] = await Promise.all([
      Promise.all(Array.from({ length: 6 }, () => evaluate(ctx({ userId: 'user-a' }), pol, store))),
      Promise.all(Array.from({ length: 6 }, () => evaluate(ctx({ userId: 'user-b' }), pol, store))),
    ]);

    expect(aResults.filter(r => r.decision === 'EXECUTE').length).toBe(2);
    expect(bResults.filter(r => r.decision === 'EXECUTE').length).toBe(2);
  });
});

// ── 6c. Rate limit — two consecutive policies (item 16 pipelining lock-in) ────
//
// Written and confirmed passing against the sequential engine BEFORE any
// pipelining change, then kept unmodified as the equivalence lock-in once
// consecutive RATE_LIMIT policies are routed through a combined store round
// trip: the two cases below are exactly the semantics a naive transport-only
// pipeline would get wrong (see item 16 report §2).
describe('rate limit — two consecutive policies (item 16 pipelining lock-in)', () => {
  test('first RATE_LIMIT denies → second policy\'s counter is left untouched', async () => {
    const polA = namedRatePolicy('POL-RATE-A', 40, 1); // tight — one request only
    const polB = namedRatePolicy('POL-RATE-B', 41, 5); // generous
    const pol  = policies([polA, polB]);
    const store = createStore();

    const d1 = await evaluate(ctx(), pol, store);
    expect(d1.decision).toBe('EXECUTE');
    expect(store.getCount('POL-RATE-B:user-test', 60)).toBe(1);

    // A is now exhausted — B must never be reached, so its counter must not move.
    const d2 = await evaluate(ctx(), pol, store);
    expect(d2.decision).toBe('BLOCK');
    expect(d2.policyId).toBe('POL-RATE-A');
    expect(store.getCount('POL-RATE-B:user-test', 60)).toBe(1);
  });

  test('first RATE_LIMIT allows, second denies → first policy\'s increment persists', async () => {
    const polA = namedRatePolicy('POL-RATE-A', 40, 5); // generous
    const polB = namedRatePolicy('POL-RATE-B', 41, 1); // tight — one request only
    const pol  = policies([polA, polB]);
    const store = createStore();

    const d1 = await evaluate(ctx(), pol, store);
    expect(d1.decision).toBe('EXECUTE');
    expect(store.getCount('POL-RATE-A:user-test', 60)).toBe(1);

    // B is now exhausted — the overall request is denied, but A's evaluator
    // still ran (and incremented) before B ever denied it.
    const d2 = await evaluate(ctx(), pol, store);
    expect(d2.decision).toBe('BLOCK');
    expect(d2.policyId).toBe('POL-RATE-B');
    expect(store.getCount('POL-RATE-A:user-test', 60)).toBe(2);
  });
});

// ── 7. Fail-closed guarantees ─────────────────────────────────────────────────

describe('fail-closed', () => {
  test('empty policy array → BLOCK NO_POLICIES_LOADED', async () => {
    const d = await evaluate(ctx(), [], createStore());
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('NO_POLICIES_LOADED');
  });

  test('null policies → BLOCK', async () => {
    const d = await evaluate(ctx(), null, createStore());
    expect(d.decision).toBe('BLOCK');
  });

  test('all policies disabled → BLOCK NO_ENABLED_POLICIES', async () => {
    const disabled = { ...CONSENT_POLICY, enabled: false };
    // bypass loader validation so we can test the engine directly with all-disabled
    const raw = [Object.freeze({ ...disabled, config: Object.freeze({ requireValidArtifact: true }) })];
    const d   = await evaluate(ctx(), raw, createStore());
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('NO_ENABLED_POLICIES');
  });

  test('evaluator throws → BLOCK EVALUATOR_ERROR with failing policyId', async () => {
    // Inject a broken evaluator via a frozen policy whose type is in registry
    // but whose config triggers an unexpected throw. We simulate this by
    // temporarily corrupting the preprocessed config.
    const broken = Object.freeze({
      id: 'POL-BROKEN', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
      config: Object.freeze({
        // getter throws on access — requiredScope is accessed by evaluate()
        get requiredScope() { throw new Error('config exploded'); },
      }),
    });
    const d = await evaluate(ctx(), [broken], createStore());
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('EVALUATOR_ERROR');
    expect(d.policyId).toBe('POL-BROKEN');
  });
});

// ── 8. Loader validation ──────────────────────────────────────────────────────

describe('loader validation', () => {
  function load(policies) { return validateAndPrepare({ policies }); }

  test('missing REQUIRE_CONSENT → throws', () => {
    expect(() => load([
      { id: 'X', type: 'BLOCK_IP', priority: 10, enabled: true,
        config: { blocklist: [], cidrs: [] } },
    ])).toThrow('REQUIRE_CONSENT');
  });

  test('duplicate id → throws', () => {
    expect(() => load([
      { id: 'DUP', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
        config: { requireValidArtifact: true } },
      { id: 'DUP', type: 'REQUIRE_CONSENT', priority: 20, enabled: true,
        config: { requireValidArtifact: true } },
    ])).toThrow('duplicate');
  });

  test('unknown policy type → throws', () => {
    expect(() => load([
      { id: 'P1', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
        config: { requireValidArtifact: true } },
      { id: 'P2', type: 'UNKNOWN_TYPE', priority: 20, enabled: true, config: {} },
    ])).toThrow('unknown type');
  });

  test('invalid CIDR → throws at load time, not runtime', () => {
    expect(() => load([
      { id: 'P1', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
        config: { requireValidArtifact: true } },
      { id: 'P2', type: 'BLOCK_IP', priority: 20, enabled: true,
        config: { blocklist: [], cidrs: ['not-a-cidr'] } },
    ])).toThrow();
  });

  test('TIME_WINDOW start >= end → throws', () => {
    expect(() => load([
      { id: 'P1', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
        config: { requireValidArtifact: true } },
      { id: 'P2', type: 'TIME_WINDOW', priority: 20, enabled: true,
        config: { allowedWindows: [{ days: ['MON'], start: '18:00', end: '09:00' }] } },
    ])).toThrow();
  });

  test('policies sorted by priority after load', () => {
    const set = load([
      { id: 'P3', type: 'BLOCK_IP',        priority: 30, enabled: true, config: { blocklist: [], cidrs: [] } },
      { id: 'P1', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } },
      { id: 'P2', type: 'RATE_LIMIT',      priority: 20, enabled: true,
        config: { windowSeconds: 60, maxRequests: 100, keyBy: 'userId' } },
    ]);
    expect(set.map(p => p.id)).toEqual(['P1', 'P2', 'P3']);
  });
});

// ── 9. Determinism ────────────────────────────────────────────────────────────

describe('determinism', () => {
  test('same (context, policies, snapshot) always produces same decision', async () => {
    const pol   = policies([BLOCK_IP_POLICY, TIME_POLICY]);
    const store = createStore();
    const c     = ctx({ timestamp: WEEKDAY_NOON_UTC });

    const results = await Promise.all(Array.from({ length: 10 }, () => evaluate(c, pol, store)));
    const first   = results[0];

    for (const r of results) {
      expect(r.decision).toBe(first.decision);
      expect(r.reason).toBe(first.reason);
      expect(r.policyId).toBe(first.policyId);
    }
  });

  test('evaluation order is stable across calls (first DENY wins)', async () => {
    const pol   = policies([BLOCK_IP_POLICY, TIME_POLICY]);
    const store = createStore();
    // IP blocked takes priority 20, time takes 30 — IP should always win
    const d = await evaluate(ctx({ ip: '5.5.5.5', timestamp: WEEKEND_UTC }), pol, store);
    expect(d.policyId).toBe('POL-BLOCK-IP');
  });

  test('DENY requests leave store unchanged (idempotent on blocked requests)', async () => {
    const pol   = policies([RATE_POLICY(2)]);
    const store = createStore();
    // 5 denied requests (consent invalid) should not affect the counter
    for (let i = 0; i < 5; i++) {
      await evaluate(ctx({ artifact: { valid: false } }), pol, store);
    }
    expect((await evaluate(ctx(), pol, store)).decision).toBe('EXECUTE'); // 1
    expect((await evaluate(ctx(), pol, store)).decision).toBe('EXECUTE'); // 2
    expect((await evaluate(ctx(), pol, store)).decision).toBe('BLOCK');  // exceeded
  });
});

// ── 10. Context validation (hardening) ────────────────────────────────────────

describe('context validation', () => {
  const { validateContext, PolicyContextError } = require('./context');
  const pol = policies();

  test('non-object context → BLOCK INVALID_CONTEXT', async () => {
    for (const bad of [null, 'string', 42, [], true]) {
      const d = await evaluate(bad, pol, createStore());
      expect(d.decision).toBe('BLOCK');
      expect(d.reason).toBe('INVALID_CONTEXT');
    }
  });

  test('prototype pollution key __proto__ → throws PolicyContextError', () => {
    expect(() => validateContext(JSON.parse('{"__proto__":{"x":1},"artifact":{"valid":true}}'))).toThrow(PolicyContextError);
  });

  test('prototype pollution key constructor → throws', () => {
    expect(() => validateContext({ constructor: {}, artifact: { valid: true } })).toThrow(PolicyContextError);
  });

  test('userId not a string → throws', () => {
    expect(() => validateContext({ artifact: { valid: true }, userId: 12345 })).toThrow(PolicyContextError);
  });

  test('userId exceeding max length → throws', () => {
    expect(() => validateContext({ artifact: { valid: true }, userId: 'x'.repeat(257) })).toThrow(PolicyContextError);
  });

  test('ip exceeding max length → throws', () => {
    expect(() => validateContext({ artifact: { valid: true }, ip: 'a'.repeat(46) })).toThrow(PolicyContextError);
  });

  test('timestamp as string → throws', () => {
    expect(() => validateContext({ artifact: { valid: true }, timestamp: '1736164800' })).toThrow(PolicyContextError);
  });

  test('timestamp as float → throws', () => {
    expect(() => validateContext({ artifact: { valid: true }, timestamp: 1736164800.5 })).toThrow(PolicyContextError);
  });

  test('timestamp too small (likely milliseconds) → throws', () => {
    expect(() => validateContext({ artifact: { valid: true }, timestamp: 999_999_999 })).toThrow(PolicyContextError);
  });

  test('timestamp too large → throws', () => {
    expect(() => validateContext({ artifact: { valid: true }, timestamp: 10_000_000_000 })).toThrow(PolicyContextError);
  });

  test('valid minimal context → passes', () => {
    const c = validateContext({ artifact: { valid: true } });
    expect(c.artifact.valid).toBe(true);
    expect(c.userId).toBeNull();
    expect(c.ip).toBeNull();
    expect(c.timestamp).toBeUndefined();
  });

  test('artifact.valid truthy non-boolean is normalised to false', () => {
    const c = validateContext({ artifact: { valid: 1 } });
    expect(c.artifact.valid).toBe(false);
  });

  test('returned context is frozen', () => {
    const c = validateContext({ artifact: { valid: true } });
    expect(Object.isFrozen(c)).toBe(true);
    expect(Object.isFrozen(c.artifact)).toBe(true);
  });
});

// ── 11. Loader hardening ─────────────────────────────────────────────────────

describe('loader hardening', () => {
  function load(policies) { return validateAndPrepare({ policies }); }

  test('policy id with special chars → throws', () => {
    expect(() => load([
      { id: 'POL 001', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
        config: { requireValidArtifact: true } },
    ])).toThrow();
  });

  test('policy id too long (> 64 chars) → throws', () => {
    expect(() => load([
      { id: 'A'.repeat(65), type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
        config: { requireValidArtifact: true } },
    ])).toThrow();
  });

  test('unknown root key on policy object → throws', () => {
    expect(() => load([
      { id: 'P1', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
        config: { requireValidArtifact: true }, extra: 'field' },
    ])).toThrow('unknown key');
  });

  test('priority out of range (negative) → throws', () => {
    expect(() => load([
      { id: 'P1', type: 'REQUIRE_CONSENT', priority: -1, enabled: true,
        config: { requireValidArtifact: true } },
    ])).toThrow();
  });

  test('config with __proto__ own property → throws', () => {
    // JSON.parse is the only standard way to create __proto__ as an own
    // enumerable key — bracket assignment (obj['__proto__'] = x) sets the
    // prototype instead and produces no own property.
    const raw = JSON.parse(`{
      "policies": [{
        "id": "P1", "type": "REQUIRE_CONSENT",
        "priority": 10, "enabled": true,
        "config": { "requireValidArtifact": true, "__proto__": {"polluted": true} }
      }]
    }`);
    expect(() => validateAndPrepare(raw)).toThrow('forbidden key');
  });

  test('policy count exceeds MAX_POLICIES → throws', () => {
    const many = Array.from({ length: 101 }, (_, i) => ({
      id: `P${i}`, type: 'REQUIRE_CONSENT', priority: i, enabled: i === 0,
      config: { requireValidArtifact: true },
    }));
    expect(() => load(many)).toThrow('maximum');
  });

  test('valid policy set returns frozen array', () => {
    const set = load([
      { id: 'P1', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
        config: { requireValidArtifact: true } },
    ]);
    expect(Object.isFrozen(set)).toBe(true);
    expect(Object.isFrozen(set[0])).toBe(true);
    expect(Object.isFrozen(set[0].config)).toBe(true);
  });
});
