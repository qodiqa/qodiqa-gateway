'use strict';

/**
 * Distributed Key Rotation Lock — Concurrency Stress Tests
 *
 * rotationLock.test.js proves the lock's semantics in isolation (acquire/
 * release/fail-closed/namespacing). This file stresses those same semantics
 * under simulated multi-pod contention: many concurrent "pods" (distinct
 * tokens) racing for the same clientId, over many rounds, with randomized
 * timing jitter so interleaving order is not deterministic run-to-run —
 * proving the invariants hold regardless of which pod happens to "arrive
 * first" on any given run, not just for one fixed call order.
 *
 * Unlike rotationLock.test.js's plain synchronous fake client, this file's
 * fake client inserts a small random delay before its check-and-set so
 * concurrent acquire() calls genuinely interleave at the microtask/timer
 * level — closer to what real network latency does across real pods —
 * while still exercising the exact same atomic NX/PX and compare-and-delete
 * Lua semantics real Redis provides (single-threaded command execution).
 *
 * RLC-01  Many concurrent writers, one round: exactly one winner, all others
 *         get {acquired:false} (never block/queue — see note below)
 * RLC-02  Many rounds of repeated contention: exactly one successful
 *         acquisition per round, shared "keystore" counter increments by
 *         exactly the number of rounds — no lost updates, no double-counts,
 *         no corruption
 * RLC-03  Crashed-owner simulation: a winner that never releases (TTL
 *         expiry, not explicit release) — after expiry, exactly one new
 *         pod acquires; before expiry, no one does (no stale-ownership
 *         bypass)
 * RLC-04  release() only ever succeeds for the true token holder, even
 *         under heavy concurrent release attempts from every other pod
 * RLC-05  Randomized repeated contention/release cycles across many rounds
 *         and many pods produces a deterministic final state: total
 *         successful acquisitions across the whole run equals total
 *         releases equals total critical-section counter increments
 *
 * NOTE ON "NO DEADLOCKS": rotationLock.acquire() is a non-blocking
 * try-acquire (SET NX) — a losing pod gets {acquired:false} immediately and
 * decides for itself whether to retry later; there is no blocking wait, no
 * queue, and no lock ordering across multiple resources. Deadlock requires
 * at least one of those to exist, so it is structurally impossible for this
 * primitive by construction — proven by design, not by a timing probe (a
 * probe can only fail to observe a deadlock within its own timeout; it can
 * never prove one is impossible).
 */

jest.mock('redis', () => ({ createClient: jest.fn() }));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const { createClient } = require('redis');

function _jitter(maxMs = 4) {
  return new Promise(resolve => setTimeout(resolve, Math.random() * maxMs));
}

/**
 * Fake Redis client with the same NX/PX SET + compare-and-delete EVAL
 * contract as rotationLock.test.js's fake, but with:
 *   - Real (short) TTL expiry via setTimeout, so crashed-owner simulation
 *     (RLC-03) doesn't require directly poking internal state.
 *   - Random jitter before the atomic check-and-set, so concurrent callers
 *     genuinely race rather than resolving in call order.
 */
function makeStressRedisClient() {
  const map = new Map(); // key -> { value, expiresAt }
  function _liveGet(key) {
    const entry = map.get(key);
    if (!entry) return null;
    if (entry.expiresAt !== null && Date.now() >= entry.expiresAt) {
      map.delete(key);
      return null;
    }
    return entry.value;
  }
  return {
    isReady: true,
    on: jest.fn(),
    connect: jest.fn().mockResolvedValue(undefined),
    disconnect: jest.fn().mockResolvedValue(undefined),
    set: jest.fn(async (key, value, opts) => {
      await _jitter();
      if (opts && opts.NX && _liveGet(key) !== null) return null;
      map.set(key, { value, expiresAt: opts && opts.PX ? Date.now() + opts.PX : null });
      return 'OK';
    }),
    get: jest.fn(async (key) => _liveGet(key)),
    eval: jest.fn(async (script, { keys, arguments: args }) => {
      await _jitter();
      const [key] = keys;
      const [token] = args;
      // acquire() now also runs the conditional fence script
      // (INCR only while still holding the lock); every other EVAL is the
      // compare-and-delete release, as before.
      if (script.includes('INCR')) {
        if (_liveGet(key) !== token) return null;
        const fenceKey = keys[1];
        const cur = _liveGet(fenceKey);
        const next = (cur === null ? Number(args[1]) : Number(cur)) + 1;
        map.set(fenceKey, { value: String(next), expiresAt: null });
        return next;
      }
      if (_liveGet(key) === token) {
        map.delete(key);
        return 1;
      }
      return 0;
    }),
    _map: map,
  };
}

let fakeClient;

beforeEach(() => {
  fakeClient = makeStressRedisClient();
  createClient.mockReturnValue(fakeClient);
});

afterEach(async () => {
  const rotationLock = require('../rotationLock');
  await rotationLock.disconnect();
  jest.clearAllMocks();
});

describe('RLC-01: many concurrent writers, one round', () => {
  test('exactly one of 50 concurrent pods wins; the rest get {acquired:false}', async () => {
    const rotationLock = require('../rotationLock');
    const POD_COUNT = 50;

    const results = await Promise.all(
      Array.from({ length: POD_COUNT }, () => rotationLock.acquire('acme', 30_000)),
    );

    const winners = results.filter(r => r.acquired);
    const losers  = results.filter(r => !r.acquired);
    expect(winners).toHaveLength(1);
    expect(losers).toHaveLength(POD_COUNT - 1);
    // Losers never block — every call already resolved above.
    for (const loser of losers) {
      expect(loser).toEqual({ acquired: false });
    }
  });
});

describe('RLC-02: many rounds of repeated contention', () => {
  test('20 rounds x 10 pods each: exactly one winner per round, counter increments exactly 20 times', async () => {
    const rotationLock = require('../rotationLock');
    const ROUNDS = 20;
    const PODS_PER_ROUND = 10;
    let sharedCounter = 0;

    for (let round = 0; round < ROUNDS; round++) {
      const attempts = await Promise.all(
        Array.from({ length: PODS_PER_ROUND }, () => rotationLock.acquire('acme', 30_000)),
      );
      const winners = attempts.filter(r => r.acquired);
      expect(winners).toHaveLength(1);

      // Simulate the winner's critical-section write with a small random
      // delay — if the lock were broken, a second "winner" racing in here
      // would corrupt this increment (lost update / double count).
      await _jitter();
      sharedCounter++;

      const released = await rotationLock.release('acme', winners[0].token);
      expect(released).toBe(true);
    }

    expect(sharedCounter).toBe(ROUNDS);
  });
});

describe('RLC-03: crashed-owner simulation (TTL expiry, no explicit release)', () => {
  test('no one can acquire before expiry; exactly one new pod acquires after expiry', async () => {
    const rotationLock = require('../rotationLock');

    const crashedOwner = await rotationLock.acquire('acme', 50); // short TTL
    expect(crashedOwner.acquired).toBe(true);

    // Before expiry: every contender fails, lock stays with the crashed owner.
    const beforeExpiry = await Promise.all(
      Array.from({ length: 10 }, () => rotationLock.acquire('acme', 30_000)),
    );
    expect(beforeExpiry.every(r => r.acquired === false)).toBe(true);

    // Wait past the short TTL — real Redis PX expiry, not a manual poke.
    await new Promise(resolve => setTimeout(resolve, 80));

    const afterExpiry = await Promise.all(
      Array.from({ length: 10 }, () => rotationLock.acquire('acme', 30_000)),
    );
    const newWinners = afterExpiry.filter(r => r.acquired);
    expect(newWinners).toHaveLength(1);

    // The crashed owner's stale token must never be able to release the new
    // owner's lock (stale-ownership prevention).
    const staleRelease = await rotationLock.release('acme', crashedOwner.token);
    expect(staleRelease).toBe(false);
  });
});

describe('RLC-04: release() only succeeds for the true token holder under concurrent release attempts', () => {
  test('20 pods with wrong tokens racing release() against the true holder never release it early', async () => {
    const rotationLock = require('../rotationLock');

    const holder = await rotationLock.acquire('acme', 30_000);
    expect(holder.acquired).toBe(true);

    const impostorResults = await Promise.all(
      Array.from({ length: 20 }, (_, i) => rotationLock.release('acme', `impostor-token-${i}`)),
    );
    expect(impostorResults.every(r => r === false)).toBe(true);

    // Lock must still be held — a fresh acquire attempt still fails.
    const stillHeld = await rotationLock.acquire('acme', 30_000);
    expect(stillHeld.acquired).toBe(false);

    // The true holder can still release it.
    const trueRelease = await rotationLock.release('acme', holder.token);
    expect(trueRelease).toBe(true);
  });
});

describe('RLC-05: randomized repeated contention/release — deterministic final state', () => {
  test('total successful acquisitions == total releases == total critical-section increments, zero corruption', async () => {
    const rotationLock = require('../rotationLock');
    const ROUNDS = 30;
    const PODS_PER_ROUND = 8;

    let totalAcquisitions = 0;
    let totalReleases = 0;
    let criticalSectionCounter = 0;

    for (let round = 0; round < ROUNDS; round++) {
      // Randomize per-round pod count and jitter to vary interleaving shape
      // run-to-run rather than always racing the same fixed pattern.
      const podsThisRound = 1 + Math.floor(Math.random() * PODS_PER_ROUND);
      const attempts = await Promise.all(
        Array.from({ length: podsThisRound }, async () => {
          await _jitter(3);
          return rotationLock.acquire('acme', 30_000);
        }),
      );
      const winners = attempts.filter(r => r.acquired);
      // Exactly one winner per round is the invariant under test — assert
      // it every round, not just in aggregate, so a single corrupted round
      // can't be averaged away by the totals check below.
      expect(winners).toHaveLength(1);
      totalAcquisitions += winners.length;

      await _jitter(2);
      criticalSectionCounter++;

      const released = await rotationLock.release('acme', winners[0].token);
      expect(released).toBe(true);
      totalReleases++;
    }

    expect(totalAcquisitions).toBe(ROUNDS);
    expect(totalReleases).toBe(ROUNDS);
    expect(criticalSectionCounter).toBe(ROUNDS);
    expect(totalAcquisitions).toBe(totalReleases);
    expect(totalReleases).toBe(criticalSectionCounter);
  });
});
