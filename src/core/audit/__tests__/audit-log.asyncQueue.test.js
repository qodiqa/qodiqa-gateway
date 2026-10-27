'use strict';

/**
 * PERF-10 — append() async write-queue behavior.
 *
 * append()'s durable disk I/O now runs via fs.promises behind a module-level
 * FIFO promise chain (_writeChain) instead of blocking the event loop
 * synchronously. This suite proves the queue itself is correct:
 *
 *   - Concurrent append() calls still commit in call (enqueue) order, with an
 *     unbroken prevHash chain — the serialization guarantee the old
 *     synchronous implementation got "for free" from blocking the process.
 *   - A failed write never advances the chain/tailHash — the next queued
 *     append still chains off the last entry that ACTUALLY committed, not
 *     off the failed attempt.
 *   - artifactId/nonce dedup races are still resolved deterministically: the
 *     loser of a race rejects with already_executed / replay_detected, same
 *     as the pre-PERF-10 synchronous contract.
 *   - drainPendingWrites() (used by graceful shutdown) resolves once every
 *     enqueued append has settled, not before, and resolves immediately when
 *     the queue is already idle.
 *
 * Mocking notes:
 *   jest.mock('fs') automocks every fs.* function but does NOT create an
 *   fs.promises object at all (it stays undefined), so freshAudit() installs
 *   fs.promises.* mocks (each resolving immediately by default) before
 *   requiring audit-log.js — see audit-log.index.test.js's file header for
 *   the full rationale.
 *
 *   `const fs = require('fs');` is done ONCE at module scope, BEFORE any
 *   jest.isolateModules() call, and deliberately kept — this primes the
 *   automock in the outer module registry so every later
 *   jest.isolateModules() block's own `require('fs')` resolves to this SAME
 *   automock instance (verified empirically: jest.isolateModules() only
 *   hands back a decoupled 'fs' instance when nothing has required 'fs' in
 *   the outer registry yet). That gives tests below a reliable handle for
 *   injecting write failures/delays into the exact fs.promises.* functions
 *   audit-log.js's closure actually calls.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
jest.mock('fs');
jest.mock('../../../infra/postgres/pg-audit-backend', () => ({
  persistEntry: jest.fn().mockResolvedValue(undefined),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const crypto = require('crypto');
const fs     = require('fs'); // primed before any isolateModules() call — see header note

function uuid() { return crypto.randomUUID(); }

function allowParams(overrides = {}) {
  return {
    artifactId:         uuid(),
    inputHash:          'a'.repeat(64),
    decision:           'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
    signature:          's'.repeat(64),
    requestHash:        'r'.repeat(64),
    policyHash:         'p'.repeat(64),
    verificationResult: true,
    ...overrides,
  };
}

// Installs fs.promises.* mocks (each resolving immediately) on the given
// automocked `fs` module — a brand new set of jest.fn()s every call, so each
// freshAudit() gets its own clean mock state even though `fs` itself is
// shared across the whole file.
function _installFsPromisesMocks(fsMod) {
  fsMod.promises = {
    writeFile:  jest.fn().mockResolvedValue(undefined),
    appendFile: jest.fn().mockResolvedValue(undefined),
    open:       jest.fn().mockResolvedValue({
      sync:  jest.fn().mockResolvedValue(undefined),
      close: jest.fn().mockResolvedValue(undefined),
      // S33: the reused WAL is written/truncated through its held FileHandle (real fs.promises FileHandle API)
      write:    jest.fn().mockImplementation((buf, off, len) => Promise.resolve({ bytesWritten: len, buffer: buf })),
      truncate: jest.fn().mockResolvedValue(undefined),
    }),
    rename:    jest.fn().mockResolvedValue(undefined),
    copyFile:  jest.fn().mockResolvedValue(undefined),
    unlink:    jest.fn().mockResolvedValue(undefined),
  };
}

function freshAudit() {
  let mod;
  jest.isolateModules(() => {
    const fsInner = require('fs');
    fsInner.existsSync.mockReturnValue(false);
    _installFsPromisesMocks(fsInner);
    mod = require('../audit-log');
  });
  return mod;
}

// ── Concurrent appends commit in order with an unbroken hash chain ──────────

describe('Concurrent append() calls commit in enqueue order', () => {
  test('20+ concurrent appends with distinct artifactIds commit in call order with an unbroken prevHash chain', async () => {
    const audit = freshAudit();
    const N = 25;

    // Fire all N appends without awaiting individually — they all enqueue
    // synchronously in this loop, in this order, before any of them settles.
    const pending = [];
    for (let i = 0; i < N; i++) pending.push(audit.append(allowParams()));
    const committed = await Promise.all(pending);

    expect(committed).toHaveLength(N);

    // The write queue is FIFO by enqueue order, so the modern chain must
    // reflect exactly the order the appends were issued in.
    const chain = await audit.getModernChain();
    expect(chain).toHaveLength(N);
    for (let i = 0; i < N; i++) {
      expect(chain[i].artifactId).toBe(committed[i].artifactId);
    }

    // Unbroken prevHash chain: genesis, then each entry's prevHash equals the
    // previous entry's hash.
    expect(chain[0].prevHash).toBe('GENESIS');
    for (let i = 1; i < N; i++) {
      expect(chain[i].prevHash).toBe(chain[i - 1].hash);
    }

    const detail = audit.verifyAuditChainDetailed();
    expect(detail.valid).toBe(true);
    expect(detail.entriesVerified).toBe(N);
    expect(detail.tamperingDetected).toBe(false);
  });
});

// ── A failed write does not corrupt or skip the next entry ──────────────────

describe('A failing write for one entry does not corrupt or skip the next entry', () => {
  test('the next append() (issued and awaited after the failure) chains off the last entry that actually committed', async () => {
    const audit = freshAudit();

    const e1 = await audit.append(allowParams());

    // Make the append-only write step reject exactly once — the entry must
    // never reach chain.push()/_indexEntry() (those only run after every I/O
    // step succeeds), so it must not advance tailHash/prevHash for anyone.
    fs.promises.appendFile.mockRejectedValueOnce(new Error('simulated disk error'));
    await expect(audit.append(allowParams())).rejects.toThrow('simulated disk error');

    // Chain length must still be 1 — the failed entry was never committed.
    expect(audit.getChainLength()).toBe(1);
    expect(audit.getAuditTailHash()).toBe(e1.hash);

    const e3 = await audit.append(allowParams());

    // e3 must chain off e1 (the last entry that ACTUALLY committed) — NOT off
    // whatever hash the failed entry would have produced.
    expect(e3.prevHash).toBe(e1.hash);
    expect(audit.getChainLength()).toBe(2);

    const detail = audit.verifyAuditChainDetailed();
    expect(detail.valid).toBe(true);
    expect(detail.entriesVerified).toBe(2);
  });

  test('a failed write does not block subsequent queued appends from running', async () => {
    const audit = freshAudit();

    fs.promises.writeFile.mockRejectedValueOnce(new Error('EBUSY'));

    // Enqueue a failing append and two healthy ones concurrently — the
    // failure of the first must not poison the queue for the other two.
    const p1 = audit.append(allowParams());
    const p2 = audit.append(allowParams());
    const p3 = audit.append(allowParams());

    const results = await Promise.allSettled([p1, p2, p3]);
    expect(results[0].status).toBe('rejected');
    expect(results[1].status).toBe('fulfilled');
    expect(results[2].status).toBe('fulfilled');

    expect(audit.getChainLength()).toBe(2);
    expect(audit.verifyAuditChainDetailed().valid).toBe(true);
  });
});

// ── Concurrent races on the same dedup key ───────────────────────────────────

describe('Concurrent append() calls racing on the same dedup key', () => {
  test('two concurrent appends with the same artifactId — the loser rejects with already_executed', async () => {
    const audit = freshAudit();
    const aid = uuid();

    const p1 = audit.append(allowParams({ artifactId: aid }));
    const p2 = audit.append(allowParams({ artifactId: aid }));
    const [r1, r2] = await Promise.allSettled([p1, p2]);

    // The write queue is FIFO, so the first-enqueued call is the winner and
    // the second-enqueued call is the loser, deterministically.
    expect(r1.status).toBe('fulfilled');
    expect(r2.status).toBe('rejected');
    expect(r2.reason.message).toMatch(/already_executed/);

    expect(audit.getChainLength()).toBe(1);
    expect(await audit.getArtifactById(aid)).not.toBeNull();
  });

  test('two concurrent appends with the same nonce — the loser rejects with replay_detected', async () => {
    const audit = freshAudit();
    const nonce = 'race-nonce-' + uuid();

    const p1 = audit.append(allowParams({ nonce }));
    const p2 = audit.append(allowParams({ nonce }));
    const [r1, r2] = await Promise.allSettled([p1, p2]);

    expect(r1.status).toBe('fulfilled');
    expect(r2.status).toBe('rejected');
    expect(r2.reason.message).toMatch(/replay_detected/);

    expect(audit.getChainLength()).toBe(1);
    expect(await audit.isNonceUsed(nonce)).toBe(true);
  });
});

// ── drainPendingWrites() ──────────────────────────────────────────────────────

describe('drainPendingWrites()', () => {
  test('resolves only once every in-flight append (including a delayed one) has settled', async () => {
    const audit = freshAudit();

    let releaseDelay;
    const delayGate = new Promise((resolve) => { releaseDelay = resolve; });

    // Delay the very first fs.promises.appendFile call (the first append's
    // main log write) until we explicitly release it.
    fs.promises.appendFile.mockImplementationOnce(async () => {
      await delayGate;
      return undefined;
    });

    // Because the write queue is a strict FIFO chain, appends #2 and #3
    // cannot even begin their own I/O until append #1's entire async
    // function (including the gated write) has settled — so all three stay
    // in flight until we release the gate.
    const p1 = audit.append(allowParams());
    const p2 = audit.append(allowParams());
    const p3 = audit.append(allowParams());

    let drained = false;
    const drainPromise = audit.drainPendingWrites().then(() => { drained = true; });

    // Let the event loop turn over a few times — drainPendingWrites() must
    // NOT resolve while the gate is still held.
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(drained).toBe(false);
    expect(audit.getChainLength()).toBe(0);

    releaseDelay();
    await drainPromise;

    expect(drained).toBe(true);
    expect(audit.getChainLength()).toBe(3);
    expect(audit.verifyAuditChainDetailed().valid).toBe(true);

    // No unhandled rejections left dangling.
    await Promise.all([p1, p2, p3]);
  });

  test('resolves immediately when the queue is already idle', async () => {
    const audit = freshAudit();
    await audit.append(allowParams());

    const start = Date.now();
    await audit.drainPendingWrites();
    expect(Date.now() - start).toBeLessThan(20);
  });

  test('resolves immediately on a brand-new audit instance with no appends at all', async () => {
    const audit = freshAudit();
    const start = Date.now();
    await audit.drainPendingWrites();
    expect(Date.now() - start).toBeLessThan(20);
  });
});
