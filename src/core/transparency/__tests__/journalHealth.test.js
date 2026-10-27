'use strict';

/**
 * (D-F5-1, option A) — journalHealth.js and the bridge's best-effort path.
 *
 *   JH-01  the unavailability window: opens on a failure, ends on a success; EXECUTE is refused only past the bound (default 60 s, configurable
 *          1 s .. 1 h, an invalid value falls back to 60 s); the refusal is a coded, counted error
 *   JH-02  the late/recovered marker: monotonic per replica, inside the payload (so it is hashed), original time kept in recordedAt
 *   JH-03  bridge: nothing durable + bestEffort → buffered in memory, pending, window opened; without bestEffort → throws (response withheld);
 *          a durable store clears the window
 *   JH-04  the buffer drains in the ORIGINAL order and stops at the first leaf that still cannot be stored; recovery ends the window
 *   JH-05  a full buffer is a counted, escalated loss (CRITICAL) and the caller's own handling applies
 *   JH-06  writeLifecycleEntry('INTENT') refuses new executions past the bound before anything is written; STREAM_OPENED and a healthy store are unaffected
 */

const mockRegister = jest.fn();
jest.mock('../registrar', () => ({ register: (...a) => mockRegister(...a) }));
const mockPg = { enabled: true };
jest.mock('../../../infra/postgres/pool', () => ({ isEnabled: () => mockPg.enabled }));
const mockEnqueueWithOutcome = jest.fn();
jest.mock('../../persistenceRecovery', () => {
  const op = jest.requireActual('../../persistenceRecovery/persistenceOperation');
  return { isPersistenceFailure: op.isPersistenceFailure, OPERATION_TYPES: op.OPERATION_TYPES, enqueueWithOutcome: (...a) => mockEnqueueWithOutcome(...a) };
});
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const jh = require('../journalHealth');
const { registerEnforcementDecision } = require('../enforcementBridge');
const log = require('../log');
const { emit } = require('../../../../services/logger');
const metrics = require('../../../observability/metrics');

const ARGS = (n) => ({ requestId: `req-${n}`, decision: 'BLOCK', reason: 'TEST', stage: 'VALIDATION', tenantId: 't1' });
const connErr = () => Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
const MAX_ENV = 'QODIQA_TRANSPARENCY_JOURNAL_MAX_UNAVAILABLE_MS';
const sum = (c) => (c._values ? [...c._values.values()].reduce((a, b) => a + b, 0) : 0);
let realNow;
beforeEach(() => { jh._reset(); jest.clearAllMocks(); mockPg.enabled = true; delete process.env[MAX_ENV]; realNow = Date.now; });
afterEach(() => { Date.now = realNow; jh._reset(); delete process.env[MAX_ENV]; });
const later = (ms) => { Date.now = () => realNow() + ms; };

describe('journal health', () => {
  test('JH-01 window opens on failure, EXECUTE is refused only past the bound, a success ends it', () => {
    expect(jh.maxUnavailableMs()).toBe(60000);
    jh.noteFailure(new Error('disk gone'));
    expect(jh.isRefusing()).toBe(false);
    expect(() => jh.assertAvailable()).not.toThrow();
    later(59000); expect(jh.isRefusing()).toBe(false);
    later(61000);
    expect(jh.isRefusing()).toBe(true);
    const before = sum(metrics.transparencyJournalRefusedTotal);
    let err; try { jh.assertAvailable(); } catch (e) { err = e; }
    expect(err).toMatchObject({ code: 'TRANSPARENCY_JOURNAL_UNAVAILABLE' });
    expect(sum(metrics.transparencyJournalRefusedTotal)).toBe(before + 1);
    expect(emit).toHaveBeenCalledWith('CRITICAL', 'TRANSPARENCY_JOURNAL_REFUSING_EXECUTE', expect.any(Object));
    jh.noteOk();
    expect(jh.isRefusing()).toBe(false);
    expect(jh.snapshot()).toMatchObject({ unavailable: false, refusing: false });
    for (const [v, want] of [['30000', 30000], ['1000', 1000], ['3600000', 3600000], ['999', 60000], ['3600001', 60000], ['abc', 60000], ['1.5', 60000], ['', 60000]]) {
      process.env[MAX_ENV] = v;
      expect({ v, got: jh.maxUnavailableMs() }).toEqual({ v, got: want });
    }
  });

  test('JH-02 the marker is monotonic per replica and carries what a verifier needs', () => {
    const a = jh.recoveryMarker(); const b = jh.recoveryMarker();
    expect(a).toEqual({ late: true, replica: jh.REPLICA, seq: expect.any(Number), queuedAt: expect.any(String) });
    expect(b.seq).toBe(a.seq + 1);
    expect(Object.keys(a).sort()).toEqual(['late', 'queuedAt', 'replica', 'seq']);     // no undefined member: the hash survives a JSON round trip
    expect(log.computePayloadHash({ recovery: a })).toBe(log.computePayloadHash(JSON.parse(JSON.stringify({ recovery: a }))));
  });

  test('JH-03 bridge: bestEffort buffers when nothing durable takes the leaf; without it the failure is thrown; the window closes only when the buffer is empty and the store is back', async () => {
    mockRegister.mockRejectedValue(connErr());
    mockEnqueueWithOutcome.mockResolvedValue({ phantom: null, durable: false });
    const r = await registerEnforcementDecision({ ...ARGS(1), bestEffort: true });
    expect(r).toMatchObject({ persisted: 'pending', durable: false });
    expect(jh.snapshot()).toMatchObject({ unavailable: true, buffered: 1 });
    expect(emit).toHaveBeenCalledWith('CRITICAL', 'TRANSPARENCY_JOURNAL_UNAVAILABLE', expect.any(Object));
    await expect(registerEnforcementDecision(ARGS(2))).rejects.toMatchObject({ code: 'ECONNREFUSED' });      // a non-streamed ALLOW: response withheld
    expect(jh.snapshot().buffered).toBe(1);
    // the store takes a NEW leaf, but one is still waiting in memory: the window stays open until the buffer has drained
    mockEnqueueWithOutcome.mockResolvedValue({ phantom: null, durable: 'journal' });
    await registerEnforcementDecision({ ...ARGS(3), bestEffort: true });
    expect(jh.snapshot()).toMatchObject({ unavailable: true, buffered: 1 });
    mockRegister.mockResolvedValue({ transparencyId: 't', persisted: true });                                  // an unrelated success does not end it either
    await registerEnforcementDecision(ARGS(4));
    expect(jh.snapshot().unavailable).toBe(true);
    expect(await jh.flushBuffer()).toEqual({ flushed: 1, remaining: 0 });
    expect(jh.snapshot()).toMatchObject({ unavailable: false, buffered: 0 });
    // with nothing buffered, a synchronous registration that persists ends a window
    jh.noteFailure(new Error('x'));
    await registerEnforcementDecision(ARGS(5));
    expect(jh.snapshot().unavailable).toBe(false);
  });

  test('JH-03b D1: a failure the replay handler would not retry (signer / KMS outage) is NOT queued and NOT reported pending: it opens the window, is counted and escalated, and is rethrown', async () => {
    mockRegister.mockRejectedValue(new Error('KMS signer unavailable'));
    const before = sum(metrics.transparencyUnrecordedTotal);
    await expect(registerEnforcementDecision({ ...ARGS(1), bestEffort: true })).rejects.toThrow('KMS signer unavailable');
    expect(mockEnqueueWithOutcome).not.toHaveBeenCalled();
    expect(jh.snapshot().unavailable).toBe(true);
    expect(sum(metrics.transparencyUnrecordedTotal)).toBe(before + 1);
    expect(emit).toHaveBeenCalledWith('CRITICAL', 'TRANSPARENCY_LEAF_UNRECORDED', expect.objectContaining({ code: null }));
    // a programming error is rethrown and counted the same way
    await expect(registerEnforcementDecision(ARGS(2))).rejects.toThrow();
  });

  test('JH-03c D4: the promised payloadHash equals the hash after a JSON round trip even when the payload has an undefined member', async () => {
    mockRegister.mockRejectedValue(connErr());
    mockEnqueueWithOutcome.mockResolvedValue({ phantom: null, durable: 'queue' });
    const r = await registerEnforcementDecision({ ...ARGS(1), semantic: { decision: 'ALLOW', score: undefined } });
    const stored = mockEnqueueWithOutcome.mock.calls[0][1].registration;
    expect(r.payloadHash).toBe(log.computePayloadHash(JSON.parse(JSON.stringify(stored.payload))));
    expect(r.payloadHash).toBe(log.computePayloadHash(stored.payload));
  });

  test('JH-03d D2: with nothing buffered the window closes by itself once the store answers a probe - no traffic needed; a probe that fails keeps it open', async () => {
    jh.noteFailure(new Error('journal volume gone'));
    jh.setProber(async () => false);
    expect(await jh.flushBuffer()).toEqual({ flushed: 0, remaining: 0 });
    expect(jh.snapshot().unavailable).toBe(true);
    jh.setProber(async () => true);
    await jh.flushBuffer();
    expect(jh.snapshot().unavailable).toBe(false);
    later(61000);
    expect(jh.isRefusing()).toBe(false);
    jh.setProber(null);
  });

  test('JH-03e D3: two overlapping flushes never take the same buffered leaf (re-entrancy guard)', async () => {
    mockRegister.mockRejectedValue(connErr());
    mockEnqueueWithOutcome.mockResolvedValue({ phantom: null, durable: false });
    for (let i = 0; i < 3; i++) await registerEnforcementDecision({ ...ARGS(i), bestEffort: true });
    const stored = []; let release;
    const gate = new Promise((res) => { release = res; });
    mockEnqueueWithOutcome.mockImplementation(async (_t, { registration }) => { await gate; stored.push(registration.payload.requestId); return { phantom: null, durable: 'journal' }; });
    const first = jh.flushBuffer();
    const second = await jh.flushBuffer();                      // overlaps the first
    expect(second).toMatchObject({ flushed: 0, skipped: true });
    release();
    expect(await first).toEqual({ flushed: 3, remaining: 0 });
    expect(stored).toEqual(['req-0', 'req-1', 'req-2']);        // each leaf stored exactly once, in order
  });

  test('JH-03f D7: at shutdown leaves that cannot be stored are reported lost (CRITICAL + counter), never silently', async () => {
    mockRegister.mockRejectedValue(connErr());
    mockEnqueueWithOutcome.mockResolvedValue({ phantom: null, durable: false });
    for (let i = 0; i < 2; i++) await registerEnforcementDecision({ ...ARGS(i), bestEffort: true });
    const before = sum(metrics.transparencyUnrecordedTotal);
    expect(await jh.flushOnShutdown()).toEqual({ lost: 2 });
    expect(sum(metrics.transparencyUnrecordedTotal)).toBe(before + 2);
    expect(emit).toHaveBeenCalledWith('CRITICAL', 'TRANSPARENCY_LEAF_LOST', expect.objectContaining({ reason: 'shutdown', count: 2 }));
    mockEnqueueWithOutcome.mockResolvedValue({ phantom: null, durable: 'journal' });
    jh._reset();
    for (let i = 0; i < 2; i++) jh.buffer({ transparencyId: 't' + i, payload: { requestId: 'r' + i } });
    expect(await jh.flushOnShutdown()).toEqual({ lost: 0 });    // a store that is back gets them
  });

  test('JH-03g N1: a window closed by the probe that re-opens within the bound is the SAME outage (original start), so a half-working store still reaches the bound; a real write ends it for good', async () => {
    jh.noteFailure(new Error('INSERT refused'));
    const t0 = realNow();
    jh.setProber(async () => true);                              // SELECT 1 answers although real writes keep failing
    await jh.flushBuffer();
    expect(jh.snapshot().unavailable).toBe(false);               // the probe closed it ...
    later(30000);
    jh.noteFailure(new Error('INSERT refused again'));           // ... and the next real failure re-opens the SAME window
    expect(jh.snapshot().unavailableSince).toBe(t0);
    later(61000);
    expect(jh.isRefusing()).toBe(true);                          // the bound is reached
    jh.noteOk();                                                 // a successful real write
    expect(jh.snapshot().unavailable).toBe(false);
    later(120000);
    jh.noteFailure(new Error('new outage'));
    expect(jh.snapshot().unavailableSince).toBeGreaterThan(t0 + 100000);   // a genuinely new window
    jh.setProber(null);
  });

  test('JH-03h N2/N3: shutdown waits for a flush that is already writing (no false loss) and never waits longer than its timeout', async () => {
    mockRegister.mockRejectedValue(connErr());
    mockEnqueueWithOutcome.mockResolvedValue({ phantom: null, durable: false });
    await registerEnforcementDecision({ ...ARGS(1), bestEffort: true });
    let release; const gate = new Promise((res) => { release = res; });
    mockEnqueueWithOutcome.mockImplementation(async () => { await gate; return { phantom: null, durable: 'journal' }; });
    const timerFlush = jh.flushBuffer();                         // a flush is already writing the leaf
    const shutdown = jh.flushOnShutdown({ timeoutMs: 2000 });
    setTimeout(release, 50);
    expect(await shutdown).toEqual({ lost: 0 });                 // it waited, and the leaf was stored
    await timerFlush;
    jh._reset();
    mockEnqueueWithOutcome.mockImplementation(() => new Promise(() => {}));   // an enqueue that never answers
    jh.buffer({ transparencyId: 'tx', payload: { requestId: 'rx' } });
    const t = Date.now();
    expect(await jh.flushOnShutdown({ timeoutMs: 200 })).toEqual({ lost: 1 });
    expect(Date.now() - t).toBeLessThan(1500);                   // bounded
  });

  test('JH-04 the buffer drains in the original order and stops at the first leaf that still cannot be stored', async () => {
    mockRegister.mockRejectedValue(connErr());
    mockEnqueueWithOutcome.mockResolvedValue({ phantom: null, durable: false });
    for (let i = 0; i < 3; i++) await registerEnforcementDecision({ ...ARGS(i), bestEffort: true });
    expect(jh.snapshot().buffered).toBe(3);
    const stored = [];
    mockEnqueueWithOutcome.mockImplementation(async (_t, { registration }) => {
      if (registration.payload.requestId === 'req-1' && stored.length === 1 && !mockEnqueueWithOutcome.allowSecond) return { phantom: null, durable: false };
      stored.push(registration.payload.requestId);
      return { phantom: null, durable: 'journal' };
    });
    expect(await jh.flushBuffer()).toEqual({ flushed: 1, remaining: 2 });                      // req-0 stored, req-1 refused, req-2 NOT stored ahead of it
    expect(stored).toEqual(['req-0']);
    mockEnqueueWithOutcome.allowSecond = true;
    expect(await jh.flushBuffer()).toEqual({ flushed: 2, remaining: 0 });
    expect(stored).toEqual(['req-0', 'req-1', 'req-2']);                                         // original order
    expect(jh.snapshot()).toMatchObject({ unavailable: false, buffered: 0 });
    expect(emit).toHaveBeenCalledWith('WARN', 'TRANSPARENCY_JOURNAL_RECOVERED', expect.any(Object));
  });

  test('JH-05 a full buffer is an escalated, counted loss; the bridge then throws', async () => {
    mockRegister.mockRejectedValue(connErr());
    mockEnqueueWithOutcome.mockResolvedValue({ phantom: null, durable: false });
    for (let i = 0; i < jh.BUFFER_CAP; i++) expect(jh.buffer({ transparencyId: `t${i}`, payload: {} })).toBe(true);
    const before = sum(metrics.transparencyUnrecordedTotal);
    await expect(registerEnforcementDecision({ ...ARGS(9), bestEffort: true })).rejects.toMatchObject({ code: 'ECONNREFUSED' });
    expect(sum(metrics.transparencyUnrecordedTotal)).toBe(before + 1);
    expect(emit).toHaveBeenCalledWith('CRITICAL', 'TRANSPARENCY_LEAF_LOST', expect.objectContaining({ reason: 'buffer_full' }));
  });

  test('JH-06 INTENT refuses new executions past the bound before anything is written; STREAM_OPENED and a healthy store are unaffected', async () => {
    const { writeLifecycleEntry } = require('../../audit/lifecycleEntry');
    const append = jest.fn().mockResolvedValue({ hash: 'h'.repeat(64) });
    const register = jest.fn().mockResolvedValue({ persisted: true, transparencyId: 't' });
    const f = { requestId: 'req-x', inputHash: 'a'.repeat(64), signature: 's', requestHash: 'a'.repeat(64), policyHash: 'b'.repeat(64), tenantId: 't1', executingProvider: 'openai' };
    await expect(writeLifecycleEntry('INTENT', f, { append, register })).resolves.toBeTruthy();   // healthy
    append.mockClear(); register.mockClear();
    jh.noteFailure(new Error('journal volume gone'));
    later(61000);
    await expect(writeLifecycleEntry('INTENT', f, { append, register })).rejects.toMatchObject({ code: 'TRANSPARENCY_JOURNAL_UNAVAILABLE' });
    expect(append).not.toHaveBeenCalled(); expect(register).not.toHaveBeenCalled();
    await expect(writeLifecycleEntry('STREAM_OPENED', { ...f, responseId: 'r1' }, { append, register })).resolves.toBeTruthy();
  });
});

describe('the journal lives on a persistent volume (boot validation)', () => {
  const { checks } = require('../../../infra/config/bootValidator');
  const path = require('path');
  const ROOT = path.resolve(__dirname, '..', '..', '..', '..');
  const prod = (extra = {}) => ({ NODE_ENV: 'production', ...extra });
  const fakeFs = (dev, rootDev, container = true) => ({
    existsSync: (p) => (p === '/.dockerenv' ? container : true),
    statSync: (p) => ({ dev: p === '/' ? rootDev : dev }),
  });

  test('JD-01 only production is checked; unset is reported (a warning in the validator), a path inside the application directory is refused', () => {
    expect(checks.productionJournalDir({ NODE_ENV: 'development' }, ROOT)).toEqual([]);
    expect(checks.productionJournalDir(prod(), ROOT).join(' ')).toMatch(/QODIQA_PRQ_JOURNAL_DIR is not set in production/);
    const inside = checks.productionJournalDir(prod({ QODIQA_PRQ_JOURNAL_DIR: path.join(ROOT, 'data', 'prq-journal') }), ROOT);
    expect(inside.join(' ')).toMatch(/inside the application directory/);
    expect(checks.productionJournalDir(prod({ QODIQA_PRQ_JOURNAL_DIR: path.join(require('os').tmpdir(), 'vol', 'prq-journal') }), ROOT, fakeFs(1, 2, false))).toEqual([]);
  });

  test('JD-03 D6: a journal path that does not exist yet is judged by its nearest existing ancestor (the journal would create it on that filesystem)', () => {
    const dir = path.join(require('os').tmpdir(), 'vol', 'new', 'prq-journal');
    const fs2 = { existsSync: (p) => (p === '/.dockerenv' ? true : p === path.join(require('os').tmpdir(), 'vol') || p === '/'), statSync: (p) => ({ dev: p === '/' ? 7 : 7 }) };
    expect(checks.productionJournalDir(prod({ QODIQA_PRQ_JOURNAL_DIR: dir }), ROOT, fs2).join(' ')).toMatch(/container root filesystem/);
    const fs3 = { ...fs2, statSync: (p) => ({ dev: p === '/' ? 7 : 8 }) };
    expect(checks.productionJournalDir(prod({ QODIQA_PRQ_JOURNAL_DIR: dir }), ROOT, fs3)).toEqual([]);
  });

  test('JD-02 in a container the journal must not be on the container root filesystem (it would not survive a restart); a mounted volume is accepted', () => {
    const dir = path.join(require('os').tmpdir(), 'vol', 'prq-journal');
    expect(checks.productionJournalDir(prod({ QODIQA_PRQ_JOURNAL_DIR: dir }), ROOT, fakeFs(7, 7)).join(' ')).toMatch(/container root filesystem/);
    expect(checks.productionJournalDir(prod({ QODIQA_PRQ_JOURNAL_DIR: dir }), ROOT, fakeFs(8, 7))).toEqual([]);                  // a different device = a mounted volume
    expect(checks.productionJournalDir(prod({ QODIQA_PRQ_JOURNAL_DIR: dir }), ROOT, fakeFs(7, 7, false))).toEqual([]);          // not a container: the host disk is persistent
    expect(checks.productionJournalDir(prod({ QODIQA_PRQ_JOURNAL_DIR: dir, KUBERNETES_SERVICE_HOST: '10.0.0.1' }), ROOT, fakeFs(7, 7, false)).join(' ')).toMatch(/container root filesystem/);
  });
});
