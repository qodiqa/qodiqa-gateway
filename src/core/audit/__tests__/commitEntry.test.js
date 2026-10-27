'use strict';

/**
 * commitEntry.js: the COMMIT recorder (AUDIT-V8-FREEZE section 3).
 *
 *   CM-01  audit schema v8 off: nothing is appended, the skip is counted
 *   CM-02  a delivered response: the exact fields of the frozen COMMIT row; the entry builds and verifies with the real entryBuilder
 *   CM-03  each failure cause maps to its completionStatus; nothing delivered = EMPTY_OUTPUT_HASH and 0 bytes
 *   CM-04  a tracker settles once; later calls return the first result
 *   CM-05  a refused append is escalated (CRITICAL AUDIT_COMMIT_FAILED) and the exact record is handed to the lifecycle reconciler; a duplicate counts as done
 *   CM-06  completionStatusForStream maps the stream vocabulary
 *   CM-07  watchResponse: finish = delivered; close before finish = CLIENT_DISCONNECTED; an already finished / destroyed response; a client that left earlier
 *   CM-08  watchStreamEnd: a connection that closes before the end was flushed turns a COMPLETE into CLIENT_DISCONNECTED
 *   CM-09  createOutputHasher().bytes(): UTF-8 bytes of exactly what is hashed (astral characters, a lone surrogate at the end)
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
const mockAppend = jest.fn();
jest.mock('../audit-log', () => ({ appendMandatory: (...a) => mockAppend(...a) }));
const mockRegister = jest.fn();
jest.mock('../lifecycleReconciler', () => ({ registerOpenLifecycle: (...a) => mockRegister(...a), setCommitRecorder: jest.fn() }));
jest.mock('../../persistenceRecovery', () => ({ setCommitWriter: jest.fn(), enqueueWithOutcome: jest.fn(), OPERATION_TYPES: { AUDIT_COMMIT_WRITE: 'AUDIT_COMMIT_WRITE' } }));

const { EventEmitter } = require('events');
const { emit } = require('../../../../services/logger');
const eb = require('../entryBuilder');
const commit = require('../commitEntry');
const metrics = require('../../../observability/metrics');

const SAVED = process.env.QODIQA_AUDIT_SCHEMA_V8;
const CTX = { requestId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', signature: 'sig-test', tenantId: 'tenant1', organizationId: 'org1' };
const H = (c) => c.repeat(64);
const count = (outcome) => { let n = 0; if (metrics.auditCommitsTotal._values) for (const [k, v] of metrics.auditCommitsTotal._values.entries()) if (k.includes(outcome)) n += v; return n; };

beforeEach(() => { mockAppend.mockReset(); mockRegister.mockReset(); emit.mockClear(); mockAppend.mockImplementation(async () => ({ hash: H('e') })); process.env.QODIQA_AUDIT_SCHEMA_V8 = 'true'; });
afterAll(() => { if (SAVED === undefined) delete process.env.QODIQA_AUDIT_SCHEMA_V8; else process.env.QODIQA_AUDIT_SCHEMA_V8 = SAVED; });

describe('commitEntry', () => {
  test('CM-01 with audit schema v8 off nothing is appended and the skip is counted', async () => {
    delete process.env.QODIQA_AUDIT_SCHEMA_V8;
    const before = count('skipped');
    const r = await commit.createCommitTracker(CTX).deliver({ outputHash: H('a'), bytesDelivered: 5 });
    expect(r).toEqual({ recorded: false, skipped: true });
    expect(mockAppend).not.toHaveBeenCalled();
    expect(count('skipped')).toBe(before + 1);
  });

  test('CM-02 a delivered response: the frozen COMMIT row, built and verified by the real entryBuilder', async () => {
    const r = await commit.createCommitTracker(CTX).deliver({ outputHash: H('a'), bytesDelivered: 14 });
    expect(r).toMatchObject({ recorded: true, auditEntryHash: H('e') });
    const [fields, opts] = mockAppend.mock.calls[0];
    expect(opts).toMatchObject({ stage: 'COMMIT' });
    expect(fields).toEqual({
      artifactId: `${CTX.requestId}:commit`, entryType: 'COMMIT', decision: 'ALLOW', reason: 'RESPONSE_DELIVERED', signature: 'sig-test', tenantId: 'tenant1',
      organizationId: 'org1', requestId: CTX.requestId, outputHash: H('a'), bytesDelivered: 14, completionStatus: 'COMPLETE',
    });
    const entry = eb.buildEntry(eb.normalizeFields(fields), 'GENESIS');
    expect(entry).toMatchObject({ schemaVersion: 8, entryType: 'COMMIT', stage: 'COMMIT', reason: 'RESPONSE_DELIVERED', bytesDelivered: 14, completionStatus: 'COMPLETE', outputHash: H('a') });
    expect(eb.v8ShapeViolation(entry)).toBeNull();
  });

  test.each([
    ['CLIENT_DISCONNECTED', 'CLIENT_DISCONNECTED'], ['TIMEOUT', 'TIMEOUT'], ['CANCELLED', 'CANCELLED'], ['ERROR', 'ERROR'], ['SOMETHING_ELSE', 'ERROR'],
  ])('CM-03 fail(%s) → RESPONSE_FAILED / %s with the hash of nothing and 0 bytes', async (cause, status) => {
    await commit.createCommitTracker(CTX).fail(cause);
    const [fields] = mockAppend.mock.calls[0];
    expect(fields).toMatchObject({ reason: 'RESPONSE_FAILED', decision: 'ALLOW', completionStatus: status, bytesDelivered: 0, outputHash: eb.EMPTY_OUTPUT_HASH });
    expect(eb.v8ShapeViolation(eb.buildEntry(eb.normalizeFields(fields), 'GENESIS'))).toBeNull();
  });

  test('CM-04 a tracker settles once: the second call returns the first result and appends nothing', async () => {
    const t = commit.createCommitTracker(CTX);
    const a = t.fail('TIMEOUT');
    const b = t.deliver({ outputHash: H('a'), bytesDelivered: 3 });
    expect(b).toBe(a);
    await a;
    expect(mockAppend).toHaveBeenCalledTimes(1);
    expect(t.settled).toBe(true);
  });

  test('CM-05 a refused append is escalated and the exact record is retried by the reconciler; "already_executed" counts as done', async () => {
    mockAppend.mockRejectedValueOnce(Object.assign(new Error('AUDIT_PERSISTENCE_FAILED: EIO'), { code: 'AUDIT_PERSISTENCE_FAILED' }));
    const before = count('failed');
    const r = await commit.createCommitTracker(CTX).deliver({ outputHash: H('a'), bytesDelivered: 14 });
    expect(r).toEqual({ recorded: false, failed: true });
    expect(emit).toHaveBeenCalledWith('CRITICAL', 'AUDIT_COMMIT_FAILED', expect.objectContaining({ requestId: CTX.requestId, bytesDelivered: 14, completionStatus: 'COMPLETE' }));
    expect(count('failed')).toBe(before + 1);
    const [key, reg] = mockRegister.mock.calls[0];
    expect(key).toBe(`${CTX.requestId}:commit`);
    expect(reg.kind).toBe('commit');
    mockAppend.mockClear();
    mockAppend.mockImplementation(async () => ({ hash: H('f') }));
    expect(await reg.retry()).toMatchObject({ recorded: true });                 // the same fields again
    expect(mockAppend.mock.calls[0][0]).toMatchObject({ artifactId: `${CTX.requestId}:commit`, bytesDelivered: 14, completionStatus: 'COMPLETE' });
    mockAppend.mockRejectedValueOnce(new Error('already_executed: artifactId already in audit log'));
    expect(await commit.createCommitTracker({ ...CTX, requestId: 'bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee' }).deliver({ outputHash: H('a'), bytesDelivered: 1 })).toEqual({ recorded: false, duplicate: true });
  });

  test('CM-06 completionStatusForStream maps the stream vocabulary', () => {
    const f = commit.completionStatusForStream;
    expect([f('completed', 'COMPLETED'), f('error', 'PROVIDER_ERROR'), f('cancelled', 'CLIENT_DISCONNECT'), f('cancelled', 'STREAM_TIMEOUT'), f('cancelled', 'SERVER_SHUTDOWN'), f('blocked', 'SEMANTIC')])
      .toEqual(['COMPLETE', 'ERROR', 'CLIENT_DISCONNECTED', 'TIMEOUT', 'CANCELLED', 'CANCELLED']);
    for (const s of [f('completed'), f('error'), f('cancelled', 'x')]) expect(eb.COMPLETION_STATUSES).toContain(s);
  });

  describe('CM-07 watchResponse', () => {
    const settled = async (res, info = { outputHash: H('a'), bytesDelivered: 9 }) => {
      const t = commit.createCommitTracker(CTX);
      commit.watchResponse(res, t, info);
      return t;
    };
    const lastFields = () => mockAppend.mock.calls[mockAppend.mock.calls.length - 1][0];

    test('finish → delivered', async () => {
      const res = new EventEmitter(); res.writableFinished = false; res.destroyed = false;
      const t = await settled(res);
      expect(t.settled).toBe(false);
      res.emit('finish');
      await new Promise((r) => setImmediate(r));
      expect(lastFields()).toMatchObject({ reason: 'RESPONSE_DELIVERED', completionStatus: 'COMPLETE', bytesDelivered: 9 });
    });

    test('close before finish → CLIENT_DISCONNECTED, 0 bytes', async () => {
      const res = new EventEmitter(); res.writableFinished = false; res.destroyed = false;
      await settled(res);
      res.emit('close');
      await new Promise((r) => setImmediate(r));
      expect(lastFields()).toMatchObject({ reason: 'RESPONSE_FAILED', completionStatus: 'CLIENT_DISCONNECTED', bytesDelivered: 0, outputHash: eb.EMPTY_OUTPUT_HASH });
    });

    test('a response that already finished is delivered at once; one already destroyed is a disconnect', async () => {
      const done = new EventEmitter(); done.writableFinished = true;
      await settled(done);
      expect(lastFields()).toMatchObject({ completionStatus: 'COMPLETE' });
      const dead = new EventEmitter(); dead.writableFinished = false; dead.destroyed = true;
      await settled(dead);
      expect(lastFields()).toMatchObject({ completionStatus: 'CLIENT_DISCONNECTED' });
    });

    test('a client that left before the response was ended (request context flag) is a disconnect even if the dead socket "finishes"', async () => {
      const rac = require('../requestAuditContext');
      const holder = { clientGone: true, requestId: null };
      const spy = jest.spyOn(rac, 'currentArtifactFacts').mockReturnValue(holder);
      try {
        const res = new EventEmitter(); res.writableFinished = true;
        await settled(res);
        expect(lastFields()).toMatchObject({ reason: 'RESPONSE_FAILED', completionStatus: 'CLIENT_DISCONNECTED', bytesDelivered: 0 });
      } finally { spy.mockRestore(); }
    });
  });

  test('CM-08 watchStreamEnd: a connection that closes before the end was flushed turns COMPLETE into CLIENT_DISCONNECTED (bytes released are kept)', async () => {
    const outcome = { delivered: true, outputHash: H('a'), bytesDelivered: 42, completionStatus: 'COMPLETE' };
    const ok = new EventEmitter(); ok.writableFinished = false; ok.destroyed = false;
    const t1 = commit.createCommitTracker(CTX); commit.watchStreamEnd(ok, t1, outcome); ok.emit('finish'); await new Promise((r) => setImmediate(r));
    expect(mockAppend.mock.calls[0][0]).toMatchObject({ reason: 'RESPONSE_DELIVERED', completionStatus: 'COMPLETE', bytesDelivered: 42 });
    const bad = new EventEmitter(); bad.writableFinished = false; bad.destroyed = false;
    const t2 = commit.createCommitTracker({ ...CTX, requestId: 'cccccccc-bbbb-4ccc-8ddd-eeeeeeeeeeee' }); commit.watchStreamEnd(bad, t2, outcome); bad.emit('close'); await new Promise((r) => setImmediate(r));
    expect(mockAppend.mock.calls[1][0]).toMatchObject({ reason: 'RESPONSE_FAILED', completionStatus: 'CLIENT_DISCONNECTED', bytesDelivered: 42, outputHash: H('a') });
    const mock = {};                                                  // a response object without events settles at once
    commit.watchStreamEnd(mock, commit.createCommitTracker({ ...CTX, requestId: 'dddddddd-bbbb-4ccc-8ddd-eeeeeeeeeeee' }), { ...outcome, completionStatus: 'ERROR', delivered: false });
    await new Promise((r) => setImmediate(r));
    expect(mockAppend.mock.calls[2][0]).toMatchObject({ completionStatus: 'ERROR', reason: 'RESPONSE_FAILED' });
  });

  test('CM-09 createOutputHasher().bytes() counts the UTF-8 bytes of exactly what is hashed', () => {
    const h = eb.createOutputHasher();
    h.update('abc'); h.update('é'); h.update('😀');
    h.digest();
    expect(h.bytes()).toBe(Buffer.byteLength('abcé😀', 'utf8'));
    expect(eb.outputHashOf('abcé😀')).toBe(eb.createOutputHasher && (() => { const g = eb.createOutputHasher(); g.update('abcé😀'); return g.digest(); })());
    const split = eb.createOutputHasher();
    split.update('x\uD83D'); split.update('\uDE00y');               // an astral character split across two chunks
    split.digest();
    expect(split.bytes()).toBe(Buffer.byteLength('x😀y', 'utf8'));
    const lone = eb.createOutputHasher();
    lone.update('a\uD83D');                                           // a lone high surrogate is carried, then hashed at digest()
    lone.digest();
    expect(lone.bytes()).toBe(Buffer.byteLength('a\uD83D', 'utf8'));
    expect(eb.createOutputHasher().bytes()).toBe(0);
  });
});
