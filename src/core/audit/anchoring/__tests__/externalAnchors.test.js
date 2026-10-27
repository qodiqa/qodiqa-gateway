'use strict';

/**
 * external anchoring of signed audit checkpoints (git commit, OpenTimestamps and RFC 3161 adapters).
 *
 *   EA-01  the statement and its domain-separated digest are what an independent verifier recomputes from the checkpoint alone
 *   EA-02  git: the statement is appended to anchors/<date>.jsonl and committed in the anchors repository (no push); republishing is idempotent
 *   EA-03  ots / rfc3161: the operator-provided executable gets { kind, digestHex, statement } on stdin and returns a receipt, stored on the row
 *   EA-04  asynchronous and never blocking: enqueue returns before publishing; nothing configured = nothing queued; it never throws
 *   EA-05  at most one checkpoint per interval unless forced
 *   EA-06  failures: an adapter that exits non-zero / prints junk / times out is counted, kept pending with its error and attempt count, retried,
 *          and becomes `failed` after MAX_ATTEMPTS; the other kinds are unaffected
 *   EA-07  a checkpoint that is already anchored is not queued twice (unique per payload hash and kind)
 */

jest.mock('../../../../../services/logger', () => ({ emit: jest.fn() }));

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const ea = require('../externalAnchors');
const { emit } = require('../../../../../services/logger');
const canonical = require('../../../../../scripts/audit-repro/verify/canonical');

const gitOk = spawnSync('git', ['--version']).status === 0;
const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p));
const signed = (n = 1) => ({
  payload: { v: 1, checkpointId: `cp-${n}`, createdAt: '2026-10-21T10:00:00.000Z', chainLength: 100 + n, headHash: crypto.createHash('sha256').update(`h${n}`).digest('hex'), pgSeq: null, evidenceHead: null, transparencyAnchor: null, previousCheckpointHash: null, keyId: 'cp:key_v1', keyVersion: 1 },
  payloadHash: crypto.createHash('sha256').update(`p${n}`).digest('hex'), signature: 'sig',
});

/** An executable that prints `body` (or exits with `code`) — a wrapper script that works on Windows and POSIX. */
function adapter(dir, name, jsBody) {
  const js = path.join(dir, `${name}.js`);
  fs.writeFileSync(js, jsBody);
  if (process.platform === 'win32') { const cmd = path.join(dir, `${name}.cmd`); fs.writeFileSync(cmd, `@echo off\r\n"${process.execPath}" "${js}"\r\n`); return cmd; }
  const sh = path.join(dir, name); fs.writeFileSync(sh, `#!/bin/sh\nexec "${process.execPath}" "${js}"\n`); fs.chmodSync(sh, 0o755); return sh;
}
const OK_ADAPTER = (tag) => `let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const i=JSON.parse(d);process.stdout.write(JSON.stringify({receipt:'${tag}:'+i.digestHex,ref:'${tag}-ref',echo:i.kind}));});`;

const ENV_KEYS = ['QODIQA_ANCHOR_GIT_REPO', 'QODIQA_ANCHOR_GIT_SIGN', 'QODIQA_ANCHOR_OTS_EXEC', 'QODIQA_ANCHOR_TSA_EXEC', 'QODIQA_ANCHOR_EXTERNAL_INTERVAL_MS', 'QODIQA_ANCHOR_GIT_AUTHOR'];
const saved = {};
beforeAll(() => { for (const k of ENV_KEYS) saved[k] = process.env[k]; });
afterAll(() => { for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } ea.stop(); });
beforeEach(() => { for (const k of ENV_KEYS) delete process.env[k]; ea._reset(); emit.mockClear(); });

describe('external anchors', () => {
  test('EA-01 the statement and digest are recomputable from the checkpoint alone (domain separation, canonical JSON)', () => {
    const s = signed(1);
    const st = ea.statementFor(s);
    expect(st).toEqual({ v: 1, checkpointId: 'cp-1', payloadHash: s.payloadHash, chainLength: 101, headHash: s.payload.headHash, createdAt: '2026-10-21T10:00:00.000Z' });
    const independent = crypto.createHash('sha256').update('QODIQA::EXTERNAL_ANCHOR::V1', 'utf8').update(canonical.canonicalize(st), 'utf8').digest('hex');
    expect(ea.digestOf(st)).toBe(independent);
    expect(ea.digestOf({ ...st, chainLength: 102 })).not.toBe(independent);
  });

  (gitOk ? test : test.skip)('EA-02 git: appended to anchors/<date>.jsonl and committed in the anchors repository; republishing is idempotent; nothing is pushed', async () => {
    const repo = tmp('qodiqa-anchors-');
    expect(spawnSync('git', ['init', '-q', repo]).status).toBe(0);
    process.env.QODIQA_ANCHOR_GIT_REPO = repo;
    const s = signed(1);
    expect(await ea.enqueue(s)).toEqual({ queued: ['git'] });
    await ea.settle();
    const file = path.join(repo, 'anchors', '2026-10-21.jsonl');
    const lines = fs.readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(lines).toHaveLength(1);
    expect(lines[0].digest).toBe(ea.digestOf(ea.statementFor(s)));
    expect(lines[0].statement).toEqual(ea.statementFor(s));
    const log = spawnSync('git', ['-C', repo, 'log', '--format=%H %an <%ae> %s'], { encoding: 'utf8' }).stdout.trim().split('\n');
    expect(log).toHaveLength(1);
    expect(log[0]).toMatch(/QODIQA Anchor <anchor@qodiqa.invalid> anchor 101 [0-9a-f]{16}$/);
    const rows = await ea.list();
    expect(rows[0]).toMatchObject({ kind: 'git', status: 'confirmed', attempts: 1 });
    expect(rows[0].receipt).toBe(log[0].split(' ')[0]);
    expect(rows[0].receipt_ref).toBe(`anchors/2026-10-21.jsonl@${rows[0].receipt}`);
    // a second checkpoint the same day appends a second line and a second commit; republishing the first changes nothing
    ea._reset(); process.env.QODIQA_ANCHOR_GIT_REPO = repo;
    await ea.enqueue(signed(2), { force: true }); await ea.settle();
    expect(fs.readFileSync(file, 'utf8').trim().split('\n')).toHaveLength(2);
    const again = await ea.publishGit({}, ea.statementFor(s), ea.digestOf(ea.statementFor(s)), process.env);
    expect(fs.readFileSync(file, 'utf8').trim().split('\n')).toHaveLength(2);
    expect(spawnSync('git', ['-C', repo, 'log', '--format=%H'], { encoding: 'utf8' }).stdout.trim().split('\n')).toHaveLength(2);
    expect(again.receipt).toMatch(/^[0-9a-f]{40,64}$/);
    expect(spawnSync('git', ['-C', repo, 'remote'], { encoding: 'utf8' }).stdout.trim()).toBe('');     // no remote, nothing pushed
  });

  test('EA-03 ots / rfc3161: the operator executable receives the digest and its receipt is stored', async () => {
    const dir = tmp('qodiqa-adapters-');
    process.env.QODIQA_ANCHOR_OTS_EXEC = adapter(dir, 'ots', OK_ADAPTER('ots'));
    process.env.QODIQA_ANCHOR_TSA_EXEC = adapter(dir, 'tsa', OK_ADAPTER('tsa'));
    const s = signed(3);
    expect((await ea.enqueue(s)).queued.sort()).toEqual(['ots', 'rfc3161']);
    await ea.settle();
    const rows = (await ea.list()).sort((a, b) => a.kind.localeCompare(b.kind));
    const digest = ea.digestOf(ea.statementFor(s));
    expect(rows.map((r) => [r.kind, r.status, r.receipt, r.receipt_ref])).toEqual([['ots', 'confirmed', `ots:${digest}`, 'ots-ref'], ['rfc3161', 'confirmed', `tsa:${digest}`, 'tsa-ref']]);
  }, 30000);

  test('EA-04 nothing configured queues nothing; enqueue returns before publishing and never throws', async () => {
    expect(await ea.enqueue(signed(1))).toEqual({ queued: [], skipped: 'NOT_CONFIGURED' });
    const dir = tmp('qodiqa-adapters-');
    process.env.QODIQA_ANCHOR_OTS_EXEC = adapter(dir, 'ots', OK_ADAPTER('ots'));
    const r = await ea.enqueue(signed(1));
    expect(r).toEqual({ queued: ['ots'] });
    expect((await ea.list())[0].status).toBe('pending');       // queued, not yet published: the caller was not made to wait
    await ea.settle();
    expect((await ea.list())[0].status).toBe('confirmed');
    await expect(ea.enqueue({ payload: null, payloadHash: 'x' }, { force: true })).resolves.toMatchObject({ queued: [], skipped: 'ERROR' });
  }, 30000);

  test('EA-05 at most one checkpoint per interval unless forced', async () => {
    const dir = tmp('qodiqa-adapters-');
    process.env.QODIQA_ANCHOR_OTS_EXEC = adapter(dir, 'ots', OK_ADAPTER('ots'));
    expect(ea.intervalMs()).toBe(24 * 3600 * 1000);
    process.env.QODIQA_ANCHOR_EXTERNAL_INTERVAL_MS = '5000';
    expect(ea.intervalMs()).toBe(5000);
    process.env.QODIQA_ANCHOR_EXTERNAL_INTERVAL_MS = '12';              // out of range: the default
    expect(ea.intervalMs()).toBe(24 * 3600 * 1000);
    await ea.enqueue(signed(1));
    expect(await ea.enqueue(signed(2))).toEqual({ queued: [], skipped: 'INTERVAL' });
    expect(await ea.enqueue(signed(3), { force: true })).toEqual({ queued: ['ots'] });
    await ea.settle();
  }, 30000);

  test('EA-06 a failing adapter is counted, kept pending with its error, retried, and becomes failed after MAX_ATTEMPTS; other kinds are unaffected', async () => {
    const dir = tmp('qodiqa-adapters-');
    process.env.QODIQA_ANCHOR_OTS_EXEC = adapter(dir, 'ots', 'process.stderr.write("calendar unreachable");process.exit(3);');
    process.env.QODIQA_ANCHOR_TSA_EXEC = adapter(dir, 'tsa', OK_ADAPTER('tsa'));
    await ea.enqueue(signed(1));
    await ea.settle();
    let rows = await ea.list();
    const ots = rows.find((x) => x.kind === 'ots'); const tsa = rows.find((x) => x.kind === 'rfc3161');
    expect(tsa.status).toBe('confirmed');
    expect(ots).toMatchObject({ status: 'pending', attempts: 1 });
    expect(ots.last_error).toMatch(/calendar unreachable/);
    expect(emit).toHaveBeenCalledWith('WARN', 'EXTERNAL_ANCHOR_FAILED', expect.objectContaining({ kind: 'ots', attempts: 1, status: 'pending' }));
    for (let i = 1; i < ea.MAX_ATTEMPTS; i++) await ea.processPending();
    rows = await ea.list();
    expect(rows.find((x) => x.kind === 'ots')).toMatchObject({ status: 'failed', attempts: ea.MAX_ATTEMPTS });
    process.env.QODIQA_ANCHOR_OTS_EXEC = adapter(dir, 'junk', 'process.stdout.write("not json");');
    ea._reset(); await ea.enqueue(signed(2), { force: true }); await ea.settle();
    expect((await ea.list()).find((x) => x.kind === 'ots').last_error).toMatch(/did not print JSON/);
  }, 120000);

  test('EA-07 the same checkpoint is not queued twice for a kind', async () => {
    const dir = tmp('qodiqa-adapters-');
    process.env.QODIQA_ANCHOR_OTS_EXEC = adapter(dir, 'ots', OK_ADAPTER('ots'));
    const s = signed(5);
    expect(await ea.enqueue(s, { force: true })).toEqual({ queued: ['ots'] });
    expect(await ea.enqueue(s, { force: true })).toEqual({ queued: [] });
    expect(await ea.list()).toHaveLength(1);
    await ea.settle();
  }, 30000);
});
