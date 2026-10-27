'use strict';

/**
 * — scripts/backup-audit-log.sh incremental runs (+ scripts/audit-log-backup-chain.js).
 *
 *   IN-1  base, then segments of ONLY the new bytes; a torn (in-flight) last line is never backed up; restore = source
 *   IN-2  a run with no new bytes writes an empty segment (cadence stays visible; verify is not stale)
 *   IN-3  a rewritten / pruned log forces a new base (shorter, different first line, changed backed-up tail)
 *   IN-4  tampering is refused by verify (exactly one alert) and by restore: changed segment data, edited meta,
 *         a missing middle segment (gap), swapped segments (order)
 * IN-5 a segment file cannot be restored on its own; an earlier full copy (no meta) still restores as before
 *   IN-6  INCREMENTAL=false → every run is a base; REBASE_HOURS=0 → scheduled rebase, deferred outside the backup window
 *   IN-7  retention prunes WHOLE old chains by their newest file and never the current chain
 *   IN-8  each run's .sum is copied before the log and restored from the LAST run
 *   IN-9  the copied WAL is kept only if it continues the backed-up prefix; a batch already committed inside it is omitted
 *         (at backup and, re-checked, at restore); a foreign WAL fails the run closed
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { spawnSync } = require('child_process');

const REPO = path.join(__dirname, '..', '..');
const SCRIPT = path.join(REPO, 'scripts', 'backup-audit-log.sh');

function findBash() {
  if (process.platform !== 'win32') return 'bash';
  for (const p of ['C:\\Program Files\\Git\\bin\\bash.exe', 'C:\\Program Files (x86)\\Git\\bin\\bash.exe']) if (fs.existsSync(p)) return p;
  return null;
}
const BASH = findBash();
const describeOrSkip = BASH ? describe : describe.skip;
jest.setTimeout(120000);

const posix = (p) => p.replace(/\\/g, '/').replace(/^([A-Za-z]):/, (_, d) => `/${d.toLowerCase()}`);
const KEY = 'aut19-test-hmac-key-0123456789abcdef-xyz';

function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aut19-'));
  return { dir, log: path.join(dir, 'audit.log'), bk: path.join(dir, 'bk') };
}
function run(sb, args, env = {}) {
  const r = spawnSync(BASH, [posix(SCRIPT), ...args], {
    encoding: 'utf8',
    env: { PATH: process.env.PATH, SYSTEMROOT: process.env.SYSTEMROOT, TEMP: process.env.TEMP, TMP: process.env.TMP, HOME: sb.dir,
      QODIQA_AUDIT_LOG: posix(sb.log), QODIQA_AUDIT_BACKUP_DIR: posix(sb.bk), QODIQA_BACKUP_HMAC_KEY: KEY,
      QODIQA_AUDIT_BACKUP_MAX_AGE_SECONDS: '600', ...env },
  });
  return { status: r.status, out: `${r.stdout}\n${r.stderr}` };
}
const event = (out, name) => out.split('\n').filter((l) => l.includes(`"event":"${name}"`)).map((l) => JSON.parse(l));
const complete = (out) => event(out, 'AUDIT_LOG_BACKUP_COMPLETE')[0];
const lines = (n0, n1) => Array.from({ length: n1 - n0 }, (_, i) => `{"n":${n0 + i},"pad":"${'x'.repeat(40)}"}\n`).join('');
const files = (sb) => fs.readdirSync(sb.bk).sort();
const tick = () => new Promise((r) => setTimeout(r, 1100));   // run names are per-second timestamps

describeOrSkip('incremental audit-log backup', () => {
  test('IN-1 base then segments of only the new bytes; torn tail excluded; restore is byte-identical', async () => {
    const sb = sandbox();
    fs.writeFileSync(sb.log, lines(0, 50));
    let r = run(sb, ['backup']); expect(r.status).toBe(0);
    let c = complete(r.out); expect(c).toMatchObject({ kind: 'base', seq: 0, from: 0, reason: 'no-state' });
    const baseBytes = fs.statSync(sb.log).size; expect(c.to).toBe(baseBytes);
    await tick();
    fs.appendFileSync(sb.log, `${lines(50, 60)}{"n":60,"torn`);
    r = run(sb, ['backup']); expect(r.status).toBe(0);
    c = complete(r.out); expect(c).toMatchObject({ kind: 'segment', seq: 1, from: baseBytes });
    expect(c.to).toBe(baseBytes + Buffer.byteLength(lines(50, 60)));   // the torn line is not in it
    const seg = path.join(sb.bk, `${c.base}.seg-000001.log.gz`);
    expect(zlib.gunzipSync(fs.readFileSync(seg)).toString()).toBe(lines(50, 60));
    await tick();
    fs.appendFileSync(sb.log, '}\n');
    expect(complete(run(sb, ['backup']).out)).toMatchObject({ kind: 'segment', seq: 2, from: c.to, to: fs.statSync(sb.log).size });
    const v = run(sb, ['verify']); expect(v.status).toBe(0);
    expect(event(v.out, 'AUDIT_LOG_BACKUP_VERIFY_OK')[0].chain).toMatchObject({ ok: true, segments: 2, bytes: fs.statSync(sb.log).size });
    const t = path.join(sb.dir, 'restored.log');
    expect(run(sb, ['restore', '', posix(t)]).status).toBe(0);
    expect(fs.readFileSync(t).equals(fs.readFileSync(sb.log))).toBe(true);
  });

  test('IN-2 no new bytes → an empty segment; verify stays green (not stale)', async () => {
    const sb = sandbox(); fs.writeFileSync(sb.log, lines(0, 5));
    run(sb, ['backup']); await tick();
    const c = complete(run(sb, ['backup']).out);
    expect(c).toMatchObject({ kind: 'segment', seq: 1 }); expect(c.to).toBe(c.from);
    expect(run(sb, ['verify']).status).toBe(0);
  });

  test('IN-3 a rewritten or pruned log forces a new base, with the reason', async () => {
    const sb = sandbox(); fs.writeFileSync(sb.log, lines(0, 20)); run(sb, ['backup']); await tick();
    fs.writeFileSync(sb.log, lines(0, 5));                                   // shorter
    expect(complete(run(sb, ['backup']).out)).toMatchObject({ kind: 'base', reason: 'log-shorter-than-backed-up' }); await tick();
    fs.writeFileSync(sb.log, lines(100, 130));                               // different first line
    expect(complete(run(sb, ['backup']).out)).toMatchObject({ kind: 'base', reason: 'first-line-changed' }); await tick();
    const keep = fs.readFileSync(sb.log, 'utf8').split('\n'); keep[keep.length - 2] = keep[keep.length - 2].replace('x', 'y');
    fs.writeFileSync(sb.log, `${keep.join('\n')}${lines(200, 205)}`);       // backed-up tail line changed in place
    expect(complete(run(sb, ['backup']).out)).toMatchObject({ kind: 'base', reason: 'backed-up-tail-changed' });
  });

  async function threeRuns() {
    const sb = sandbox(); fs.writeFileSync(sb.log, lines(0, 10));
    const base = complete(run(sb, ['backup']).out).base; await tick();
    fs.appendFileSync(sb.log, lines(10, 20)); run(sb, ['backup']); await tick();
    fs.appendFileSync(sb.log, lines(20, 30)); run(sb, ['backup']);
    return { sb, base, seg: (n, ext) => path.join(sb.bk, `${base}.seg-00000${n}.${ext}`) };
  }
  const refused = (sb, r, re) => {
    expect(r.status).toBe(1);
    expect(r.out.split('\n').filter((l) => l.includes('"event":"AUDIT_LOG_BACKUP_FAILED"'))).toHaveLength(1);   // one alert
    expect(r.out).toMatch(re);
    const t = path.join(sb.dir, `r-${Date.now()}.log`);
    const rr = run(sb, ['restore', '', posix(t)]);
    expect(rr.status).toBe(1); expect(rr.out).toMatch(/refusing to restore/); expect(fs.existsSync(t)).toBe(false);
  };

  test('IN-4a changed segment data (even if re-sealed with the key) → refused', async () => {
    const { sb, seg } = await threeRuns();
    fs.writeFileSync(seg(1, 'log.gz'), zlib.gzipSync(lines(10, 20).replace('"n":11', '"n":99')));
    // the data file's own seal is recomputed WITH the key — the sealed meta (its recorded sha256) still catches it
    fs.writeFileSync(seg(1, 'log.gz.seal'), `${require('crypto').createHmac('sha256', KEY).update(fs.readFileSync(seg(1, 'log.gz'))).digest('hex')}\n`);
    refused(sb, run(sb, ['verify']), /does not match its recorded sha256/);
  });
  test('IN-4b edited meta → seal mismatch, refused', async () => {
    const { sb, seg } = await threeRuns();
    const m = JSON.parse(fs.readFileSync(seg(1, 'meta.json'))); m.to += 1; fs.writeFileSync(seg(1, 'meta.json'), JSON.stringify(m));
    refused(sb, run(sb, ['verify']), /seal verification failed/i);
  });
  test('IN-4c a missing middle segment (gap) → refused', async () => {
    const { sb, seg } = await threeRuns();
    for (const ext of ['log.gz', 'log.gz.seal', 'meta.json', 'meta.json.seal', 'log.sum.gz']) { const p = seg(1, ext); if (fs.existsSync(p)) fs.renameSync(p, `${p}.moved`); }
    refused(sb, run(sb, ['verify']), /sequence gap|byte gap/);
  });
  test('IN-4d swapped segments (order) → refused', async () => {
    const { sb, seg } = await threeRuns();
    for (const ext of ['log.gz', 'log.gz.seal']) { fs.renameSync(seg(1, ext), `${seg(1, ext)}.tmp`); fs.renameSync(seg(2, ext), seg(1, ext)); fs.renameSync(`${seg(1, ext)}.tmp`, seg(2, ext)); }
    refused(sb, run(sb, ['verify']), /does not match its recorded sha256/);
  });

  test('IN-5 a segment cannot be restored alone; an earlier full copy (no meta) restores as before', async () => {
    const { sb, seg } = await threeRuns();
    const r = run(sb, ['restore', posix(seg(1, 'log.gz')), posix(path.join(sb.dir, 'x.log'))]);
    expect(r.status).toBe(1); expect(r.out).toMatch(/is a segment — restore its base/);
    const legacy = sandbox(); fs.mkdirSync(legacy.bk);
    const lf = path.join(legacy.bk, 'audit-20200101T000000Z.log.gz'); fs.writeFileSync(lf, zlib.gzipSync(lines(0, 3)));
    const crypto = require('crypto');
    fs.writeFileSync(`${lf}.seal`, `${crypto.createHmac('sha256', KEY).update(fs.readFileSync(lf)).digest('hex')}\n`);
    const t = path.join(legacy.dir, 'legacy.log');
    expect(run(legacy, ['restore', posix(lf), posix(t)]).status).toBe(0);
    expect(fs.readFileSync(t, 'utf8')).toBe(lines(0, 3));
  });

  test('IN-6 INCREMENTAL=false → every run is a base; REBASE_HOURS=0 → scheduled rebase, deferred outside the window', async () => {
    const sb = sandbox(); fs.writeFileSync(sb.log, lines(0, 5));
    run(sb, ['backup']); await tick();
    expect(complete(run(sb, ['backup'], { QODIQA_AUDIT_BACKUP_INCREMENTAL: 'false' }).out)).toMatchObject({ kind: 'base', reason: 'incremental-disabled' });
    await tick(); fs.appendFileSync(sb.log, lines(5, 6));
    const hm = (ms) => new Date(Date.now() + ms).toISOString().slice(11, 16);
    expect(complete(run(sb, ['backup'], { QODIQA_AUDIT_BACKUP_REBASE_HOURS: '0', QODIQA_BACKUP_WINDOW_UTC: `${hm(2 * 3600e3)}-${hm(3 * 3600e3)}` }).out))
      .toMatchObject({ kind: 'segment' });                                   // outside the window: no planned rebase
    await tick(); fs.appendFileSync(sb.log, lines(6, 7));
    expect(complete(run(sb, ['backup'], { QODIQA_AUDIT_BACKUP_REBASE_HOURS: '0' }).out)).toMatchObject({ kind: 'base', reason: 'scheduled-rebase' });
  });

  test('IN-7 retention prunes whole old chains by their newest file, never the current chain', async () => {
    const sb = sandbox(); fs.writeFileSync(sb.log, lines(0, 5));
    const old = complete(run(sb, ['backup']).out).base; await tick();
    fs.appendFileSync(sb.log, lines(5, 6)); run(sb, ['backup']); await tick();
    fs.writeFileSync(sb.log, lines(50, 55));                                 // forces a new (current) chain
    const age = (b, days) => { for (const f of fs.readdirSync(sb.bk).filter((x) => x.startsWith(`${b}.`))) { const t = Date.now() / 1000 - days * 86400; fs.utimesSync(path.join(sb.bk, f), t, t); } };
    age(old, 120);
    const r = run(sb, ['backup'], { QODIQA_AUDIT_BACKUP_RETAIN_DAYS: '90' });
    const cur = complete(r.out).base;
    expect(event(r.out, 'AUDIT_LOG_BACKUP_PRUNED').map((e) => e.chain)).toEqual([old]);
    expect(files(sb).some((f) => f.startsWith(`${old}.`))).toBe(false);
    expect(files(sb).some((f) => f.startsWith(`${cur}.`))).toBe(true);
    await tick(); age(cur, 120); fs.appendFileSync(sb.log, lines(55, 56));
    const r2 = run(sb, ['backup'], { QODIQA_AUDIT_BACKUP_RETAIN_DAYS: '90' });
    expect(event(r2.out, 'AUDIT_LOG_BACKUP_PRUNED')).toHaveLength(0);    // the current chain is never pruned
    expect(run(sb, ['verify']).status).toBe(0);
  });

  test('IN-8 each run keeps its own .sum (copied before the log); restore takes the LAST run’s', async () => {
    const sb = sandbox(); fs.writeFileSync(sb.log, lines(0, 5)); fs.writeFileSync(`${sb.log}.sum`, 'S1\n');
    run(sb, ['backup']); await tick();
    fs.appendFileSync(sb.log, lines(5, 8)); fs.writeFileSync(`${sb.log}.sum`, 'S2\n'); run(sb, ['backup']);
    const t = path.join(sb.dir, 'r.log');
    expect(run(sb, ['restore', '', posix(t)]).status).toBe(0);
    expect(fs.readFileSync(`${t}.sum`, 'utf8')).toBe('S2\n');
    const script = fs.readFileSync(SCRIPT, 'utf8');
    expect(script.indexOf('cp "${AUDIT_LOG}.sum"')).toBeLessThan(script.indexOf('chain_js probe "${AUDIT_LOG}"'));
  });

  // Hash-chained lines (the WAL fit test reads hash/prevHash, as boot recovery does).
  const ch = (n0, n1) => Array.from({ length: n1 - n0 }, (_, i) => `{"hash":"h${n0 + i}","prevHash":"${n0 + i === 0 ? 'GENESIS' : `h${n0 + i - 1}`}","pad":"${'x'.repeat(40)}"}\n`).join('');
  test('IN-9 the WAL is kept only when it continues the backed-up prefix (found at real size: a committed batch made boot refuse)', async () => {
    // (a) the batch is already committed INSIDE the prefix (more entries followed before the log was measured) → omitted
    const sb = sandbox(); fs.writeFileSync(sb.log, ch(0, 20)); fs.writeFileSync(`${sb.log}.wal`, ch(12, 14));
    let r = run(sb, ['backup']); expect(r.status).toBe(0);
    let c = complete(r.out);
    const meta = JSON.parse(fs.readFileSync(path.join(sb.bk, `${c.base}.meta.json`), 'utf8'));
    expect(meta).toMatchObject({ walDisposition: 'committed', walFile: null });
    let t = path.join(sb.dir, 'a.log'); expect(run(sb, ['restore', '', posix(t)]).status).toBe(0);
    expect(fs.existsSync(`${t}.wal`)).toBe(false);
    // (b) the batch continues the prefix (not yet appended) → kept and restored
    await tick(); fs.writeFileSync(`${sb.log}.wal`, ch(20, 22));
    r = run(sb, ['backup']); expect(r.status).toBe(0); c = complete(r.out);
    expect(JSON.parse(fs.readFileSync(path.join(sb.bk, `${c.base}.seg-000001.meta.json`), 'utf8'))).toMatchObject({ walDisposition: 'continues' });
    t = path.join(sb.dir, 'b.log'); expect(run(sb, ['restore', '', posix(t)]).status).toBe(0);
    expect(fs.readFileSync(`${t}.wal`, 'utf8')).toBe(ch(20, 22));
    // (c) a WAL from another log (links nowhere in this one) → the run fails closed with exactly one alert
    await tick(); fs.writeFileSync(`${sb.log}.wal`, ch(500, 502));
    r = run(sb, ['backup']); expect(r.status).toBe(1);
    expect(r.out.split('\n').filter((l) => l.includes('"event":"AUDIT_LOG_BACKUP_FAILED"'))).toHaveLength(1);
    expect(r.out).toMatch(/neither continues the log prefix nor is committed/);
    // (d) restore re-checks a backed-up WAL against the RESTORED log: a committed one is omitted, a foreign one refused
    const { walFit } = require(path.join(REPO, 'scripts', 'audit-log-backup-chain.js'));
    const w = path.join(sb.dir, 'w');
    fs.writeFileSync(w, ch(12, 14)); expect(walFit(sb.log, fs.statSync(sb.log).size, w)).toMatchObject({ disposition: 'committed' });
    fs.writeFileSync(w, ch(0, 2)); expect(walFit(sb.log, fs.statSync(sb.log).size, w)).toMatchObject({ disposition: 'committed', offset: 0 });
    fs.writeFileSync(w, ch(18, 22)); expect(walFit(sb.log, fs.statSync(sb.log).size, w)).toMatchObject({ disposition: 'continues', alreadyInLog: 2 });
    fs.writeFileSync(w, `${ch(20, 21)}{"hash":"h2`); expect(walFit(sb.log, fs.statSync(sb.log).size, w)).toMatchObject({ disposition: 'torn' });
    fs.writeFileSync(w, ch(500, 502)); expect(() => walFit(sb.log, fs.statSync(sb.log).size, w)).toThrow(/neither continues/);
  });
});
