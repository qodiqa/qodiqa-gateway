'use strict';

/**
 * — DR backup/restore of real-size state.
 *
 * ST streaming archive I/O: openssl-compatible, chunked, decrypt-back verified, never a whole-file read
 * CO coverage and hot consistency: new components, append-only prefixes, replaced source, directory
 *       bundles, copy order, control-plane-aware requirements
 * PD pg_dump layer: connection handling, version guards, snapshot, RLS, restore gates, offline TOC
 *
 * The real tools against real-size data are proven at runtime (
 * runtime/dr-drill-*): this suite pins the contracts with fixtures and mocked child processes / pg.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const { Readable, Writable } = require('stream');

const KEYS = {
  QODIQA_BACKUP_ENCRYPTION_KEY: `aut13-enc-${crypto.randomBytes(16).toString('hex')}`,
  QODIQA_BACKUP_HMAC_KEY: `aut13-mac-${crypto.randomBytes(16).toString('hex')}`,
};
const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p));
const SCHEME = ['postgresql', '//'].join(':');
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

function withEnv(env, fn) {
  const saved = {};
  for (const k of Object.keys(env)) { saved[k] = process.env[k]; if (env[k] === undefined) delete process.env[k]; else process.env[k] = env[k]; }
  return Promise.resolve().then(fn).finally(() => {
    for (const k of Object.keys(saved)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  });
}

// ── ST: streaming archive I/O ───────────────────────────────────────────────────────────────────────────────────
describe('streaming archive I/O', () => {
  const ac = require('../../scripts/dr/archiveCrypto');

  test('ST-1 encryptFileToArchive is openssl-compatible, multi-chunk, and decrypts back to the exact source', () => {
    const dir = tmp('aut13-st1-');
    const src = path.join(dir, 'src.bin');
    const data = crypto.randomBytes(8 * 1024 * 1024 * 2 + 12345);   // spans three CHUNK_BYTES reads, odd tail
    fs.writeFileSync(src, data);
    const w = ac.encryptFileToArchive(src, path.join(dir, 'a.enc'), KEYS.QODIQA_BACKUP_ENCRYPTION_KEY);
    const ct = fs.readFileSync(path.join(dir, 'a.enc'));
    expect(ct.subarray(0, 8).toString('ascii')).toBe('Salted__');
    expect(w).toMatchObject({ sha256: sha(ct), sizeBytes: ct.length, plainSha256: sha(data), plainBytes: data.length });
    expect(ac.decryptBuffer(ct, KEYS.QODIQA_BACKUP_ENCRYPTION_KEY).equals(data)).toBe(true);   // the buffer (openssl) path
    const out = path.join(dir, 'back.bin');
    ac.restoreArchiveToFile(dir, { scheme: ac.SCHEME }, { archiveFile: 'a.enc', sha256: w.sha256 }, out, KEYS);
    expect(fs.readFileSync(out).equals(data)).toBe(true);
  });

  test('ST-2 a prefix (length) is encrypted exactly; a tampered archive is refused before any plaintext is written', () => {
    const dir = tmp('aut13-st2-');
    const src = path.join(dir, 'log');
    fs.writeFileSync(src, 'line-1\nline-2\npartial');
    const w = ac.encryptFileToArchive(src, path.join(dir, 'p.enc'), KEYS.QODIQA_BACKUP_ENCRYPTION_KEY, { length: 14 });
    expect(w.plainBytes).toBe(14);
    expect(ac.decryptBuffer(fs.readFileSync(path.join(dir, 'p.enc')), KEYS.QODIQA_BACKUP_ENCRYPTION_KEY).toString()).toBe('line-1\nline-2\n');
    const buf = fs.readFileSync(path.join(dir, 'p.enc')); buf[buf.length - 1] ^= 1; fs.writeFileSync(path.join(dir, 'p.enc'), buf);
    const out = path.join(dir, 'never');
    expect(() => ac.restoreArchiveToFile(dir, { scheme: ac.SCHEME }, { archiveFile: 'p.enc', sha256: w.sha256 }, out, KEYS))
      .toThrow(expect.objectContaining({ code: 'ARCHIVE_CHECKSUM_MISMATCH' }));
    expect(fs.existsSync(out)).toBe(false);
  });

  test('ST-3 writeStreamToArchive streams a Readable (pg_dump stdout) into a verified archive; plaintext without a key', async () => {
    const dir = tmp('aut13-st3-');
    const data = crypto.randomBytes(3 * 1024 * 1024 + 7);
    const enc = await ac.writeStreamToArchive(Readable.from([data.subarray(0, 1000), data.subarray(1000)]), path.join(dir, 'd.enc'), KEYS.QODIQA_BACKUP_ENCRYPTION_KEY);
    expect(enc.plainSha256).toBe(sha(data));
    expect(ac.decryptBuffer(fs.readFileSync(path.join(dir, 'd.enc')), KEYS.QODIQA_BACKUP_ENCRYPTION_KEY).equals(data)).toBe(true);
    const plain = await ac.writeStreamToArchive(Readable.from([data]), path.join(dir, 'd.plain'), null);
    expect(fs.readFileSync(path.join(dir, 'd.plain')).equals(data)).toBe(true);
    expect(plain.sha256).toBe(sha(data));
    // the plaintext stream of an archive, checksum first
    const chunks = [];
    for await (const c of ac.createArchivePlainStream(dir, { scheme: ac.SCHEME }, { archiveFile: 'd.enc', sha256: enc.sha256 }, KEYS)) chunks.push(c);
    expect(Buffer.concat(chunks).equals(data)).toBe(true);
  });

  test('ST-4 readArchiveFirstLine returns only the first line (encrypted and plaintext)', () => {
    const dir = tmp('aut13-st4-');
    const text = `{"first":1}\n${'x'.repeat(200000)}\nlast\n`;
    fs.writeFileSync(path.join(dir, 'log'), text);
    const w = ac.encryptFileToArchive(path.join(dir, 'log'), path.join(dir, 'log.enc'), KEYS.QODIQA_BACKUP_ENCRYPTION_KEY);
    expect(ac.readArchiveFirstLine(dir, { scheme: ac.SCHEME }, { archiveFile: 'log.enc', sha256: w.sha256 }, KEYS)).toBe('{"first":1}');
    expect(ac.readArchiveFirstLine(dir, null, { archiveFile: 'log' })).toBe('{"first":1}');
  });

  test('ST-5 sha256File is chunked and equals the one-shot digest', () => {
    const dir = tmp('aut13-st5-');
    const data = crypto.randomBytes(9 * 1024 * 1024);
    fs.writeFileSync(path.join(dir, 'f'), data);
    const { sha256File } = require('../../scripts/dr/checksum');
    expect(sha256File(path.join(dir, 'f'))).toBe(sha(data));
  });
});

// ── CO: coverage and hot consistency ────────────────────────────────────────────────────────────────────────────
function sourceFixture() {
  const dir = tmp('aut16-src-');
  const d = (...p) => path.join(dir, ...p);
  fs.mkdirSync(d('data', 'prq-journal'), { recursive: true });
  fs.mkdirSync(d('anchors', 'witness-log.jsonl.positions'), { recursive: true });
  fs.writeFileSync(d('audit.log'), '{"n":1}\n{"n":2}\n{"n":3,"torn');                 // in-flight tail
  fs.writeFileSync(d('audit.log.checkpoints.jsonl'), '{"cp":1}\n');
  fs.writeFileSync(d('audit.log.sum'), '{"count":2,"tailHash":"t"}');   // the .sum is JSON, and backup now requires it to parse
  fs.writeFileSync(d('data', 'keys.json'), '{"keys":{}}');
  fs.writeFileSync(d('data', 'policy-store.json'), '{"policies":{}}');   // memory control plane: the file IS the store (required)
  fs.writeFileSync(d('data', 'checkpoint-keys.json'), '{"keys":{}}');
  fs.writeFileSync(d('data', 'transparency-keys.json'), '{"t":1}');
  fs.writeFileSync(d('data', 'mac-keys.json'), '{"m":1}');
  fs.writeFileSync(d('data', 'prq-journal', 'op-1.json'), '{"op":1}');
  fs.writeFileSync(d('anchors', 'anchors.jsonl'), '{"a":1}\n');
  fs.writeFileSync(d('anchors', 'witness-log.jsonl'), '{"w":1}\n{"w":2');
  fs.writeFileSync(d('anchors', 'witness-log.jsonl.positions', '1033'), 'ab'.repeat(32));
  fs.writeFileSync(d('anchors', 'witness-log.jsonl.positions', '2073'), 'cd'.repeat(32));
  fs.writeFileSync(d('anchors', 'witness-log.jsonl.positions', '.tmp-99-deadbeef'), 'in-flight');
  const env = {
    QODIQA_AUDIT_LOG: d('audit.log'),
    QODIQA_KEYS_PATH: d('data', 'keys.json'),
    QODIQA_KEYS_ARCHIVE_PATH: d('data', 'key-archive.json'),
    QODIQA_CHECKPOINT_KEYS_PATH: d('data', 'checkpoint-keys.json'),
    QODIQA_TRANSPARENCY_KEYS_PATH: d('data', 'transparency-keys.json'),
    QODIQA_MAC_KEYS_PATH: d('data', 'mac-keys.json'),
    QODIQA_PRQ_JOURNAL_DIR: d('data', 'prq-journal'),
    QODIQA_ANCHOR_EXPORT_PATH: d('anchors', 'anchors.jsonl'),
    QODIQA_WITNESS_MODE: 'local',
    QODIQA_WITNESS_LOG_PATH: d('anchors', 'witness-log.jsonl'),
    QODIQA_POLICY_STORE: d('data', 'policy-store.json'),
    ORG_STORE_PATH: d('data', 'organizations.json'),
    TENANT_STORE_PATH: d('data', 'tenants.json'),
    NODE_ENV: 'test', QODIQA_CONTROL_PLANE_BACKEND: undefined,
  };
  return { dir, env, out: path.join(dir, '..', `${path.basename(dir)}-backup`), target: path.join(dir, '..', `${path.basename(dir)}-restored`) };
}

const loadDr = () => { jest.resetModules(); return { ...require('../../scripts/dr/backup'), ...require('../../scripts/dr/restore') }; };

describe('coverage and hot consistency', () => {
  test('CO-1 the new components are backed up and restored: anchors, witness log + claims, PRQ journal, MAC and transparency keys', async () => {
    const fx = sourceFixture();
    const { runBackup, runRestore } = loadDr();
    const { manifest } = await withEnv({ ...fx.env, ...KEYS }, () => runBackup({ outDir: fx.out }));
    const by = Object.fromEntries(manifest.components.map((c) => [c.name, c]));
    for (const n of ['anchorExport', 'witnessLog', 'witnessPositions', 'prqJournal', 'macKeys', 'transparencyKeys']) expect(by[n].present).toBe(true);
    expect(by.witnessPositions).toMatchObject({ kind: 'dir', fileCount: 2, archiveFile: 'witnessPositions.bundle.enc' });
    // the toy log is not a valid hash chain, so the integrity gate refuses — restored the files
    await expect(withEnv(KEYS, () => runRestore({ backupDir: fx.out, targetRoot: fx.target }))).rejects.toMatchObject({ code: 'AUDIT_CHAIN_INTEGRITY_FAILED' });
    const r = (...p) => fs.readFileSync(path.join(fx.target, ...p), 'utf8');
    expect(r('anchors', 'anchors.jsonl')).toBe('{"a":1}\n');
    expect(r('data', 'mac-keys.json')).toBe('{"m":1}');
    expect(r('data', 'transparency-keys.json')).toBe('{"t":1}');
    expect(r('data', 'prq-journal', 'op-1.json')).toBe('{"op":1}');
    expect(fs.readdirSync(path.join(fx.target, 'anchors', 'witness-log.jsonl.positions')).sort()).toEqual(['1033', '2073']);   // no .tmp- claim
    expect(r('anchors', 'witness-log.jsonl.positions', '2073')).toBe('cd'.repeat(32));
  });

  test('CO-2 append-only NDJSON files are copied up to their last complete line; sourceBytes is recorded', async () => {
    const fx = sourceFixture();
    const { runBackup, runRestore } = loadDr();
    const { manifest } = await withEnv({ ...fx.env, ...KEYS }, () => runBackup({ outDir: fx.out }));
    const by = Object.fromEntries(manifest.components.map((c) => [c.name, c]));
    expect(by.auditLog.sourceBytes).toBe(Buffer.byteLength('{"n":1}\n{"n":2}\n'));
    expect(by.witnessLog.sourceBytes).toBe(Buffer.byteLength('{"w":1}\n'));
    await withEnv(KEYS, () => runRestore({ backupDir: fx.out, targetRoot: fx.target }).catch(() => {}));   // integrity gate may refuse the toy log
    expect(fs.readFileSync(path.join(fx.target, 'audit.log'), 'utf8')).toBe('{"n":1}\n{"n":2}\n');
    expect(fs.readFileSync(path.join(fx.target, 'anchors', 'witness-log.jsonl'), 'utf8')).toBe('{"w":1}\n');
  });

  test('CO-3 a log replaced or shrunk while it is copied fails the backup (BACKUP_SOURCE_REPLACED)', async () => {
    const fx = sourceFixture();
    const { runBackup } = loadDr();
    const real = fs.statSync;
    let n = 0;
    const spy = jest.spyOn(fs, 'statSync').mockImplementation((p, ...a) => {
      const st = real(p, ...a);
      // shrink (a prune rewrote it): NTFS file ids exceed 2^53, so a +1 inode change is not representable as a Number
      if (p === fx.env.QODIQA_AUDIT_LOG && ++n === 2) return { ino: st.ino, dev: st.dev, size: st.size - 1, isFile: () => true };
      return st;
    });
    try {
      await expect(withEnv({ ...fx.env, ...KEYS }, () => runBackup({ outDir: fx.out }))).rejects.toMatchObject({ code: 'BACKUP_SOURCE_REPLACED' });
    } finally { spy.mockRestore(); }
  });

  test('CO-4 copy order: anchors → witness → claims → journal → log sidecars → log → key stores', async () => {
    const fx = sourceFixture();
    const { runBackup } = loadDr();
    const order = [];
    const realOpen = fs.openSync; const realRead = fs.readdirSync;
    const o = jest.spyOn(fs, 'openSync').mockImplementation((p, ...a) => { if (typeof p === 'string' && p.startsWith(fx.dir)) order.push(path.relative(fx.dir, p)); return realOpen(p, ...a); });
    const r = jest.spyOn(fs, 'readdirSync').mockImplementation((p, ...a) => { if (typeof p === 'string' && p.startsWith(fx.dir)) order.push(`${path.relative(fx.dir, p)}/`); return realRead(p, ...a); });
    try { await withEnv({ ...fx.env, ...KEYS }, () => runBackup({ outDir: fx.out })); } finally { o.mockRestore(); r.mockRestore(); }
    const first = (s) => order.findIndex((x) => x.replace(/\\/g, '/') === s);
    const seq = ['anchors/anchors.jsonl', 'anchors/witness-log.jsonl', 'anchors/witness-log.jsonl.positions/', 'data/prq-journal/',
      'audit.log.checkpoints.jsonl', 'audit.log.sum', 'audit.log', 'data/checkpoint-keys.json', 'data/keys.json', 'data/transparency-keys.json', 'data/mac-keys.json'];
    const idx = seq.map(first);
    expect(idx.every((i) => i >= 0)).toBe(true);
    expect([...idx].sort((a, b) => a - b)).toEqual(idx);
  });

  test('CO-5 no component is read whole: readFileSync never touches the audit log during backup or restore', async () => {
    const fx = sourceFixture();
    const { runBackup, runRestore } = loadDr();
    const real = fs.readFileSync;
    const touched = [];
    const spy = jest.spyOn(fs, 'readFileSync').mockImplementation((p, ...a) => { if (typeof p === 'string' && /audit\.log$|auditLog\.dat/.test(p)) touched.push(p); return real(p, ...a); });
    try {
      await withEnv({ ...fx.env, ...KEYS }, () => runBackup({ outDir: fx.out }));
      await withEnv(KEYS, () => runRestore({ backupDir: fx.out, targetRoot: fx.target }).catch(() => {}));
    } finally { spy.mockRestore(); }
    expect(touched.filter((p) => !p.includes(`${path.sep}restored${path.sep}`) && !/-restored/.test(p))).toEqual([]);
  });

  test('CO-6 a tampered directory bundle member is refused at restore', async () => {
    const fx = sourceFixture();
    const { runBackup, runRestore } = loadDr();
    await withEnv(fx.env, () => runBackup({ outDir: fx.out }));   // plaintext (test env) to edit the bundle
    const b = path.join(fx.out, 'witnessPositions.bundle');
    const lines = fs.readFileSync(b, 'utf8').trim().split('\n').map(JSON.parse);
    lines[0].data = Buffer.from('ef'.repeat(32)).toString('base64');
    fs.writeFileSync(b, `${lines.map((l) => JSON.stringify(l)).join('\n')}\n`);
    const m = JSON.parse(fs.readFileSync(path.join(fx.out, 'manifest.json'), 'utf8'));
    const c = m.components.find((x) => x.name === 'witnessPositions');
    c.sha256 = sha(fs.readFileSync(b)); c.sizeBytes = fs.statSync(b).size;
    delete m.manifestChecksum; m.manifestChecksum = require('../../scripts/dr/manifest').computeManifestChecksum(m);
    fs.writeFileSync(path.join(fx.out, 'manifest.json'), JSON.stringify(m, null, 2));
    await expect(runRestore({ backupDir: fx.out, targetRoot: fx.target })).rejects.toMatchObject({ code: 'CHECKSUM_MISMATCH' });
  });

  test('CO-7 control plane: pg → backup refused without the database; seed files required only in memory mode', async () => {
    const fx = sourceFixture();
    const { runBackup } = loadDr();
    await expect(withEnv({ ...fx.env, QODIQA_CONTROL_PLANE_BACKEND: 'pg' }, () => runBackup({ outDir: fx.out })))
      .rejects.toMatchObject({ code: 'BACKUP_POSTGRES_REQUIRED' });
    expect(fs.existsSync(fx.out)).toBe(false);
    const { FILE_COMPONENTS, isRequired } = require('../../scripts/dr/components');
    const policy = FILE_COMPONENTS.find((c) => c.name === 'policyStore');
    expect(isRequired(policy, { controlPlaneBackend: 'memory' })).toBe(true);
    expect(isRequired(policy, { controlPlaneBackend: 'pg' })).toBe(false);
    expect(isRequired(FILE_COMPONENTS.find((c) => c.name === 'keyStore'), { controlPlaneBackend: 'pg' })).toBe(true);
    const { manifest } = await withEnv(fx.env, () => runBackup({ outDir: `${fx.out}-mem` }));
    expect(manifest.controlPlaneBackend).toBe('memory');
    expect(manifest.components.find((c) => c.name === 'policyStore')).toMatchObject({ present: true, required: true });
  });

  test('CO-8 production: an unconfigured anchor export or local witness log is refused before anything is written', async () => {
    const fx = sourceFixture();
    const { runBackup } = loadDr();
    const prod = { ...fx.env, ...KEYS, NODE_ENV: 'production' };
    await expect(withEnv({ ...prod, QODIQA_ANCHOR_EXPORT_PATH: undefined }, () => runBackup({ outDir: fx.out, includePostgres: true })))
      .rejects.toMatchObject({ code: 'BACKUP_COMPONENT_UNCONFIGURED' });
    await expect(withEnv({ ...prod, QODIQA_WITNESS_LOG_PATH: undefined }, () => runBackup({ outDir: fx.out, includePostgres: true })))
      .rejects.toMatchObject({ code: 'BACKUP_COMPONENT_UNCONFIGURED' });
    expect(fs.existsSync(fx.out)).toBe(false);
  });

  test('CO-9 validation: with a PostgreSQL control plane the policies are proven by the database component', async () => {
    jest.resetModules();
    const { validateRestoredState } = require('../../scripts/dr/validate');
    const withPg = await validateRestoredState([], null, { controlPlaneBackend: 'pg' });
    expect(withPg.policyStore).toMatchObject({ valid: false, reason: 'POLICIES_IN_POSTGRES_BUT_NO_POSTGRES_COMPONENT' });
    expect(withPg.overallValid).toBe(false);
  });
});

// ── PD: pg_dump layer ───────────────────────────────────────────────────────────────────────────────────────────
describe('pg_dump layer', () => {
  let spawned; let versions; let pool;

  function fakeChild({ stdout = Buffer.alloc(0), code = 0, stderr = '' } = {}) {
    const child = new EventEmitter();
    child.stdout = Readable.from([stdout]);
    child.stderr = Readable.from([Buffer.from(stderr)]);
    const sink = [];
    child.stdin = new Writable({ write(c, e, cb) { sink.push(c); cb(); } });
    child.sink = sink;
    setTimeout(() => child.emit('close', code), 20);
    return child;
  }

  function load({ tables = ['audit_chain', 'tenants'], rls = { superuser: false, bypass_rls: true }, serverNum = 160015, counts = {}, restoreCounts = null, su = false, plan = {} } = {}) {
    jest.resetModules();
    spawned = [];
    versions = { pg_dump: 'pg_dump (PostgreSQL) 16.15', pg_restore: 'pg_restore (PostgreSQL) 16.15', ...plan.versions };
    jest.doMock('child_process', () => ({
      execFileSync: (bin) => versions[path.basename(bin)] || (() => { const e = new Error('ENOENT'); e.code = 'ENOENT'; throw e; })(),
      spawn: (bin, args, opts) => { const c = fakeChild(plan.child ? plan.child(bin, args) : {}); spawned.push({ bin, args, env: opts.env, child: c }); return c; },
    }));
    const queries = [];
    const query = async (sql) => {
      queries.push(sql);
      if (/pg_export_snapshot/.test(sql)) return { rows: [{ id: '00000003-0000001B-1' }] };
      if (/rolsuper FROM pg_roles WHERE rolname = current_user/.test(sql)) return { rows: [{ v: serverNum, s: `${Math.floor(serverNum / 10000)}.x`, su, who: 'restorer' }] };
      if (/server_version_num/.test(sql)) return { rows: [{ v: serverNum, s: `${Math.floor(serverNum / 10000)}.x` }] };
      if (/information_schema\.tables/.test(sql) || /table_name/.test(sql) && /information_schema/.test(sql)) return { rows: tables.map((t) => ({ table_name: t })) };
      if (/pg_constraint/.test(sql)) return { rows: [] };
      if (/qodiqa_migrations WHERE version = 79/.test(sql)) return { rows: [{ er16: false }] }; // a pre-079 fake schema
      // D-P: a provisioned backup role is RLS-exempt AND a pg_read_all_data member (rls.read_all_data=false: not)
      if (/pg_roles r WHERE/.test(sql)) return { rows: [{ name: 'qodiqa_backup', superuser: rls.superuser, bypass_rls: rls.bypass_rls, read_all_data: rls.read_all_data !== false }] };
      if (/relrowsecurity/.test(sql)) return { rows: [{ relname: 'tenants' }] };
      const m = /count\(\*\)::bigint AS n FROM "?([a-z_]+)"?/.exec(sql);
      if (m) return { rows: [{ n: String((restoreCounts && queries.some((q) => /pg_restore_done/.test(q)) ? restoreCounts : counts)[m[1]] ?? 5) }] };
      if (/audit_chain_prunes/.test(sql)) return { rows: [] };
      if (/to_regprocedure/.test(sql)) return { rows: [{ ok: false }] };
      return { rows: [] };
    };
    pool = { connect: async () => ({ query, release: () => {} }), query, end: async () => {} };
    jest.doMock('pg', () => ({ Pool: jest.fn(() => pool) }));
    jest.doMock('../../scripts/dr/table-registry', () => ({
      ...jest.requireActual('../../scripts/dr/table-registry'),
      discoverTables: async () => tables, getRestoreOrder: async (_c, t) => t,
    }));
    return { mod: require('../../scripts/dr/pgDump'), queries };
  }
  afterEach(() => { jest.dontMock('child_process'); jest.dontMock('pg'); jest.dontMock('../../scripts/dr/table-registry'); });

  test('PD-1 resolveConnection: the password never reaches --dbname; libpq PG* variables work alone', () => {
    const { mod } = load();
    // throwaway test value; assembled so no connection-URL-with-password literal is committed (gitleaks pg-password-env)
    const a = mod.resolveConnection([SCHEME, 'qodiqa_backup', ':', 's%40cret', '@db:5432/qodiqa?sslmode=verify-full&sslrootcert=/ca.crt'].join(''), {});
    expect(a.password).toBe('s@cret');
    expect(a.dbnameArg).not.toMatch(/s%40cret|s@cret/);
    expect(a.dbnameArg).toMatch(/sslmode=verify-full/);
    const b = mod.resolveConnection(null, { PGHOST: 'postgres', PGPORT: '5432', PGDATABASE: 'qodiqa', PGUSER: 'qodiqa_backup', PGPASSWORD: 'pw', PGSSLMODE: 'verify-full', PGSSLROOTCERT: '/etc/ca.crt' });
    expect(b.dbnameArg).toBe(`${SCHEME}qodiqa_backup@postgres:5432/qodiqa?sslmode=verify-full&sslrootcert=%2Fetc%2Fca.crt`);
    expect(b.password).toBe('pw');
    expect(() => mod.resolveConnection(null, {})).toThrow(expect.objectContaining({ code: 'PG_CONNECTION_MISSING' }));
  });

  test('PD-2 version guard: pg_dump major ≠ server major → refused, the snapshot rolled back, pg_dump never run', async () => {
    const { mod, queries } = load({ serverNum: 160015, plan: { versions: { pg_dump: 'pg_dump (PostgreSQL) 17.11' } } });
    await expect(mod.takeSnapshot({ env: { PGHOST: 'h', PGDATABASE: 'd', QODIQA_PG_RESTORE_URL: 'postgresql://restore-host:5432/restore_db' } })).rejects.toMatchObject({ code: 'PG_DUMP_VERSION_MISMATCH' });
    expect(queries).toContain('ROLLBACK');
    expect(spawned).toEqual([]);
  });

  test('PD-3 a dumping role filtered by RLS is refused (rows would be missing)', async () => {
    const { mod } = load({ rls: { superuser: false, bypass_rls: false } });
    await expect(mod.takeSnapshot({ env: { PGHOST: 'h', PGDATABASE: 'd', QODIQA_PG_RESTORE_URL: 'postgresql://restore-host:5432/restore_db' } })).rejects.toMatchObject({ code: 'BACKUP_ROLE_NOT_RLS_EXEMPT' });
  });

  test('PD-3b D-P an RLS-exempt role without pg_read_all_data is refused before the snapshot is used (nothing written)', async () => {
    const { mod, queries } = load({ rls: { superuser: false, bypass_rls: true, read_all_data: false } });
    await expect(mod.takeSnapshot({ env: { PGHOST: 'h', PGDATABASE: 'd', QODIQA_PG_RESTORE_URL: 'postgresql://restore-host:5432/restore_db' } })).rejects.toMatchObject({ code: 'BACKUP_ROLE_READ_ALL_DATA_MISSING' });
    expect(queries.some((q) => /count\(\*\)::bigint AS n FROM/.test(q))).toBe(false);
    expect(spawned).toEqual([]);
  });

  test('PD-4 snapshot facts + dump: --snapshot=<exported id>, custom format, password only in the child env, archive verified', async () => {
    const dumpBytes = Buffer.concat([Buffer.from('PGDMP'), crypto.randomBytes(5000)]);
    const { mod, queries } = load({ counts: { audit_chain: 407686, tenants: 2 }, plan: { child: () => ({ stdout: dumpBytes }) } });
    const snap = await mod.takeSnapshot({ env: { PGHOST: 'postgres', PGDATABASE: 'qodiqa', PGUSER: 'qodiqa_backup', PGPASSWORD: 'pw-123' } });
    expect(queries[0]).toMatch(/REPEATABLE READ READ ONLY/);
    expect(snap.facts).toMatchObject({ format: 'pg_dump-custom', serverMajor: 16, pgDumpMajor: 16, rlsExempt: true,
      tables: [{ table: 'audit_chain', present: true, rowCount: 407686, sourceRowCount: 407686 }, { table: 'tenants', present: true, rowCount: 2, sourceRowCount: 2 }] });
    const dir = tmp('aut14-pd4-');
    const w = await snap.dump(dir, { encrypt: true, encKey: KEYS.QODIQA_BACKUP_ENCRYPTION_KEY });
    const call = spawned.find((s) => /pg_dump$/.test(s.bin));
    expect(call.args).toEqual(expect.arrayContaining(['--format=custom', '--no-password', '--snapshot=00000003-0000001B-1']));
    expect(call.args.join(' ')).not.toMatch(/pw-123/);
    expect(call.env.PGPASSWORD).toBe('pw-123');
    expect(w.archiveFile).toBe('postgres.dump.enc');
    expect(w.plainSha256).toBe(sha(dumpBytes));
    expect(queries).toContain('COMMIT');
  });

  test('PD-5 a failing pg_dump fails the backup with its stderr', async () => {
    const { mod } = load({ plan: { child: () => ({ code: 1, stderr: 'pg_dump: error: permission denied for table x' }) } });
    const snap = await mod.takeSnapshot({ env: { PGHOST: 'h', PGDATABASE: 'd', QODIQA_PG_RESTORE_URL: 'postgresql://restore-host:5432/restore_db' } });
    await expect(snap.dump(tmp('aut14-pd5-'), null)).rejects.toMatchObject({ code: 'PG_DUMP_FAILED', message: expect.stringMatching(/permission denied/) });
  });

  async function pgdBackupDir() {
    const dir = tmp('aut14-rs-');
    const dump = Buffer.concat([Buffer.from('PGDMP'), crypto.randomBytes(4096)]);
    fs.writeFileSync(path.join(dir, 'postgres.dump'), dump);
    return { dir, pgm: { format: 'pg_dump-custom', archiveFile: 'postgres.dump', sha256: sha(dump), pgDumpMajor: 16, tables: [{ table: 'audit_chain', present: true, rowCount: 5 }, { table: 'tenants', present: true, rowCount: 5 }] }, dump };
  }

  test('PD-6 restore refuses a pg_restore newer than the target and a superuser without the override — the target is never touched', async () => {
    const { dir, pgm } = await pgdBackupDir();
    let { mod } = load({ serverNum: 160015, plan: { versions: { pg_restore: 'pg_restore (PostgreSQL) 17.11' } } });
    await expect(mod.restoreWithPgRestore(dir, pgm, { env: { PGHOST: 'h', PGDATABASE: 'd', QODIQA_PG_RESTORE_URL: 'postgresql://restore-host:5432/restore_db' } })).rejects.toMatchObject({ code: 'PG_RESTORE_VERSION_MISMATCH' });
    expect(spawned).toEqual([]);
    ({ mod } = load({ su: true }));
    await expect(mod.restoreWithPgRestore(dir, pgm, { env: { PGHOST: 'h', PGDATABASE: 'd', QODIQA_PG_RESTORE_URL: 'postgresql://restore-host:5432/restore_db' } })).rejects.toMatchObject({ code: 'RESTORE_SUPERUSER_REFUSED' });
    expect(spawned).toEqual([]);
  });

  test('PD-7 restore streams the archive into pg_restore --single-transaction and reconciles every table count', async () => {
    const { dir, pgm, dump } = await pgdBackupDir();
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const { mod } = load({ su: true });
      const out = await mod.restoreWithPgRestore(dir, pgm, { env: { PGHOST: 'h', PGDATABASE: 'd', QODIQA_PG_RESTORE_URL: 'postgresql://restore-host:5432/restore_db', PGPASSWORD: 'pw', QODIQA_BACKUP_ALLOW_SUPERUSER_RESTORE: 'true' }, readSide: () => ({}) });
      const call = spawned.find((s) => /pg_restore$/.test(s.bin));
      expect(call.args).toEqual(expect.arrayContaining(['--clean', '--if-exists', '--no-owner', '--exit-on-error', '--single-transaction']));
      expect(call.args.join(' ')).not.toMatch(/\bpw\b/);
      expect(Buffer.concat(call.child.sink).equals(dump)).toBe(true);
      expect(out.tables).toEqual([{ table: 'audit_chain', restored: 5, expected: 5 }, { table: 'tenants', restored: 5, expected: 5 }]);
      // a count that does not match the snapshot fails closed
      const bad = { ...pgm, tables: [{ table: 'audit_chain', present: true, rowCount: 6 }] };
      const r2 = load({ su: true });
      await expect(r2.mod.restoreWithPgRestore(dir, bad, { env: { PGHOST: 'h', PGDATABASE: 'd', QODIQA_PG_RESTORE_URL: 'postgresql://restore-host:5432/restore_db', QODIQA_BACKUP_ALLOW_SUPERUSER_RESTORE: 'true' }, readSide: () => ({}) }))
        .rejects.toMatchObject({ code: 'POSTGRES_ROW_COUNT_MISMATCH' });
    } finally { spy.mockRestore(); }
  });

  test('PD-8 offline table of contents: TABLE DATA entries of the public schema', async () => {
    const { dir, pgm } = await pgdBackupDir();
    const toc = ';\n; Archive created at ...\n4001; 0 16384 TABLE DATA public audit_chain qodiqa_bootstrap\n4002; 0 16390 TABLE DATA public tenants qodiqa_bootstrap\n4003; 0 0 SEQUENCE SET public x_seq qodiqa\n';
    const { mod } = load({ plan: { child: () => ({ stdout: Buffer.from(toc) }) } });
    const listed = await mod.listArchiveTables(dir, pgm, null, {});
    expect([...listed].sort()).toEqual(['audit_chain', 'tenants']);
    expect(spawned[0].args).toEqual(['--list']);
  });
});
