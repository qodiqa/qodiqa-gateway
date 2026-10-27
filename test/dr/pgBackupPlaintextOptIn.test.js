'use strict';

/**
 * — scripts/pg-backup.sh no longer writes plaintext by default.
 *
 * Before: REQUIRE_ENC="${QODIQA_BACKUP_REQUIRE_ENCRYPTION:-false}", so any standalone run without a key (systemd host,
 * operator shell) silently wrote a plaintext dump of every tenant's data. Now encryption is required unless
 * QODIQA_BACKUP_ALLOW_PLAINTEXT=true is set (logged as BACKUP_PLAINTEXT_OPT_IN), and an explicit
 * QODIQA_BACKUP_REQUIRE_ENCRYPTION=true is never lifted by that opt-in.
 *
 *   PO-01 no key, no opt-in        → exit 1, BACKUP_ENCRYPTION_REQUIRED, pg_dump never ran, nothing written
 *   PO-02 no key, ALLOW_PLAINTEXT  → plaintext dump with BACKUP_PLAINTEXT_OPT_IN; verify passes only with the opt-in
 *   PO-03 ALLOW_PLAINTEXT + explicit REQUIRE_ENCRYPTION=true → still refused
 *   PO-04 both keys, no opt-in     → encrypted .dump.enc + seal, verify passes
 *
 * Same stub technique as test/pgBackupEncryption.test.js (stub pg_dump / pg_restore on PATH; no database).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync, execFileSync } = require('child_process');

const REPO = path.join(__dirname, '..', '..');
const SCRIPT = path.join(REPO, 'scripts', 'pg-backup.sh');

function findBash() {
  if (process.platform !== 'win32') return 'bash';
  for (const p of ['C:\\Program Files\\Git\\bin\\bash.exe', 'C:\\Program Files (x86)\\Git\\bin\\bash.exe']) if (fs.existsSync(p)) return p;
  return null;
}
const BASH = findBash();
const describeOrSkip = BASH ? describe : describe.skip;
jest.setTimeout(120_000);

const posix = (p) => p.replace(/\\/g, '/').replace(/^([A-Za-z]):/, (_, d) => `/${d.toLowerCase()}`);
const TABLES = execFileSync(process.execPath, [path.join(REPO, 'scripts', 'dr', 'table-registry.js'), '--list'], { encoding: 'utf8' })
  .split(/\r?\n/).filter(Boolean);
const DUMP = ['; pg_restore --list image (stub)', ...TABLES.map((t, i) => `${4000 + i}; 0 0 TABLE DATA public ${t} qodiqa`)].join('\n') + '\n';
// Throwaway test-only keys, random per run.
const KEYS = {
  QODIQA_BACKUP_ENCRYPTION_KEY: `dd005-sh-enc-${crypto.randomBytes(16).toString('hex')}`,
  QODIQA_BACKUP_HMAC_KEY: `dd005-sh-mac-${crypto.randomBytes(16).toString('hex')}`,
};

function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-dd005sh-'));
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(dir, 'dump.txt'), DUMP);
  // the stubs answer --version / server_version_num like the real tools (pg-backup.sh compares the majors).
  fs.writeFileSync(path.join(bin, 'pg_dump'),
    `#!/usr/bin/env bash\n[[ "$1" == --version ]] && { echo "pg_dump (PostgreSQL) 16.15"; exit 0; }\nfor a in "$@"; do case "$a" in --file=*) out="\${a#--file=}";; esac; done\ntouch "${posix(path.join(dir, 'pg_dump.ran'))}"\ncp "${posix(path.join(dir, 'dump.txt'))}" "$out"\n`, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, 'pg_restore'), '#!/usr/bin/env bash\n[[ "$1" == --version ]] && { echo "pg_restore (PostgreSQL) 16.15"; exit 0; }\nfor a in "$@"; do f="$a"; done\ncat "$f"\n', { mode: 0o755 });
  // D-P: + the backup-role preflight (a verified qodiqa_backup: RLS-exempt and pg_read_all_data member).
  fs.writeFileSync(path.join(bin, 'psql'), '#!/usr/bin/env bash\n[[ "$*" == *server_version_num* ]] && { echo 160015; exit 0; }\n'
    + '[[ "$*" == *backup-role-preflight* ]] && { echo t; exit 0; }\necho f\n', { mode: 0o755 });
  return { dir, bin, backups: path.join(dir, 'backups') };
}

function run(sb, args, env = {}) {
  const r = spawnSync(BASH, [posix(SCRIPT), ...args], {
    encoding: 'utf8',
    env: {
      PATH: `${sb.bin}${path.delimiter}${process.env.PATH}`,
      SYSTEMROOT: process.env.SYSTEMROOT, TEMP: process.env.TEMP, TMP: process.env.TMP, HOME: process.env.HOME || sb.dir,
      QODIQA_BACKUP_DIR: posix(sb.backups), PGDATABASE: 'stub',
      ...env,
    },
  });
  return { status: r.status, out: `${r.stdout}\n${r.stderr}` };
}
const tierFiles = (sb) => { const d = path.join(sb.backups, 'full', 'daily'); return fs.existsSync(d) ? fs.readdirSync(d).sort() : []; };

describeOrSkip('pg-backup.sh: plaintext is opt-in', () => {
  test('PO-01 no key and no opt-in → refused before pg_dump runs, nothing written', () => {
    const sb = sandbox();
    const r = run(sb, ['full', 'daily'], { QODIQA_BACKUP_HMAC_KEY: KEYS.QODIQA_BACKUP_HMAC_KEY });
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/BACKUP_ENCRYPTION_REQUIRED/);
    expect(r.out).not.toMatch(/BACKUP_FULL_COMPLETE/);
    expect(fs.existsSync(path.join(sb.dir, 'pg_dump.ran'))).toBe(false);
    expect(tierFiles(sb).filter((f) => /\.dump/.test(f))).toEqual([]);
  });

  test('PO-02 QODIQA_BACKUP_ALLOW_PLAINTEXT=true → plaintext dump, loudly logged; verify needs the same opt-in', () => {
    const sb = sandbox();
    const optIn = { QODIQA_BACKUP_HMAC_KEY: KEYS.QODIQA_BACKUP_HMAC_KEY, QODIQA_BACKUP_ALLOW_PLAINTEXT: 'true' };
    const r = run(sb, ['full', 'daily'], optIn);
    expect(r.status).toBe(0);
    expect(r.out).toMatch(/"event":"BACKUP_PLAINTEXT_OPT_IN"/);
    expect(r.out).toMatch(/BACKUP_UNENCRYPTED/);
    expect(tierFiles(sb).filter((f) => f.endsWith('.dump'))).toHaveLength(1);
    expect(run(sb, ['verify', 'daily'], optIn).status).toBe(0);
    const strict = run(sb, ['verify', 'daily'], { QODIQA_BACKUP_HMAC_KEY: KEYS.QODIQA_BACKUP_HMAC_KEY });
    expect(strict.status).not.toBe(0);
    expect(strict.out).toMatch(/BACKUP_PLAINTEXT_REFUSED/);
  });

  test('PO-03 the opt-in never lifts an explicit QODIQA_BACKUP_REQUIRE_ENCRYPTION=true', () => {
    const sb = sandbox();
    const r = run(sb, ['full', 'daily'], { QODIQA_BACKUP_HMAC_KEY: KEYS.QODIQA_BACKUP_HMAC_KEY, QODIQA_BACKUP_ALLOW_PLAINTEXT: 'true', QODIQA_BACKUP_REQUIRE_ENCRYPTION: 'true' });
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/BACKUP_ENCRYPTION_REQUIRED/);
    expect(fs.existsSync(path.join(sb.dir, 'pg_dump.ran'))).toBe(false);
  });

  test('PO-04 with both keys and no opt-in → encrypted, sealed, verifiable (the default path)', () => {
    const sb = sandbox();
    const r = run(sb, ['full', 'daily'], KEYS);
    expect(r.status).toBe(0);
    const fl = tierFiles(sb);
    expect(fl.filter((f) => f.endsWith('.dump'))).toEqual([]);
    expect(fl.filter((f) => f.endsWith('.dump.enc'))).toHaveLength(1);
    expect(fl.filter((f) => f.endsWith('.dump.enc.seal'))).toHaveLength(1);
    expect(run(sb, ['verify', 'daily'], KEYS).status).toBe(0);
  });
});
