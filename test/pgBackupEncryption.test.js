'use strict';

/**
 * — scripts/pg-backup.sh encrypts backups at rest and can hand them to an
 * off-site copy command. Runs the REAL bash script (real openssl, real seal, real retention/verify code) with stub
 * pg_dump / pg_restore binaries first on PATH, so no database is needed; the dump content is a pg_restore --list
 * image covering every table of scripts/dr/table-registry.js, which the script's own coverage check reads.
 *
 *   EN-01 with an encryption key: only <dump>.enc + .seal remain (no plaintext), the ciphertext does not contain the
 *         dump, it decrypts with the key to the exact dump, and `verify` passes and leaves no decrypted temp file
 *   EN-02 a tampered ciphertext fails `verify` (seal over the ciphertext — encrypt-then-MAC)
 *   EN-03 QODIQA_BACKUP_REQUIRE_ENCRYPTION=true without a key: exit 1, pg_dump never runs, nothing is written
 *   EN-04 an encryption key without an HMAC key: exit 1, nothing is written (an encrypted backup must be authenticated)
 *   EN-05 the off-site command receives the encrypted file and its seal; a failing off-site command fails the run
 *   EN-06 `verify` with the wrong encryption key fails (decryption refused), even though the seal matches
 *   EN-07 control: no key and not required → plaintext .dump as before, with a BACKUP_UNENCRYPTED warning
 *   EN-08 the shipped placeholder key (or any key under 32 characters) is refused: nothing is written
 *
 * Correction pass. A fault-injecting `openssl` wrapper sits
 * first on PATH (it forwards to the real openssl unless OPENSSL_FAIL_MODE is set for `enc -e`), and a `curl` stub
 * records the alert webhook:
 *   EN-09 N1: every encryption failure mode — non-zero exit, empty output with exit 0, truncated output with exit 0,
 *         block-aligned truncation with exit 0, partial output then non-zero exit, and a SIGKILLed openssl — fails the
 *         run; no .enc / .seal / .partial is left; the off-site command never runs; BACKUP_FULL_COMPLETE and
 *         BACKUP_ENCRYPTED are never logged; the alert fires and the success metric is 0; the plaintext dump is kept
 *         (quarantined, byte-identical) instead of deleted
 *   EN-10 N1 control: the same wrapper with no fault injected → normal encrypted backup that verifies
 *   EN-11 N2: a crash leftover (plaintext .dump + .dump.enc.partial) makes `verify` fail loudly when encryption is
 *         required, even when a valid newer encrypted backup exists
 *   EN-12 N2: the next encrypted full run quarantines the leftover plaintext and removes the partial ciphertext; verify
 *         then passes on the encrypted backup
 *   EN-13 N2: `restore` refuses a plaintext file when encryption is required, and auto-selects only .dump.enc
 *   EN-14 N2: a stale decrypted temp file (> 60 min) left by a killed verify/restore is swept; a fresh one is not
 * EN-15 a placeholder, short, or encryption-key-equal seal key is refused before pg_dump runs
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync, execFileSync } = require('child_process');

const REPO = path.join(__dirname, '..');
const SCRIPT = path.join(REPO, 'scripts', 'pg-backup.sh');

function findBash() {
  if (process.platform !== 'win32') return 'bash';
  for (const p of ['C:\\Program Files\\Git\\bin\\bash.exe', 'C:\\Program Files (x86)\\Git\\bin\\bash.exe']) if (fs.existsSync(p)) return p;
  return null;
}
const BASH = findBash();
const describeOrSkip = BASH ? describe : describe.skip;
const REAL_OPENSSL = BASH ? spawnSync(BASH, ['-c', 'command -v openssl'], { encoding: 'utf8' }).stdout.trim() : '';
jest.setTimeout(120_000);

const TABLES = execFileSync(process.execPath, [path.join(REPO, 'scripts', 'dr', 'table-registry.js'), '--list'], { encoding: 'utf8' })
  .split(/\r?\n/).filter(Boolean);
const DUMP = ['; pg_restore --list image (stub)', ...TABLES.map((t, i) => `${4000 + i}; 0 0 TABLE DATA public ${t} qodiqa`)].join('\n') + '\n';

function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-dep12-'));
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(dir, 'dump.txt'), DUMP);
  const posix = (p) => p.replace(/\\/g, '/').replace(/^([A-Za-z]):/, (_, d) => `/${d.toLowerCase()}`);
  // stub pg_dump: writes the listing image to --file=; records that it ran. PG_DUMP_FAIL=1:
  // writes a truncated dump, then exits 1 the way a real pg_dump does on a lost connection / auth / version error.
  // the client tools answer --version like the real ones (PG_STUB_DUMP_MAJOR / PG_STUB_RESTORE_MAJOR,
  // default 16) and psql answers `SHOW server_version_num` (PSQL_STUB_SERVER_NUM, default 160015) — pg-backup.sh now
  // compares the client and server majors before it dumps or restores.
  fs.writeFileSync(path.join(bin, 'pg_dump'),
    `#!/usr/bin/env bash\n[[ "$1" == --version ]] && { echo "pg_dump (PostgreSQL) \${PG_STUB_DUMP_MAJOR:-16}.15"; exit 0; }\nfor a in "$@"; do case "$a" in --file=*) out="\${a#--file=}";; esac; done\ntouch "${posix(path.join(dir, 'pg_dump.ran'))}"\nif [[ -n "\${PG_DUMP_FAIL:-}" ]]; then head -c 40 "${posix(path.join(dir, 'dump.txt'))}" > "$out"; echo "pg_dump: error: connection to server lost" >&2; exit 1; fi\ncp "${posix(path.join(dir, 'dump.txt'))}" "$out"\n`, { mode: 0o755 });
  // stub pg_restore --list <file>: prints the file
  // PG_RESTORE_FAIL=1: an unreadable / corrupt archive — pg_restore exits non-zero
  fs.writeFileSync(path.join(bin, 'pg_restore'), '#!/usr/bin/env bash\n[[ "$1" == --version ]] && { echo "pg_restore (PostgreSQL) ${PG_STUB_RESTORE_MAJOR:-16}.15"; exit 0; }\n[[ -n "${PG_RESTORE_FAIL:-}" ]] && { echo "pg_restore: error: corrupt archive" >&2; exit 1; }\nfor a in "$@"; do f="$a"; done\ncat "$f"\n', { mode: 0o755 });
  // D-P / it also answers the backup-role preflight (PSQL_STUB_BACKUP_ROLE, default t) and the restore-side
  // migration-79 probe (PSQL_STUB_ER16, default 0 = pre-ER-16 schema) / definer-ownership run (PSQL_STUB_DEFINER_RC).
  fs.writeFileSync(path.join(bin, 'psql'), '#!/usr/bin/env bash\n[[ "$*" == *server_version_num* ]] && { echo "${PSQL_STUB_SERVER_NUM:-160015}"; exit 0; }\n'
    + '[[ "$*" == *backup-role-preflight* ]] && { echo "${PSQL_STUB_BACKUP_ROLE:-t}"; exit 0; }\n'
    + '[[ "$*" == *qodiqa_migrations* ]] && { echo "${PSQL_STUB_ER16:-0}"; exit 0; }\n'
    + '[[ "$*" == *schema-ownership.sql* ]] && exit "${PSQL_STUB_SCHEMA_RC:-0}"\n'
    + '[[ "$*" == *definer-ownership.sql* ]] && exit "${PSQL_STUB_DEFINER_RC:-0}"\necho f\n', { mode: 0o755 });
  // off-site stub: records its arguments; fails when OFFSITE_FAIL=1
  fs.writeFileSync(path.join(bin, 'offsite'), `#!/usr/bin/env bash\necho "$1|$2" >> "${posix(path.join(dir, 'offsite.log'))}"\n[[ "\${OFFSITE_FAIL:-0}" == 1 ]] && exit 7\nexit 0\n`, { mode: 0o755 });
  // N1: fault-injecting openssl wrapper (only `openssl enc -e` with OPENSSL_FAIL_MODE set is altered)
  fs.writeFileSync(path.join(bin, 'openssl'), [
    '#!/usr/bin/env bash',
    `REAL="${REAL_OPENSSL}"`,
    'mode="${OPENSSL_FAIL_MODE:-}"',
    'if [[ "$1" == enc && "$2" == -e && -n "$mode" ]]; then',
    '  out=""; prev=""; for a in "$@"; do [[ "$prev" == -out ]] && out="$a"; prev="$a"; done',
    '  half() { local sz; sz=$(wc -c < "$out"); head -c $((sz / 2)) "$out" > "$out.t"; mv -f "$out.t" "$out"; }',
    '  case "$mode" in',
    '    exit) exit 1 ;;',
    '    empty) : > "$out"; exit 0 ;;',
    '    truncated) "$REAL" "$@" || exit $?; half; exit 0 ;;',
    '    truncated-aligned) "$REAL" "$@" || exit $?; sz=$(wc -c < "$out"); head -c $((sz - 16)) "$out" > "$out.t"; mv -f "$out.t" "$out"; exit 0 ;;',
    '    partial-exit) "$REAL" "$@" || exit $?; half; exit 1 ;;',
    '    killed) "$REAL" "$@" || exit $?; half; kill -9 $$ ;;',
    '  esac',
    'fi',
    'exec "$REAL" "$@"',
    '',
  ].join('\n'), { mode: 0o755 });
  // alert webhook stub: records every alert body (argv), and — PL13-05 — a curl config read from stdin (`-K -`), which
  // is how the scripts now hand over the webhook URL so it never appears on a command line.
  fs.writeFileSync(path.join(bin, 'curl'), [
    '#!/usr/bin/env bash',
    `log="${posix(path.join(dir, 'alerts.log'))}"`,
    'echo "ARGV: $*" >> "$log"',
    'prev=""; for a in "$@"; do if [[ "$prev" == -K && "$a" == - ]]; then sed "s/^/STDIN: /" >> "$log"; fi; [[ "$prev" == -d ]] && echo "BODY: $a" >> "$log"; prev="$a"; done',
    'exit 0', ''].join('\n'), { mode: 0o755 });
  // Git Bash prepends /mingw64/bin and /usr/bin to PATH, so a stub named like a real tool is shadowed there. BASH_ENV
  // (sourced by the non-interactive script shell before it starts) defines functions that take precedence over PATH on
  // every platform — no test hook in the production script.
  const inject = path.join(dir, 'inject.sh');
  fs.writeFileSync(inject, `openssl() { "${posix(path.join(bin, 'openssl'))}" "$@"; }\ncurl() { "${posix(path.join(bin, 'curl'))}" "$@"; }\n`);
  return { dir, bin, backups: path.join(dir, 'backups'), posix, inject };
}

function run(sb, args, env = {}, input = undefined) {
  const r = spawnSync(BASH, [sb.posix(SCRIPT), ...args], {
    encoding: 'utf8',
    input,
    env: {
      PATH: `${sb.bin}${path.delimiter}${process.env.PATH}`,
      SYSTEMROOT: process.env.SYSTEMROOT, TEMP: process.env.TEMP, TMP: process.env.TMP, HOME: process.env.HOME || sb.dir,
      QODIQA_BACKUP_DIR: sb.posix(sb.backups), PGDATABASE: 'stub', BASH_ENV: sb.posix(sb.inject),
      ...env,
    },
  });
  return { status: r.status, out: `${r.stdout}\n${r.stderr}` };
}

const files = (dir) => (fs.existsSync(dir) ? fs.readdirSync(dir) : []).sort();
const KEYS = { QODIQA_BACKUP_ENCRYPTION_KEY: 'dep12-test-encryption-key-0123456789abcdef', QODIQA_BACKUP_HMAC_KEY: 'dep12-test-hmac-key-fedcba9876543210-xyz' };

describeOrSkip('pg-backup.sh encryption at rest and off-site hook', () => {
  test('EN-01 encrypted backup: no plaintext left, ciphertext opaque, decrypts exactly, verify passes and cleans up', () => {
    const sb = sandbox();
    const r = run(sb, ['full', 'daily'], KEYS);
    expect(r.status).toBe(0);
    const tier = path.join(sb.backups, 'full', 'daily');
    const fl = files(tier);
    expect(fl.filter((f) => f.endsWith('.dump'))).toEqual([]);
    const enc = fl.find((f) => f.endsWith('.dump.enc'));
    expect(enc).toBeDefined();
    expect(fl).toContain(`${enc}.seal`);
    const ct = fs.readFileSync(path.join(tier, enc));
    expect(ct.includes(Buffer.from('TABLE DATA public'))).toBe(false);
    const pt = execFileSync('openssl', ['enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', '200000', '-md', 'sha256', '-pass', 'env:QODIQA_BACKUP_ENCRYPTION_KEY', '-in', path.join(tier, enc)],
      { env: { ...process.env, ...KEYS } });
    expect(pt.toString()).toBe(DUMP);
    const v = run(sb, ['verify', 'daily'], KEYS);
    expect(v.status).toBe(0);
    expect(v.out).toMatch(/BACKUP_VERIFY_OK/);
    expect(files(path.join(sb.backups, 'tmp'))).toEqual([]); // the decrypted temp file is gone
  });

  test('EN-02 a tampered ciphertext fails verify', () => {
    const sb = sandbox();
    expect(run(sb, ['full', 'daily'], KEYS).status).toBe(0);
    const tier = path.join(sb.backups, 'full', 'daily');
    const enc = path.join(tier, files(tier).find((f) => f.endsWith('.dump.enc')));
    const b = fs.readFileSync(enc); b[b.length - 1] ^= 0xff; fs.writeFileSync(enc, b);
    const v = run(sb, ['verify', 'daily'], KEYS);
    expect(v.status).not.toBe(0);
    expect(v.out).toMatch(/BACKUP_SEAL_MISMATCH|Seal verification FAILED/);
  });

  test('EN-03 encryption required but no key: refused before pg_dump runs, nothing written', () => {
    const sb = sandbox();
    const r = run(sb, ['full', 'daily'], { QODIQA_BACKUP_REQUIRE_ENCRYPTION: 'true', QODIQA_BACKUP_HMAC_KEY: KEYS.QODIQA_BACKUP_HMAC_KEY });
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/BACKUP_ENCRYPTION_REQUIRED/);
    expect(fs.existsSync(path.join(sb.dir, 'pg_dump.ran'))).toBe(false);
    expect(files(path.join(sb.backups, 'full', 'daily')).filter((f) => /\.dump/.test(f))).toEqual([]);
  });

  test('EN-04 encryption key without an HMAC key: refused, nothing written', () => {
    const sb = sandbox();
    const r = run(sb, ['full', 'daily'], { QODIQA_BACKUP_ENCRYPTION_KEY: KEYS.QODIQA_BACKUP_ENCRYPTION_KEY });
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/BACKUP_ENCRYPTION_NEEDS_HMAC/);
    expect(fs.existsSync(path.join(sb.dir, 'pg_dump.ran'))).toBe(false);
  });

  test('EN-05 off-site command gets the encrypted file and its seal; a failing command fails the run', () => {
    const sb = sandbox();
    const ok = run(sb, ['full', 'daily'], { ...KEYS, QODIQA_BACKUP_OFFSITE_COMMAND: 'offsite' });
    expect(ok.status).toBe(0);
    const line = fs.readFileSync(path.join(sb.dir, 'offsite.log'), 'utf8').trim();
    expect(line).toMatch(/\.dump\.enc\|.*\.dump\.enc\.seal$/);
    const sb2 = sandbox();
    const bad = run(sb2, ['full', 'daily'], { ...KEYS, QODIQA_BACKUP_OFFSITE_COMMAND: 'offsite', OFFSITE_FAIL: '1' });
    expect(bad.status).not.toBe(0);
    expect(bad.out).toMatch(/BACKUP_OFFSITE_FAILED|Off-site copy FAILED/);
  });

  // EN-06 / EN-06b: the format is AES-256-CBC + PBKDF2 (openssl enc) with an HMAC seal over
  // the CIPHERTEXT under a separate key — encrypt-then-MAC, no AEAD. A wrong decryption key therefore cannot be
  // detected by the seal, and CBC padding rejects it only with probability ~255/256: about 1 wrong key in 256 decrypts
  // to garbage with VALID padding. The former EN-06 used one fixed wrong key against a fresh random salt, so it took
  // the second branch ~1/256 of the time. Its regex accepted only the first
  // branch, which is not the contract. The contract is: a wrong key NEVER yields an accepted backup — either openssl
  // refuses the padding (BACKUP_DECRYPT_FAILED) or the bytes it produces are refused as not-the-dump. Both branches
  // are now tested DETERMINISTICALLY, each asserting its own exact outcome:
  //   EN-06  a wrong key whose padding check fails for THIS ciphertext (pre-checked here in Node, same KDF/cipher)
  //   EN-06b the other branch: a sealed archive that decrypts with valid padding to bytes that are not a pg_dump
  //          archive (exactly what a valid-padding wrong key produces) is refused, never verified OK.
  const OPENSSL_KDF = (pass, salt) => crypto.pbkdf2Sync(Buffer.from(pass, 'utf8'), salt, 200000, 48, 'sha256');
  const paddingAccepts = (encFile, pass) => {
    const buf = fs.readFileSync(encFile);
    expect(buf.subarray(0, 8).toString('latin1')).toBe('Salted__');
    const km = OPENSSL_KDF(pass, buf.subarray(8, 16));
    const d = crypto.createDecipheriv('aes-256-cbc', km.subarray(0, 32), km.subarray(32, 48));
    try { d.update(buf.subarray(16)); d.final(); return true; } catch { return false; }
  };
  const latestEnc = (sb) => { const dir = path.join(sb.backups, 'full', 'daily'); return path.join(dir, files(dir).find((f) => f.endsWith('.dump.enc'))); };

  test('EN-06 verify with a wrong key that the CBC padding check rejects fails with BACKUP_DECRYPT_FAILED (deterministic)', () => {
    const sb = sandbox();
    expect(run(sb, ['full', 'daily'], KEYS).status).toBe(0);
    const enc = latestEnc(sb);
    expect(paddingAccepts(enc, KEYS.QODIQA_BACKUP_ENCRYPTION_KEY)).toBe(true); // the KDF/cipher model matches the script
    let wrong = null;
    for (let i = 0; i < 64 && !wrong; i++) {
      const k = `en06-wrong-key-${i}-${'0'.repeat(32)}`;
      if (!paddingAccepts(enc, k)) wrong = k;
    }
    expect(wrong).not.toBeNull(); // P(no rejecting key among 64) ≈ 256^-64
    const v = run(sb, ['verify', 'daily'], { ...KEYS, QODIQA_BACKUP_ENCRYPTION_KEY: wrong });
    expect(v.status).toBe(1);
    expect(v.out).toMatch(/BACKUP_SEAL_OK/);
    expect(v.out).toMatch(/Decryption FAILED for /);
    expect(v.out).not.toMatch(/BACKUP_VERIFY_OK/);
    expect(files(path.join(sb.backups, 'tmp'))).toEqual([]);
  });

  test('EN-06b a sealed archive that decrypts with valid padding to bytes that are not the dump is refused, never verified OK', () => {
    const sb = sandbox();
    expect(run(sb, ['full', 'daily'], KEYS).status).toBe(0);
    const enc = latestEnc(sb);
    // the valid-padding wrong-key outcome, constructed deterministically: openssl-format ciphertext of non-dump bytes
    // under the CONFIGURED key, with a correct seal (the seal key is separate and authenticates only the ciphertext)
    const salt = Buffer.from('en06bslt', 'latin1');
    const km = OPENSSL_KDF(KEYS.QODIQA_BACKUP_ENCRYPTION_KEY, salt);
    const c = crypto.createCipheriv('aes-256-cbc', km.subarray(0, 32), km.subarray(32, 48));
    const body = Buffer.concat([c.update(Buffer.from('\u0007garbage-not-a-pg_dump-archive\n', 'utf8')), c.final()]);
    fs.writeFileSync(enc, Buffer.concat([Buffer.from('Salted__', 'latin1'), salt, body]));
    fs.writeFileSync(`${enc}.seal`, `${crypto.createHmac('sha256', Buffer.from(KEYS.QODIQA_BACKUP_HMAC_KEY, 'utf8')).update(fs.readFileSync(enc)).digest('hex')}\n`);
    const v = run(sb, ['verify', 'daily'], KEYS);
    expect(v.status).toBe(1);
    expect(v.out).toMatch(/BACKUP_SEAL_OK/);
    expect(v.out).not.toMatch(/Decryption FAILED/);
    expect(v.out).toMatch(/pg_restore --list returned suspicious output \(1 lines\)/);
    expect(v.out).not.toMatch(/BACKUP_VERIFY_OK/);
    expect(files(path.join(sb.backups, 'tmp'))).toEqual([]);
  });

  test('EN-08 a placeholder or short encryption key is refused before pg_dump runs', () => {
    for (const k of ['REPLACE_WITH_REAL_BACKUP_ENCRYPTION_KEY_BEFORE_DEPLOY', 'short-key']) {
      const sb = sandbox();
      const r = run(sb, ['full', 'daily'], { ...KEYS, QODIQA_BACKUP_ENCRYPTION_KEY: k });
      expect(r.status).toBe(1);
      expect(r.out).toMatch(/BACKUP_ENCRYPTION_KEY_INVALID/);
      expect(fs.existsSync(path.join(sb.dir, 'pg_dump.ran'))).toBe(false);
    }
  });

  const tierOf = (sb) => path.join(sb.backups, 'full', 'daily');
  const quarantined = (sb) => files(path.join(sb.backups, 'quarantine'));

  test.each(['exit', 'empty', 'truncated', 'truncated-aligned', 'partial-exit', 'killed'])(
    'EN-09 N1 encryption failure mode "%s" fails closed: nothing sealed/copied/completed, alert fires, plaintext kept', (mode) => {
      const sb = sandbox();
      const r = run(sb, ['full', 'daily'], {
        ...KEYS, OPENSSL_FAIL_MODE: mode, QODIQA_BACKUP_OFFSITE_COMMAND: 'offsite', ALERT_WEBHOOK_URL: 'https://alerts.invalid/hook',
      });
      expect(r.status).not.toBe(0);
      expect(r.out).toMatch(/BACKUP_ENCRYPTION_FAILED/);
      expect(r.out).not.toMatch(/BACKUP_FULL_COMPLETE/);
      expect(r.out).not.toMatch(/"event":"BACKUP_ENCRYPTED"/);
      expect(r.out).not.toMatch(/BACKUP_OFFSITE_COPIED/);
      expect(fs.existsSync(path.join(sb.dir, 'offsite.log'))).toBe(false);
      // no artifact that could be mistaken for a backup
      expect(files(tierOf(sb)).filter((f) => /\.dump|\.seal|\.partial/.test(f))).toEqual([]);
      // the plaintext was NOT deleted: it is quarantined, byte-identical to the dump
      const q = quarantined(sb);
      expect(q).toHaveLength(1);
      expect(fs.readFileSync(path.join(sb.backups, 'quarantine', q[0]), 'utf8')).toBe(DUMP);
      // alert and failure metric
      expect(fs.readFileSync(path.join(sb.dir, 'alerts.log'), 'utf8')).toMatch(/FAILED/);
      // each mode/tier now owns its own textfile (was the shared qodiqa_pg_backup.prom)
      const prom = fs.readFileSync(path.join(sb.backups, 'metrics', 'qodiqa_pg_backup_full_daily.prom'), 'utf8');
      expect(prom).toMatch(/qodiqa_pg_backup_success\{mode="full",tier="daily"\} 0/);
    });

  test('EN-10 N1 control: the wrapper with no fault injected produces a normal encrypted backup that verifies', () => {
    const sb = sandbox();
    const r = run(sb, ['full', 'daily'], KEYS);
    expect(r.status).toBe(0);
    expect(r.out).toMatch(/BACKUP_FULL_COMPLETE/);
    expect(files(tierOf(sb)).filter((f) => f.endsWith('.dump.enc'))).toHaveLength(1);
    expect(files(tierOf(sb)).filter((f) => /\.partial$|\.dump$/.test(f))).toEqual([]);
    expect(quarantined(sb)).toEqual([]);
    expect(run(sb, ['verify', 'daily'], { ...KEYS, QODIQA_BACKUP_REQUIRE_ENCRYPTION: 'true' }).status).toBe(0);
  });

  // the state a crash between pg_dump and encryption leaves behind
  function crashLeftover(sb, stamp = '20991231T000000Z') {
    fs.mkdirSync(tierOf(sb), { recursive: true });
    fs.writeFileSync(path.join(tierOf(sb), `qodiqa_${stamp}.dump`), DUMP);
    fs.writeFileSync(path.join(tierOf(sb), `qodiqa_${stamp}.dump.enc.partial`), 'Salted__partial');
  }

  test('EN-11 N2 a crash leftover plaintext fails verify when encryption is required, even beside a valid encrypted backup', () => {
    const sb = sandbox();
    expect(run(sb, ['full', 'daily'], KEYS).status).toBe(0);
    crashLeftover(sb);
    const v = run(sb, ['verify', 'daily'], { ...KEYS, QODIQA_BACKUP_REQUIRE_ENCRYPTION: 'true' });
    expect(v.status).not.toBe(0);
    expect(v.out).toMatch(/BACKUP_PLAINTEXT_REFUSED/);
    expect(v.out).not.toMatch(/BACKUP_VERIFY_OK/);
  });

  test('EN-12 N2 the next encrypted full run quarantines the leftover plaintext and removes the partial; verify then passes', () => {
    const sb = sandbox();
    crashLeftover(sb, '20000101T000000Z');
    const r = run(sb, ['full', 'daily'], KEYS);
    expect(r.status).toBe(0);
    expect(r.out).toMatch(/BACKUP_PLAINTEXT_QUARANTINED/);
    expect(r.out).toMatch(/BACKUP_PARTIAL_CIPHERTEXT_REMOVED/);
    expect(files(tierOf(sb)).filter((f) => /\.dump$|\.partial$/.test(f))).toEqual([]);
    expect(quarantined(sb)).toEqual(['qodiqa_20000101T000000Z.dump.plaintext']);
    const v = run(sb, ['verify', 'daily'], { ...KEYS, QODIQA_BACKUP_REQUIRE_ENCRYPTION: 'true' });
    expect(v.status).toBe(0);
    expect(v.out).toMatch(/BACKUP_VERIFY_OK.*\.dump\.enc/);
  });

  test('EN-13 N2 restore refuses plaintext when encryption is required and auto-selects only .dump.enc', () => {
    const sb = sandbox();
    expect(run(sb, ['full'], KEYS).status).toBe(0);           // untiered → backups/full/*.dump.enc
    const full = path.join(sb.backups, 'full');
    const plain = path.join(full, 'qodiqa_20991231T000000Z.dump'); // newer, plaintext
    fs.writeFileSync(plain, DUMP);
    const req = { ...KEYS, QODIQA_BACKUP_REQUIRE_ENCRYPTION: 'true' };
    const refused = run(sb, ['restore', sb.posix(plain)], req, 'RESTORE\n');
    expect(refused.status).toBe(1);
    expect(refused.out).toMatch(/refusing to restore a plaintext backup/);
    expect(refused.out).not.toMatch(/RESTORE_START/);
    const auto = run(sb, ['restore'], req, 'no\n');            // declined at the prompt: shows the file it chose
    expect(auto.out).toMatch(/Backup file\s+: .*\.dump\.enc/);
    expect(auto.out).toMatch(/Aborted/);
    // control: without the requirement the plaintext file is still restorable as before (seal check is what stops it)
    // plaintext is now opt-in (QODIQA_BACKUP_ALLOW_PLAINTEXT=true); this control is that opt-in.
    const ctl = run(sb, ['restore', sb.posix(plain)], { ...KEYS, QODIQA_BACKUP_ALLOW_PLAINTEXT: 'true' }, 'no\n');
    expect(ctl.out).toMatch(/Backup file\s+: .*\.dump\n/);
  });

  // OA4-F1: restore uses pg_restore --no-owner, so the restoring role owns every restored object,
  // SECURITY DEFINER functions included. A psql stub (BASH_ENV function, like openssl/curl) answers the role check.
  const withPsqlStub = (sb) => {
    fs.appendFileSync(sb.inject, 'psql() { [[ "$*" == *server_version_num* ]] && { echo "${PSQL_STUB_SERVER_NUM:-160015}"; return 0; }; '
      + '[[ "$*" == *backup-role-preflight* ]] && { echo "${PSQL_STUB_BACKUP_ROLE:-t}"; return 0; }; '
      + '[[ "$*" == *qodiqa_migrations* ]] && { echo "${PSQL_STUB_ER16:-0}"; return 0; }; '
      + '[[ "$*" == *schema-ownership.sql* ]] && { echo "SCHEMA_SQL_RUN" >&2; return "${PSQL_STUB_SCHEMA_RC:-0}"; }; '
      + '[[ "$*" == *definer-ownership.sql* ]] && { echo "DEFINER_SQL_RUN" >&2; return "${PSQL_STUB_DEFINER_RC:-0}"; }; '
      + '[[ -n "${PSQL_STUB_FAIL:-}" ]] && return 2; echo "${PSQL_STUB_SUPER:-f}"; }\n');
    return sb;
  };
  const restoreEnc = (sb, env) => {
    const full = path.join(sb.backups, 'full');
    const enc = files(full).find((f) => f.endsWith('.dump.enc'));
    return run(sb, ['restore', sb.posix(path.join(full, enc))], { ...KEYS, QODIQA_BACKUP_REQUIRE_ENCRYPTION: 'true', ...env }, 'RESTORE\n');
  };

  test('EN-16 OA4-F1 restore as a superuser is refused (no pg_restore, no RESTORE_START)', () => {
    const sb = withPsqlStub(sandbox());
    expect(run(sb, ['full'], KEYS).status).toBe(0);
    const r = restoreEnc(sb, { PSQL_STUB_SUPER: 't' });
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/RESTORE_SUPERUSER_REFUSED/);
    expect(r.out).toMatch(/refusing to restore as a superuser/);
    expect(r.out).not.toMatch(/RESTORE_START/);
  });

  test('EN-17 OA4-F1 a superuser restore proceeds only with the explicit override, and is logged as a WARN', () => {
    const sb = withPsqlStub(sandbox());
    expect(run(sb, ['full'], KEYS).status).toBe(0);
    const r = restoreEnc(sb, { PSQL_STUB_SUPER: 't', QODIQA_BACKUP_ALLOW_SUPERUSER_RESTORE: 'true' });
    expect(r.status).toBe(0);
    expect(r.out).toMatch(/"level":"WARN","event":"RESTORE_AS_SUPERUSER_ALLOWED"/);
    expect(r.out).toMatch(/RESTORE_COMPLETE/);
    // any other value is not an override
    const notTrue = restoreEnc(sb, { PSQL_STUB_SUPER: 't', QODIQA_BACKUP_ALLOW_SUPERUSER_RESTORE: '1' });
    expect(notTrue.status).toBe(1);
    expect(notTrue.out).toMatch(/RESTORE_SUPERUSER_REFUSED/);
  });

  test('EN-18 OA4-F1 a non-superuser restore proceeds unchanged (no override needed, no warning)', () => {
    const sb = withPsqlStub(sandbox());
    expect(run(sb, ['full'], KEYS).status).toBe(0);
    const r = restoreEnc(sb, { PSQL_STUB_SUPER: 'f' });
    expect(r.status).toBe(0);
    expect(r.out).toMatch(/RESTORE_START/);
    expect(r.out).toMatch(/RESTORE_COMPLETE/);
    expect(r.out).not.toMatch(/RESTORE_AS_SUPERUSER_ALLOWED|RESTORE_SUPERUSER_REFUSED/);
  });

  test('EN-19 OA4-F1 if the role cannot be determined the restore fails closed', () => {
    const sb = withPsqlStub(sandbox());
    expect(run(sb, ['full'], KEYS).status).toBe(0);
    const r = restoreEnc(sb, { PSQL_STUB_FAIL: '1', QODIQA_BACKUP_ALLOW_SUPERUSER_RESTORE: 'true' });
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/RESTORE_ROLE_CHECK_FAILED/);
    expect(r.out).not.toMatch(/RESTORE_START/);
  });

  // after pg_restore --no-owner, a schema at migration 079+ gets its SECURITY DEFINER ownership
  // re-established (scripts/dr/definer-ownership.sql); a failure there makes the restore INCOMPLETE (exit 1, alert).
  test('EN-30 a restored 079+ schema runs the definer-ownership step and completes only when it succeeds', () => {
    const sb = withPsqlStub(sandbox());
    expect(run(sb, ['full'], KEYS).status).toBe(0);
    const ok = restoreEnc(sb, { PSQL_STUB_SUPER: 'f', PSQL_STUB_ER16: '1' });
    expect(ok.status).toBe(0);
    expect(ok.out).toMatch(/SCHEMA_SQL_RUN/); // closure (migration 081): schema ownership first, then the definers
    expect(ok.out).toMatch(/DEFINER_SQL_RUN/);
    expect(ok.out).toMatch(/RESTORE_DEFINER_OWNERSHIP_OK/);
    expect(ok.out).toMatch(/RESTORE_COMPLETE/);
    const bad = restoreEnc(sb, { PSQL_STUB_SUPER: 'f', PSQL_STUB_ER16: '1', PSQL_STUB_DEFINER_RC: '3' });
    expect(bad.status).toBe(1);
    expect(bad.out).toMatch(/RESTORE_DEFINER_OWNERSHIP_FAILED/);
    expect(bad.out).toMatch(/INCOMPLETE/);
    expect(bad.out).not.toMatch(/RESTORE_COMPLETE/);
    // closure (081): a failing schema-ownership step fails the restore before the definer step runs
    const badSchema = restoreEnc(sb, { PSQL_STUB_SUPER: 'f', PSQL_STUB_ER16: '1', PSQL_STUB_SCHEMA_RC: '3' });
    expect(badSchema.status).toBe(1);
    expect(badSchema.out).toMatch(/RESTORE_SCHEMA_OWNERSHIP_FAILED/);
    expect(badSchema.out).not.toMatch(/DEFINER_SQL_RUN/);
    expect(badSchema.out).not.toMatch(/RESTORE_COMPLETE/);
  });

  test('EN-31 a pre-079 restored schema is reported (WARN), and an unreadable migration table fails closed', () => {
    const sb = withPsqlStub(sandbox());
    expect(run(sb, ['full'], KEYS).status).toBe(0);
    const pre = restoreEnc(sb, { PSQL_STUB_SUPER: 'f', PSQL_STUB_ER16: '0' });
    expect(pre.status).toBe(0);
    expect(pre.out).toMatch(/"level":"WARN","event":"RESTORE_DEFINER_OWNERSHIP_PRE_ER16"/);
    expect(pre.out).not.toMatch(/DEFINER_SQL_RUN/);
    const unknown = restoreEnc(sb, { PSQL_STUB_SUPER: 'f', PSQL_STUB_ER16: 'x' });
    expect(unknown.status).toBe(1);
    expect(unknown.out).toMatch(/RESTORE_DEFINER_OWNERSHIP_UNKNOWN/);
    expect(unknown.out).not.toMatch(/RESTORE_COMPLETE/);
  });

  // D-P: the dumping role must be RLS-exempt AND a pg_read_all_data member, checked before anything is written.
  test('EN-32 D-P a backup role without pg_read_all_data (or RLS exemption) is refused before anything is written', () => {
    const sb = sandbox();
    const r = run(sb, ['full'], { ...KEYS, PSQL_STUB_BACKUP_ROLE: 'f' });
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/BACKUP_ROLE_READ_ALL_DATA_MISSING/);
    expect(r.out).not.toMatch(/BACKUP_FULL_START/);
    expect(fs.existsSync(path.join(sb.backups, 'full')) ? files(path.join(sb.backups, 'full')).filter((f) => /\.dump/.test(f)) : []).toEqual([]);
  });

  test('EN-33 D-P an unverifiable backup role fails closed; a verified one proceeds', () => {
    const sb = sandbox();
    const r = run(sb, ['full'], { ...KEYS, PSQL_STUB_BACKUP_ROLE: 'x' });
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/BACKUP_ROLE_PREFLIGHT_FAILED/);
    expect(r.out).not.toMatch(/BACKUP_FULL_START/);
    const ok = run(sb, ['full'], { ...KEYS, PSQL_STUB_BACKUP_ROLE: 't' });
    expect(ok.status).toBe(0);
    expect(ok.out).toMatch(/BACKUP_ROLE_PREFLIGHT_OK/);
    expect(ok.out).toMatch(/BACKUP_FULL_START/);
  });

  test('EN-14 N2 a stale decrypted temp file from a killed verify/restore is swept; a fresh one is not', () => {
    const sb = sandbox();
    expect(run(sb, ['full', 'daily'], KEYS).status).toBe(0);
    const tmp = path.join(sb.backups, 'tmp');
    fs.mkdirSync(tmp, { recursive: true });
    fs.writeFileSync(path.join(tmp, 'restore.stale1'), DUMP);
    const old = new Date(Date.now() - 2 * 3600 * 1000);
    fs.utimesSync(path.join(tmp, 'restore.stale1'), old, old);
    fs.writeFileSync(path.join(tmp, 'restore.fresh1'), 'in use by a concurrent run');
    expect(run(sb, ['verify', 'daily'], KEYS).status).toBe(0);
    expect(files(tmp)).toEqual(['restore.fresh1']);
  });

  test('EN-15 a placeholder, short, or encryption-key-equal seal key is refused before pg_dump runs', () => {
    for (const k of ['REPLACE_WITH_REAL_BACKUP_HMAC_SEAL_KEY_BEFORE_DEPLOY', 'short-hmac', KEYS.QODIQA_BACKUP_ENCRYPTION_KEY]) {
      const sb = sandbox();
      const r = run(sb, ['full', 'daily'], { ...KEYS, QODIQA_BACKUP_HMAC_KEY: k });
      expect(r.status).toBe(1);
      expect(r.out).toMatch(/BACKUP_HMAC_KEY_INVALID/);
      expect(fs.existsSync(path.join(sb.dir, 'pg_dump.ran'))).toBe(false);
    }
  });

  // plaintext output now needs the explicit QODIQA_BACKUP_ALLOW_PLAINTEXT=true opt-in; EN-07b proves
  // the default refuses it.
  test('EN-07 control: no key, explicit plaintext opt-in → plaintext dump, with a warning', () => {
    const sb = sandbox();
    const plain = { QODIQA_BACKUP_HMAC_KEY: KEYS.QODIQA_BACKUP_HMAC_KEY, QODIQA_BACKUP_ALLOW_PLAINTEXT: 'true' };
    const r = run(sb, ['full', 'daily'], plain);
    expect(r.status).toBe(0);
    expect(r.out).toMatch(/BACKUP_UNENCRYPTED/);
    const fl = files(path.join(sb.backups, 'full', 'daily'));
    expect(fl.filter((f) => f.endsWith('.dump'))).toHaveLength(1);
    expect(run(sb, ['verify', 'daily'], plain).status).toBe(0);
  });

  test('EN-07b no key and no plaintext opt-in → refused, no plaintext dump written', () => {
    const sb = sandbox();
    const r = run(sb, ['full', 'daily'], { QODIQA_BACKUP_HMAC_KEY: KEYS.QODIQA_BACKUP_HMAC_KEY });
    expect(r.status).not.toBe(0);
    expect(files(path.join(sb.backups, 'full', 'daily')).filter((f) => f.endsWith('.dump'))).toHaveLength(0);
  });

  // ── 2026-10-06 ──────────────────────────────────────────────
  const SCRIPT_TEXT = fs.readFileSync(SCRIPT, 'utf8').replace(/\r\n/g, '\n');
  // The seal pipeline pg-backup.sh used, verbatim (key on openssl's argv).
  const OLD_SEAL = 'echo -n "${K}" | openssl dgst -sha256 -hmac "$(cat)" "$F" | awk \'{print $2}\'';
  const oldSeal = (key, file) => spawnSync(BASH, ['-c', OLD_SEAL], { encoding: 'utf8', env: { ...process.env, K: key, F: file } }).stdout;

  test('EN-20 hmac_hex is byte-identical to the former openssl argv pipeline, and the key never reaches argv', () => {
    // (a) the shipped function, extracted from the script, against the old pipeline — several keys and contents,
    // including a key with trailing newlines (the old "$(cat)" stripped them) and a non-ASCII UTF-8 key
    const fn = SCRIPT_TEXT.match(/^hmac_hex\(\) \{[\s\S]*?^\}$/m);
    expect(fn).not.toBeNull();
    const sb = sandbox();
    const posixFile = (name, content) => { const p = path.join(sb.dir, name); fs.writeFileSync(p, content); return sb.posix(p); };
    const inputs = [posixFile('a.bin', DUMP), posixFile('b.bin', Buffer.from([0, 1, 2, 255, 10, 13, 0])), posixFile('c.bin', '')];
    // The non-ASCII key runs only where argv is byte-transparent (Linux — where the script runs in production). On a
    // Windows host mingw openssl receives argv in the ANSI code page, so the OLD pipeline itself hashed `é` as one
    // latin-1 byte there; the Linux equivalence (both MATCH) was proven in the backup image itself, see
    //
    const keys = [KEYS.QODIQA_BACKUP_HMAC_KEY, `${KEYS.QODIQA_BACKUP_HMAC_KEY}\n\n`,
      ...(process.platform === 'win32' ? [] : ['clé-ünïcödé-0123456789abcdef-0123456789'])];
    for (const key of keys) {
      for (const f of inputs) {
        const r = spawnSync(BASH, ['-c', `log_json() { :; }\n${fn[0]}\nhmac_hex "$F"`], { encoding: 'utf8', env: { ...process.env, HMAC_KEY: key, F: f } });
        expect(r.status).toBe(0);
        const before = oldSeal(key, f);
        expect(before).toMatch(/^[0-9a-f]{64}\n$/);
        expect({ key: JSON.stringify(key), f, seal: r.stdout }).toEqual({ key: JSON.stringify(key), f, seal: before });
      }
    }
    // (b) a real encrypted backup's .seal file is byte-for-byte what the old pipeline produces over the ciphertext,
    // so seals written before the change verify after it and vice versa
    expect(run(sb, ['full', 'daily'], KEYS).status).toBe(0);
    const tier = path.join(sb.backups, 'full', 'daily');
    const enc = files(tier).find((f) => f.endsWith('.dump.enc'));
    const sealPath = path.join(tier, `${enc}.seal`);
    expect(fs.readFileSync(sealPath, 'utf8')).toBe(oldSeal(KEYS.QODIQA_BACKUP_HMAC_KEY, sb.posix(path.join(tier, enc))));
    // (c) a seal WRITTEN by the old pipeline verifies with the new script
    fs.writeFileSync(sealPath, oldSeal(KEYS.QODIQA_BACKUP_HMAC_KEY, sb.posix(path.join(tier, enc))));
    const v = run(sb, ['verify', 'daily'], KEYS);
    expect(v.status).toBe(0);
    expect(v.out).toMatch(/BACKUP_SEAL_OK/);
    // (d) the key is never an argument: no `-hmac` anywhere in the script, and hmac_hex hands it over in the environment
    expect(SCRIPT_TEXT.split('-hmac').length - 1).toBe(0);
    expect(fn[0]).toMatch(/QODIQA_SEAL_HMAC_KEY="\$\{HMAC_KEY\}" node -e/);
    expect(fn[0]).not.toMatch(/"\$\{?HMAC_KEY\}?"\s*$/m);
  });

  test('EN-21 each mode/tier writes its own metrics textfile; a later verify no longer erases a failed full', () => {
    const sb = sandbox();
    const metrics = path.join(sb.backups, 'metrics');
    fs.mkdirSync(metrics, { recursive: true });
    fs.writeFileSync(path.join(metrics, 'qodiqa_pg_backup.prom'), 'qodiqa_pg_backup_success{mode="full",tier="daily"} 1\n'); // pre-change shared file
    // a FAILED full daily, then a good full daily is not run — the verify of an older good backup must not hide it
    expect(run(sb, ['full', 'daily'], KEYS).status).toBe(0);                                    // good backup to verify
    expect(run(sb, ['full', 'daily'], { ...KEYS, OPENSSL_FAIL_MODE: 'exit' }).status).not.toBe(0); // failed full
    expect(run(sb, ['verify', 'daily'], KEYS).status).toBe(0);                                  // verify passes
    const full = fs.readFileSync(path.join(metrics, 'qodiqa_pg_backup_full_daily.prom'), 'utf8');
    const verify = fs.readFileSync(path.join(metrics, 'qodiqa_pg_backup_verify_daily.prom'), 'utf8');
    expect(full).toMatch(/^qodiqa_pg_backup_success\{mode="full",tier="daily"\} 0$/m); // still visible after the verify
    expect(full).not.toMatch(/mode="verify"/);
    expect(verify).toMatch(/^qodiqa_pg_backup_success\{mode="verify",tier="daily"\} 1$/m);
    expect(verify).toMatch(/^qodiqa_pg_backup_last_run_timestamp_seconds\{mode="verify",tier="daily"\} \d+$/m);
    expect(verify).not.toMatch(/mode="full"/);
    // the pre-change shared file is retired (renamed, not deleted) so its series cannot collide with the new files'
    const names = files(metrics);
    expect(names).not.toContain('qodiqa_pg_backup.prom');
    expect(names).toContain('qodiqa_pg_backup.prom.superseded');
    expect(names.filter((n) => n.endsWith('.prom')).sort()).toEqual(['qodiqa_pg_backup_full_daily.prom', 'qodiqa_pg_backup_verify_daily.prom']);
  });

  test('EN-22 a placeholder ALERT_WEBHOOK_URL is treated as unset (logged), a real one is still called', () => {
    const fail = { QODIQA_BACKUP_REQUIRE_ENCRYPTION: 'true' }; // EN-03 path: alert_failure, no key
    const sb1 = sandbox();
    const r1 = run(sb1, ['full', 'daily'], { ...fail, ALERT_WEBHOOK_URL: 'REPLACE_WITH_REAL_ALERT_WEBHOOK_URL_BEFORE_DEPLOY_OPTIONAL' });
    expect(r1.status).toBe(1);
    expect(r1.out).toMatch(/ALERT_WEBHOOK_PLACEHOLDER/);
    expect(fs.existsSync(path.join(sb1.dir, 'alerts.log'))).toBe(false);
    const sb2 = sandbox();
    const r2 = run(sb2, ['full', 'daily'], { ...fail, ALERT_WEBHOOK_URL: 'https://alerts.invalid/hook' });
    expect(r2.status).toBe(1);
    expect(r2.out).not.toMatch(/ALERT_WEBHOOK_PLACEHOLDER/);
    expect(fs.readFileSync(path.join(sb2.dir, 'alerts.log'), 'utf8')).toMatch(/alerts\.invalid/);
  });

  test('EN-23 follow-up: pg-wal-archive.sh and backup-audit-log.sh seal byte-identically without the key on argv', () => {
    const sb = sandbox();
    const posixFile = (name, content) => { const p = path.join(sb.dir, name); fs.writeFileSync(p, content); return sb.posix(p); };
    const inputs = [posixFile('w.bin', DUMP), posixFile('e.bin', '')];
    for (const rel of ['pg-wal-archive.sh', 'backup-audit-log.sh']) {
      const text = fs.readFileSync(path.join(path.dirname(SCRIPT), rel), 'utf8').replace(/\r\n/g, '\n');
      const code = text.split(/\n/).filter((l) => !l.trim().startsWith('#')).join(' ');
      expect(code).not.toMatch(/-hmac/); // no key-on-argv pipeline left (code lines)
      const fn = text.match(/^hmac_hex\(\) \{[\s\S]*?^\}$/m);
      expect(fn).not.toBeNull();
      for (const key of [KEYS.QODIQA_BACKUP_HMAC_KEY, `${KEYS.QODIQA_BACKUP_HMAC_KEY}\n`]) {
        for (const f of inputs) {
          const r = spawnSync(BASH, ['-c', `log_json() { :; }\n${fn[0]}\nhmac_hex "$F"`], { encoding: 'utf8', env: { ...process.env, HMAC_KEY: key, F: f } });
          expect({ rel, status: r.status, seal: r.stdout }).toEqual({ rel, status: 0, seal: oldSeal(key, f) });
        }
      }
    }
  });

  // ── phase 13/14 ─────────────────────────────
  const runOther = (sb, rel, args, env = {}) => {
    const r = spawnSync(BASH, [sb.posix(path.join(path.dirname(SCRIPT), rel)), ...args], {
      encoding: 'utf8',
      env: {
        PATH: `${sb.bin}${path.delimiter}${process.env.PATH}`,
        SYSTEMROOT: process.env.SYSTEMROOT, TEMP: process.env.TEMP, TMP: process.env.TMP, HOME: process.env.HOME || sb.dir,
        BASH_ENV: sb.posix(sb.inject), ...env,
      },
    });
    return { status: r.status, out: `${r.stdout}\n${r.stderr}` };
  };
  const count = (s, re) => (s.match(new RegExp(re, 'gm')) || []).length;
  const alertsLog = (sb) => (fs.existsSync(path.join(sb.dir, 'alerts.log')) ? fs.readFileSync(path.join(sb.dir, 'alerts.log'), 'utf8') : '');
  const HOOK = 'https://alerts.invalid/hook/T0K3N-secret-path';

  test('EN-24 PL13-03 a failing pg_dump alerts exactly once, records success=0, and leaves no backup-shaped file', () => {
    const sb = sandbox();
    const r = run(sb, ['full', 'daily'], { ...KEYS, PG_DUMP_FAIL: '1', ALERT_WEBHOOK_URL: HOOK });
    expect(r.status).not.toBe(0);
    // before PL13-03 (no errtrace) the ERR trap never ran inside run_full_backup: exit 1 with NO alert of any kind
    expect(count(r.out, '"event":"BACKUP_FAILED"')).toBe(1);
    expect(r.out).not.toMatch(/BACKUP_FULL_COMPLETE|BACKUP_ENCRYPTED/);
    expect(count(alertsLog(sb), '^ARGV: ')).toBe(1);
    const prom = fs.readFileSync(path.join(sb.backups, 'metrics', 'qodiqa_pg_backup_full_daily.prom'), 'utf8');
    expect(prom).toMatch(/^qodiqa_pg_backup_success\{mode="full",tier="daily"\} 0$/m);
    // PL13-04: the truncated plaintext never sits in the tier directory under a backup name
    expect(files(tierOf(sb)).filter((f) => /\.dump/.test(f))).toEqual([]);
    expect(quarantined(sb)).toHaveLength(1);
    expect(quarantined(sb)[0]).toMatch(/\.dump\.partial\.plaintext$/);
    // a later verify must not pick anything up from the failed run
    expect(run(sb, ['verify', 'daily'], KEYS).out).toMatch(/No backup found to verify/);
  });

  test('EN-25 PL13-04 a SIGKILL leftover <dump>.partial is refused by verify (encryption required) and quarantined by the next full run', () => {
    const sb = sandbox();
    expect(run(sb, ['full', 'daily'], KEYS).status).toBe(0);
    fs.writeFileSync(path.join(tierOf(sb), 'qodiqa_20991231T000000Z.dump.partial'), DUMP.slice(0, 50));
    const v = run(sb, ['verify', 'daily'], { ...KEYS, QODIQA_BACKUP_REQUIRE_ENCRYPTION: 'true' });
    expect(v.status).toBe(1);
    expect(v.out).toMatch(/BACKUP_PLAINTEXT_REFUSED/);
    const f = run(sb, ['full', 'daily'], KEYS);
    expect(f.status).toBe(0);
    expect(f.out).toMatch(/BACKUP_PLAINTEXT_QUARANTINED.*incomplete pg_dump output left by an interrupted run/);
    expect(files(tierOf(sb)).filter((x) => /\.partial$/.test(x))).toEqual([]);
    expect(quarantined(sb)).toEqual(['qodiqa_20991231T000000Z.dump.partial.plaintext']);
    expect(run(sb, ['verify', 'daily'], { ...KEYS, QODIQA_BACKUP_REQUIRE_ENCRYPTION: 'true' }).status).toBe(0);
    // unencrypted mode too: the leftover is never counted as a backup by verify/retention
    const sb2 = sandbox();
    fs.mkdirSync(tierOf(sb2), { recursive: true });
    fs.writeFileSync(path.join(tierOf(sb2), 'qodiqa_20991231T000000Z.dump.partial'), DUMP.slice(0, 50));
    const hk = { QODIQA_BACKUP_HMAC_KEY: KEYS.QODIQA_BACKUP_HMAC_KEY, QODIQA_BACKUP_ALLOW_PLAINTEXT: 'true' }; // opt-in
    expect(run(sb2, ['full', 'daily'], hk).status).toBe(0);
    expect(quarantined(sb2)).toEqual(['qodiqa_20991231T000000Z.dump.partial.plaintext']);
  });

  (process.platform === 'win32' ? test.skip : test)('EN-26 PL13-04 the plaintext dump is created owner-only (0600) whatever the umask', () => {
    // POSIX modes only (NTFS has none) — proven on Linux in the backup image, see DEPLOY-BACKUP.md
    const sb = sandbox();
    // made unencrypted backups opt-in; this POSIX-only case predates that and never ran on Windows.
    const hk = { QODIQA_BACKUP_HMAC_KEY: KEYS.QODIQA_BACKUP_HMAC_KEY, QODIQA_BACKUP_ALLOW_PLAINTEXT: 'true' };
    const r = spawnSync(BASH, ['-c', `umask 022; exec "${SCRIPT}" full daily`], {
      encoding: 'utf8', env: { ...process.env, QODIQA_BACKUP_DIR: sb.backups, PGDATABASE: 'stub', PATH: `${sb.bin}:${process.env.PATH}`, BASH_ENV: sb.inject, ...hk },
    });
    expect(r.status).toBe(0);
    const dump = files(tierOf(sb)).find((f) => f.endsWith('.dump'));
    expect(fs.statSync(path.join(tierOf(sb), dump)).mode & 0o777).toBe(0o600);
    expect(fs.statSync(path.join(sb.backups, 'metrics', 'qodiqa_pg_backup_full_daily.prom')).mode & 0o777).toBe(0o644);
  });

  test('EN-27 PL13-05 the webhook URL (it embeds the token) never reaches curl argv in any of the three scripts — it goes via stdin', () => {
    const sb = sandbox();
    const env = { ALERT_WEBHOOK_URL: HOOK, QODIQA_BACKUP_HMAC_KEY: KEYS.QODIQA_BACKUP_HMAC_KEY };
    expect(run(sb, ['full', 'daily'], { ...env, QODIQA_BACKUP_REQUIRE_ENCRYPTION: 'true' }).status).toBe(1);
    expect(runOther(sb, 'pg-wal-archive.sh', ['--verify'], { ...env, QODIQA_WAL_ARCHIVE_DIR: sb.posix(path.join(sb.dir, 'wal')) }).status).toBe(1);
    expect(runOther(sb, 'backup-audit-log.sh', ['verify'], { ...env, QODIQA_AUDIT_BACKUP_DIR: sb.posix(path.join(sb.dir, 'audit')) }).status).toBe(1);
    const log = alertsLog(sb);
    const argv = log.split('\n').filter((l) => l.startsWith('ARGV: '));
    expect(argv).toHaveLength(3);
    for (const l of argv) expect(l).not.toContain('alerts.invalid');
    expect(log.split('\n').filter((l) => l === `STDIN: url = "${HOOK}"`)).toHaveLength(3);
    expect(argv.join('\n')).toMatch(/QODIQA Backup FAILED/);
    expect(argv.join('\n')).toMatch(/WAL archiving FAILED/);
    expect(argv.join('\n')).toMatch(/audit-log backup FAILED/);
  });

  test('EN-28 PL13-03 an empty backup directory fails every verify loudly and exactly once (no silent exit, no duplicate alert)', () => {
    const sb = sandbox();
    // pg-backup.sh: was TWO BACKUP_FAILED lines (the specific one, then the top-level ERR trap's generic one)
    const p = run(sb, ['verify', 'daily'], KEYS);
    expect(p.status).toBe(1);
    expect(count(p.out, '"event":"BACKUP_FAILED"')).toBe(1);
    // pg-wal-archive.sh --verify: was a SILENT exit (pipefail on an empty `ls`) — no event, no metric, no alert
    const walDir = path.join(sb.dir, 'wal');
    const w = runOther(sb, 'pg-wal-archive.sh', ['--verify'], { QODIQA_WAL_ARCHIVE_DIR: sb.posix(walDir) });
    expect(w.status).toBe(1);
    expect(count(fs.readFileSync(path.join(walDir, 'archive-audit.jsonl'), 'utf8'), 'WAL_ARCHIVE_VERIFY_FAILED')).toBe(1);
    expect(fs.readFileSync(path.join(walDir, 'metrics', 'qodiqa_wal_archive.prom'), 'utf8')).toMatch(/^qodiqa_wal_archive_verify_success 0$/m);
    // backup-audit-log.sh verify: was a silent exit as well; backup with no audit log: was two alerts
    const auditDir = path.join(sb.dir, 'audit');
    const a = runOther(sb, 'backup-audit-log.sh', ['verify'], { QODIQA_AUDIT_BACKUP_DIR: sb.posix(auditDir) });
    expect(a.status).toBe(1);
    expect(count(a.out, '"event":"AUDIT_LOG_BACKUP_FAILED"')).toBe(1);
    const b = runOther(sb, 'backup-audit-log.sh', ['backup'], { QODIQA_AUDIT_BACKUP_DIR: sb.posix(auditDir), QODIQA_AUDIT_LOG: sb.posix(path.join(sb.dir, 'missing.log')) });
    expect(b.status).toBe(1);
    expect(count(b.out, '"event":"AUDIT_LOG_BACKUP_FAILED"')).toBe(1);
    expect(fs.readFileSync(path.join(auditDir, 'metrics', 'qodiqa_audit_log_backup.prom'), 'utf8')).toMatch(/^qodiqa_audit_log_backup_success 0$/m);
  });

  test('EN-29 PL13-06 a WAL segment archived without its seal (crash between copy and seal) is sealed by the retry, atomically', () => {
    const sb = sandbox();
    const walDir = path.join(sb.dir, 'wal');
    const seg = path.join(sb.dir, '000000010000000000000001');
    fs.writeFileSync(seg, Buffer.alloc(64 * 1024, 7));
    const env = { QODIQA_WAL_ARCHIVE_DIR: sb.posix(walDir), QODIQA_BACKUP_HMAC_KEY: KEYS.QODIQA_BACKUP_HMAC_KEY };
    expect(runOther(sb, 'pg-wal-archive.sh', [sb.posix(seg), '000000010000000000000001'], env).status).toBe(0);
    const sealPath = path.join(walDir, '000000010000000000000001.gz.seal');
    const seal = fs.readFileSync(sealPath, 'utf8');
    expect(seal).toMatch(/^[0-9a-f]{64}\n$/);
    fs.renameSync(sealPath, `${sealPath}.lost`); // the state a crash after the copy and before the seal leaves
    // PostgreSQL retries archive_command for the same segment: identical content → exit 0, and now ALSO sealed
    expect(runOther(sb, 'pg-wal-archive.sh', [sb.posix(seg), '000000010000000000000001'], env).status).toBe(0);
    expect(fs.existsSync(sealPath)).toBe(true);
    expect(fs.readFileSync(sealPath, 'utf8')).toBe(seal);
    expect(files(walDir).filter((f) => /\.tmp$/.test(f))).toEqual([]);
    const v = runOther(sb, 'pg-wal-archive.sh', ['--verify'], env);
    expect(v.status).toBe(0);
    // different content under the same name is still refused (archive_command contract)
    fs.writeFileSync(seg, Buffer.alloc(64 * 1024, 8));
    expect(runOther(sb, 'pg-wal-archive.sh', [sb.posix(seg), '000000010000000000000001'], env).status).toBe(1);
  });

  test('EN-30 PL13-07 verify fails closed on a STALE newest backup (per-tier default, override, 0 = off)', () => {
    const sb = sandbox();
    expect(run(sb, ['full', 'daily'], KEYS).status).toBe(0);
    const enc = path.join(tierOf(sb), files(tierOf(sb)).find((f) => f.endsWith('.dump.enc')));
    const old = new Date(Date.now() - 27 * 3600 * 1000);
    fs.utimesSync(enc, old, old);
    const v = run(sb, ['verify', 'daily'], { ...KEYS, ALERT_WEBHOOK_URL: HOOK });
    expect(v.status).toBe(1);
    expect(v.out).toMatch(/Backup is stale — newest backup .* is 9\d{4}s old \(max 93600s\)/);
    expect(v.out).not.toMatch(/BACKUP_VERIFY_OK/);
    expect(count(v.out, '"event":"BACKUP_FAILED"')).toBe(1);
    expect(fs.readFileSync(path.join(sb.backups, 'metrics', 'qodiqa_pg_backup_verify_daily.prom'), 'utf8'))
      .toMatch(/^qodiqa_pg_backup_success\{mode="verify",tier="daily"\} 0$/m);
    expect(run(sb, ['verify', 'daily'], { ...KEYS, QODIQA_BACKUP_MAX_AGE_SECONDS: '0' }).status).toBe(0);
    expect(run(sb, ['verify', 'daily'], { ...KEYS, QODIQA_BACKUP_MAX_AGE_SECONDS: '200000' }).status).toBe(0);
    expect(run(sb, ['verify', 'daily'], { ...KEYS, QODIQA_BACKUP_MAX_AGE_SECONDS: 'soon' }).status).toBe(1);
    // weekly tier: 3 days old is fresh
    const sbw = sandbox();
    expect(run(sbw, ['full', 'weekly'], KEYS).status).toBe(0);
    const wdir = path.join(sbw.backups, 'full', 'weekly');
    const wenc = path.join(wdir, files(wdir).find((f) => f.endsWith('.dump.enc')));
    const d3 = new Date(Date.now() - 3 * 86400 * 1000);
    fs.utimesSync(wenc, d3, d3);
    const vw = run(sbw, ['verify', 'weekly'], KEYS);
    expect(vw.status).toBe(0);
    expect(vw.out).toMatch(/"maxAgeSeconds":691200/);
  });

  test('EN-32 PL13-03 an unexpected failure inside a command substitution alerts exactly once (errtrace subshell guard)', () => {
    const sb = sandbox();
    expect(run(sb, ['full', 'daily'], KEYS).status).toBe(0);
    // pg_restore --list fails inside `verify_output=$(pg_restore --list … | wc -l)`: with set -E the ERR trap is inherited
    // by the command substitution, so without the BASH_SUBSHELL guard it fired twice (once inside, its alert line
    // swallowed into the variable, once for the failed assignment) — two webhook posts for one failure.
    const v = run(sb, ['verify', 'daily'], { ...KEYS, PG_RESTORE_FAIL: '1', ALERT_WEBHOOK_URL: HOOK });
    expect(v.status).not.toBe(0);
    expect(v.out).not.toMatch(/BACKUP_VERIFY_OK/);
    const events = fs.readFileSync(path.join(sb.backups, 'backup-audit.jsonl'), 'utf8');
    expect(count(events, '"event":"BACKUP_FAILED"')).toBe(1);
    expect(count(alertsLog(sb), '^ARGV: ')).toBe(1);
    expect(files(path.join(sb.backups, 'tmp'))).toEqual([]); // the decrypted temp file is still cleaned up
  });

  test('EN-33 PL13-13 an unexpected-error alert is valid JSON in the log AND in the webhook body (the message quotes the failed command)', () => {
    const sb = sandbox();
    // ERR-trap path: the failing command (pg_dump … --file="${DUMP_PARTIAL}" …) contains double quotes
    const r = run(sb, ['full', 'daily'], { ...KEYS, PG_DUMP_FAIL: '1', ALERT_WEBHOOK_URL: HOOK });
    expect(r.status).not.toBe(0);
    const lines = fs.readFileSync(path.join(sb.backups, 'backup-audit.jsonl'), 'utf8').split('\n').filter(Boolean);
    const bad = lines.filter((l) => { try { JSON.parse(l); return false; } catch { return true; } });
    expect(bad).toEqual([]);
    const failed = lines.map((l) => JSON.parse(l)).find((e) => e.event === 'BACKUP_FAILED');
    expect(failed.message).toMatch(/Unexpected error on line \d+: pg_dump .*--file="\$\{DUMP_PARTIAL\}"/);
    const bodies = alertsLog(sb).split('\n').filter((l) => l.startsWith('BODY: ')).map((l) => l.slice(6));
    expect(bodies).toHaveLength(1);
    expect(JSON.parse(bodies[0]).text).toMatch(/QODIQA Backup FAILED on .*: Unexpected error on line \d+: pg_dump /);
    // same contract in all three scripts: alert_failure escapes its message with json_escape, which round-trips through
    // JSON.parse for quotes, backslashes and control characters (a `"` cannot be put in a Windows path to drive the
    // sibling scripts end to end, so their shipped function is extracted and exercised directly, as EN-20 does)
    const tricky = 'cmd --file="${X}" C:\\path\\to "q"\nnext\tline\r';
    for (const rel of ['pg-backup.sh', 'pg-wal-archive.sh', 'backup-audit-log.sh']) {
      const text = fs.readFileSync(path.join(path.dirname(SCRIPT), rel), 'utf8').replace(/\r\n/g, '\n');
      expect({ rel, escapes: /^alert_failure\(\) \{\n  local msg; msg="\$\(json_escape "\$1"\)"$/m.test(text) }).toEqual({ rel, escapes: true });
      const fn = text.match(/^json_escape\(\) \{[\s\S]*?^\}$/m);
      const out = spawnSync(BASH, ['-c', `${fn[0]}\njson_escape "$V"`], { encoding: 'utf8', env: { ...process.env, V: tricky } }).stdout;
      expect({ rel, back: JSON.parse(`"${out}"`) }).toEqual({ rel, back: tricky });
    }
  });

  // measured with postgresql17-client against postgres:16.15 — the dump was restorable by no shipped
  // tool. A client/server major mismatch is now refused before anything is dumped or restored.
  test('EN-35 full refuses a pg_dump whose major differs from the server: no dump, alert, failure metric', () => {
    const sb = sandbox();
    const r = run(sb, ['full', 'daily'], { ...KEYS, PG_STUB_DUMP_MAJOR: '17', ALERT_WEBHOOK_URL: HOOK });
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/"event":"PG_CLIENT_VERSION_MISMATCH","tool":"pg_dump","toolMajor":17,"serverMajor":16/);
    expect(r.out).not.toMatch(/BACKUP_FULL_START/);
    expect(fs.existsSync(path.join(sb.dir, 'pg_dump.ran'))).toBe(false);
    expect(files(path.join(sb.backups, 'full', 'daily')).filter((f) => /\.dump/.test(f))).toEqual([]);
    expect(fs.readFileSync(path.join(sb.dir, 'alerts.log'), 'utf8')).toMatch(/pg_dump major 17 does not match server major 16/);
    // control: matching majors dump as before
    expect(run(sb, ['full', 'daily'], { ...KEYS, PG_STUB_DUMP_MAJOR: '16' }).status).toBe(0);
  });

  // Pilot backup window.
  test('EN-37 backup window: full refuses outside QODIQA_BACKUP_WINDOW_UTC (no dump, alert); runs inside it', () => {
    const hm = (ms) => new Date(Date.now() + ms).toISOString().slice(11, 16);
    const sb = sandbox();
    const out = run(sb, ['full', 'daily'], { ...KEYS, QODIQA_BACKUP_WINDOW_UTC: `${hm(2 * 3600e3)}-${hm(3 * 3600e3)}`, ALERT_WEBHOOK_URL: HOOK });
    expect(out.status).toBe(1);
    expect(out.out).toMatch(/"event":"BACKUP_OUTSIDE_WINDOW"/);
    expect(out.out).not.toMatch(/BACKUP_FULL_START/);
    expect(fs.existsSync(path.join(sb.dir, 'pg_dump.ran'))).toBe(false);
    expect(fs.readFileSync(path.join(sb.dir, 'alerts.log'), 'utf8')).toMatch(/outside the backup window/);
    expect(run(sb, ['full', 'daily'], { ...KEYS, QODIQA_BACKUP_WINDOW_UTC: `${hm(-60e3)}-${hm(5 * 60e3)}` }).status).toBe(0);
  });

  test('EN-38 backup window: a malformed value is refused; the explicit override runs one (logged)', () => {
    const hm = (ms) => new Date(Date.now() + ms).toISOString().slice(11, 16);
    const sb = sandbox();
    const bad = run(sb, ['full', 'daily'], { ...KEYS, QODIQA_BACKUP_WINDOW_UTC: 'nightly' });
    expect(bad.status).toBe(1);
    expect(bad.out).toMatch(/BACKUP_WINDOW_INVALID/);
    const ov = run(sb, ['full', 'daily'], { ...KEYS, QODIQA_BACKUP_WINDOW_UTC: `${hm(2 * 3600e3)}-${hm(3 * 3600e3)}`, QODIQA_BACKUP_WINDOW_OVERRIDE: 'true' });
    expect(ov.status).toBe(0);
    expect(ov.out).toMatch(/"event":"BACKUP_WINDOW_OVERRIDDEN"/);
  });

  test('EN-36 restore refuses a pg_restore newer than the target server, before RESTORE_START', () => {
    const sb = withPsqlStub(sandbox());
    expect(run(sb, ['full'], KEYS).status).toBe(0);
    const r = restoreEnc(sb, { PSQL_STUB_SUPER: 'f', PG_STUB_RESTORE_MAJOR: '17' });
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/"event":"PG_CLIENT_VERSION_MISMATCH","tool":"pg_restore","toolMajor":17,"serverMajor":16/);
    expect(r.out).not.toMatch(/RESTORE_START/);
    // an OLDER server's dump restored by the server's own (equal) major is the supported path
    expect(restoreEnc(sb, { PSQL_STUB_SUPER: 'f', PG_STUB_RESTORE_MAJOR: '16' }).out).toMatch(/RESTORE_COMPLETE/);
  });

  test('EN-34 PL13-10 a restore that fails part-way is reported as an INCOMPLETE target, once, and leaves no plaintext temp', () => {
    const sb = withPsqlStub(sandbox());
    expect(run(sb, ['full'], KEYS).status).toBe(0);
    const r = restoreEnc(sb, { PSQL_STUB_SUPER: 'f', PG_RESTORE_FAIL: '1', ALERT_WEBHOOK_URL: HOOK });
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/RESTORE_START/);
    expect(r.out).toMatch(/"event":"RESTORE_FAILED"/);
    expect(r.out).not.toMatch(/RESTORE_COMPLETE/);
    expect(count(r.out, '"event":"BACKUP_FAILED"')).toBe(1);
    expect(r.out).toMatch(/target is INCOMPLETE .* never switch the application to it/);
    expect(files(path.join(sb.backups, 'tmp'))).toEqual([]);
  });

  test('EN-31 PL13-08 the completion record carries the SHA-256 of the stored (encrypted) artifact', () => {
    const sb = sandbox();
    const r = run(sb, ['full', 'daily'], KEYS);
    expect(r.status).toBe(0);
    const m = r.out.match(/"event":"BACKUP_FULL_COMPLETE".*"sha256":"([0-9a-f]{64})"/);
    expect(m).not.toBeNull();
    const enc = path.join(tierOf(sb), files(tierOf(sb)).find((f) => f.endsWith('.dump.enc')));
    expect(m[1]).toBe(require('crypto').createHash('sha256').update(fs.readFileSync(enc)).digest('hex'));
  });
});
