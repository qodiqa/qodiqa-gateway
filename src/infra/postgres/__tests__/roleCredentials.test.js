'use strict';

// placeholder-credential probe for migration-created roles.

const fs = require('fs');
const path = require('path');
const rc = require('../roleCredentials');

function fakeClient(outcome) {
  return class {
    constructor(cfg) { this.cfg = cfg; fakeClient.last = cfg; }
    on() {}
    async connect() { if (outcome instanceof Error) throw outcome; }
    async end() {}
  };
}
const err = (code, message) => Object.assign(new Error(message), { code });
const target = { host: 'h', port: 5432, database: 'd', ssl: false };
const spec = { role: 'qodiqa_read', placeholder: 'REPLACE_WITH_VAULT_SECRET_READ', migration: '002' };

describe('classifyError', () => {
  test.each([
    [err('28P01', 'password authentication failed for user "x"'), 'REJECTED'],
    [err('28000', 'role "x" is not permitted to log in'), 'NOT_PERMITTED'],
    [err('28000', 'no pg_hba.conf entry for host "1.2.3.4", user "x"'), 'HBA_REJECTED'],
    [err('28000', 'role "x" does not exist'), 'REJECTED'],
    [err('ECONNREFUSED', 'connect ECONNREFUSED'), 'INCONCLUSIVE'],
    [new Error('timeout expired'), 'INCONCLUSIVE'],
  ])('%s → %s', (e, want) => expect(rc.classifyError(e)).toBe(want));
});

describe('probeRole', () => {
  test('a successful login with the placeholder is ACCEPTED (violation)', async () => {
    const r = await rc.probeRole(spec, target, { ClientImpl: fakeClient(null) });
    expect(r).toEqual({ role: 'qodiqa_read', migration: '002', result: 'ACCEPTED', code: null });
  });
  test('it logs in as the role with exactly the published placeholder', async () => {
    await rc.probeRole(spec, target, { ClientImpl: fakeClient(null) });
    expect(fakeClient.last.user).toBe('qodiqa_read');
    expect(fakeClient.last.password).toBe('REPLACE_WITH_VAULT_SECRET_READ');
    expect(fakeClient.last.database).toBe('d');
  });
  test('the result never carries the password', async () => {
    const r = await rc.probeRole(spec, target, { ClientImpl: fakeClient(err('28P01', 'x')) });
    expect(JSON.stringify(r)).not.toMatch(/REPLACE_WITH/);
    expect(r.result).toBe('REJECTED');
  });
});

describe('probeMigrationRoles', () => {
  test('all rejected / not-permitted → ok and proven', async () => {
    const p = await rc.probeMigrationRoles({ target, ClientImpl: fakeClient(err('28P01', 'x')) });
    expect(p.ok).toBe(true); expect(p.proven).toBe(true);
    expect(p.results).toHaveLength(rc.MIGRATION_LOGIN_ROLES.length);
  });
  test('any ACCEPTED → not ok', async () => {
    const p = await rc.probeMigrationRoles({ target, ClientImpl: fakeClient(null) });
    expect(p.ok).toBe(false);
    expect(p.violations.map((v) => v.role)).toEqual(rc.MIGRATION_LOGIN_ROLES.map((x) => x.role));
  });
  test('unreachable roles → ok but NOT proven (never silently "safe")', async () => {
    const p = await rc.probeMigrationRoles({ target, ClientImpl: fakeClient(err('ECONNREFUSED', 'x')) });
    expect(p.ok).toBe(true); expect(p.proven).toBe(false);
    expect(p.unproven).toHaveLength(rc.MIGRATION_LOGIN_ROLES.length);
  });
  test('qodiqa_backup (BYPASSRLS) and qodiqa_read are probed', () => {
    const roles = rc.MIGRATION_LOGIN_ROLES.map((x) => x.role);
    expect(roles).toEqual(expect.arrayContaining(['qodiqa_backup', 'qodiqa_read']));
  });
});

describe('migration drift guard — every literal role password in the chain is probed', () => {
  const dir = path.join(__dirname, '..', 'migrations');
  const files = fs.readdirSync(dir).filter((f) => /^\d{3}_.*\.sql$/.test(f)).sort();
  const re = /CREATE\s+ROLE\s+([a-z_][a-z0-9_]*)[^;]*?PASSWORD\s+'([^']+)'/gi;
  const found = [];
  for (const f of files) {
    const sql = fs.readFileSync(path.join(dir, f), 'utf8');
    let m; while ((m = re.exec(sql))) found.push({ file: f, role: m[1], password: m[2] });
  }
  test('the scan finds the eight known placeholder roles', () => {
    expect(found.length).toBeGreaterThanOrEqual(8);
  });
  test('each (role, literal password) pair is in MIGRATION_LOGIN_ROLES', () => {
    for (const x of found) {
      const spec2 = rc.MIGRATION_LOGIN_ROLES.find((r) => r.role === x.role);
      expect({ file: x.file, role: x.role, listed: !!spec2 }).toEqual({ file: x.file, role: x.role, listed: true });
      expect(spec2.placeholder).toBe(x.password);
    }
  });
  test('no migration after 075 may create a role with a literal password (create NOLOGIN, operator sets the secret)', () => {
    const late = found.filter((x) => parseInt(x.file.slice(0, 3), 10) > 75);
    expect(late).toEqual([]);
  });
});

describe('isMigrationPlaceholder', () => {
  test('recognises the published placeholders only', () => {
    expect(rc.isMigrationPlaceholder('REPLACE_WITH_VAULT_SECRET_BACKUP')).toBe(true);
    expect(rc.isMigrationPlaceholder('d7c2…realsecret')).toBe(false);
    expect(rc.isMigrationPlaceholder(undefined)).toBe(false);
  });
});

describe('operator tool SCRAM verifier', () => {
  const { scramVerifier } = require('../../../../scripts/db/role-credentials');
  test('PostgreSQL stored format; the plaintext never appears', () => {
    const v = scramVerifier('a-very-long-and-random-secret-value-123');
    expect(v).toMatch(/^SCRAM-SHA-256\$4096:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]{44}:[A-Za-z0-9+/=]{44}$/);
    expect(v).not.toContain('a-very-long');
  });
  test('deterministic for a fixed salt; a fresh random salt per call otherwise', () => {
    const salt = Buffer.alloc(16, 7);
    expect(scramVerifier('pw-0123456789abcdefghij', { salt })).toBe(scramVerifier('pw-0123456789abcdefghij', { salt }));
    expect(scramVerifier('pw-0123456789abcdefghij')).not.toBe(scramVerifier('pw-0123456789abcdefghij'));
  });
  // That PostgreSQL ACCEPTS the verifier (login with the plaintext succeeds) is proven against a real
  // server in test/integration/ind01RoleCredentialGate.integration.test.js.
});
