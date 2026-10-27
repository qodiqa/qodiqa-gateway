'use strict';

const { createLdapProvider, validateConfig, ldapEscape } = require('../ldap');

const base = () => ({ id: 'corp', url: 'ldaps://dir.example.test:636', baseDn: 'dc=example,dc=test', bindDn: 'cn=svc,dc=example,dc=test', bindPasswordEnv: 'LDAP_SVC_PASSWORD' });
const ENV = { LDAP_SVC_PASSWORD: 'svc-secret-for-tests' };

/** A fake directory: users by uid; records every call so injection and ordering can be asserted. */
function fakeDirectory(users) {
  const calls = [];
  const factory = () => {
    let boundAs = null;
    return {
      async bind(dn, pw) {
        calls.push({ op: 'bind', dn, hasPw: pw.length > 0 });
        if (dn === 'cn=svc,dc=example,dc=test') { if (pw !== ENV.LDAP_SVC_PASSWORD) { const e = new Error('x'); e.name = 'InvalidCredentialsError'; throw e; } boundAs = dn; return; }
        const u = Object.values(users).find((x) => x.dn === dn);
        if (!u || u.password !== pw) { const e = new Error('invalid'); e.name = 'InvalidCredentialsError'; throw e; }
        boundAs = dn;
      },
      async search(baseDn, opts) {
        calls.push({ op: 'search', baseDn, filter: opts.filter, sizeLimit: opts.sizeLimit });
        const m = /uid=([^)]*)\)\)$/.exec(opts.filter);
        const uid = m ? m[1] : null;
        const hit = Object.entries(users).filter(([k]) => k === uid).map(([, u]) => ({ dn: u.dn, entryUUID: u.uuid, memberOf: u.groups }));
        return { searchEntries: hit };
      },
      async unbind() { calls.push({ op: 'unbind', boundAs }); },
    };
  };
  return { factory, calls };
}
const USERS = { alice: { dn: 'uid=alice,ou=people,dc=example,dc=test', password: 'correct horse', uuid: '1111-aaaa', groups: ['cn=ops,ou=groups,dc=example,dc=test'] }, bob: { dn: 'uid=bob,ou=people,dc=example,dc=test', password: 'pw-bob', uuid: '2222-bbbb', groups: [] } };

describe('ldap escaping and configuration', () => {
  test('LD-01 filter metacharacters, NUL and non-ASCII are escaped', () => {
    expect(ldapEscape('a*)(uid=*))(|(uid=*')).toBe('a\\2a\\29\\28uid=\\2a\\29\\29\\28|\\28uid=\\2a');
    expect(ldapEscape('x\\y\u0000z')).toBe('x\\5cy\\00z');
    expect(ldapEscape('é')).toBe('\\c3\\a9');
  });
  test('LD-02 a clear-text url, a credentialed url, a template without or with extra placeholders are refused', () => {
    expect(() => validateConfig({ ...base(), url: 'ldap://dir.example.test' })).toThrow(/startTls/);
    expect(() => validateConfig({ ...base(), url: 'ldaps://u:p@dir.example.test' })).toThrow(/credentials/);
    expect(() => validateConfig({ ...base(), userFilter: '(uid=alice)' })).toThrow(/exactly once/);
    expect(() => validateConfig({ ...base(), userFilter: '(&(uid={username})(x={other}))' })).toThrow(/placeholder/);
    expect(() => validateConfig({ ...base(), bindPasswordEnv: 'lower' })).toThrow(/environment variable/);
    expect(() => validateConfig({ ...base(), extra: 1 })).toThrow(/unknown member/);
    expect(() => validateConfig({ ...base(), url: 'ldap://localhost:389', allowInsecure: true })).not.toThrow();
    expect(() => validateConfig({ ...base(), url: 'ldap://dir.example.test', allowInsecure: true })).toThrow(/startTls/);
    expect(() => validateConfig(base())).not.toThrow();
  });
});

describe('ldap authentication', () => {
  const mk = (extra = {}, users = USERS) => { const d = fakeDirectory(users); return { p: createLdapProvider({ ...base(), ...extra }, { env: ENV, clientFactory: d.factory }), d }; };

  test('LD-03 a right password yields (issuer, subject = the stable directory id), groups, never "assured"', async () => {
    const { p } = mk();
    const r = await p.authenticate('alice', 'correct horse');
    expect(r).toEqual({ ok: true, issuer: 'ldap:corp', subject: '1111-aaaa', username: 'alice', groups: ['cn=ops,ou=groups,dc=example,dc=test'], assured: false });
  });
  test('LD-04 a wrong password, an unknown user and the service account being wrong are all plain refusals, and the user bind is on the DN the search returned', async () => {
    const { p, d } = mk();
    expect((await p.authenticate('alice', 'nope')).reason).toBe('LDAP_INVALID_CREDENTIALS');
    expect((await p.authenticate('mallory', 'x')).reason).toBe('LDAP_NO_SUCH_USER');
    expect(d.calls.filter((c) => c.op === 'bind' && c.dn.startsWith('uid=') && !c.dn.includes('qodiqa-no-such-user')).every((c) => c.dn === USERS.alice.dn)).toBe(true);
  });
  test('LD-05 an empty password never reaches the directory (unauthenticated-bind trap)', async () => {
    const { p, d } = mk();
    expect((await p.authenticate('alice', '')).reason).toBe('LDAP_EMPTY_PASSWORD');
    expect(d.calls.length).toBe(0);
  });
  test('LD-06 injection: a wildcard / filter-breaking username cannot widen the search', async () => {
    const { p, d } = mk();
    for (const evil of ['*', 'alice)(|(uid=*', 'alice)(uid=bob', '*)(uid=*))(|(uid=*']) {
      const r = await p.authenticate(evil, 'correct horse');
      expect(r.ok).toBe(false);
    }
    const filters = d.calls.filter((c) => c.op === 'search').map((c) => c.filter);
    for (const f of filters) { expect(f.startsWith('(&(objectClass=person)(uid=')).toBe(true); expect(f.slice('(&(objectClass=person)(uid='.length, -2)).not.toMatch(/[*()]/); }
  });
  test('LD-07 control characters, NUL, over-long username or password are refused before any call', async () => {
    const { p, d } = mk();
    for (const [u, pw] of [['al\u0000ice', 'x'], ['al\nice', 'x'], ['a'.repeat(257), 'x'], ['alice', 'x'.repeat(1025)], ['alice', 'a\u0000b'], ['', 'x'], [null, 'x']]) expect((await p.authenticate(u, pw)).ok).toBe(false);
    expect(d.calls.length).toBe(0);
  });
  test('LD-08 requiredGroups: any one admits; DN comparison ignores case and spaces after commas; no group is a refusal', async () => {
    const { p } = mk({ requiredGroups: ['CN=Ops, OU=groups, DC=example, DC=test'] });
    expect((await p.authenticate('alice', 'correct horse')).ok).toBe(true);
    expect((await p.authenticate('bob', 'pw-bob')).reason).toBe('LDAP_NOT_IN_REQUIRED_GROUP');
  });
  test('LD-09 two matching entries are a refusal (never pick one)', async () => {
    const d = fakeDirectory(USERS);
    const factory = () => { const c = d.factory(); const s = c.search; c.search = async (b, o) => { const r = await s(b, o); return { searchEntries: [...r.searchEntries, ...r.searchEntries] }; }; return c; };
    const p = createLdapProvider(base(), { env: ENV, clientFactory: factory });
    expect((await p.authenticate('alice', 'correct horse')).reason).toBe('LDAP_AMBIGUOUS_USER');
  });
  test('LD-10 directory down is "unavailable", the service password unset is "unavailable"; every connection is unbound', async () => {
    const down = () => ({ async bind() { throw new Error('ECONNREFUSED'); }, async unbind() {} });
    const p = createLdapProvider(base(), { env: ENV, clientFactory: down });
    const r = await p.authenticate('alice', 'x'); expect(r.unavailable).toBe(true);
    const q = createLdapProvider(base(), { env: {}, clientFactory: down });
    expect((await q.authenticate('alice', 'x')).reason).toBe('LDAP_SERVICE_ACCOUNT_UNSET');
    const { p: p2, d } = mk(); await p2.authenticate('alice', 'correct horse');
    expect(d.calls.filter((c) => c.op === 'unbind').length).toBe(2);
  });
  test('LD-11 a binary subject (Active Directory objectGUID) becomes hex', async () => {
    const d = fakeDirectory(USERS);
    const factory = () => { const c = d.factory(); const s = c.search; c.search = async (b, o) => { const r = await s(b, o); return { searchEntries: r.searchEntries.map((e) => ({ ...e, objectGUID: Buffer.from([1, 2, 255]) })) }; }; return c; };
    const p = createLdapProvider({ ...base(), subjectAttribute: 'objectGUID', binarySubject: true }, { env: ENV, clientFactory: factory });
    expect((await p.authenticate('alice', 'correct horse')).subject).toBe('0102ff');
  });
});

describe('LDAP verification findings', () => {
  const mk2 = () => { const d = fakeDirectory(USERS); return { p: createLdapProvider(base(), { env: ENV, clientFactory: d.factory }), d }; };
  test('LD-F1 a username with leading or trailing whitespace is refused before any call (a directory may fold the spaces) (F10V-01)', async () => {
    const { p, d } = mk2();
    for (const u of ['alice ', ' alice', 'alice  ', '\talice']) expect((await p.authenticate(u, 'correct horse')).reason).toBe('LDAP_BAD_USERNAME');
    expect(d.calls.length).toBe(0);
  });
  test('LD-F7 an unknown user costs the same directory round trips as a wrong password (F10V-07)', async () => {
    const { p, d } = mk2();
    await p.authenticate('alice', 'wrong'); const wrong = d.calls.filter((c) => c.op === 'bind' || c.op === 'search').length;
    d.calls.length = 0; await p.authenticate('ghost', 'wrong'); const unknown = d.calls.filter((c) => c.op === 'bind' || c.op === 'search').length;
    expect(unknown).toBe(wrong);
  });
});
