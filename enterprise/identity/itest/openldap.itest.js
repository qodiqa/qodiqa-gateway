'use strict';

/**
 * LDAP against a REAL test directory (OpenLDAP in a container, started by run.sh), through the real `ldapts` client. Claim: "validated with a test directory", not a production one.
 * Plain ldap:// on loopback with allowInsecure (test only): TLS and StartTLS are NOT exercised here (documented limit).
 */

const assert = require('assert');
const { createLdapProvider } = require('../ldap');

process.env.LDAP_ITEST_SVC = 'itest-admin-password';
const base = { id: 'corp', url: 'ldap://127.0.0.1:56932', allowInsecure: true, baseDn: 'dc=example,dc=org', bindDn: 'cn=admin,dc=example,dc=org', bindPasswordEnv: 'LDAP_ITEST_SVC', userFilter: '(&(objectClass=inetOrgPerson)(uid={username}))', groupAttribute: 'employeeType', timeoutMs: 5000 };
const results = [];
const check = async (name, fn) => { try { await fn(); results.push(['PASS', name]); } catch (e) { results.push(['FAIL', `${name}: ${e.message}`]); } };

(async () => {
  const p = createLdapProvider(base);
  let aliceSubject = null;
  await check('OL-01 right password: ok, a stable entryUUID subject, group attribute carried', async () => {
    const r = await p.authenticate('alice', 'alice-test-password');
    assert.strictEqual(r.ok, true, JSON.stringify(r)); assert.match(r.subject, /^[0-9a-f-]{36}$/); assert.deepStrictEqual(r.groups, ['cn=ops,ou=groups,dc=example,dc=org']); aliceSubject = r.subject;
  });
  await check('OL-02 the subject is stable across logins and differs between users', async () => {
    const again = await p.authenticate('alice', 'alice-test-password'); const bob = await p.authenticate('bob', 'bob-test-password');
    assert.strictEqual(again.subject, aliceSubject); assert.notStrictEqual(bob.subject, aliceSubject);
  });
  await check('OL-03 wrong password is LDAP_INVALID_CREDENTIALS (a real invalid-credentials bind), unknown user is LDAP_NO_SUCH_USER', async () => {
    assert.strictEqual((await p.authenticate('alice', 'nope')).reason, 'LDAP_INVALID_CREDENTIALS'); assert.strictEqual((await p.authenticate('ghost', 'x')).reason, 'LDAP_NO_SUCH_USER');
  });
  await check('OL-04 an empty password is refused locally, before any network call', async () => {
    assert.strictEqual((await p.authenticate('alice', '')).reason, 'LDAP_EMPTY_PASSWORD');
    const { Client } = require('ldapts'); const c = new Client({ url: base.url });
    let accepted = false; try { await c.bind('uid=alice,ou=people,dc=example,dc=org', ''); accepted = true; } catch { /* refused by this server config */ } finally { await c.unbind().catch(() => {}); }
    results.push(['INFO', `server-side check: an empty-password bind with a DN was ${accepted ? 'ACCEPTED (unauthenticated bind) - the local refusal is what protects us' : 'refused by this server'}`]);
  });
  await check('OL-05 injection: wildcard and filter-breaking usernames never authenticate', async () => {
    for (const evil of ['*', 'alice)(|(uid=*', 'a*', '*)(uid=*))(|(uid=*', 'alice\u0000']) assert.strictEqual((await p.authenticate(evil, 'alice-test-password')).ok, false, evil);
  });
  await check('OL-06 requiredGroups admits alice (ops) and refuses bob (guests)', async () => {
    const g = createLdapProvider({ ...base, requiredGroups: ['cn=ops,ou=groups,dc=example,dc=org'] });
    assert.strictEqual((await g.authenticate('alice', 'alice-test-password')).ok, true); assert.strictEqual((await g.authenticate('bob', 'bob-test-password')).reason, 'LDAP_NOT_IN_REQUIRED_GROUP');
  });
  await check('OL-07 a wrong service-account password is "directory unavailable", never a user failure', async () => {
    process.env.LDAP_ITEST_SVC = 'wrong'; try { const r = await createLdapProvider(base).authenticate('alice', 'alice-test-password'); assert.strictEqual(r.ok, false); assert.strictEqual(r.unavailable, true); } finally { process.env.LDAP_ITEST_SVC = 'itest-admin-password'; }
  });
  await check('OL-08 a dead directory is "unavailable"', async () => {
    const r = await createLdapProvider({ ...base, url: 'ldap://127.0.0.1:1', timeoutMs: 1000 }).authenticate('alice', 'alice-test-password'); assert.strictEqual(r.unavailable, true);
  });

  for (const [s, n] of results) console.log(`${s}  ${n}`);
  const failed = results.filter(([s]) => s === 'FAIL').length;
  console.log(`openldap itest: ${results.filter(([s]) => s === 'PASS').length} pass, ${failed} FAIL (validated with a TEST directory, plain ldap:// on loopback)`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error('openldap itest crashed:', e.message); process.exit(2); });
