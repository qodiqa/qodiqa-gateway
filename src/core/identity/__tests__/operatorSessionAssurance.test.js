'use strict';

/** F10V-06 - a session minted after a second-factor login carries that assurance only until the end of the provider's maximum authentication age. */

const fs = require('fs');
const os = require('os');
const path = require('path');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-sess-'));
process.env.QODIQA_MAC_KEYS_PATH = path.join(dir, 'mac-keys.json');
process.env.QODIQA_KEYS_PATH = path.join(dir, 'keys.json');
process.env.QODIQA_KEY_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.QODIQA_RBAC_STORE_PATH = path.join(dir, 'rbac.json');
process.env.QODIQA_LDAP_CONFIG_PATH = path.join(dir, 'ldap.json');
fs.writeFileSync(process.env.QODIQA_LDAP_CONFIG_PATH, JSON.stringify({ providers: [{ id: 'corp', url: 'ldaps://dir.example.test:636', baseDn: 'dc=example,dc=test', bindDn: 'cn=svc,dc=example,dc=test', bindPasswordEnv: 'LDAP_SVC_PASSWORD' }] }));

const operatorSession = require('../operatorSession');
const operatorFederation = require('../operatorFederation');
const rbacStore = require('../../rbac/store');

test('OS-01 assured is true while now < au, false after; a session without au (older tokens) keeps its flag; LDAP-only config still enables sessions', async () => {
  const u = await rbacStore.createUser({ username: 'sess-user', role: 'admin', externalIdentity: { issuer: 'ldap:corp', subject: 'uuid-sess' } });
  const fed = operatorFederation.create(rbacStore);
  expect(fed).not.toBeNull();
  const nowSec = Math.floor(Date.now() / 1000);
  const mintAt = (au) => operatorSession.mint({ userId: u.id, issuer: 'ldap:corp', subject: 'uuid-sess', providerId: 'corp', assured: true, assuredUntilSec: au }).token;
  expect((await fed.resolve(mintAt(nowSec + 300))).assured).toBe(true);
  expect((await fed.resolve(mintAt(nowSec - 1))).assured).toBe(false);
  expect((await fed.resolve(mintAt(null))).assured).toBe(true);
});
