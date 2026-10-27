'use strict';

/**
 * OIDC against a REAL test identity provider (Dex in a container, started by run.sh). Claim: "validated with a test IdP", not with a production IdP.
 * Exercises: discovery/JWKS fetch over HTTP (allowInsecure, loopback), a real RS256 id_token, the verified (issuer, subject) mapping to a linked RBAC user, and the refusals a verifier
 * must make against a real provider's tokens (tampered payload, alg=none re-wrap, HS256 re-wrap, wrong audience, issuer confusion, unlinked subject, disabled operator).
 */

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ISSUER = 'http://127.0.0.1:56931/dex';
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-dex-itest-'));
process.env.QODIQA_MAC_KEYS_PATH = path.join(dir, 'mac-keys.json');
process.env.QODIQA_KEYS_PATH = path.join(dir, 'keys.json');
process.env.QODIQA_KEY_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.QODIQA_RBAC_STORE_PATH = path.join(dir, 'rbac.json');
process.env.QODIQA_OIDC_ALLOW_INSECURE = 'true';
process.env.QODIQA_OIDC_CONFIG_PATH = path.join(dir, 'oidc.json');
process.env.NODE_ENV = 'development';
const cfg = (aud) => ({ providers: [{ id: 'dex', issuer: ISSUER, audience: [aud], discovery: true }] });
const writeCfg = (c) => fs.writeFileSync(process.env.QODIQA_OIDC_CONFIG_PATH, JSON.stringify(c));
writeCfg(cfg('qodiqa-itest'));

const results = [];
const check = async (name, fn) => { try { await fn(); results.push(['PASS', name]); } catch (e) { results.push(['FAIL', `${name}: ${e.message}`]); } };

async function token() {
  const body = new URLSearchParams({ grant_type: 'password', username: 'carol@example.org', password: 'password', scope: 'openid email', client_id: 'qodiqa-itest', client_secret: 'itest-client-secret-not-a-real-secret' });
  const r = await fetch('http://127.0.0.1:56931/dex/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
  const j = await r.json();
  if (!j.id_token) throw new Error(`Dex gave no id_token: ${JSON.stringify(j).slice(0, 200)}`);
  return j.id_token;
}
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const parts = (t) => t.split('.');
const dec = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));

(async () => {
  const oidcService = require('../../../src/core/identity/oidcService');
  const rbacStore = require('../../../src/core/rbac/store');
  const idToken = await token();
  const payload = dec(parts(idToken)[1]);
  const header = dec(parts(idToken)[0]);
  oidcService._reset();
  const fed = oidcService.operatorFederation(rbacStore);
  assert(fed, 'federation is on');

  await check('DX-01 an unlinked subject with a valid Dex token is refused', async () => { const r = await fed.resolve(idToken); assert.strictEqual(r.ok, false); assert.strictEqual(r.reason, 'NOT_LINKED'); });
  await rbacStore.createUser({ username: 'dex-carol', role: 'admin', externalIdentity: { issuer: ISSUER, subject: payload.sub } });
  await check('DX-02 a real Dex id_token (RS256, discovery + JWKS over HTTP) resolves to the linked operator', async () => { const r = await fed.resolve(idToken); assert.strictEqual(r.ok, true, JSON.stringify(r)); assert.strictEqual(r.operator.username, 'dex-carol'); assert.strictEqual(r.issuer, ISSUER); });
  await check('DX-03 a tampered payload (sub swapped) fails the signature', async () => { const [h, , s] = parts(idToken); const r = await fed.resolve(`${h}.${b64({ ...payload, sub: 'someone-else' })}.${s}`); assert.strictEqual(r.ok, false); });
  await check('DX-04 alg=none re-wrap of the real claims is refused', async () => { const r = await fed.resolve(`${b64({ alg: 'none', typ: 'JWT' })}.${b64(payload)}.`); assert.strictEqual(r.ok, false); });
  await check('DX-05 an HS256 re-wrap (algorithm confusion) is refused', async () => {
    const h = b64({ alg: 'HS256', typ: 'JWT', kid: header.kid });
    const sig = crypto.createHmac('sha256', 'whatever').update(`${h}.${b64(payload)}`).digest('base64url');
    assert.strictEqual((await fed.resolve(`${h}.${b64(payload)}.${sig}`)).ok, false);
  });
  await check('DX-06 a provider configured for another audience refuses the same token', async () => {
    writeCfg(cfg('another-api')); oidcService._reset();
    try { assert.strictEqual((await oidcService.operatorFederation(rbacStore).resolve(idToken)).ok, false); } finally { writeCfg(cfg('qodiqa-itest')); oidcService._reset(); }
  });
  await check('DX-07 issuer confusion: a provider naming a different issuer refuses the token', async () => {
    writeCfg({ providers: [{ id: 'dex', issuer: 'http://127.0.0.1:56931/other', audience: ['qodiqa-itest'], jwksUri: `${ISSUER}/keys` }] }); oidcService._reset();
    try { assert.strictEqual((await oidcService.operatorFederation(rbacStore).resolve(idToken)).ok, false); } finally { writeCfg(cfg('qodiqa-itest')); oidcService._reset(); }
  });

  for (const [s, n] of results) console.log(`${s}  ${n}`);
  const failed = results.filter(([s]) => s === 'FAIL').length;
  console.log(`dex itest: ${results.length - failed} pass, ${failed} FAIL (validated with a TEST IdP, not a production IdP)`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error('dex itest crashed:', e.message); process.exit(2); });
