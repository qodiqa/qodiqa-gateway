'use strict';

/**
 * SAML single sign-on end to end through the real routes, services and stores: login redirect -> signed response -> operator session -> admin API.
 *   SL-01  the whole flow; the session works on the admin API; role from the RBAC user; assurance reaches the MFA step-up
 *   SL-02  refusals: replay, wrong signer, unlinked subject, disabled user, forged / foreign / expired relay state, unknown provider, bad form, tampered session
 *   SL-03  sessions die with their user: disabled, unlinked, relinked to another subject; expired; malformed
 *   SL-04  metadata, rate limit, configuration errors
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');

jest.mock('../../../../services/logger', () => { const a = jest.requireActual('../../../../services/logger'); return { ...a, emit: jest.fn() }; });

const { makeIdp, buildResponse } = require('../../../../enterprise/identity/testkit/samlTestKit');

const idp = makeIdp('sso-idp');
const rogue = makeIdp('rogue-idp');
const SP = 'https://gw.example.com/saml/sp';
const ACS = 'https://gw.example.com/auth/saml/acs?provider=corp';
const IDP_ID = 'https://idp.example.com/metadata';
const MFA = 'urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract';
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-saml-sso-'));
const cfgPath = path.join(dir, 'saml.json');
const baseCfg = { id: 'corp', spEntityId: SP, acsUrl: ACS, idpEntityId: IDP_ID, ssoUrl: 'https://idp.example.com/sso', idpCerts: [idp.cert], assurance: { authnContexts: [MFA], maxAuthnAgeSec: 300 }, sessionTtlSec: 600 };
fs.writeFileSync(cfgPath, JSON.stringify({ providers: [baseCfg] }));
process.env.QODIQA_SAML_CONFIG_PATH = cfgPath;
delete process.env.QODIQA_OIDC_CONFIG_PATH;
process.env.QODIQA_OPS_MFA_REQUIRED = 'true';

const request = require('supertest');
const express = require('express');
const samlService = require('../samlService');
const operatorSession = require('../operatorSession');
const operatorFederation = require('../operatorFederation');
const replayStore = require('../replayStore');
const rbacStore = require('../../rbac/store');
const mfa = require('../../rbac/mfa');
const { createSamlAuthRouter, createLimiter } = require('../../../api/routes/samlAuth');
const { createOpsAuthMiddleware } = require('../../../middleware/opsAuth');
const { createMfaStepUp } = require('../../../middleware/mfaStepUp');
const attachClientIp = require('../../../../middleware/clientIp');

let admin;
function makeApp(limiter) {
  samlService._reset(); replayStore._reset();
  const a = express(); a.use(attachClientIp); a.use(express.json());
  a.use('/auth/saml', createSamlAuthRouter(limiter ? { limiter } : {}));
  const ops = createOpsAuthMiddleware({}, rbacStore);
  ops.useFederation(operatorFederation.create(rbacStore));
  a.use('/admin', ops);
  a.get('/admin/whoami', (req, res) => res.json({ id: req.rbacUser.id, role: req.rbacUser.role, method: req.operatorAuthMethod, sso: req.operatorSso }));
  a.post('/admin/change', createMfaStepUp({ mfa }), (req, res) => res.json({ changed: true }));
  return a;
}

async function startLogin(a, id = 'corp') {
  const r = await request(a).get(`/auth/saml/login?provider=${id}`);
  if (r.status !== 302) return { status: r.status };
  const u = new URL(r.headers.location);
  const reqXml = zlib.inflateRawSync(Buffer.from(u.searchParams.get('SAMLRequest'), 'base64')).toString('utf8');
  return { status: 302, relay: u.searchParams.get('RelayState'), requestId: /ID="([^"]+)"/.exec(reqXml)[1] };
}
const post = (a, id, SAMLResponse, RelayState) => request(a).post(`/auth/saml/acs?provider=${id}`).type('form').send({ SAMLResponse, ...(RelayState ? { RelayState } : {}) });
const resp = (over = {}) => buildResponse({ idp, idpEntityId: IDP_ID, spEntityId: SP, acsUrl: ACS, nameId: 'carol@corp.example.com', ...over });

beforeAll(async () => {
  admin = await rbacStore.createUser({ username: 'saml-admin', role: 'admin', externalIdentity: { issuer: IDP_ID, subject: 'carol@corp.example.com' } });
  await rbacStore.createUser({ username: 'saml-viewer', role: 'viewer', externalIdentity: { issuer: IDP_ID, subject: 'vic@corp.example.com' } });
});

describe('SAML flow', () => {
  test('SL-01 login -> signed response -> session token -> admin API; a second-factor login satisfies the step-up, a password login does not', async () => {
    const a = makeApp();
    const l = await startLogin(a);
    expect(l.status).toBe(302);
    const ok = await post(a, 'corp', resp({ inResponseTo: l.requestId, authnContext: MFA }).base64, l.relay);
    expect(ok.status).toBe(200); expect(ok.headers['cache-control']).toBe('no-store');
    expect(ok.body.data).toMatchObject({ tokenType: 'Bearer', assured: true, user: { id: admin.id, username: 'saml-admin', role: 'admin' } });
    const who = await request(a).get('/admin/whoami').set('Authorization', `Bearer ${ok.body.data.token}`);
    expect(who.body).toMatchObject({ id: admin.id, role: 'admin', method: 'sso-session', sso: { providerId: 'corp', assured: true } });
    expect((await request(a).post('/admin/change').set('Authorization', `Bearer ${ok.body.data.token}`).send({})).status).toBe(200);      // the IdP vouched for the second factor
    // a password-only login: authenticated, but the TOTP step-up still applies (nothing enrolled -> refused)
    const l2 = await startLogin(a);
    const pw = await post(a, 'corp', resp({ inResponseTo: l2.requestId }).base64, l2.relay);
    expect(pw.body.data.assured).toBe(false);
    const step = await request(a).post('/admin/change').set('Authorization', `Bearer ${pw.body.data.token}`).send({});
    expect(step.status).toBe(403);
  });

  test('SL-02 refusals all answer the same generic 401 and issue nothing', async () => {
    const a = makeApp();
    const refuse = async (r, status = 401) => { expect(r.status).toBe(status); expect((r.body.data || {}).token).toBeUndefined(); if (status === 401) expect(r.body.error.code).toBe('AUTHENTICATION_FAILED'); };
    const l = await startLogin(a);
    const good = resp({ inResponseTo: l.requestId });
    expect((await post(a, 'corp', good.base64, l.relay)).status).toBe(200);
    await refuse(await post(a, 'corp', good.base64, l.relay));                                                            // replay of the same assertion
    const l2 = await startLogin(a);
    await refuse(await post(a, 'corp', resp({ idp: rogue, inResponseTo: l2.requestId }).base64, l2.relay));              // signed by another key
    await refuse(await post(a, 'corp', resp({ nameId: 'nobody@corp.example.com', inResponseTo: l2.requestId }).base64, l2.relay));            // valid, but no operator is linked to this subject
    await refuse(await post(a, 'corp', resp({ inResponseTo: l2.requestId }).base64, 'forged.relay'));                  // relay state not from us
    await refuse(await post(a, 'corp', resp({ inResponseTo: l2.requestId }).base64));                                     // no relay state: IdP-initiated is off
    await refuse(await post(a, 'corp', resp({ inResponseTo: '_not_this_request' }).base64, l2.relay));                  // answers a different request
    const mismatched = samlService.mintState('other-provider', l2.requestId);
    await refuse(await post(a, 'corp', resp({ inResponseTo: l2.requestId }).base64, mismatched));                        // relay state of another provider
    const expired = samlService.mintState('corp', l2.requestId, Date.now() - 3_600_000);
    await refuse(await post(a, 'corp', resp({ inResponseTo: l2.requestId }).base64, expired));
    await rbacStore.updateUser((await rbacStore.getUserByUsername('saml-viewer')).id, { enabled: false });
    const l3 = await startLogin(a);
    await refuse(await post(a, 'corp', resp({ nameId: 'vic@corp.example.com', inResponseTo: l3.requestId }).base64, l3.relay));              // linked but disabled
    await rbacStore.updateUser((await rbacStore.getUserByUsername('saml-viewer')).id, { enabled: true });
    await refuse(await post(a, 'unknown', good.base64, l.relay), 404);
    expect((await request(a).get('/auth/saml/login?provider=unknown')).status).toBe(404); expect((await request(a).get('/auth/saml/login?provider=BAD_ID')).status).toBe(404);
    await refuse(await request(a).post('/auth/saml/acs?provider=corp').type('form').send({}), 400);
    await refuse(await request(a).post('/auth/saml/acs?provider=corp').send({ SAMLResponse: 'x' }));                                 // a JSON body is parsed but is no valid response: the same generic refusal
  });

  test('SL-03 a session lives only as long as its user stays enabled and linked to the same subject', async () => {
    const a = makeApp();
    const l = await startLogin(a);
    const tok = (await post(a, 'corp', resp({ nameId: 'vic@corp.example.com', inResponseTo: l.requestId }).base64, l.relay)).body.data.token;
    const who = () => request(a).get('/admin/whoami').set('Authorization', `Bearer ${tok}`);
    const viewer = await rbacStore.getUserByUsername('saml-viewer');
    expect((await who()).status).toBe(200);
    await rbacStore.updateUser(viewer.id, { enabled: false }); expect((await who()).status).toBe(401);
    await rbacStore.updateUser(viewer.id, { enabled: true }); expect((await who()).status).toBe(200);
    await rbacStore.updateUser(viewer.id, { externalIdentity: { issuer: IDP_ID, subject: 'someone-else' } }); expect((await who()).status).toBe(401);       // relinked: the old session dies
    await rbacStore.updateUser(viewer.id, { externalIdentity: null }); expect((await who()).status).toBe(401);
    await rbacStore.updateUser(viewer.id, { externalIdentity: { issuer: IDP_ID, subject: 'vic@corp.example.com' } });
    // token handling
    const bad = [tok.slice(0, -2) + 'AA', tok.replace('qos1.', 'qos1.x'), 'qos1.a.b.c', `${tok}.extra`];
    for (const t of bad) expect((await request(a).get('/admin/whoami').set('Authorization', `Bearer ${t}`)).status).toBe(401);
    const m = operatorSession.mint({ userId: viewer.id, issuer: IDP_ID, subject: 'vic@corp.example.com', providerId: 'corp', ttlSec: 120, now: Date.now() - 3_600_000 });
    expect(operatorSession.verify(m.token).reason).toBe('SESSION_EXPIRED');
    expect(operatorSession.verify(operatorSession.mint({ userId: viewer.id, issuer: IDP_ID, subject: 'x', providerId: 'corp', ttlSec: 999999 }).token).ok).toBe(true);
    const long = operatorSession.mint({ userId: 'u', issuer: 'i', subject: 's', providerId: 'p', ttlSec: 10_000_000 }); expect(long.expiresAt - Math.floor(Date.now() / 1000)).toBeLessThanOrEqual(operatorSession.MAX_TTL_SEC);
  });

  test('SL-04 metadata, rate limit, configuration', async () => {
    const a = makeApp();
    const md = await request(a).get('/auth/saml/metadata?provider=corp');
    expect(md.status).toBe(200); expect(md.headers['content-type']).toMatch(/samlmetadata\+xml/); expect(md.text).toContain(SP); expect(md.text).toContain(ACS);
    expect((await request(a).get('/auth/saml/metadata?provider=nope')).status).toBe(404);
    const limited = makeApp(createLimiter({ max: 3 }));
    const codes = []; for (let i = 0; i < 5; i++) codes.push((await request(limited).get('/auth/saml/metadata?provider=nope')).status);
    expect(codes).toEqual([404, 404, 404, 429, 429]);
    // configuration errors fail at boot
    const write = (cfg) => { const p = path.join(dir, `c${Math.random().toString(36).slice(2, 6)}.json`); fs.writeFileSync(p, JSON.stringify(cfg)); return p; };
    const keep = process.env.QODIQA_SAML_CONFIG_PATH;
    try {
      for (const [cfg, re] of [[{ providers: [] }, /providers/], [{ providers: [{ ...baseCfg, acsUrl: 'http://x/y' }] }, /https/], [{ providers: [baseCfg, { ...baseCfg, id: 'two' }] }, /share the IdP/], [{ providers: [{ ...baseCfg, sessionTtlSec: 5 }] }, /sessionTtlSec/], [{ providers: [{ ...baseCfg, idpCerts: ['nope'] }] }, /certificate/]]) {
        process.env.QODIQA_SAML_CONFIG_PATH = write(cfg); samlService._reset(); expect(() => samlService.assertConfigured()).toThrow(re);
      }
      process.env.QODIQA_SAML_CONFIG_PATH = path.join(dir, 'missing.json'); samlService._reset(); expect(() => samlService.assertConfigured()).toThrow(/cannot be read/);
      delete process.env.QODIQA_SAML_CONFIG_PATH; samlService._reset(); expect(samlService.isEnabled()).toBe(false); expect(operatorFederation.create(rbacStore)).toBeNull();
    } finally { process.env.QODIQA_SAML_CONFIG_PATH = keep; samlService._reset(); }
  });
});
