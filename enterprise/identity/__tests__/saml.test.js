'use strict';

/**
 * SAML 2.0 service provider, against locally generated keys and signed responses (no production IdP).
 *   SM-01  a valid signed response is accepted; subject, attributes, assurance
 *   SM-02  refusals: wrong key, tampered content, signature wrapping, audience, time window, issuer, InResponseTo, SHA-1, DOCTYPE, unsigned, oversize, error status, replay, store down
 *   SM-03  login URL, metadata, configuration validation
 */

const zlib = require('zlib');
const { createSamlProvider, validateConfig } = require('../saml');
const { makeIdp, buildResponse, memoryReplayStore } = require('../testkit/samlTestKit');

const idp = makeIdp('idp-one');
const other = makeIdp('idp-two');
const SP = 'https://gw.example.com/saml/sp';
const ACS = 'https://gw.example.com/auth/saml/corp/acs';
const IDP_ID = 'https://idp.example.com/metadata';
const MFA = 'urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract';
const base = { id: 'corp', spEntityId: SP, acsUrl: ACS, idpEntityId: IDP_ID, ssoUrl: 'https://idp.example.com/sso', idpCerts: [idp.cert] };
const mk = (over = {}, store = memoryReplayStore()) => createSamlProvider({ ...base, ...over }, { replayStore: store });
const resp = (over = {}) => buildResponse({ idp, idpEntityId: IDP_ID, spEntityId: SP, acsUrl: ACS, inResponseTo: '_req1', ...over });
const consume = (sp, r, expectedRequestId = '_req1') => sp.consume({ samlResponse: r.base64, expectedRequestId });

describe('SAML responses', () => {
  test('SM-01 a valid signed response is accepted; the projection is bounded; assurance needs a listed context and a recent instant', async () => {
    const sp = mk({ assurance: { authnContexts: [MFA], maxAuthnAgeSec: 300 } });
    const r = resp({ nameId: 'alice@example.com', authnContext: MFA, attributes: { email: 'alice@example.com', groups: ['a', 'b'], big: 'x'.repeat(600) } });
    const out = await consume(sp, r);
    expect(out).toMatchObject({ ok: true, providerId: 'corp', issuer: IDP_ID, subject: 'alice@example.com', assured: true, assertionId: r.assertionId, sessionIndex: '_s1', authnContext: MFA });
    expect(out.attributes.email).toEqual(['alice@example.com']); expect(out.attributes.groups).toEqual(['a', 'b']); expect(out.attributes.big).toBeUndefined();
    expect((await consume(mk({ assurance: { authnContexts: [MFA] } }), resp({ authnContext: 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password' }))).assured).toBe(false);
    expect((await consume(mk({ assurance: { authnContexts: [MFA], maxAuthnAgeSec: 300 } }), resp({ authnContext: MFA, authnAgeMs: 3_600_000 }))).assured).toBe(false);          // authenticated too long ago
    expect((await consume(mk(), resp({ authnContext: MFA }))).assured).toBe(false);                                                                                              // no assurance configured: never assured
    expect((await consume(mk({ wantResponseSigned: true }), resp({ signResponse: true }))).ok).toBe(true);
    expect((await consume(mk({ wantResponseSigned: true }), resp({ signResponse: false }))).ok).toBe(false);
    // a second pinned certificate (rotation)
    expect((await consume(mk({ idpCerts: [other.cert, idp.cert] }), resp())).ok).toBe(true);
  });

  test('SM-02 refusals', async () => {
    const no = async (r, reason, sp = mk(), expected = '_req1') => { const out = await consume(sp, r, expected); expect({ ok: out.ok, reason: out.reason }).toEqual({ ok: false, reason }); };
    await no(resp({ idp: other }), 'SAML_SIGNATURE_INVALID');                                                       // signed by a key we do not trust
    await no(resp({ tamper: (x) => x.replace('alice@example.com', 'root@example.com') }), 'SAML_SIGNATURE_INVALID');   // content changed after signing
    await no(resp({ signAssertion: false }), 'SAML_UNSIGNED');
    await no(resp({ audience: 'https://other.example.com/sp' }), 'SAML_AUDIENCE');
    await no(resp({ notOnOrAfterMs: Date.now() - 600_000, notBeforeMs: Date.now() - 900_000, now: Date.now() - 700_000 }), 'SAML_TIME');
    await no(resp({ notBeforeMs: Date.now() + 600_000, now: Date.now() + 600_000 }), 'SAML_TIME');
    await no(resp({ issuer: 'https://evil.example.com/idp' }), 'SAML_ISSUER');
    await no(resp({ inResponseTo: '_someone_elses_request' }), 'SAML_IN_RESPONSE_TO');
    await no(resp({ inResponseTo: null }), 'SAML_IN_RESPONSE_TO');
    await no(resp({ sigAlg: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1', digestAlg: 'http://www.w3.org/2000/09/xmldsig#sha1' }), 'SAML_ALGORITHM');
    await no(resp({ status: 'urn:oasis:names:tc:SAML:2.0:status:Responder' }), 'SAML_STATUS');
    const doctype = resp({ tamper: (x) => `<!DOCTYPE r [<!ENTITY a "aaaa">]>${x}` });
    await no(doctype, 'SAML_DOCTYPE');
    await no({ base64: Buffer.from('x'.repeat(300_000)).toString('base64') }, 'SAML_TOO_LARGE');
    expect((await mk().consume({ samlResponse: '', expectedRequestId: '_req1' })).reason).toBe('SAML_MALFORMED');
    expect((await mk().consume({ samlResponse: 5, expectedRequestId: '_req1' })).reason).toBe('SAML_MALFORMED');
    // signature wrapping: a second, UNSIGNED assertion for another user is added next to the signed one
    const evil = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_evil" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>' + IDP_ID + '</saml:Issuer><saml:Subject><saml:NameID>root@example.com</saml:NameID></saml:Subject></saml:Assertion>';
    const wrapped = await consume(mk(), resp({ extraAssertion: evil }));
    expect(wrapped.ok === false || wrapped.subject === 'alice@example.com').toBe(true);                              // never the attacker's subject
    // replay: the same assertion once only
    const sp = mk(); const r = resp();
    expect((await consume(sp, r)).ok).toBe(true);
    await no(r, 'SAML_REPLAY', sp);
    await no(resp(), 'SAML_REPLAY_STORE_UNAVAILABLE', createSamlProvider(base, { replayStore: { claim: async () => { throw new Error('redis down'); } } }));
    await no(resp(), 'SAML_REPLAY_STORE_UNAVAILABLE', createSamlProvider(base, {}));
    // unsolicited (IdP-initiated) responses
    await no(resp({ inResponseTo: null }), 'SAML_IN_RESPONSE_TO', mk(), null);
    expect((await mk({ allowIdpInitiated: true }).consume({ samlResponse: resp({ inResponseTo: null }).base64, expectedRequestId: null })).ok).toBe(true);
  });

  test('SM-03 login URL, metadata, configuration', async () => {
    const sp = mk();
    const { url, requestId } = await sp.loginUrl('relay-xyz');
    const u = new URL(url);
    expect(u.origin + u.pathname).toBe('https://idp.example.com/sso'); expect(u.searchParams.get('RelayState')).toBe('relay-xyz');
    const req = zlib.inflateRawSync(Buffer.from(u.searchParams.get('SAMLRequest'), 'base64')).toString('utf8');
    expect(req).toContain(`ID="${requestId}"`); expect(req).toContain(`AssertionConsumerServiceURL="${ACS}"`); expect(req).toContain(SP);
    expect(requestId).toMatch(/^_/);
    const md = sp.metadata(); expect(md).toContain(`entityID="${SP}"`); expect(md).toContain(ACS); expect(md).toContain('WantAssertionsSigned="true"');
    const bad = (over) => expect(() => validateConfig({ ...base, ...over })).toThrow();
    bad({ id: 'Bad' }); bad({ spEntityId: '' }); bad({ acsUrl: 'http://x/y' }); bad({ ssoUrl: 'ftp://x' }); bad({ idpCerts: [] }); bad({ idpCerts: ['nope'] }); bad({ idpCerts: ['-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----'] });
    bad({ clockSkewMs: 500_000 }); bad({ maxAssertionAgeMs: 10 }); bad({ assurance: { authnContexts: [] } }); bad({ assurance: { authnContexts: [MFA], maxAuthnAgeSec: 5 } });
    expect(() => validateConfig({ ...base, clockSkewMs: 30_000, maxAssertionAgeMs: 120_000, assurance: { authnContexts: [MFA] } })).not.toThrow();
  });
});

describe('SAML verification findings', () => {
  const no = async (r, reason, sp = mk(), expected = '_req1') => { const out = await consume(sp, r, expected); expect({ ok: out.ok, reason: out.reason }).toEqual({ ok: false, reason }); };
  const blind = (x) => x.replace(/(<(?:\w+:)?(?:SignatureMethod|DigestMethod)\s)/g, '$1xmlns:zz="a>b" ');   // an unused namespace whose value contains ">" before the Algorithm attribute

  test('SM-04 a SHA-1 algorithm cannot be hidden behind a ">" inside an attribute value (F10V-02)', async () => {
    await no(resp({ sigAlg: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1', tamper: blind }), 'SAML_ALGORITHM');
    await no(resp({ digestAlg: 'http://www.w3.org/2000/09/xmldsig#sha1', tamper: blind }), 'SAML_ALGORITHM');
    // the same blinding on a good algorithm still verifies: only the algorithm decides
    expect((await consume(mk(), resp({ tamper: blind }))).ok).toBe(true);
  });

  test('SM-05 a response or confirmation meant for another service is refused (F10V-03)', async () => {
    await no(resp({ destination: 'https://other-sp.example.net/acs' }), 'SAML_DESTINATION');
    await no(resp({ recipient: 'https://other-sp.example.net/acs' }), 'SAML_RECIPIENT');
  });

  test('SM-06 an IdP-initiated response must not claim to answer a request (F10V-04)', async () => {
    const sp = mk({ allowIdpInitiated: true });
    await no(resp({ inResponseTo: '_foreignRequestIdNeverIssuedHere' }), 'SAML_IN_RESPONSE_TO', sp, null);
    const ok = await sp.consume({ samlResponse: resp({ inResponseTo: null }).base64, expectedRequestId: null });
    expect(ok.ok).toBe(true);
  });

  test('SM-07 an IdP entity id in the ldap: namespace is refused (F10V-08)', () => {
    expect(() => validateConfig({ ...base, idpEntityId: 'ldap:corp' })).toThrow(/ldap:/);
  });
});

describe('SAML preflight reads names the way XML allows', () => {
  const { preflight } = require('../saml');
  const doc = (inner, resp = '') => `<samlp:Response xmlns:samlp="p" ID="_r"${resp}><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${inner}</samlp:Response>`;
  const SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  const SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
  test('SM-08 a non-ASCII namespace prefix cannot hide an algorithm, a status or an InResponseTo', () => {
    expect(preflight(doc(`<!-- <ds:SignatureMethod Algorithm="${SHA256}"/> --><dé:SignatureMethod Algorithm="${SHA1}"/>`))).toBe('SAML_ALGORITHM');
    expect(preflight(doc(`<dé:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:SignatureMethod Algorithm="${SHA256}"/>`))).toBe('SAML_ALGORITHM');
    expect(preflight(doc(`<ds:SignatureMethod Algorithm="${SHA256}"/><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`).replace('status:Success', 'status:Responder').replace('<samlp:StatusCode', '<sé:StatusCode').replace('xmlns:samlp="p"', 'xmlns:samlp="p" xmlns:sé="p"'))).toBe('SAML_STATUS');
    const ok = `<ds:SignatureMethod Algorithm="${SHA256}"/><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`;
    expect(preflight(doc(`${ok}<sé:SubjectConfirmationData InResponseTo="_x"/>`), { solicited: false })).toBe('SAML_IN_RESPONSE_TO');
    expect(preflight(doc(ok), { solicited: false })).toBeNull();
  });
  test('SM-09 an ACS URL with an ampersand is compared after XML unescaping', () => {
    const ok = `<ds:SignatureMethod Algorithm="${SHA256}"/>`;
    const acs = 'https://gw.example.com/auth/saml/acs?provider=corp&tenant=a';
    expect(preflight(doc(ok, ` Destination="${acs.replace(/&/g, '&amp;')}"`), { acsUrl: acs })).toBeNull();
    expect(preflight(doc(ok, ' Destination="https://other.example/acs"'), { acsUrl: acs })).toBe('SAML_DESTINATION');
  });
});
