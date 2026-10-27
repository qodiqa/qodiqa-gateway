'use strict';

/**
 * Test kit for SAML: a throw-away IdP key and certificate (generated with openssl at run time - no key material is committed) and a builder of signed SAML Responses.
 * Not a test file (no .test suffix).
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

function makeIdp(cn = 'test-idp') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-saml-'));
  const keyFile = path.join(dir, 'k.pem'); const certFile = path.join(dir, 'c.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile, '-out', certFile, '-days', '2', '-subj', `/CN=${cn}`], { stdio: 'ignore' });
  return { privateKey: fs.readFileSync(keyFile, 'utf8'), cert: fs.readFileSync(certFile, 'utf8') };
}

const iso = (ms) => new Date(ms).toISOString();
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');

/**
 * @param {object} o  { idp, idpEntityId, spEntityId, acsUrl, nameId, inResponseTo, now, assertionId, authnContext, authnAgeMs, attributes, notOnOrAfterMs, notBeforeMs,
 *                      audience, issuer, sigAlg, digestAlg, recipient, destination, signAssertion, signResponse, status, tamper(xml)=>xml, extraAssertion }
 */
function buildResponse(o) {
  const now = o.now ?? Date.now();
  const assertionId = o.assertionId || `_a${crypto.randomBytes(8).toString('hex')}`;
  const respId = `_r${crypto.randomBytes(8).toString('hex')}`;
  const issuer = o.issuer ?? o.idpEntityId;
  const attrs = Object.entries(o.attributes || {}).map(([k, v]) => `<saml:Attribute Name="${esc(k)}">${[].concat(v).map((x) => `<saml:AttributeValue>${esc(x)}</saml:AttributeValue>`).join('')}</saml:Attribute>`).join('');
  const irt = o.inResponseTo === null ? '' : ` InResponseTo="${esc(o.inResponseTo)}"`;
  const assertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" Version="2.0" IssueInstant="${iso(now)}">`
    + `<saml:Issuer>${esc(issuer)}</saml:Issuer>`
    + `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">${esc(o.nameId ?? 'alice@example.com')}</saml:NameID>`
    + `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData${irt} Recipient="${esc(o.recipient ?? o.acsUrl)}" NotOnOrAfter="${iso(o.notOnOrAfterMs ?? now + 300_000)}"/></saml:SubjectConfirmation></saml:Subject>`
    + `<saml:Conditions NotBefore="${iso(o.notBeforeMs ?? now - 5_000)}" NotOnOrAfter="${iso(o.notOnOrAfterMs ?? now + 300_000)}"><saml:AudienceRestriction><saml:Audience>${esc(o.audience ?? o.spEntityId)}</saml:Audience></saml:AudienceRestriction></saml:Conditions>`
    + `<saml:AuthnStatement AuthnInstant="${iso(now - (o.authnAgeMs ?? 5_000))}" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>${esc(o.authnContext ?? 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport')}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`
    + (attrs ? `<saml:AttributeStatement>${attrs}</saml:AttributeStatement>` : '')
    + '</saml:Assertion>';
  const status = o.status || 'urn:oasis:names:tc:SAML:2.0:status:Success';
  let xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${respId}" Version="2.0" IssueInstant="${iso(now)}" Destination="${esc(o.destination ?? o.acsUrl)}"${irt}>`
    + `<saml:Issuer>${esc(issuer)}</saml:Issuer><samlp:Status><samlp:StatusCode Value="${status}"/></samlp:Status>${assertion}${o.extraAssertion || ''}</samlp:Response>`;

  const { SignedXml } = require('xml-crypto');
  const sign = (xmlIn, refXpath, locationRef) => {
    const sig = new SignedXml({ privateKey: o.idp.privateKey, publicCert: o.idp.cert, signatureAlgorithm: o.sigAlg || 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#' });
    sig.addReference({ xpath: refXpath, transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'], digestAlgorithm: o.digestAlg || 'http://www.w3.org/2001/04/xmlenc#sha256' });
    sig.computeSignature(xmlIn, { location: { reference: locationRef, action: 'after' } });
    return sig.getSignedXml();
  };
  if (o.signAssertion !== false) xml = sign(xml, `//*[@ID='${assertionId}']`, `//*[@ID='${assertionId}']/*[local-name(.)='Issuer']`);
  if (o.signResponse) xml = sign(xml, `//*[@ID='${respId}']`, `/*[local-name(.)='Response']/*[local-name(.)='Issuer']`);
  if (typeof o.tamper === 'function') xml = o.tamper(xml);
  return { xml, base64: Buffer.from(xml, 'utf8').toString('base64'), assertionId, responseId: respId };
}

function memoryReplayStore() {
  const seen = new Map();
  return { claim: async (key, ttlMs) => { const now = Date.now(); for (const [k, exp] of seen) if (exp < now) seen.delete(k); if (seen.has(key)) return false; seen.set(key, now + ttlMs); return true; } };
}

module.exports = { makeIdp, buildResponse, memoryReplayStore };
