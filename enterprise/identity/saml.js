'use strict';

/**
 * SAML 2.0 service provider: web-browser SSO, HTTP-Redirect AuthnRequest, HTTP-POST Response. Signature validation and assertion parsing are done by the vetted library
 * @node-saml/node-saml (an optional dependency, like openid-client); this module configures it strictly and adds what the library leaves to the application.
 *
 *   const sp = createSamlProvider(config, { replayStore, now })
 *   sp.loginUrl(relayState)            -> Promise<{ url, requestId }>
 *   sp.consume({ samlResponse, expectedRequestId }) -> Promise<{ ok: true, issuer, subject, nameIdFormat, attributes, sessionIndex, authnInstant, authnContext, assured, assertionId, notOnOrAfter }
 *                                                              | { ok: false, reason }>
 *   sp.metadata()                      -> SP metadata XML
 *
 * config: { id, spEntityId, acsUrl, idpEntityId, ssoUrl, idpCerts: [PEM...], wantResponseSigned?, clockSkewMs? (<= 120000, default 60000), maxAssertionAgeMs? (<= 600000, default 300000),
 *           forceAuthn?, allowIdpInitiated?, assurance?: { authnContexts: [...], maxAuthnAgeSec? } }
 *
 * What is enforced (each failure is a distinct `reason`, SAML_*):
 *   - the ASSERTION is signed by one of the pinned IdP certificates (wantAssertionsSigned is always true; wantResponseSigned optional); the Issuer is the configured IdP entity id; the
 *     audience is this SP; Destination/Recipient is the ACS URL; NotBefore / NotOnOrAfter and the assertion age are within the (small) skew and age bounds; the SubjectConfirmation is
 *     bearer. All by the library.
 *   - SAML_ALGORITHM: every SignatureMethod / DigestMethod in the document is SHA-256, SHA-384 or SHA-512 based (SHA-1 and unknown algorithms are refused, even though the library
 *     would accept them); SAML_DOCTYPE: a DOCTYPE or ENTITY declaration is refused before parsing (XXE / entity expansion); SAML_TOO_LARGE: more than 256 KiB decoded.
 *   - SAML_IN_RESPONSE_TO: the response answers the AuthnRequest this login started (the request id travels in the signed relay state, so any replica can check it); an unsolicited
 *     (IdP-initiated) response is refused unless allowIdpInitiated is true, and then it still must not carry a foreign InResponseTo.
 *   - SAML_REPLAY: an assertion id is accepted ONCE (replayStore.claim(key, ttlMs) -> true the first time) until its NotOnOrAfter; a store failure refuses (fail closed).
 *   - assured: true only when the AuthnContextClassRef is one of assurance.authnContexts AND the AuthnInstant is not older than maxAuthnAgeSec (default 900).
 * The attribute projection is bounded (at most 50 attributes, 20 values each, 512 characters per value).
 */

const crypto = require('crypto');

const MAX_BYTES = 256 * 1024;
const OK_ALG = /(rsa-sha(256|384|512)|ecdsa-sha(256|384|512)|rsa-sha(256|384|512)-mgf1|xmlenc#sha(256|512)|xmldsig-more#sha384|xmldsig-more#sha384-rsa-mgf1)$/;
// A start tag, matched with the XML attribute grammar (quoted values may contain ">"): a regular expression that stops at the first ">" can be blinded by `xmlns:x="a>b"` before the attribute it looks for (F10V-02).
// XML allows any Unicode letter in a namespace prefix and in an attribute name: a pattern that only knows ASCII could be blinded by a prefix such as `dsé:`. The prefix and the
// attribute names are therefore "anything that is not markup", and values are unescaped before they are compared (N-02: an ACS URL with "&").
const NAME = '[^\\s<>/=:"\'&;]+';
const unescapeXml = (v) => v.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|amp|lt|gt|quot|apos);/g, (m, e) => {
  if (e === 'amp') return '&'; if (e === 'lt') return '<'; if (e === 'gt') return '>'; if (e === 'quot') return '"'; if (e === 'apos') return "'";
  const cp = e[1] === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
  return Number.isInteger(cp) && cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
});
const attrsOf = (raw) => { const out = {}; const re = new RegExp('(' + NAME + '(?::' + NAME + ')?)\\s*=\\s*(?:"([^"]*)"|\'([^\']*)\')', 'g'); let m; while ((m = re.exec(raw)) !== null) out[m[1]] = unescapeXml(m[2] !== undefined ? m[2] : m[3]); return out; };
// A start tag, matched with the XML attribute grammar (quoted values may contain ">"): a regular expression that stops at the first ">" can be blinded by `xmlns:x="a>b"` before the attribute it looks for (F10V-02).
function startTags(xml, localName) {
  const re = new RegExp('<(?:' + NAME + ':)?' + localName + '((?:\\s+' + NAME + '(?::' + NAME + ')?\\s*=\\s*(?:"[^"]*"|\'[^\']*\'))*)\\s*/?>', 'g');
  const out = []; let m;
  while ((m = re.exec(xml)) !== null) out.push(attrsOf(m[1]));
  return out;
}
const countWord = (xml, w) => (xml.match(new RegExp('<(?:' + NAME + ':)?' + w + '(?![^\\s<>/=:"\'&;])', 'g')) || []).length;

function lazyLib() {
  try { return require('@node-saml/node-saml'); } catch { throw new Error('saml: @node-saml/node-saml is not installed (npm install @node-saml/node-saml)'); }
}

function validateConfig(c) {
  const bad = (m) => { throw new Error(`saml ${c && c.id}: ${m}`); };
  if (!c || typeof c !== 'object') throw new Error('saml: a provider is an object');
  if (typeof c.id !== 'string' || !/^[a-z][a-z0-9-]{0,30}$/.test(c.id)) bad('id must match [a-z][a-z0-9-]{0,30}');
  for (const k of ['spEntityId', 'idpEntityId']) if (typeof c[k] !== 'string' || !c[k] || c[k].length > 512 || /\s/.test(c[k])) bad(`${k} is required`);
  if (/^ldap:/i.test(c.idpEntityId)) bad('idpEntityId must not use the ldap: namespace (it is the issuer of LDAP sign-ins)');   // F10V-08
  for (const k of ['acsUrl', 'ssoUrl']) if (typeof c[k] !== 'string' || !/^https:\/\/[^\s]+$/.test(c[k])) bad(`${k} must be an https URL`);
  if (!Array.isArray(c.idpCerts) || c.idpCerts.length === 0 || c.idpCerts.length > 5 || c.idpCerts.some((p) => typeof p !== 'string' || !/-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/.test(p))) bad('idpCerts is a list of 1..5 PEM certificates');
  const certs = c.idpCerts.map((p) => { try { return new crypto.X509Certificate(p); } catch { return null; } });
  if (certs.some((x) => x === null)) bad('an idpCert is not a valid certificate');
  if (c.clockSkewMs !== undefined && !(Number.isInteger(c.clockSkewMs) && c.clockSkewMs >= 0 && c.clockSkewMs <= 120_000)) bad('clockSkewMs is an integer between 0 and 120000');
  if (c.maxAssertionAgeMs !== undefined && !(Number.isInteger(c.maxAssertionAgeMs) && c.maxAssertionAgeMs >= 30_000 && c.maxAssertionAgeMs <= 600_000)) bad('maxAssertionAgeMs is an integer between 30000 and 600000');
  if (c.assurance !== undefined) {
    const a = c.assurance;
    if (!a || typeof a !== 'object' || !Array.isArray(a.authnContexts) || a.authnContexts.length === 0 || a.authnContexts.length > 32 || a.authnContexts.some((x) => typeof x !== 'string' || !x || x.length > 512)) bad('assurance.authnContexts is a non-empty list of AuthnContextClassRef values');
    if (a.maxAuthnAgeSec !== undefined && !(Number.isInteger(a.maxAuthnAgeSec) && a.maxAuthnAgeSec >= 60 && a.maxAuthnAgeSec <= 86400)) bad('assurance.maxAuthnAgeSec is an integer between 60 and 86400');
  }
}

/**
 * Refuse what must never reach the XML parser or the signature check. Returns a reason or null.
 * `ctx.acsUrl`: when the response names a Destination it must be this service's ACS URL; `ctx.solicited`: false for an IdP-initiated response, which then must not claim to answer a request.
 */
function preflight(xml, ctx = {}) {
  if (xml.length > MAX_BYTES) return 'SAML_TOO_LARGE';
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) return 'SAML_DOCTYPE';
  let any = false;
  for (const w of ['SignatureMethod', 'DigestMethod']) {
    const tags = startTags(xml, w);
    if (tags.length !== countWord(xml, w)) return 'SAML_ALGORITHM';      // a tag the strict grammar cannot read is a tag we cannot vouch for
    for (const t of tags) { any = true; if (typeof t.Algorithm !== 'string' || !OK_ALG.test(t.Algorithm)) return 'SAML_ALGORITHM'; }
  }
  if (!any) return 'SAML_UNSIGNED';
  // the library accepts a valid assertion inside a non-success response: refuse it (an error response must never log anyone in)
  const codes = startTags(xml, 'StatusCode');
  if (codes.length !== countWord(xml, 'StatusCode')) return 'SAML_STATUS';
  if (codes.length > 0 && codes[0].Value !== 'urn:oasis:names:tc:SAML:2.0:status:Success') return 'SAML_STATUS';
  const responses = startTags(xml, 'Response');
  if (responses.length !== 1 || countWord(xml, 'Response') !== 1) return 'SAML_MALFORMED';
  const resp = responses[0];
  if (ctx.acsUrl && resp.Destination !== undefined && resp.Destination !== ctx.acsUrl) return 'SAML_DESTINATION';   // F10V-03
  if (ctx.solicited === false) {
    if (resp.InResponseTo !== undefined) return 'SAML_IN_RESPONSE_TO';                                               // F10V-04
    for (const t of startTags(xml, 'SubjectConfirmationData')) if (t.InResponseTo !== undefined) return 'SAML_IN_RESPONSE_TO';
  }
  return null;
}

const first = (v) => (Array.isArray(v) ? v[0] : v);
const toArray = (v) => (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]);

function project(profile) {
  const attrs = {}; let n = 0;
  for (const [k, v] of Object.entries(profile)) {
    if (typeof v === 'function' || ['issuer', 'sessionIndex', 'nameID', 'nameIDFormat', 'nameQualifier', 'spNameQualifier', 'ID'].includes(k)) continue;
    if (n >= 50 || k.length > 256) continue;
    const vals = (Array.isArray(v) ? v : [v]).filter((x) => typeof x === 'string' && x.length <= 512).slice(0, 20);
    if (vals.length) { attrs[k] = vals; n++; }
  }
  return attrs;
}

function authnOf(profile) {
  try {
    const a = profile.getAssertion && profile.getAssertion();
    const root = a && (a.Assertion || a);
    const stmt = first(root && root.AuthnStatement);
    const instant = stmt && stmt.$ && stmt.$.AuthnInstant;
    const ctx = first(stmt && stmt.AuthnContext);
    const ref = first(ctx && ctx.AuthnContextClassRef);
    const notOnOrAfter = first(root && root.Conditions) && first(root.Conditions).$ && first(root.Conditions).$.NotOnOrAfter;
    const id = root && root.$ && root.$.ID;
    const recipients = [];
    for (const sc of toArray(root && root.Subject && first(root.Subject) && first(root.Subject).SubjectConfirmation)) for (const d of toArray(sc && sc.SubjectConfirmationData)) recipients.push(d && d.$ && d.$.Recipient);
    return { recipients, assertionId: typeof id === 'string' ? id : null, authnInstant: typeof instant === 'string' ? instant : null, authnContext: typeof ref === 'string' ? ref : (ref && typeof ref._ === 'string' ? ref._ : null), notOnOrAfter: typeof notOnOrAfter === 'string' ? notOnOrAfter : null };
  } catch { return { recipients: [], assertionId: null, authnInstant: null, authnContext: null, notOnOrAfter: null }; }
}

function createSamlProvider(config, { replayStore, now = () => Date.now() } = {}) {
  validateConfig(config);
  const lib = lazyLib();
  const clockSkewMs = config.clockSkewMs ?? 60_000;
  const maxAssertionAgeMs = config.maxAssertionAgeMs ?? 300_000;

  const make = (cacheProvider, validateIn, generateUniqueId) => new lib.SAML({
    ...(generateUniqueId ? { generateUniqueId } : {}),
    callbackUrl: config.acsUrl, entryPoint: config.ssoUrl, issuer: config.spEntityId, idpIssuer: config.idpEntityId, audience: config.spEntityId,
    idpCert: config.idpCerts, wantAssertionsSigned: true, wantAuthnResponseSigned: config.wantResponseSigned === true,
    acceptedClockSkewMs: clockSkewMs, maxAssertionAgeMs, forceAuthn: config.forceAuthn === true, disableRequestedAuthnContext: true,
    validateInResponseTo: validateIn, requestIdExpirationPeriodMs: 600_000, cacheProvider, identifierFormat: null,
  });

  function captureCache() {
    const saved = new Map();
    return { saved, saveAsync: async (k, v) => { saved.set(k, v); return { value: v, createdAt: now() }; }, getAsync: async (k) => saved.get(k) ?? null, removeAsync: async (k) => { saved.delete(k); return k; } };
  }

  /** `relayState` is a string, or a function given the AuthnRequest id that returns the string (so the id can travel in a signed relay state). */
  async function loginUrl(relayState) {
    const cache = captureCache();
    const requestId = `_${crypto.randomBytes(16).toString('hex')}`;
    const relay = typeof relayState === 'function' ? relayState(requestId) : relayState;
    const url = await make(cache, lib.ValidateInResponseTo.always, () => requestId).getAuthorizeUrlAsync(relay, undefined, {});
    if (!cache.saved.has(requestId)) throw new Error('saml: the AuthnRequest id could not be determined');
    return { url, requestId };
  }

  async function consume({ samlResponse, expectedRequestId = null }) {
    if (typeof samlResponse !== 'string' || !samlResponse || samlResponse.length > MAX_BYTES * 2) return { ok: false, reason: 'SAML_MALFORMED' };
    let xml;
    try { xml = Buffer.from(samlResponse, 'base64').toString('utf8'); } catch { return { ok: false, reason: 'SAML_MALFORMED' }; }
    const pre = preflight(xml, { acsUrl: config.acsUrl, solicited: !!expectedRequestId });
    if (pre) return { ok: false, reason: pre };

    const cache = captureCache();
    let validateIn = lib.ValidateInResponseTo.always;
    if (expectedRequestId) cache.saved.set(expectedRequestId, new Date(now()).toISOString());
    else if (config.allowIdpInitiated === true) validateIn = lib.ValidateInResponseTo.never;      // IdP-initiated: no request to answer
    else return { ok: false, reason: 'SAML_IN_RESPONSE_TO' };

    let result;
    try { result = await make(cache, validateIn).validatePostResponseAsync({ SAMLResponse: samlResponse }); } catch (e) {
      const msg = String(e && e.message);
      const reason = /InResponseTo/i.test(msg) ? 'SAML_IN_RESPONSE_TO' : /signature/i.test(msg) ? 'SAML_SIGNATURE_INVALID' : /audience/i.test(msg) ? 'SAML_AUDIENCE' : /(NotBefore|NotOnOrAfter|expired|too old|timestamp|not yet valid|subject confirmation)/i.test(msg) ? 'SAML_TIME' : /Issuer/i.test(msg) ? 'SAML_ISSUER' : /status/i.test(msg) ? 'SAML_STATUS' : 'SAML_INVALID';
      return { ok: false, reason };
    }
    const profile = result && result.profile;
    if (!profile || typeof profile.nameID !== 'string' || !profile.nameID || profile.nameID.length > 255) return { ok: false, reason: 'SAML_SUBJECT_MISSING' };
    if (profile.issuer !== config.idpEntityId) return { ok: false, reason: 'SAML_ISSUER' };
    const authn = authnOf(profile);
    // the Recipient of the bearer confirmation is this service's ACS URL (a response meant for another service must not log in here): at least one, and none different (F10V-03)
    if (!authn.recipients.length || authn.recipients.some((r) => r !== config.acsUrl)) return { ok: false, reason: 'SAML_RECIPIENT' };
    const assertionId = authn.assertionId || (typeof profile.ID === 'string' ? profile.ID : null);
    if (!assertionId) return { ok: false, reason: 'SAML_INVALID' };

    // replay: one assertion id is consumed once, until it could no longer be valid anyway
    const until = authn.notOnOrAfter ? Date.parse(authn.notOnOrAfter) : NaN;
    const ttlMs = Math.min(Math.max((Number.isFinite(until) ? until - now() : maxAssertionAgeMs) + clockSkewMs, 60_000), maxAssertionAgeMs + 2 * clockSkewMs + 600_000);
    if (!replayStore || typeof replayStore.claim !== 'function') return { ok: false, reason: 'SAML_REPLAY_STORE_UNAVAILABLE' };
    let fresh;
    try { fresh = await replayStore.claim(`saml:${config.id}:${crypto.createHash('sha256').update(assertionId).digest('hex')}`, ttlMs); } catch { return { ok: false, reason: 'SAML_REPLAY_STORE_UNAVAILABLE' }; }
    if (fresh !== true) return { ok: false, reason: 'SAML_REPLAY' };

    const a = config.assurance;
    const instantMs = authn.authnInstant ? Date.parse(authn.authnInstant) : NaN;
    const assured = !!a && authn.authnContext !== null && a.authnContexts.includes(authn.authnContext) && Number.isFinite(instantMs)
      && instantMs <= now() + clockSkewMs && now() - instantMs <= (a.maxAuthnAgeSec ?? 900) * 1000;
    return { ok: true, providerId: config.id, issuer: config.idpEntityId, subject: profile.nameID, nameIdFormat: profile.nameIDFormat || null, attributes: project(profile),
      sessionIndex: profile.sessionIndex || null, authnInstant: authn.authnInstant, authnContext: authn.authnContext, assured, assertionId, notOnOrAfter: authn.notOnOrAfter };
  }

  function metadata() {
    return lib.generateServiceProviderMetadata({ issuer: config.spEntityId, callbackUrl: config.acsUrl, wantAssertionsSigned: true, identifierFormat: null });
  }

  return { id: config.id, idpEntityId: config.idpEntityId, loginUrl, consume, metadata };
}

module.exports = { createSamlProvider, validateConfig, preflight, project };
