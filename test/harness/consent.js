'use strict';

/**
 * /consent routes (src/api/routes/consent.js) — used so a signed artifact's
 * /verify call can satisfy this repo's default REQUIRE_CONSENT policy
 * (POL-001 in policies.json) and reach decision:EXECUTE. See helpers/rbac.js
 * for how the operator API key is obtained.
 *
 * server.js mounts the ENTIRE /consent router behind
 * `_adminStack('MANAGE_CONSENT')` (server.js:543) — this is not limited to
 * the mutating routes (grant/suspend/resume/revoke); /consent/verify and
 * /consent/health require the same operator bearer token too, even though
 * they are read-only ad-hoc checks.
 */

const { post, get } = require('./http');

function _authHeaders(apiKey) {
  return apiKey ? { Authorization: `Bearer ${apiKey}` } : {};
}

// POST /consent requires a GDPR Art. 6(1) lawful basis and a
// purpose. Cases that do not test those fields get a stated default; a case that
// passes its own (or passes null to test the refusal) keeps it.
const GRANT_DEFAULTS = Object.freeze({ lawfulBasis: 'consent', purpose: 'QODIQA acceptance test' });
function grantConsent(baseUrl, apiKey, payload) {
  const hasOwn = (k, snake) => Object.prototype.hasOwnProperty.call(payload, k) || Object.prototype.hasOwnProperty.call(payload, snake);
  const body = { ...(hasOwn('lawfulBasis', 'lawful_basis') ? {} : { lawfulBasis: GRANT_DEFAULTS.lawfulBasis }),
    ...(hasOwn('purpose', 'purpose') ? {} : { purpose: GRANT_DEFAULTS.purpose }), ...payload };
  return post(`${baseUrl}/consent`, {
    headers: { Authorization: `Bearer ${apiKey}` },
    body,
  });
}

function suspendConsent(baseUrl, apiKey, id, payload = {}) {
  return post(`${baseUrl}/consent/${id}/suspend`, {
    headers: { Authorization: `Bearer ${apiKey}` },
    body: payload,
  });
}

function resumeConsent(baseUrl, apiKey, id, payload = {}) {
  return post(`${baseUrl}/consent/${id}/resume`, {
    headers: { Authorization: `Bearer ${apiKey}` },
    body: payload,
  });
}

function revokeConsent(baseUrl, apiKey, id, payload = {}) {
  return post(`${baseUrl}/consent/${id}/revoke`, {
    headers: { Authorization: `Bearer ${apiKey}` },
    body: payload,
  });
}

function verifyConsent(baseUrl, apiKey, payload) {
  return post(`${baseUrl}/consent/verify`, { headers: _authHeaders(apiKey), body: payload });
}

function consentHealth(baseUrl, apiKey) {
  return get(`${baseUrl}/consent/health`, { headers: _authHeaders(apiKey) });
}

/**
 * Revokes every ACTIVE consent record matching the given actor/action/tenant
 * — used by cases that must exercise the consent-gate BLOCK path (
 * refresh 2026-08-25): scripts/lib/devConsent.js auto-grants (dev identity,
 * <each configured provider>, dev tenant) on every bootstrap, so a
 * case signing with the banner identity and provider 'local' is otherwise
 * legitimately consented and can never observe a BLOCK. registry.grant()
 * never reactivates a REVOKED record, and the per-test DB truncation
 * restores the auto-grant for whichever case runs next.
 *
 * @returns {Promise<number>} how many records were revoked
 */
async function revokeMatchingConsents(baseUrl, apiKey, { actorId, action, tenantId }) {
  const q = new URLSearchParams({ actorId, ...(action ? { action } : {}), ...(tenantId ? { tenantId } : {}) });
  const listRes = await get(`${baseUrl}/consent?${q}`, { headers: _authHeaders(apiKey) });
  if (listRes.status !== 200) {
    throw new Error(`revokeMatchingConsents: list failed HTTP ${listRes.status}: ${listRes.text}`);
  }
  const records = (listRes.json.data && listRes.json.data.records) || [];
  let revoked = 0;
  for (const record of records) {
    if (record.state !== 'ACTIVE') continue;
    const res = await revokeConsent(baseUrl, apiKey, record.id, tenantId ? { tenantId } : {});
    if (res.status !== 200) {
      throw new Error(`revokeMatchingConsents: revoke of ${record.id} failed HTTP ${res.status}: ${res.text}`);
    }
    revoked += 1;
  }
  return revoked;
}

module.exports = { grantConsent, suspendConsent, resumeConsent, revokeConsent, verifyConsent, consentHealth, revokeMatchingConsents };
