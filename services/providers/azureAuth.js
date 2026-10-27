'use strict';

/**
 * Azure OpenAI authentication: an `api-key`, or a Microsoft Entra ID bearer token obtained with the client-credentials flow.
 *
 *   AZURE_OPENAI_API_KEY                                   -> the `api-key` header (the SDK sends it)
 *   AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET -> Entra: POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token, scope
 *                                                              https://cognitiveservices.azure.com/.default, token cached until a minute before it expires
 *
 * The Entra token host is fixed (never operator- or request-supplied), is validated with the same SSRF policy as every provider URL, redirects are refused, and the call is
 * bounded by a timeout and the caller's signal. A failure is PROVIDER_AUTH_FAILED (a configuration problem, not a provider outage). If both an API key and Entra credentials
 * are set, Entra wins (it is the stronger identity); AZURE_OPENAI_AUTH=api-key forces the key.
 */

const { validateProviderUrl } = require('./ssrf');
const { composeSignals } = require('./signalUtil');

const TOKEN_HOST = 'https://login.microsoftonline.com';
const SCOPE = 'https://cognitiveservices.azure.com/.default';
const GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

function mode(env = process.env) {
  const forced = (env.AZURE_OPENAI_AUTH || '').toLowerCase();
  const hasEntra = !!(env.AZURE_TENANT_ID && env.AZURE_CLIENT_ID && env.AZURE_CLIENT_SECRET);
  const hasKey = !!env.AZURE_OPENAI_API_KEY;
  if (forced === 'api-key') return hasKey ? 'api-key' : null;
  if (forced === 'entra') return hasEntra ? 'entra' : null;
  if (hasEntra) return 'entra';
  if (hasKey) return 'api-key';
  return null;
}

function authFailed(why) { const e = new Error('PROVIDER_AUTH_FAILED'); e.code = 'PROVIDER_AUTH_FAILED'; e.detail = why; return e; }

let cache = null;       // { token, expiresAtMs, key }
function _reset() { cache = null; }

/** @returns {Promise<string>} a bearer token (cached). `fetchImpl` and `nowMs` are test seams. */
async function entraToken({ env = process.env, signal, timeoutMs = 10_000, fetchImpl = fetch, nowMs = Date.now() } = {}) {
  const tenant = env.AZURE_TENANT_ID; const clientId = env.AZURE_CLIENT_ID; const secret = env.AZURE_CLIENT_SECRET;
  if (!GUID.test(tenant || '') || !GUID.test(clientId || '') || !secret) throw authFailed('entra credentials are incomplete or malformed');
  const cacheKey = `${tenant}:${clientId}`;
  if (cache && cache.key === cacheKey && cache.expiresAtMs - 60_000 > nowMs) return cache.token;

  const url = `${TOKEN_HOST}/${tenant}/oauth2/v2.0/token`;
  const check = validateProviderUrl(url);
  if (!check.valid) throw authFailed('token endpoint failed the SSRF policy');

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, {
      method: 'POST', redirect: 'error',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'client_credentials', client_id: clientId, client_secret: secret, scope: SCOPE }).toString(),
      signal: composeSignals(signal, controller.signal),
    });
    if (!res.ok) throw authFailed(`token endpoint answered HTTP ${res.status}`);
    const j = await res.json();
    if (!j || typeof j.access_token !== 'string' || !j.access_token || !Number.isFinite(Number(j.expires_in))) throw authFailed('token response malformed');
    cache = { key: cacheKey, token: j.access_token, expiresAtMs: nowMs + Number(j.expires_in) * 1000 };
    return cache.token;
  } catch (e) {
    if (e && e.code === 'PROVIDER_AUTH_FAILED') throw e;
    if (signal && signal.aborted) throw e;                                  // a cancellation stays a cancellation
    throw authFailed('token request failed');
  } finally { clearTimeout(timer); }
}

module.exports = { mode, entraToken, _reset, TOKEN_HOST, SCOPE };
