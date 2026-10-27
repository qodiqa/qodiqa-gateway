'use strict';

/**
 * Thin JSON-over-HTTP wrapper around the global fetch (Node 22, no axios/
 * node-fetch dependency in this repo — see test/serverStartupSmoke.test.js
 * for the existing precedent of using global fetch against a spawned
 * server). Every call captures status/headers/body/duration for evidence.
 */

const crypto = require('crypto');

// REL-01 — operator MFA step-up. every privileged mutation needs an enrolled operator
// and an X-QODIQA-OTP code. The acceptance cases predate it, so this wrapper does what a real operator does, through the
// real API: on the step-up's OWN refusals (403 MFA_ENROLLMENT_REQUIRED / 401 MFA_REQUIRED — returned before any route
// handler runs, so a retry has no side effect) it enrolls the bearer's operator (POST /rbac/me/mfa/enroll, then
// /confirm with a computed TOTP) and resends the request with a one-time recovery code. Any other status, and every
// request that never meets the step-up, passes through untouched — nothing is disabled and nothing is skipped.
const _mfaByKey = new Map(); // `${origin} ${bearer}` -> { secret, recoveryCodes: string[] }

function _base32Decode(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0; let v = 0; const out = [];
  for (const ch of String(s).toUpperCase().replace(/=+$/, '')) {
    v = (v << 5) | A.indexOf(ch); bits += 5;
    if (bits >= 8) { out.push((v >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
function _totp(secret, ms = Date.now()) {
  const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(Math.floor(ms / 30000)));
  const h = crypto.createHmac('sha1', _base32Decode(secret)).update(buf).digest(); const o = h[h.length - 1] & 0x0f;
  return String((((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1e6).padStart(6, '0');
}
function _bearer(headers) {
  const k = Object.keys(headers || {}).find((h) => h.toLowerCase() === 'authorization');
  return k ? headers[k] : null;
}

async function _enrollOperatorMfa(origin, authorization) {
  const auth = { Authorization: authorization, 'Content-Type': 'application/json' };
  const en = await _rawRequest(`${origin}/rbac/me/mfa/enroll`, { method: 'POST', headers: auth, body: {} });
  const secret = en.json && en.json.data && en.json.data.secret;
  if (!secret) throw new Error(`acceptance MFA enrolment failed: POST /rbac/me/mfa/enroll -> ${en.status} ${en.text}`);
  const cf = await _rawRequest(`${origin}/rbac/me/mfa/confirm`, { method: 'POST', headers: auth, body: { code: _totp(secret) } });
  const codes = cf.json && cf.json.data && cf.json.data.recoveryCodes;
  if (!Array.isArray(codes) || codes.length === 0) throw new Error(`acceptance MFA confirm failed: ${cf.status} ${cf.text}`);
  // the confirm consumed the current TOTP step (server-side replay guard), so the next TOTP must be a later step
  const state = { secret, recoveryCodes: [...codes], lastTotpStep: Math.floor(Date.now() / 30000) };
  _mfaByKey.set(`${origin} ${authorization}`, state);
  return state;
}

async function request(url, opts = {}) {
  const first = await _rawRequest(url, opts);
  const code = first.json && first.json.error && first.json.error.code;
  const authorization = _bearer(opts.headers);
  if (!authorization || !((first.status === 403 && code === 'MFA_ENROLLMENT_REQUIRED') || (first.status === 401 && code === 'MFA_REQUIRED'))) {
    return first;
  }
  const origin = new URL(url).origin;
  let state = _mfaByKey.get(`${origin} ${authorization}`);
  if (!state && code === 'MFA_ENROLLMENT_REQUIRED') state = await _enrollOperatorMfa(origin, authorization);
  if (!state) return first;
  let otp; let method = 'recovery_code';
  if (state.recoveryCodes.length > 0) {
    otp = state.recoveryCodes.shift();
  } else {
    // recovery codes spent: a fresh TOTP step (each step is accepted once — the server's replay guard)
    let step = Math.floor(Date.now() / 30000);
    if (state.lastTotpStep !== undefined && step <= state.lastTotpStep) {
      await new Promise((r) => setTimeout(r, (state.lastTotpStep + 1) * 30000 - Date.now() + 250));
      step = Math.floor(Date.now() / 30000);
    }
    state.lastTotpStep = step; otp = _totp(state.secret); method = 'totp';
  }
  const retried = await _rawRequest(url, { ...opts, headers: { ...(opts.headers || {}), 'X-QODIQA-OTP': otp } });
  retried.mfaStepUp = { enrolled: true, method, remainingRecoveryCodes: state.recoveryCodes.length };
  return retried;
}

async function _rawRequest(url, { method = 'GET', headers = {}, body, rawBody } = {}) {
  const start = Date.now();
  const init = { method, headers: { ...headers } };
  if (rawBody !== undefined) {
    init.body = rawBody;
  } else if (body !== undefined) {
    init.headers['Content-Type'] = init.headers['Content-Type'] || 'application/json';
    init.body = JSON.stringify(body);
  }

  const res = await fetch(url, init);
  const durationMs = Date.now() - start;
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = undefined; }

  return {
    status: res.status,
    headers: Object.fromEntries(res.headers.entries()),
    text,
    json,
    durationMs,
    request: { url, method, headers: init.headers, body: init.body },
  };
}

const get = (url, opts) => request(url, { ...opts, method: 'GET' });
const post = (url, opts) => request(url, { ...opts, method: 'POST' });

module.exports = { request, get, post };
