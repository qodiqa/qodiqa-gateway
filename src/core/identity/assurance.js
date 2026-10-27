'use strict';

/**
 * Second-factor assurance for single-sign-on logins that do not go through the operator MFA step-up: the tenant portal's users.
 *
 *   portalAssured(claims, env, nowMs) -> boolean
 *
 * The identity provider vouches for the second factor in the ID token (`amr` / `acr`, with a recent `auth_time`); QODIQA does not run a TOTP for portal users - it requires the provider
 * to have done it. Configured by QODIQA_PORTAL_REQUIRE_MFA=true (the callback then refuses a login without it), QODIQA_PORTAL_MFA_AMR (default "mfa,otp,hwk"),
 * QODIQA_PORTAL_MFA_ACR (optional list) and QODIQA_PORTAL_MFA_MAX_AGE_SEC (default 900). If the enterprise identity module is not installed the answer is false: fail closed.
 */

const ext = require('./extensionPoint');

const list = (v, dflt) => (typeof v === 'string' && v.trim() ? v.split(',').map((x) => x.trim()).filter(Boolean) : dflt);

function portalAssurance(env = process.env) {
  const a = { amr: list(env.QODIQA_PORTAL_MFA_AMR, ['mfa', 'otp', 'hwk']) };
  const acr = list(env.QODIQA_PORTAL_MFA_ACR, null);
  if (acr) a.acr = acr;
  const age = parseInt(env.QODIQA_PORTAL_MFA_MAX_AGE_SEC, 10);
  a.maxAuthAgeSec = Number.isInteger(age) && age >= 60 && age <= 86400 ? age : 900;
  return a;
}

function portalAssured(claims, env = process.env, nowMs = Date.now()) {
  const mod = ext.get();
  if (!mod || !claims || typeof claims !== 'object') return false;
  return mod.oidc.isAssured(claims, portalAssurance(env), nowMs);
}

const required = (env = process.env) => env.QODIQA_PORTAL_REQUIRE_MFA === 'true';

module.exports = { portalAssured, portalAssurance, required };
