'use strict';

/**
 * Tenant-portal session token —.
 *
 * A self-contained, HMAC-signed bearer token, following the SAME design as
 * services/executionInvariantToken.js, extended to carry a small
 * signed payload rather than proving a prior computation:
 *
 *   - HMAC-SHA256 over a domain-separated canonical message.
 *   - Secret is a dedicated, purpose-isolated secret
 *     (QODIQA_PORTAL_SESSION_SECRET) — never the KEK, never the execution-
 *     invariant secret, never derived from any other secret. Read directly
 *     from process.env, the SAME pattern src/core/dsr/ErasureService.js's
 *     _pepper() already uses for QODIQA_DSR_PSEUDONYM_PEPPER — this is
 * application-authentication secret material ('s config-secrets
 *     domain), not KEK-class cryptographic material owned by
 *     services/secrets/secretsProvider.js. See src/infra/configSecrets/
 *     managedSecrets.js.
 *   - issuedAt/expiresAt are always server-generated at mint time. Callers
 *     never supply them and verification never trusts a client-controlled
 *     timestamp.
 *   - Constant-time comparison (crypto.timingSafeEqual).
 *   - Bounded lifetime (QODIQA_PORTAL_SESSION_TTL_MS, default 8 hours).
 *
 * WHY NOT A SERVER-SIDE SESSION STORE (Redis/Postgres): this codebase's
 * existing credential model is uniformly bearer-token, self-contained,
 * `Authorization: Bearer <token>` (ok_ operator keys, sk_ signing-identity
 * keys — both hash-lookup against a durable store because they are
 * long-lived, revocable API credentials). A portal SESSION is different in
 * kind: short-lived, minted after a real OIDC authentication, and its
 * "revocation" story for this MVP is client-side logout (see
 *'s Session/token model section) — exactly the
 * shape services/executionInvariantToken.js already established a pattern
 * for. Reusing that pattern (self-contained, HMAC-signed, no new store)
 * avoids introducing a second, differently-shaped session mechanism for no
 * benefit this MVP needs.
 *
 * SERVER-SIDE REVOCATION: the payload now also
 * carries `sv`, the portal user's session version at mint time (a
 * non-negative integer held on the user record in
 * src/core/portal/tenantPortalUserStore.js). src/middleware/portalAuth.js
 * refuses any token whose `sv` differs from the record's CURRENT value, so
 * incrementing the record's sessionVersion (operator "sign out everywhere",
 * self-service logout, disable) invalidates every session minted before it,
 * on the next request, without a token deny-list. BACKWARD COMPATIBILITY: a
 * token minted has no `sv`; it verifies as sessionVersion 0,
 * which equals the implicit 0 of a user record that has never been revoked,
 * so upgrading forces no global logout — such a token keeps working until it
 * expires or its user's sessions are revoked (the first increment moves the
 * record to 1 and kills it). The "client-side logout only" story below is
 * SUPERSEDED by this for revocation; the stateless format is unchanged.
 *
 * TOKEN FORMAT: `pt_<base64url(JSON payload)>.<hex HMAC-SHA256 signature>`
 * The `pt_` prefix mirrors this codebase's existing sk_/ok_ bearer-token
 * naming convention (services/artifact aside) so a portal token is
 * immediately recognisable in logs/grep, while remaining structurally
 * distinct — never confusable with a real operator or signing-identity key.
 */

const crypto = require('crypto');

const TOKEN_PREFIX      = 'pt_';
const SIGNATURE_RE       = /^[a-f0-9]{64}$/; // HMAC-SHA256 digest, hex-encoded
const TENANT_ID_RE       = /^[A-Za-z0-9_-]{1,64}$/; // mirrors tenantContext.js
const DEFAULT_TTL_MS     = 8 * 60 * 60 * 1000; // 8 hours

function _resolveTtlMs() {
  const v = parseInt(process.env.QODIQA_PORTAL_SESSION_TTL_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : DEFAULT_TTL_MS;
}

/**
 * @returns {Buffer} the raw secret bytes (UTF-8), never logged, never cached
 *   across calls (process.env is already in-memory; re-reading is cheap and
 *   avoids a second place a stale value could linger).
 * @throws {Error} if the secret is unset — fail closed, never a default key.
 */
function _secret() {
  const raw = process.env.QODIQA_PORTAL_SESSION_SECRET;
  if (!raw) {
    throw new Error(
      'QODIQA_PORTAL_SESSION_SECRET must be set to mint or verify tenant-portal ' +
      'session tokens. Generate one with: ' +
      'node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
    );
  }
  return Buffer.from(raw, 'utf8');
}

function _hmac(message) {
  return crypto.createHmac('sha256', _secret()).update(message, 'utf8').digest();
}

function _base64UrlEncode(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

function _base64UrlDecode(str) {
  return JSON.parse(Buffer.from(str, 'base64url').toString('utf8'));
}

/**
 * Mint a fresh portal session token. Called exactly once per successful
 * OIDC callback (src/api/routes/tenantPortal.js) or approved dev-auth
 * request (non-production only — see that same file).
 *
 * @param {{ portalUserId: string, tenantId: string, role: string, sessionVersion?: number }} fields
 * sessionVersion — the user record's current session version;
 *   omitted/undefined means 0 (a record never revoked).
 * @returns {string} the bearer token, `pt_<payload>.<signature>`
 * @throws {TypeError} on invalid input; {Error} if the secret is unset
 */
function mintSessionToken({ portalUserId, tenantId, role, sessionVersion }) {
  if (typeof portalUserId !== 'string' || portalUserId.length === 0) {
    throw new TypeError('mintSessionToken: portalUserId must be a non-empty string');
  }
  if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) {
    throw new TypeError('mintSessionToken: tenantId must match [A-Za-z0-9_-]{1,64}');
  }
  if (typeof role !== 'string' || role.length === 0) {
    throw new TypeError('mintSessionToken: role must be a non-empty string');
  }
  const sv = sessionVersion === undefined ? 0 : sessionVersion;
  if (!Number.isSafeInteger(sv) || sv < 0) {
    throw new TypeError('mintSessionToken: sessionVersion must be a non-negative safe integer');
  }

  const issuedAt  = Date.now();
  const expiresAt = issuedAt + _resolveTtlMs();
  const payload   = { sub: portalUserId, tenantId, role, issuedAt, expiresAt, sv };
  const encoded   = _base64UrlEncode(payload);
  const signature = _hmac(encoded).toString('hex');

  return `${TOKEN_PREFIX}${encoded}.${signature}`;
}

/**
 * Verify a portal session bearer token. Fail-closed: any structural defect,
 * signature mismatch, or expiry returns null — never throws, so callers
 * (src/middleware/portalAuth.js) can treat every failure mode identically
 * (401, no further distinction that would help an attacker).
 *
 * @param {unknown} token
 * @param {{ _now?: number }} [opts] — injectable for tests only
 * @returns {{ portalUserId: string, tenantId: string, role: string, issuedAt: number, expiresAt: number, sessionVersion: number } | null}
 *   sessionVersion is 0 for a pre-DD-095 token that carries no `sv`.
 */
function verifySessionToken(token, opts = {}) {
  if (typeof token !== 'string' || !token.startsWith(TOKEN_PREFIX)) return null;

  const body = token.slice(TOKEN_PREFIX.length);
  const dot  = body.lastIndexOf('.');
  if (dot === -1) return null;

  const encoded   = body.slice(0, dot);
  const signature = body.slice(dot + 1);
  if (!SIGNATURE_RE.test(signature)) return null;

  let expected;
  try {
    expected = _hmac(encoded);
  } catch {
    // Secret unavailable/misconfigured — fail closed, never fall back to an
    // unsigned or default-keyed comparison.
    return null;
  }

  const provided = Buffer.from(signature, 'hex');
  if (provided.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(provided, expected)) return null;

  let payload;
  try {
    payload = _base64UrlDecode(encoded);
  } catch {
    return null;
  }

  const { sub, tenantId, role, issuedAt, expiresAt, sv } = payload || {};
  if (typeof sub !== 'string' || sub.length === 0) return null;
  if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) return null;
  if (typeof role !== 'string' || role.length === 0) return null;
  if (typeof issuedAt !== 'number' || !Number.isFinite(issuedAt) || issuedAt <= 0) return null;
  if (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt) || expiresAt <= issuedAt) return null;
  // absent `sv` = a pre-DD-095 token (session version 0); present but
  // malformed is refused (it was signed by us, so it can only be a defect).
  if (sv !== undefined && (!Number.isSafeInteger(sv) || sv < 0)) return null;

  const now = typeof opts._now === 'number' ? opts._now : Date.now();
  // No client clock is ever consulted — issuedAt/expiresAt were minted by
  // this same process. A future-dated issuedAt is tampering, not skew.
  if (issuedAt > now + 1000) return null; // 1s tolerance for clock granularity only
  if (now >= expiresAt) return null;

  return { portalUserId: sub, tenantId, role, issuedAt, expiresAt, sessionVersion: sv === undefined ? 0 : sv };
}

module.exports = {
  mintSessionToken,
  verifySessionToken,
  // Exported for targeted unit testing only.
  _resolveTtlMs,
  DEFAULT_TTL_MS,
  TOKEN_PREFIX,
};
