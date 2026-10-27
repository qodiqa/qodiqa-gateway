'use strict';

/**
 * OIDC relying-party client — tenant self-service portal.
 *
 * Thin wrapper around `openid-client` (an `optionalDependency` in
 * package.json, same "not installed unless a deployment actually selects
 * this backend" pattern as node-vault/pkcs11js/the cloud KMS SDKs — see
 * src/infra/keys/sdkAvailability.js for the established precedent this
 * mirrors). QODIQA is never forced to pull in an OIDC client library unless
 * an operator sets QODIQA_PORTAL_ENABLED=true.
 *
 * Scope, deliberately narrow ( for the full
 * decision record):
 *   - Authorization Code flow with PKCE (S256) — no implicit flow, no
 *     resource-owner-password flow.
 *   - Discovery via the issuer's /.well-known/openid-configuration
 *     (Issuer.discover), memoised for the process lifetime — one network
 *     round trip at first use, not per request.
 *   - ID token validation (issuer, audience, signature via the issuer's
 *     JWKS, exp, nonce) is performed by openid-client's own client.callback()
 *     — this module does NOT hand-roll any JWT/JWS verification. "Do not
 *     invent cryptography" applies as much to token validation as to
 *     signing.
 *   - The authorization `state` parameter doubles as the CSRF/flow-integrity
 *     token AND the carrier for the PKCE code_verifier + nonce (HMAC-signed
 *     via services/portal/oidcFlowState.js) — see that module's header
 *     comment for why this avoids needing a cookie for the redirect
 *     round-trip, keeping the portal on this codebase's existing
 *     bearer-token-only, credentials:false CORS model
 *     (src/infra/cors/corsPolicy.js) with no new cookie/CSRF surface.
 */

const CLIENT_SECRET_ROLE = 'confidential'; // matches the OIDC "confidential client" model chosen in the SSO decision doc

function _requireOpenidClient() {
  try {
    // eslint-disable-next-line global-require
    return require('openid-client');
  } catch {
    throw new Error(
      'oidcClient: openid-client is not installed. Run: npm install openid-client',
    );
  }
}

function _config() {
  const issuer      = process.env.QODIQA_OIDC_ISSUER;
  const clientId    = process.env.QODIQA_OIDC_CLIENT_ID;
  const clientSecret = process.env.QODIQA_OIDC_CLIENT_SECRET;
  const redirectUri  = process.env.QODIQA_OIDC_REDIRECT_URI;

  const missing = [];
  if (!issuer) missing.push('QODIQA_OIDC_ISSUER');
  if (!clientId) missing.push('QODIQA_OIDC_CLIENT_ID');
  if (!clientSecret) missing.push('QODIQA_OIDC_CLIENT_SECRET');
  if (!redirectUri) missing.push('QODIQA_OIDC_REDIRECT_URI');
  if (missing.length > 0) {
    throw new Error(`oidcClient: missing required configuration: ${missing.join(', ')}`);
  }

  return { issuer, clientId, clientSecret, redirectUri };
}

let _cachedClient = null;

/**
 * Lazily discover the issuer and construct the RP client. Memoized for the
 * process lifetime — discovery is a network round trip and the issuer's
 * configuration does not change while this process is running.
 * @returns {Promise<object>} an openid-client Client instance
 */
async function getClient() {
  if (_cachedClient) return _cachedClient;

  const { Issuer } = _requireOpenidClient();
  const { issuer, clientId, clientSecret, redirectUri } = _config();

  const discovered = await Issuer.discover(issuer);
  _cachedClient = new discovered.Client({
    client_id:     clientId,
    client_secret: clientSecret,
    redirect_uris: [redirectUri],
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_basic',
  });
  return _cachedClient;
}

/**
 * Build the IdP authorization-endpoint redirect URL.
 * @param {{ state: string, nonce: string, codeChallenge: string }} params
 * @returns {Promise<string>}
 */
async function buildAuthorizationUrl({ state, nonce, codeChallenge }) {
  const client = await getClient();
  return client.authorizationUrl({
    scope: 'openid email profile',
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });
}

/**
 * Exchange an authorization code for tokens and return VALIDATED ID-token
 * claims. openid-client's client.callback() performs issuer, audience,
 * signature (via the issuer's JWKS), expiry, and nonce validation
 * internally — this function adds no validation logic of its own beyond
 * passing the expected state/nonce through.
 *
 * @param {{ callbackParams: object, codeVerifier: string, expectedState: string, expectedNonce: string }} params
 *   callbackParams — the query params from the IdP redirect (code, state, ...),
 *   exactly as `client.callbackParams(req)` would produce.
 * @returns {Promise<{ claims: object, tokenSet: object }>}
 * @throws on any validation failure — issuer/audience/signature/expiry/
 *   nonce/state mismatch all surface as a thrown error from openid-client,
 *   which the caller (src/api/routes/tenantPortal.js) treats uniformly as
 *   an authentication failure (never distinguishing which check failed in
 *   the user-facing response — see that file's error-handling section).
 */
async function exchangeCode({ callbackParams, codeVerifier, expectedState, expectedNonce }) {
  const client = await getClient();
  const { redirectUri } = _config();
  const tokenSet = await client.callback(redirectUri, callbackParams, {
    code_verifier: codeVerifier,
    state:         expectedState,
    nonce:         expectedNonce,
  });
  return { claims: tokenSet.claims(), tokenSet };
}

// ── Test-only reset ──────────────────────────────────────────────────────────

function _resetForTests() {
  _cachedClient = null;
}

module.exports = {
  getClient,
  buildAuthorizationUrl,
  exchangeCode,
  _resetForTests,
  CLIENT_SECRET_ROLE,
};
