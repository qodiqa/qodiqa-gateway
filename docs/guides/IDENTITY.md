# Enterprise identity

QODIQA authenticates machine callers with per-identity API keys (`sk_...`, `/sign`) and operators with RBAC keys. The enterprise identity module lets an organisation bring its own
identity provider instead. Code lives in `enterprise/identity/` (a separable directory: it imports nothing from the core); the core reaches it only through
`src/core/identity/extensionPoint.js`.

Status of each part is stated honestly: **tested against locally generated keys and mocked/recorded identity-provider traffic, and (when the containers are available) against test
identity providers; not against a production identity provider.**

## OpenID Connect bearer tokens

`Authorization: Bearer <JWT>` on `POST /sign` is accepted as an alternative to an `sk_` key.

**Configuration.** Set `QODIQA_OIDC_CONFIG_PATH` to a JSON file:

```json
{ "providers": [ {
    "id": "corp",
    "issuer": "https://login.example.com/realms/corp",
    "audience": ["qodiqa-api"],
    "discovery": true,
    "algorithms": ["RS256", "ES256"],
    "clockSkewSec": 60,
    "maxLifetimeSec": 3600
} ] }
```

Use `jwksUri` instead of `discovery: true` to name the key set directly. Unset = federation off (API keys only). A bad file or provider fails the start of the gateway.

**What is verified, in this order.**

1. The token is a JWT of at most 16 KiB with three base64url segments and JSON objects for header and payload (a header or payload with a repeated member name is refused).
2. `alg` is on the allowlist (default RS256/384/512, PS256/384/512, ES256/384/512, EdDSA; a provider can only narrow it). `none` and every HMAC algorithm are **never** accepted, so a
   public key cannot be replayed as an HMAC secret. A `crit` header is refused. The key comes only from the provider's own key set (selected by `kid`): the token's `jku`, `x5u` and
   `jwk` members are ignored.
3. The key's type and curve must fit `alg`. The signature must verify.
4. After the signature: `iss` equals the configured issuer exactly, `aud` contains a configured audience, `exp` is present and not past (bounded clock skew, default 60 s, at most 300 s),
   `nbf` and `iat` are not in the future, the lifetime is bounded (default 24 h), `sub` is a non-empty string.

**Keys.** Fetched from `jwksUri` (or from the discovery document, whose `issuer` must equal the configured one and whose `jwks_uri` must be https), cached 10 minutes. A token with an
unknown `kid` causes one refetch at most every 30 seconds, so random key ids cannot make the gateway hammer the provider; a failed or empty refetch never discards keys that were good;
if the provider is unreachable the last good key set keeps serving for one more hour, then every lookup fails closed. Only usable keys are kept: signature keys, RSA of 2048 bits or
more, P-256/384/521, Ed25519; symmetric keys, keys with private members and unknown curves are dropped.

**Network.** One outbound door (`src/core/identity/safeFetch.js`): https to a public DNS name, through the guarded agent (every resolved address re-checked, so a name that later
resolves to a private or metadata address is refused), no redirects, 5 s timeout, 256 KiB limit enforced while reading, JSON content type.
`QODIQA_OIDC_ALLOW_INSECURE=true` permits a plain-http / loopback provider for local development; it is ignored when `NODE_ENV=production` and refused by the boot rules.

**From token to identity.** A verified token proves *who* the caller is at the provider. It grants nothing by itself: the verified `(issuer, subject)` must be **linked** to a signing
identity (`credentialType: "oidc"`, `externalIdentity: { issuer, subject }`, created through `POST /signing-identities`). An unlinked subject is refused (401). The linked identity then goes through exactly the checks
an API-key identity does: enabled, not revoked, `SIGN_ARTIFACT`, tenant, environment, provider scope. An `oidc` identity has no API key (`POST .../api-key` is refused); revoking it
revokes the identity. The artifact's caller context records `credentialType: "oidc"`.

**Failure modes.** A refused token is `401 UNAUTHORIZED` (the reason is only in the log/metrics: `OIDC_TOKEN_REFUSED`), counted against the caller's lockout like a bad key. A provider
that cannot be reached (and has no usable cached keys) is `503 AUTH_BACKEND_UNAVAILABLE` with `Retry-After`, not a credential failure.

## Operator single sign-on and step-up

The operator admin API accepts, besides an API key, an OIDC bearer token (`Authorization: Bearer <jwt>`) from a configured provider, or an operator session token (below). The verified
`(issuer, subject)` must be linked to an RBAC user (`externalIdentity`, set when the user is created or updated); an unlinked subject is refused and the user must be enabled. The user's
role gives the permissions: nothing is read from IdP claims.

A provider may declare `assurance { amr, acr, maxAuthAgeSec }`. A login whose `amr`/`acr` is listed and whose `auth_time` is recent counts as **assured**: the IdP vouched for a second factor, and the
operator MFA step-up (`X-QODIQA-OTP`) is satisfied by it. Without that, the normal TOTP step-up applies. `QODIQA_PORTAL_REQUIRE_MFA` and a signing identity's `requireAssurance` use the same rule.

## SAML 2.0 single sign-on

Set `QODIQA_SAML_CONFIG_PATH` to a JSON file `{ "providers": [ ... ] }` (1 to 16 providers; unset = SAML off; a bad file stops the start). A provider has `id`, `spEntityId`, `acsUrl`, `idpEntityId`,
`ssoUrl`, `idpCerts` (PEM, pinned) and the options of `enterprise/identity/saml.js` (`allowIdpInitiated` false by default, `sessionTtlSec` 60..28800, default 1800).

| Endpoint | Purpose |
| --- | --- |
| `GET /auth/saml/login?provider=<id>` | 302 to the IdP; the relay state is signed (MAC keyring purpose `SAML_STATE`) and carries the AuthnRequest id, so any replica can finish the login |
| `POST /auth/saml/acs?provider=<id>` | the IdP's response (form post); success returns an operator session token, every refusal is the same generic 401 (the reason is only in the log) |
| `GET /auth/saml/metadata?provider=<id>` | service-provider metadata to give the IdP |

Checks: signature by a pinned certificate (no SHA-1, no unknown algorithms), `DOCTYPE`/`ENTITY` refused, issuer, audience, `InResponseTo` equals the request this relay state belongs to, validity window,
status success, and the assertion id is consumed once (replay store: Redis `SET NX PX`, or memory without Redis; if the store is unreachable the login is refused, 503). The subject (NameID) must be
linked to an enabled RBAC user. The endpoints are public by nature and limited per client address (plus the `public_verify` bucket).

**Operator session token** `qos1.<payload>.<kid>.<mac>` (MAC keyring purpose `OPERATOR_SESSION`): it names the RBAC user, is accepted by the admin API as a bearer, and is re-checked on every request
(user exists, enabled, still linked to the same `(issuer, subject)`), so disabling or unlinking the user ends every session at once. Lifetime default 30 min, maximum 8 h. A token minted under a key that
was later retired stops verifying when that key is removed.

**The MAC keyring key file is created at boot, never by a request path**: outside production the start creates it if absent; in production a missing file stops the start.

## LDAP / Active Directory sign-in

Set `QODIQA_LDAP_CONFIG_PATH` to a JSON file `{ "providers": [ ... ] }` (1 to 16 providers; unset = LDAP off; a bad file stops the start). A provider has `id`, `url` (`ldaps://...`, or `ldap://` with
`startTls: true`; a clear-text URL is refused except loopback with `allowInsecure` for tests), `baseDn`, `bindDn`, `bindPasswordEnv` (the NAME of the environment variable that holds the service-account
password: the password is never in the file), `userFilter` (default `(&(objectClass=person)(uid={username}))`; Active Directory: `(&(objectClass=user)(sAMAccountName={username}))`; `{username}` is the only
placeholder and is always escaped), `subjectAttribute` (default `entryUUID`; Active Directory `objectGUID` with `binarySubject: true`), `groupAttribute` (default `memberOf`), `requiredGroups` (optional: any one
admits), `tlsCa`, `timeoutMs`, `sessionTtlSec`.

`POST /auth/ldap/login` with `{ provider, username, password }` (JSON, 4 KB) -> an operator session token (the same `qos1...` token as SAML, accepted by the admin API). The flow: service-account bind, a search
that must match exactly one entry, then a bind **as that entry's own DN** with the password (the directory itself proves it), then the verified `(issuer = "ldap:<id>", subject = the directory's stable id)` must be
linked to an enabled RBAC user. There is no automatic account creation, and the role is the RBAC user's, never read from the directory; directory groups can only admit (`requiredGroups`).

Refused before any network call: an empty password (a bind with a DN and an empty password is an UNAUTHENTICATED bind that many servers accept), a username with control characters or over 256 characters, a password
over 1,024 characters or with NUL, a filter template with anything but one `{username}`. The username is escaped per RFC 4515 (`* ( ) \ NUL` and non-ASCII), so it cannot widen the search. Every refusal is the same
generic 401. After 5 failures for one (provider, username) in 15 minutes the pair is locked for the rest of the window (per process; the per-client-address limiter, 10/min, and the directory's own lockout are the
other bounds); a directory outage is 503 and does not count.

## Known limits

- OIDC bearer tokens are accepted by `/sign` and by the operator admin API; the operator console has no browser redirect login for OIDC (bearer or SAML session token only).
- SAML: no single logout, no encrypted assertions in this version; validated only against a test IdP, not a production IdP.
- Session assurance ends with the provider's maximum authentication age (`assurance.maxAuthnAgeSec`, default 900 s, counted from the IdP's authentication instant): after that a SAML session is treated as an unassured login (the TOTP step-up applies again) even though the session itself lasts up to `sessionTtlSec`.
- SAML refusals checked before the signature: DOCTYPE/ENTITY, any SHA-1 or unknown algorithm (read with the XML attribute grammar, so a `>` inside an attribute value cannot hide one), a `Destination` or `Recipient` other than this service's ACS URL, and, for an IdP-initiated response, any `InResponseTo`. An `idpEntityId` in the `ldap:` namespace is refused (it is the issuer of LDAP sign-ins).
- LDAP: a username with leading or trailing whitespace is refused (a directory may fold it), the lockout key folds case, compatibility forms and spacing, and an unknown user costs the same directory round trips as a wrong password; the remaining timing difference on a real network was not measured.
- The OIDC/SAML fetches refuse private and loopback addresses but allow names such as `*.internal` that resolve publicly; deployments that must forbid them should use an egress policy.
- LDAP: a username with non-ASCII characters does not match in the directory with the current client library (its filter parser mangles the escapes): it fails closed, such users cannot sign in through LDAP yet.
- LDAP: no paged search and no referral following; the lockout counter is per process; validated only with a test directory, not a production one.
- Operator session tokens cannot be revoked individually (disable or unlink the user, rotate/retire the keyring key, or wait for expiry).
- No token revocation list: a stolen token is valid until `exp` (keep lifetimes short; the provider's `maxLifetimeSec` bounds it). Disabling the linked identity takes effect on the next request.
- Group/role claims are carried in the verified projection but are not mapped to permissions: permissions are the linked identity's.
- Claims `email`, `name` etc. are never used for linking: only `(issuer, subject)`.
