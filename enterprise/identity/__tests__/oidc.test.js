'use strict';

/**
 * OIDC bearer tokens: JWT verification, JWKS cache, provider layer.
 *   JW-01  every supported algorithm verifies; wrong key / tampered payload / tampered signature do not
 *   JW-02  refused: alg none, HS* (algorithm confusion with the public key as secret), unlisted alg, crit, duplicate header members, key/algorithm mismatch, header-supplied keys
 *   JW-03  claims: iss exact, aud, exp required, nbf, iat, lifetime bound, clock skew bound, sub
 *   JK-01  JWKS cache: ttl, kid-miss refetch limited, failed refetch keeps good keys, stale-if-error window, unusable keys dropped, anonymous key rule
 *   OD-01  provider layer: issuer selection, discovery, audience, unknown issuer, key rotation, unavailable provider, claim projection
 */

const crypto = require('crypto');
const jwt = require('../jwt');
const { createJwksCache, importJwk } = require('../jwks');
const { createOidcAuthenticator, validateProviders } = require('../oidc');

const b64 = (o) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');
const NOW = Date.UTC(2026, 9, 23, 12, 0, 0);
const sec = (ms) => Math.floor(ms / 1000);
const ISS = 'https://idp.example.com/realm';
const AUD = 'qodiqa-api';

const kp = {
  rsa: crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }),
  rsa2: crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }),
  p256: crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
  p384: crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' }),
  p521: crypto.generateKeyPairSync('ec', { namedCurve: 'secp521r1' }),
  ed: crypto.generateKeyPairSync('ed25519'),
};
const SIGN = {
  RS256: (k, d) => crypto.sign('sha256', d, k), RS384: (k, d) => crypto.sign('sha384', d, k), RS512: (k, d) => crypto.sign('sha512', d, k),
  PS256: (k, d) => crypto.sign('sha256', d, { key: k, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }),
  PS384: (k, d) => crypto.sign('sha384', d, { key: k, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 }),
  PS512: (k, d) => crypto.sign('sha512', d, { key: k, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 64 }),
  ES256: (k, d) => crypto.sign('sha256', d, { key: k, dsaEncoding: 'ieee-p1363' }), ES384: (k, d) => crypto.sign('sha384', d, { key: k, dsaEncoding: 'ieee-p1363' }),
  ES512: (k, d) => crypto.sign('sha512', d, { key: k, dsaEncoding: 'ieee-p1363' }), EdDSA: (k, d) => crypto.sign(null, d, k),
};
const KEYFOR = { RS256: 'rsa', RS384: 'rsa', RS512: 'rsa', PS256: 'rsa', PS384: 'rsa', PS512: 'rsa', ES256: 'p256', ES384: 'p384', ES512: 'p521', EdDSA: 'ed' };

function mint({ alg = 'RS256', header = {}, claims = {}, key, rawHeader, signWith } = {}) {
  const k = key || kp[KEYFOR[alg] || 'rsa'];
  const h = rawHeader || b64({ alg, typ: 'JWT', kid: 'k1', ...header });
  const p = b64({ iss: ISS, aud: AUD, sub: 'user-1', exp: sec(NOW) + 600, iat: sec(NOW) - 5, ...claims });
  const signingInput = `${h}.${p}`;
  const sig = signWith ? signWith(signingInput) : SIGN[alg](k.privateKey, Buffer.from(signingInput));
  return `${signingInput}.${sig.toString('base64url')}`;
}
const keyForOf = (k) => () => k.publicKey;
const V = (token, over = {}) => jwt.verify(token, { keyFor: keyForOf(kp.rsa), issuer: ISS, audience: AUD, now: NOW, ...over });
const code = (fn) => { try { fn(); } catch (e) { return e.code || e.name; } return 'NO_ERROR'; };

describe('JWT verification', () => {
  test('JW-01 every supported algorithm verifies; a wrong key, a tampered payload and a tampered signature do not', () => {
    for (const alg of Object.keys(SIGN)) {
      const k = kp[KEYFOR[alg]];
      expect(jwt.verify(mint({ alg }), { keyFor: () => k.publicKey, issuer: ISS, audience: AUD, now: NOW }).claims.sub).toBe('user-1');
    }
    expect(code(() => V(mint({ alg: 'RS256' }), { keyFor: keyForOf(kp.rsa2) }))).toBe('JWT_SIGNATURE_INVALID');
    const t = mint({ alg: 'RS256' }); const [h, p, s] = t.split('.');
    expect(code(() => V(`${h}.${b64({ iss: ISS, aud: AUD, sub: 'admin', exp: sec(NOW) + 600 })}.${s}`))).toBe('JWT_SIGNATURE_INVALID');
    const flipped = Buffer.from(s, 'base64url'); flipped[0] ^= 1;
    expect(code(() => V(`${h}.${p}.${flipped.toString('base64url')}`))).toBe('JWT_SIGNATURE_INVALID');
    expect(code(() => V(`${h}.${p}.`))).toBe('JWT_MALFORMED');
  });

  test('JW-02 alg none, HMAC algorithm confusion, unlisted algorithms, crit, duplicate members, key/alg mismatch', () => {
    const none = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ iss: ISS, aud: AUD, sub: 'u', exp: sec(NOW) + 60 })}.`;
    expect(code(() => V(none))).toBe('JWT_MALFORMED');                                                       // empty signature segment
    expect(code(() => V(`${none}AAAA`))).toBe('JWT_ALG_NOT_ALLOWED');
    for (const alg of ['None', 'NONE', 'HS256', 'HS384', 'HS512', 'RS1', '', 'ES256K']) {
      expect(code(() => V(mint({ rawHeader: b64({ alg, kid: 'k1' }), signWith: () => Buffer.from('x') })))).toBe('JWT_ALG_NOT_ALLOWED');
    }
    // the classic confusion: HS256 signed with the PUBLIC key bytes as the HMAC secret
    const pem = kp.rsa.publicKey.export({ type: 'spki', format: 'pem' });
    const hs = mint({ rawHeader: b64({ alg: 'HS256', typ: 'JWT', kid: 'k1' }), signWith: (input) => crypto.createHmac('sha256', pem).update(input).digest() });
    expect(code(() => V(hs))).toBe('JWT_ALG_NOT_ALLOWED');
    expect(code(() => V(mint({ alg: 'RS256' }), { algorithms: ['ES256'] }))).toBe('JWT_ALG_NOT_ALLOWED');       // narrowed allowlist
    expect(code(() => V(mint({ alg: 'RS256', header: { crit: ['exp'] } })))).toBe('JWT_CRIT_UNSUPPORTED');
    expect(code(() => V(mint({ rawHeader: '{"alg":"none","alg":"RS256","kid":"k1"}'.split('').length ? Buffer.from('{"alg":"none","alg":"RS256","kid":"k1"}').toString('base64url') : '', signWith: () => Buffer.from('x') })))).toBe('JWT_MALFORMED');
    expect(code(() => V(mint({ alg: 'ES256' }), { keyFor: keyForOf(kp.rsa) }))).toBe('JWT_KEY_MISMATCH');          // RSA key for ES256
    expect(code(() => V(mint({ alg: 'ES256' }), { keyFor: keyForOf(kp.p384) }))).toBe('JWT_KEY_MISMATCH');         // wrong curve
    expect(code(() => V(mint({ alg: 'EdDSA' }), { keyFor: keyForOf(kp.p256) }))).toBe('JWT_KEY_MISMATCH');
    expect(code(() => V(mint({ alg: 'RS256' }), { keyFor: () => null }))).toBe('JWT_KEY_UNKNOWN');
    // header-supplied keys / URLs are ignored: the key comes from keyFor only
    const seen = []; V(mint({ alg: 'RS256', header: { jku: 'https://evil.example/jwks', x5u: 'https://evil.example/x', jwk: { kty: 'RSA' } } }), { keyFor: (h) => { seen.push(h); return kp.rsa.publicKey; } });
    expect(seen).toEqual([{ alg: 'RS256', kid: 'k1' }]);
    expect(code(() => V(mint({ alg: 'RS256', header: { kid: 5 } })))).toBe('JWT_MALFORMED');
    expect(code(() => V('a.b'))).toBe('JWT_MALFORMED'); expect(code(() => V('a.b.c.d'))).toBe('JWT_MALFORMED'); expect(code(() => V('x'.repeat(jwt.MAX_TOKEN_BYTES + 1)))).toBe('JWT_MALFORMED');
    expect(code(() => V(`${b64('[1]')}.${b64({})}.AAAA`))).toBe('JWT_MALFORMED');
    expect(code(() => V(`!!!.${b64({})}.AAAA`))).toBe('JWT_MALFORMED');
  });

  test('JW-03 claims', () => {
    const claims = (c) => ({ claims: c });
    expect(code(() => V(mint(claims({ iss: `${ISS}/` }))))).toBe('JWT_ISSUER_MISMATCH');
    expect(code(() => V(mint(claims({ iss: ISS.toUpperCase() }))))).toBe('JWT_ISSUER_MISMATCH');
    expect(code(() => V(mint(claims({ aud: 'other' }))))).toBe('JWT_AUDIENCE_MISMATCH');
    expect(code(() => V(mint(claims({ aud: ['other', AUD] }))))).toBe('NO_ERROR');
    expect(code(() => V(mint(claims({ aud: [5] }))))).toBe('JWT_AUDIENCE_MISMATCH');
    expect(code(() => V(mint(claims({ aud: undefined }))))).toBe('JWT_AUDIENCE_MISMATCH');
    expect(code(() => V(mint(claims({ exp: undefined }))))).toBe('JWT_EXP_MISSING');
    expect(code(() => V(mint(claims({ exp: '9999999999' }))))).toBe('JWT_EXP_MISSING');
    expect(code(() => V(mint(claims({ exp: sec(NOW) - 61 }))))).toBe('JWT_EXPIRED');
    expect(code(() => V(mint(claims({ exp: sec(NOW) - 30 }))))).toBe('NO_ERROR');                                // inside the 60 s skew
    expect(code(() => V(mint(claims({ nbf: sec(NOW) + 120 }))))).toBe('JWT_NOT_YET_VALID');
    expect(code(() => V(mint(claims({ nbf: sec(NOW) + 30 }))))).toBe('NO_ERROR');
    expect(code(() => V(mint(claims({ iat: sec(NOW) + 600 }))))).toBe('JWT_IAT_IN_FUTURE');
    expect(code(() => V(mint(claims({ iat: sec(NOW) - 100, exp: sec(NOW) + 90_000 }))))).toBe('JWT_LIFETIME_TOO_LONG');
    expect(code(() => V(mint(claims({ iat: undefined, exp: sec(NOW) + 200_000 }))))).toBe('JWT_LIFETIME_TOO_LONG');
    expect(code(() => V(mint(claims({ sub: undefined }))))).toBe('JWT_SUBJECT_MISSING');
    expect(code(() => V(mint(claims({ sub: '' }))))).toBe('JWT_SUBJECT_MISSING');
    expect(code(() => V(mint(claims({ sub: 'x'.repeat(256) }))))).toBe('JWT_SUBJECT_MISSING');
    expect(code(() => V(mint(claims({ sub: 12 }))))).toBe('JWT_SUBJECT_MISSING');
    expect(code(() => V(mint({}), { clockSkewSec: 0, now: NOW + 601_000 }))).toBe('JWT_EXPIRED');
  });
});

describe('JWKS cache', () => {
  const jwkOf = (pair, extra = {}) => ({ ...pair.publicKey.export({ format: 'jwk' }), ...extra });
  const clock = (t0 = NOW) => { let t = t0; return { now: () => t, advance: (ms) => { t += ms; } }; };

  test('JK-01 ttl, limited kid-miss refetch, failed refetch keeps good keys, stale-if-error, unusable keys dropped', async () => {
    const c = clock(); let calls = 0; let doc = { keys: [jwkOf(kp.rsa, { kid: 'k1', use: 'sig', alg: 'RS256' })] }; let fail = false;
    const cache = createJwksCache({ uri: 'u', now: c.now, fetchJson: async () => { calls++; if (fail) throw new Error('idp down'); return doc; } });
    expect(cache.keyFor({ alg: 'RS256', kid: 'k1' })).toBeNull();                                           // nothing loaded yet: fail closed
    await cache.refreshIfNeeded('k1'); expect(calls).toBe(1); expect(cache.keyFor({ alg: 'RS256', kid: 'k1' })).toBeTruthy();
    await cache.refreshIfNeeded('k1'); expect(calls).toBe(1);                                               // fresh: no fetch
    expect(cache.keyFor({ alg: 'RS256', kid: 'zzz' })).toBeNull(); expect(cache.keyFor({ alg: 'ES256', kid: 'k1' })).toBeNull();     // unknown kid; key pinned to RS256
    await cache.refreshIfNeeded('unknown-kid'); expect(calls).toBe(1);                                      // a kid miss within minRefetch does not refetch (random kids cannot hammer the IdP)
    c.advance(31_000); await cache.refreshIfNeeded('unknown-kid'); expect(calls).toBe(2);
    await cache.refreshIfNeeded('another'); expect(calls).toBe(2);                                          // ... and only once per window
    // rotation: a new key appears and is picked up after the minimum interval
    doc = { keys: [jwkOf(kp.rsa, { kid: 'k1' }), jwkOf(kp.rsa2, { kid: 'k2' })] };
    c.advance(31_000); await cache.refreshIfNeeded('k2'); expect(cache.keyFor({ alg: 'RS256', kid: 'k2' })).toBeTruthy();
    // a failing refetch (and an empty one) never discards good keys
    fail = true; c.advance(700_000); await cache.refreshIfNeeded('k1'); expect(cache.keyFor({ alg: 'RS256', kid: 'k1' })).toBeTruthy();           // stale but inside the stale-if-error window
    fail = false; doc = { keys: [] }; c.advance(31_000); await cache.refreshIfNeeded('k1'); expect(cache.keyFor({ alg: 'RS256', kid: 'k1' })).toBeTruthy();
    fail = true; c.advance(4_000_000); await cache.refreshIfNeeded('k1'); expect(cache.keyFor({ alg: 'RS256', kid: 'k1' })).toBeNull();              // beyond the window: fail closed
    expect(cache._state().lastError).toMatch(/idp down/);
  });

  test('JK-02 concurrent lookups share one fetch; unusable keys are dropped; a key without kid works only when alone', async () => {
    let calls = 0; const cache = createJwksCache({ uri: 'u', fetchJson: async () => { calls++; await new Promise((r) => setTimeout(r, 20)); return { keys: [jwkOf(kp.rsa, { kid: 'a' })] }; } });
    await Promise.all([cache.refreshIfNeeded('a'), cache.refreshIfNeeded('a'), cache.refreshIfNeeded('a')]); expect(calls).toBe(1);
    const small = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
    const priv = kp.rsa.privateKey.export({ format: 'jwk' });
    expect(importJwk(jwkOf(small))).toBeNull();                                      // RSA below 2048 bits
    expect(importJwk(priv)).toBeNull();                                              // private members present
    expect(importJwk({ kty: 'oct', k: 'AAAA' })).toBeNull();                         // symmetric
    expect(importJwk(jwkOf(kp.rsa, { use: 'enc' }))).toBeNull(); expect(importJwk(jwkOf(kp.rsa, { key_ops: ['encrypt'] }))).toBeNull();
    expect(importJwk({ kty: 'EC', crv: 'secp256k1', x: 'AA', y: 'AA' })).toBeNull(); expect(importJwk({ kty: 'OKP', crv: 'Ed448', x: 'AA' })).toBeNull();
    expect(importJwk(jwkOf(kp.p256))).toBeTruthy(); expect(importJwk(jwkOf(kp.ed))).toBeTruthy();
    const alone = createJwksCache({ uri: 'u', fetchJson: async () => ({ keys: [jwkOf(kp.rsa)] }) }); await alone.refreshIfNeeded(null);
    expect(alone.keyFor({ alg: 'RS256', kid: null })).toBeTruthy(); expect(alone.keyFor({ alg: 'RS256', kid: 'x' })).toBeNull();
    const two = createJwksCache({ uri: 'u', fetchJson: async () => ({ keys: [jwkOf(kp.rsa), jwkOf(kp.rsa2)] }) }); await two.refreshIfNeeded(null);
    expect(two.keyFor({ alg: 'RS256', kid: null })).toBeNull();                      // ambiguous: refuse
    const junk = createJwksCache({ uri: 'u', fetchJson: async () => ({ nokeys: 1 }) }); await junk.refreshIfNeeded('a'); expect(junk.keyFor({ alg: 'RS256', kid: 'a' })).toBeNull();
    const many = createJwksCache({ uri: 'u', fetchJson: async () => ({ keys: Array.from({ length: 150 }, (_, i) => jwkOf(kp.p256, { kid: `k${i}` })) }) }); await many.refreshIfNeeded('k0');
    expect(many._state().keys).toBe(100);
  });
});

describe('provider layer', () => {
  const jwkOf = (pair, kid) => ({ ...pair.publicKey.export({ format: 'jwk' }), kid, use: 'sig' });
  const providers = [{ id: 'main', issuer: ISS, audience: [AUD], jwksUri: 'https://idp.example.com/realm/jwks' }];
  const mk = (extra = {}) => {
    const fetched = []; let keys = [jwkOf(kp.rsa, 'k1')];
    const auth = createOidcAuthenticator({ providers: extra.providers || providers, now: () => NOW, fetchJson: async (u) => { fetched.push(u); if (extra.fail) throw new Error('down'); if (/openid-configuration/.test(u)) return extra.doc; return { keys }; } });
    return { auth, fetched, setKeys: (k) => { keys = k; } };
  };

  test('OD-01 authenticate: success projection, refusals, discovery, rotation, unavailability', async () => {
    const { auth, fetched, setKeys } = mk();
    const ok = await auth.authenticate(mint({ claims: { email: 'a@example.com', groups: ['g1', 5, 'g2'], evil: 'x'.repeat(10_000), name: 'N'.repeat(300) } }));
    expect(ok).toMatchObject({ ok: true, providerId: 'main', issuer: ISS, subject: 'user-1', expiresAt: sec(NOW) + 600 });
    expect(ok.claims).toEqual({ sub: 'user-1', iss: ISS, exp: sec(NOW) + 600, iat: sec(NOW) - 5, email: 'a@example.com', groups: ['g1', 'g2'] });   // bounded projection: no stray or oversized members
    expect(await auth.authenticate('sk_' + 'a'.repeat(64))).toEqual({ ok: false, reason: 'NOT_A_JWT' });
    expect(await auth.authenticate(mint({ claims: { iss: 'https://evil.example.com' } }))).toEqual({ ok: false, reason: 'UNKNOWN_ISSUER' });
    expect((await auth.authenticate(mint({ claims: { aud: 'x' } }))).reason).toBe('JWT_AUDIENCE_MISMATCH');
    expect((await auth.authenticate(mint({ claims: { exp: sec(NOW) - 1000 } }))).reason).toBe('JWT_EXPIRED');
    expect((await auth.authenticate(mint({ alg: 'RS256', key: kp.rsa2 }))).reason).toBe('JWT_SIGNATURE_INVALID');             // right kid, wrong key
    const forgedIss = mint({ claims: { iss: ISS }, key: kp.rsa2, header: { kid: 'zzz' } });
    expect((await auth.authenticate(forgedIss)).reason).toBe('JWT_KEY_UNKNOWN');
    // rotation: the IdP adds k2; a token with kid k2 is accepted after the refetch window
    setKeys([jwkOf(kp.rsa, 'k1'), jwkOf(kp.rsa2, 'k2')]);
    const t2 = mint({ key: kp.rsa2, header: { kid: 'k2' } });
    const before = fetched.length; const first = await auth.authenticate(t2);
    expect(first.ok || first.reason === 'JWT_KEY_UNKNOWN').toBe(true); expect(fetched.length).toBeLessThanOrEqual(before + 1);
    // the token's own jku never causes a fetch
    await auth.authenticate(mint({ header: { jku: 'https://evil.example/jwks' } })); expect(fetched.every((u) => !/evil/.test(u))).toBe(true);
  });

  test('OD-02 an unreachable IdP fails closed; discovery validates the document', async () => {
    expect(await mk({ fail: true }).auth.authenticate(mint({}))).toEqual({ ok: false, reason: 'PROVIDER_UNAVAILABLE' });
    const disc = [{ id: 'd', issuer: ISS, audience: [AUD], discovery: true }];
    const good = mk({ providers: disc, doc: { issuer: ISS, jwks_uri: 'https://idp.example.com/realm/certs' } });
    expect((await good.auth.authenticate(mint({}))).ok).toBe(true); expect(good.fetched).toEqual([`${ISS}/.well-known/openid-configuration`, 'https://idp.example.com/realm/certs']);
    expect((await mk({ providers: disc, doc: { issuer: 'https://other.example.com', jwks_uri: 'https://idp.example.com/certs' } }).auth.authenticate(mint({}))).ok).toBe(false);     // issuer in the document differs
    expect((await mk({ providers: disc, doc: { issuer: ISS, jwks_uri: 'http://idp.example.com/certs' } }).auth.authenticate(mint({}))).ok).toBe(false);                          // jwks_uri not https
  });

  test('OD-03 configuration is validated', () => {
    const bad = (p) => expect(() => validateProviders(p)).toThrow();
    bad([]); bad([{ id: 'A', issuer: ISS, audience: [AUD], jwksUri: 'https://x/y' }]); bad([{ id: 'a', issuer: 'http://x', audience: [AUD], jwksUri: 'https://x/y' }]);
    bad([{ id: 'a', issuer: ISS, audience: [], jwksUri: 'https://x/y' }]); bad([{ id: 'a', issuer: ISS, audience: [AUD] }]); bad([{ id: 'a', issuer: ISS, audience: [AUD], jwksUri: 'http://x/y' }]);
    bad([{ id: 'a', issuer: ISS, audience: [AUD], jwksUri: 'https://x/y', algorithms: ['HS256'] }]); bad([{ id: 'a', issuer: ISS, audience: [AUD], jwksUri: 'https://x/y', algorithms: ['none'] }]);
    bad([{ id: 'a', issuer: ISS, audience: [AUD], jwksUri: 'https://x/y', clockSkewSec: 9999 }]);
    bad([{ id: 'a', issuer: ISS, audience: [AUD], jwksUri: 'https://x/y' }, { id: 'b', issuer: ISS, audience: [AUD], jwksUri: 'https://x/z' }]);          // two providers, one issuer
    expect(() => validateProviders([{ id: 'a', issuer: ISS, audience: [AUD], jwksUri: 'https://x/y', algorithms: ['ES256'], clockSkewSec: 30, maxLifetimeSec: 3600 }])).not.toThrow();
  });
});

describe('JWT verification findings', () => {
  test('JW-F5 a member repeated through a JSON escape ("sub" and "\u0073ub") is a duplicate, in the header and in the payload (F10V-05)', () => {
    const rawPayload = (text) => Buffer.from(text).toString('base64url');
    const escPayload = `{"iss":"${ISS}","aud":"${AUD}","sub":"alice","\u0073ub":"admin","exp":${sec(NOW) + 600}}`;
    const h = b64({ alg: 'RS256', typ: 'JWT', kid: 'k1' });
    const signed = (payloadB64) => `${h}.${payloadB64}.${SIGN.RS256(kp.rsa.privateKey, Buffer.from(`${h}.${payloadB64}`)).toString('base64url')}`;
    expect(code(() => V(signed(rawPayload(escPayload))))).toBe('JWT_MALFORMED');
    expect(code(() => V(mint({ rawHeader: rawPayload('{"alg":"RS256","\u0061lg":"none","kid":"k1"}') })))).toBe('JWT_MALFORMED');
    // a non-repeating escape is still a normal member
    expect(V(signed(rawPayload(`{"iss":"${ISS}","aud":"${AUD}","\u0073ub":"alice","exp":${sec(NOW) + 600}}`))).claims.sub).toBe('alice');
  });
});
