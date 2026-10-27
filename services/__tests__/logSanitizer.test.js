'use strict';

/**
 * Logging Security Tests — Component 44.7
 *
 * LS-CFG-01…05   logSanitizerConfig: defaults and env var overrides
 * LS-CLS-01…20   logClassifier: AUDIT / SECURITY / OPERATIONAL classification
 * LS-FLD-01…20   sanitize: field-name-based redaction
 * LS-PII-01…25   sanitize: PII value pattern scanning
 * LS-TOK-01…18   sanitize: token / credential value pattern scanning
 * LS-CRY-01…12   sanitize: cryptographic material detection
 * LS-STR-01…25   sanitize: data-structure handling (arrays, maps, sets, errors, …)
 * LS-EDG-01…20   sanitize: edge cases (circular, depth, large payloads, …)
 * LS-MET-01…08   sanitize: metrics (snapshot / reset)
 * LS-INT-01…10   logger integration: emit() produces sanitized, classified records
 */

// ── Imports ───────────────────────────────────────────────────────────────────

const {
  sanitize,
  snapshot,
  reset,
  _isSensitiveField,
  _sanitizeString,
  SENSITIVE_FIELD_STEMS,
} = require('../logSanitizer');

const { classify }                   = require('../logClassifier');
const { buildConfig, defaultConfig } = require('../logSanitizerConfig');

// ── Shared helpers ────────────────────────────────────────────────────────────

function cfg(overrides = {}) {
  return Object.freeze({ ...defaultConfig, ...overrides });
}

const SAMPLE_JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
  '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ' +
  '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

const SAMPLE_PEM_PRIVATE =
  '-----BEGIN RSA PRIVATE KEY-----\n' +
  'MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5TNJT3OMZP5gYMFhBWFzLBj9HQTH8ZNHB\n' +
  '-----END RSA PRIVATE KEY-----';

const SAMPLE_PEM_EC =
  '-----BEGIN EC PRIVATE KEY-----\n' +
  'MHQCAQEEIOPm8+VR3pA7ygTFe9Sv8kNlYxHuG5LrM9mBD8KdNSuooAoGCCqGSM49\n' +
  '-----END EC PRIVATE KEY-----';

const SAMPLE_ED25519_PEM =
  '-----BEGIN PRIVATE KEY-----\n' +
  'MC4CAQAwBQYDK2VwBCIEIFmEkWY+TNqGqp7YZBxCc7VCQqG8y3W/dH9U7lRrpvzr\n' +
  '-----END PRIVATE KEY-----';

beforeEach(() => reset());

// ── LS-CFG: logSanitizerConfig ────────────────────────────────────────────────

describe('LS-CFG — logSanitizerConfig', () => {
  test('LS-CFG-01 defaultConfig has expected defaults', () => {
    expect(defaultConfig.scanPii).toBe(true);
    expect(defaultConfig.scanTokens).toBe(true);
    expect(defaultConfig.scanCrypto).toBe(true);
    expect(defaultConfig.redactIpAddresses).toBe(false);
    expect(defaultConfig.maxDepth).toBe(10);
    expect(defaultConfig.maxStringLength).toBe(10000);
  });

  test('LS-CFG-02 defaultConfig is frozen', () => {
    expect(Object.isFrozen(defaultConfig)).toBe(true);
  });

  test('LS-CFG-03 buildConfig returns object with all placeholder keys', () => {
    const c = buildConfig();
    expect(c.placeholderRedacted).toBe('[REDACTED]');
    expect(c.placeholderEmail).toBe('[EMAIL]');
    expect(c.placeholderPhone).toBe('[PHONE]');
    expect(c.placeholderToken).toBe('[TOKEN]');
    expect(c.placeholderCrypto).toBe('[CRYPTO]');
    expect(c.placeholderPii).toBe('[PII]');
    expect(c.placeholderBuffer).toBe('[BUFFER]');
    expect(c.placeholderCircular).toBe('[CIRCULAR]');
    expect(c.placeholderDepthExceeded).toBe('[MAX_DEPTH]');
  });

  test('LS-CFG-04 buildConfig returns frozen object', () => {
    expect(Object.isFrozen(buildConfig())).toBe(true);
  });

  test('LS-CFG-05 _isSensitiveField matches normalized forms', () => {
    expect(_isSensitiveField('Authorization')).toBe(true);
    expect(_isSensitiveField('AUTHORIZATION')).toBe(true);
    expect(_isSensitiveField('X-Api-Key')).toBe(true);  // strips "X-" prefix -> 'apikey'
    expect(_isSensitiveField('apiKey')).toBe(true);     // normalizes to 'apikey'
    expect(_isSensitiveField('private_key')).toBe(true);// normalizes to 'privatekey'
    expect(_isSensitiveField('count')).toBe(false);
  });

  describe('LS-CFG-06 "X-" HTTP header prefix normalization', () => {
    test('X-Api-Key (mixed case, as sent over the wire) is sensitive', () => {
      expect(_isSensitiveField('X-Api-Key')).toBe(true);
    });

    test('x-api-key (lowercase) is sensitive', () => {
      expect(_isSensitiveField('x-api-key')).toBe(true);
    });

    test('X-Auth-Token is sensitive', () => {
      expect(_isSensitiveField('X-Auth-Token')).toBe(true);
    });

    test('X-Access-Token is sensitive', () => {
      expect(_isSensitiveField('X-Access-Token')).toBe(true);
    });

    test('X-Csrf-Token is sensitive', () => {
      expect(_isSensitiveField('X-Csrf-Token')).toBe(true);
    });

    test('X-Authorization is sensitive', () => {
      expect(_isSensitiveField('X-Authorization')).toBe(true);
    });

    test('sanitize() fully redacts an X-Api-Key object field', () => {
      expect(sanitize({ 'X-Api-Key': 'sk_live_abcdef123456' })['X-Api-Key']).toBe('[REDACTED]');
    });

    test('unrelated "X-" headers remain unaffected (no false positives)', () => {
      const r = sanitize({
        'X-Request-Id':      'req-abc-123',
        'X-Forwarded-For':   '203.0.113.5',
        'X-Correlation-Id':  'corr-456',
      });
      expect(r['X-Request-Id']).toBe('req-abc-123');
      expect(r['X-Forwarded-For']).toBe('203.0.113.5');
      expect(r['X-Correlation-Id']).toBe('corr-456');
    });

    test('words that merely start with "x" but have no hyphen are unaffected', () => {
      expect(_isSensitiveField('xray')).toBe(false);
      expect(_isSensitiveField('xerox')).toBe(false);
    });
  });
});

// ── LS-CLS: logClassifier ─────────────────────────────────────────────────────

describe('LS-CLS — logClassifier: classification', () => {
  test('LS-CLS-01 CRITICAL level → SECURITY regardless of event', () => {
    expect(classify('CRITICAL', 'EXECUTION_INVARIANT_VIOLATED')).toBe('SECURITY');
    expect(classify('CRITICAL', 'KEYSTORE_LOADED')).toBe('SECURITY');
  });

  test('LS-CLS-02 FATAL level → SECURITY', () => {
    expect(classify('FATAL', 'STARTUP_FAILURE')).toBe('SECURITY');
  });

  test('LS-CLS-03 GATEWAY_ALLOW → AUDIT', () => {
    expect(classify('INFO', 'GATEWAY_ALLOW')).toBe('AUDIT');
  });

  test('LS-CLS-04 GATEWAY_BLOCK → AUDIT', () => {
    expect(classify('WARN', 'GATEWAY_BLOCK')).toBe('AUDIT');
  });

  test('LS-CLS-05 RBAC_ALLOW → AUDIT', () => {
    expect(classify('INFO', 'RBAC_ALLOW')).toBe('AUDIT');
  });

  test('LS-CLS-06 RBAC_DENY → SECURITY', () => {
    expect(classify('WARN', 'RBAC_DENY')).toBe('SECURITY');
  });

  test('LS-CLS-07 WEBHOOK_DNS_REBINDING_DETECTED → SECURITY', () => {
    expect(classify('CRITICAL', 'WEBHOOK_DNS_REBINDING_DETECTED')).toBe('SECURITY');
  });

  test('LS-CLS-08 WEBHOOK_DELIVERY_BLOCKED → SECURITY', () => {
    expect(classify('WARN', 'WEBHOOK_DELIVERY_BLOCKED')).toBe('SECURITY');
  });

  test('LS-CLS-09 WEBHOOK_DELIVERY_SENT → AUDIT', () => {
    expect(classify('INFO', 'WEBHOOK_DELIVERY_SENT')).toBe('AUDIT');
  });

  test('LS-CLS-10 WEBHOOK_DELIVERY_FAILED → AUDIT', () => {
    expect(classify('WARN', 'WEBHOOK_DELIVERY_FAILED')).toBe('AUDIT');
  });

  test('LS-CLS-11 WEBHOOK_CIRCUIT_BREAKER_STATE → SECURITY (contains CIRCUIT_BREAKER)', () => {
    expect(classify('WARN', 'WEBHOOK_CIRCUIT_BREAKER_STATE')).toBe('SECURITY');
  });

  test('LS-CLS-12 OPS_AUTH_INVALID_TOKEN → SECURITY', () => {
    expect(classify('WARN', 'OPS_AUTH_INVALID_TOKEN')).toBe('SECURITY');
  });

  test('LS-CLS-13 OPS_ALLOWLIST_BLOCKED → SECURITY', () => {
    expect(classify('WARN', 'OPS_ALLOWLIST_BLOCKED')).toBe('SECURITY');
  });

  test('LS-CLS-14 event ending in _REJECTED → SECURITY', () => {
    expect(classify('WARN', 'PROVIDER_SSRF_REJECTED')).toBe('SECURITY');
    expect(classify('WARN', 'WEBHOOK_REQUEST_REJECTED')).toBe('SECURITY');
  });

  test('LS-CLS-15 STREAM_STARTED → AUDIT', () => {
    expect(classify('INFO', 'STREAM_STARTED')).toBe('AUDIT');
  });

  test('LS-CLS-16 STREAM_AUDIT_RECORDED → AUDIT', () => {
    expect(classify('INFO', 'STREAM_AUDIT_RECORDED')).toBe('AUDIT');
  });

  test('LS-CLS-17 KEYSTORE_LOADED → OPERATIONAL', () => {
    expect(classify('INFO', 'KEYSTORE_LOADED')).toBe('OPERATIONAL');
  });

  test('LS-CLS-18 KEY_CREATED → OPERATIONAL', () => {
    expect(classify('INFO', 'KEY_CREATED')).toBe('OPERATIONAL');
  });

  test('LS-CLS-19 SHUTDOWN_STARTED → OPERATIONAL', () => {
    expect(classify('INFO', 'SHUTDOWN_STARTED')).toBe('OPERATIONAL');
  });

  test('LS-CLS-20 ALERTING_FRAMEWORK_INITIALIZED → OPERATIONAL', () => {
    expect(classify('INFO', 'ALERTING_FRAMEWORK_INITIALIZED')).toBe('OPERATIONAL');
  });
});

// ── LS-FLD: field-name-based redaction ───────────────────────────────────────

describe('LS-FLD — sanitize: field-name redaction', () => {
  test('LS-FLD-01 authorization field is redacted', () => {
    expect(sanitize({ authorization: 'Bearer abc' }).authorization).toBe('[REDACTED]');
  });

  test('LS-FLD-02 password field is redacted', () => {
    expect(sanitize({ password: 's3cr3t' }).password).toBe('[REDACTED]');
  });

  test('LS-FLD-03 token field is redacted', () => {
    expect(sanitize({ token: 'mytoken' }).token).toBe('[REDACTED]');
  });

  test('LS-FLD-04 secret field is redacted', () => {
    expect(sanitize({ secret: 'hmac-secret' }).secret).toBe('[REDACTED]');
  });

  test('LS-FLD-05 apiKey (camelCase) is redacted via normalization', () => {
    expect(sanitize({ apiKey: 'key-value' }).apiKey).toBe('[REDACTED]');
  });

  test('LS-FLD-06 private_key (snake_case) is redacted via normalization', () => {
    expect(sanitize({ private_key: 'pem-data' }).private_key).toBe('[REDACTED]');
  });

  test('LS-FLD-07 accessToken (camelCase) is redacted', () => {
    expect(sanitize({ accessToken: 'oauth-access' }).accessToken).toBe('[REDACTED]');
  });

  test('LS-FLD-08 refreshToken is redacted', () => {
    expect(sanitize({ refreshToken: 'refresh-val' }).refreshToken).toBe('[REDACTED]');
  });

  test('LS-FLD-09 clientSecret is redacted', () => {
    expect(sanitize({ clientSecret: 'cs-val' }).clientSecret).toBe('[REDACTED]');
  });

  test('LS-FLD-10 signingKey is redacted', () => {
    expect(sanitize({ signingKey: 'key-data' }).signingKey).toBe('[REDACTED]');
  });

  test('LS-FLD-11 email field is redacted', () => {
    expect(sanitize({ email: 'john@example.com' }).email).toBe('[REDACTED]');
  });

  test('LS-FLD-12 phone field is redacted', () => {
    expect(sanitize({ phone: '555-867-5309' }).phone).toBe('[REDACTED]');
  });

  test('LS-FLD-13 ssn field is redacted', () => {
    expect(sanitize({ ssn: '123-45-6789' }).ssn).toBe('[REDACTED]');
  });

  test('LS-FLD-14 iban field is redacted', () => {
    expect(sanitize({ iban: 'GB82WEST12345698765432' }).iban).toBe('[REDACTED]');
  });

  test('LS-FLD-15 creditCard field is redacted', () => {
    expect(sanitize({ creditCard: '4111111111111111' }).creditCard).toBe('[REDACTED]');
  });

  test('LS-FLD-16 non-sensitive fields are preserved', () => {
    const result = sanitize({ eventId: 'abc-123', count: 5, ok: true });
    expect(result.eventId).toBe('abc-123');
    expect(result.count).toBe(5);
    expect(result.ok).toBe(true);
  });

  test('LS-FLD-17 nested sensitive field is redacted', () => {
    const result = sanitize({ outer: { inner: { token: 'secret-token' } } });
    expect(result.outer.inner.token).toBe('[REDACTED]');
  });

  test('LS-FLD-18 sessionId field is redacted', () => {
    expect(sanitize({ sessionId: 'sess-abc123' }).sessionId).toBe('[REDACTED]');
  });

  test('LS-FLD-19 credentials field is redacted', () => {
    expect(sanitize({ credentials: { user: 'a', pass: 'b' } }).credentials).toBe('[REDACTED]');
  });

  test('LS-FLD-20 SENSITIVE_FIELD_STEMS is a non-empty Set', () => {
    expect(SENSITIVE_FIELD_STEMS).toBeInstanceOf(Set);
    expect(SENSITIVE_FIELD_STEMS.size).toBeGreaterThan(30);
  });
});

// ── LS-PII: PII value scanning ────────────────────────────────────────────────

describe('LS-PII — sanitize: PII value pattern scanning', () => {
  test('LS-PII-01 email in string value is replaced with [EMAIL]', () => {
    const r = sanitize({ msg: 'Contact john@example.com for support' });
    expect(r.msg).toBe('Contact [EMAIL] for support');
  });

  test('LS-PII-02 multiple emails in one string are all replaced', () => {
    const r = sanitize({ msg: 'From a@b.com to c@d.io' });
    expect(r.msg).not.toContain('@');
    expect(r.msg).toContain('[EMAIL]');
  });

  test('LS-PII-03 email with plus-addressing is replaced', () => {
    const r = sanitize({ msg: 'Tag address: user+tag@domain.co.uk found' });
    expect(r.msg).toContain('[EMAIL]');
    expect(r.msg).not.toContain('@');
  });

  test('LS-PII-04 SSN (xxx-xx-xxxx format) is replaced with [PII]', () => {
    const r = sanitize({ msg: 'SSN on file: 123-45-6789' });
    expect(r.msg).toContain('[PII]');
    expect(r.msg).not.toContain('123-45-6789');
  });

  test('LS-PII-05 SSN with invalid area code 000 is not replaced', () => {
    const r = sanitize({ msg: 'Ref: 000-45-6789' });
    expect(r.msg).not.toContain('[PII]');
  });

  test('LS-PII-06 US phone (NXX-NXX-XXXX) is replaced with [PHONE]', () => {
    const r = sanitize({ msg: 'Call 555-867-5309 now' });
    expect(r.msg).toContain('[PHONE]');
    expect(r.msg).not.toContain('555');
  });

  test('LS-PII-07 US phone with area code in parentheses is replaced', () => {
    const r = sanitize({ msg: 'Reach us at (800) 555-0100' });
    expect(r.msg).toContain('[PHONE]');
  });

  test('LS-PII-08 NANP phone with +1 prefix is replaced', () => {
    const r = sanitize({ msg: 'International: +1-800-555-0100' });
    expect(r.msg).toContain('[PHONE]');
  });

  test('LS-PII-09 international E.164 phone is replaced', () => {
    const r = sanitize({ msg: 'UK: +447911123456' });
    expect(r.msg).toContain('[PHONE]');
    expect(r.msg).not.toContain('+4479');
  });

  test('LS-PII-09b (NF-16): a decimal run INSIDE a hex digest is not a phone number — hashes survive intact', () => {
    // real BOOT_REPORT fingerprint that was logged as "...bc[PHONE]e5289c..." before the fix
    const digest = 'bb57656afe373bc6235090912e5289c90f58f28d6b1bd0035b27be87b5dd5fe5';
    expect(sanitize({ msg: `fingerprint ${digest}` }).msg).toBe(`fingerprint ${digest}`);
    expect(sanitize({ msg: `x1${'8005550100'}ab` }).msg).toBe('x18005550100ab');
    // phones delimited by punctuation/whitespace are still redacted
    expect(sanitize({ msg: 'tel:8005550100;' }).msg).toBe('tel:[PHONE];');
    expect(sanitize({ msg: '(800) 555-0100.' }).msg).toBe('[PHONE].');
    expect(sanitize({ msg: 'n=+1-800-555-0100,' }).msg).toBe('n=[PHONE],');
  });

  test('LS-PII-09c (Gate A #24): UUIDs are never rewritten as [PHONE] (or any PII placeholder)', () => {
    // deterministic pseudo-random UUIDs (LCG) plus adversarial all-digit / phone-like groups
    let x = 0x2545f491;
    const nx = () => { x = (Math.imul(x, 1103515245) + 12345) >>> 0; return x; };
    const hex = (n) => Array.from({ length: n }, () => '0123456789abcdef'[nx() % 16]).join('');
    const dig = (n) => Array.from({ length: n }, () => String(nx() % 10)).join('');
    const uuids = [
      '12345678-1234-1234-1234-123456789012', '80055501-0080-5550-1008-005550100800', '20000000-0000-4000-8000-000000000000',
      '550e8400-e29b-41d4-a716-446655440000',
      ...Array.from({ length: 2000 }, () => `${hex(8)}-${hex(4)}-4${hex(3)}-a${hex(3)}-${hex(12)}`),
      ...Array.from({ length: 1000 }, () => `${dig(8)}-${dig(4)}-${dig(4)}-${dig(4)}-${dig(12)}`),
    ];
    const changed = uuids.filter((u) => sanitize({ msg: `request ${u} done`, id: u }).msg !== `request ${u} done`);
    expect(changed).toEqual([]);
    for (const u of uuids.slice(0, 50)) expect(sanitize({ id: u }).id).toBe(u);
  });

  test('LS-PII-10 Visa credit card (Luhn-valid) is replaced with [PII]', () => {
    // 4111111111111111 — classic Visa test number, passes Luhn
    const r = sanitize({ msg: 'Card: 4111111111111111' });
    expect(r.msg).toContain('[PII]');
    expect(r.msg).not.toContain('4111');
  });

  test('LS-PII-11 Mastercard (Luhn-valid) is replaced with [PII]', () => {
    // 5500005555555559 — Mastercard test number
    const r = sanitize({ msg: 'MC: 5500005555555559' });
    expect(r.msg).toContain('[PII]');
  });

  test('LS-PII-12 Amex (Luhn-valid) is replaced with [PII]', () => {
    // 378282246310005 — Amex test number
    const r = sanitize({ msg: 'Amex: 378282246310005' });
    expect(r.msg).toContain('[PII]');
  });

  test('LS-PII-13 random 16-digit number failing Luhn is not replaced', () => {
    // 4111111111111112 — fails Luhn (last digit incremented)
    const r = sanitize({ msg: 'Ref: 4111111111111112' });
    expect(r.msg).toBe('Ref: 4111111111111112');
  });

  test('LS-PII-14 UK IBAN is replaced with [PII]', () => {
    const r = sanitize({ msg: 'IBAN: GB82WEST12345698765432' });
    expect(r.msg).toContain('[PII]');
    expect(r.msg).not.toContain('GB82');
  });

  test('LS-PII-15 German IBAN is replaced with [PII]', () => {
    const r = sanitize({ msg: 'DE89370400440532013000' });
    expect(r.msg).toContain('[PII]');
  });

  test('LS-PII-16 PII scanning disabled by config leaves values unchanged', () => {
    const c = cfg({ scanPii: false });
    const r = sanitize({ msg: 'john@example.com' }, c);
    expect(r.msg).toBe('john@example.com');
  });

  test('LS-PII-17 email in nested object value is replaced', () => {
    const r = sanitize({ user: { info: { contact: 'alice@example.org' } } });
    expect(r.user.info.contact).toContain('[EMAIL]');
  });

  test('LS-PII-18 email in array element is replaced', () => {
    const r = sanitize({ emails: ['a@b.com', 'c@d.org'] });
    expect(r.emails).toEqual(['[EMAIL]', '[EMAIL]']);
  });

  test('LS-PII-19 PII detection does not affect non-PII strings', () => {
    const r = sanitize({ msg: 'All systems operational', count: 42 });
    expect(r.msg).toBe('All systems operational');
  });

  test('LS-PII-20 IP address not redacted by default', () => {
    const r = sanitize({ ip: '192.168.1.1' });
    // 'ip' field name is not a sensitive stem, value scanner skips IPs by default
    expect(r.ip).toBe('192.168.1.1');
  });

  test('LS-PII-21 IP address redacted when redactIpAddresses = true', () => {
    const c = cfg({ redactIpAddresses: true });
    const r = sanitize({ msg: 'Request from 10.0.0.1' }, c);
    expect(r.msg).toContain('[IP]');
    expect(r.msg).not.toContain('10.0.0.1');
  });

  test('LS-PII-22 multiple PII types in one string are all replaced', () => {
    const r = sanitize({ msg: 'User john@acme.com SSN 321-54-9876 called' });
    expect(r.msg).not.toContain('@');
    expect(r.msg).not.toContain('321-54-9876');
    expect(r.msg).toContain('[EMAIL]');
    expect(r.msg).toContain('[PII]');
  });

  test('LS-PII-23 standalone sanitize call on a string works', () => {
    const r = sanitize('Email me at hello@test.example');
    expect(r).toContain('[EMAIL]');
  });

  test('LS-PII-24 Discover card (Luhn-valid) is replaced with [PII]', () => {
    // 6011111111111117 — Discover test number
    const r = sanitize({ msg: '6011111111111117' });
    expect(r.msg).toContain('[PII]');
  });

  test('LS-PII-25 PII scanning in Error message works', () => {
    const err = new Error('Failed for user admin@corp.example.com');
    const r = sanitize(err);
    expect(r.message).toContain('[EMAIL]');
    expect(r.message).not.toContain('@');
  });
});

// ── LS-TOK: token and credential scanning ────────────────────────────────────

describe('LS-TOK — sanitize: token / credential value scanning', () => {
  test('LS-TOK-01 JWT in string value is replaced with [TOKEN]', () => {
    const r = sanitize({ msg: `Auth: ${SAMPLE_JWT}` });
    expect(r.msg).toContain('[TOKEN]');
    expect(r.msg).not.toContain('eyJ');
  });

  test('LS-TOK-02 standalone JWT string is replaced', () => {
    expect(sanitize(SAMPLE_JWT)).toBe('[TOKEN]');
  });

  test('LS-TOK-03 Bearer token in string is replaced', () => {
    const r = sanitize({ header: 'Bearer supersecretbearertokenvalue123' });
    expect(r.header).toContain('[TOKEN]');
    expect(r.header).not.toContain('supersecret');
  });

  test('LS-TOK-04 Bearer token scanning disabled does not redact value', () => {
    const c = cfg({ scanTokens: false });
    const r = sanitize({ header: 'Bearer supersecretbearertokenvalue123' }, c);
    expect(r.header).toContain('Bearer');
  });

  test('LS-TOK-05 authorization field name causes full value redaction (field-name gate wins)', () => {
    const r = sanitize({ authorization: `Bearer ${SAMPLE_JWT}` });
    expect(r.authorization).toBe('[REDACTED]');
  });

  test('LS-TOK-06 Basic auth header in string is replaced', () => {
    const r = sanitize({ msg: 'Basic dXNlcm5hbWU6cGFzc3dvcmQ=' });
    expect(r.msg).toContain('[TOKEN]');
    expect(r.msg).not.toContain('dXNlcm');
  });

  test('LS-TOK-07 Token keyword prefix triggers replacement', () => {
    const r = sanitize({ msg: 'Token a1b2c3d4e5f6g7h8i9j0k1l2m3' });
    expect(r.msg).toContain('[TOKEN]');
  });

  test('LS-TOK-08 OAuth access token in object field by name is redacted', () => {
    expect(sanitize({ oauthToken: 'ya29.abcdefghijklmno' }).oauthToken).toBe('[REDACTED]');
  });

  test('LS-TOK-09 OAuth refresh token in object field by name is redacted', () => {
    expect(sanitize({ refreshToken: '1//0efgh' }).refreshToken).toBe('[REDACTED]');
  });

  test('LS-TOK-10 csrfToken field by name is redacted', () => {
    expect(sanitize({ csrfToken: 'csrf-abc-123' }).csrfToken).toBe('[REDACTED]');
  });

  test('LS-TOK-11 idToken field by name is redacted', () => {
    expect(sanitize({ idToken: 'openid-token-xyz' }).idToken).toBe('[REDACTED]');
  });

  test('LS-TOK-12 JWT in nested object is replaced', () => {
    const r = sanitize({ auth: { value: SAMPLE_JWT } });
    // 'auth' field is sensitive by name → [REDACTED] (field gate wins)
    expect(r.auth).toBe('[REDACTED]');
  });

  test('LS-TOK-13 JWT embedded mid-string is replaced', () => {
    const r = sanitize({ msg: `Token is ${SAMPLE_JWT} for user 42` });
    expect(r.msg).toContain('[TOKEN]');
    expect(r.msg).not.toContain('eyJ');
  });

  test('LS-TOK-14 non-JWT base64 string without eyJ is not replaced', () => {
    const r = sanitize({ msg: 'aGVsbG8gd29ybGQ=' });
    expect(r.msg).toBe('aGVsbG8gd29ybGQ=');
  });

  test('LS-TOK-15 API key field name triggers field-name redaction', () => {
    expect(sanitize({ apiKey: 'sk_live_abcdefghij1234567890' }).apiKey).toBe('[REDACTED]');
  });

  test('LS-TOK-16 accessKey field by name is redacted', () => {
    expect(sanitize({ accessKey: 'AKIAIOSFODNN7EXAMPLE' }).accessKey).toBe('[REDACTED]');
  });

  test('LS-TOK-17 secretKey field by name is redacted', () => {
    expect(sanitize({ secretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' }).secretKey).toBe('[REDACTED]');
  });

  test('LS-TOK-18 webhookSecret field by name is redacted', () => {
    expect(sanitize({ webhookSecret: 'whsec_abcde12345' }).webhookSecret).toBe('[REDACTED]');
  });
});

// ── LS-CRY: cryptographic material ───────────────────────────────────────────

describe('LS-CRY — sanitize: cryptographic material', () => {
  test('LS-CRY-01 RSA private key PEM block is replaced with [CRYPTO]', () => {
    const r = sanitize({ msg: `Key: ${SAMPLE_PEM_PRIVATE}` });
    expect(r.msg).toContain('[CRYPTO]');
    expect(r.msg).not.toContain('BEGIN RSA');
  });

  test('LS-CRY-02 EC private key PEM block is replaced with [CRYPTO]', () => {
    const r = sanitize({ keyData: SAMPLE_PEM_EC });
    // 'keyData' is sensitive by field name → [REDACTED] (field gate wins)
    expect(r.keyData).toBe('[REDACTED]');
  });

  test('LS-CRY-03 Ed25519 private key PEM in string value is replaced', () => {
    const r = sanitize({ msg: `Signing key: ${SAMPLE_ED25519_PEM}` });
    expect(r.msg).toContain('[CRYPTO]');
    expect(r.msg).not.toContain('BEGIN PRIVATE KEY');
  });

  test('LS-CRY-04 RSA public key PEM is replaced with [CRYPTO]', () => {
    const pemPub =
      '-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA\n-----END RSA PUBLIC KEY-----';
    const r = sanitize({ msg: pemPub });
    expect(r.msg).toContain('[CRYPTO]');
  });

  test('LS-CRY-05 CERTIFICATE PEM block is replaced with [CRYPTO]', () => {
    const pemCert =
      '-----BEGIN CERTIFICATE-----\nMIICITANBgkqhkiG\n-----END CERTIFICATE-----';
    const r = sanitize({ msg: `Cert: ${pemCert}` });
    expect(r.msg).toContain('[CRYPTO]');
  });

  test('LS-CRY-06 multiple PEM blocks in one string are all replaced', () => {
    const twoKeys = `${SAMPLE_PEM_PRIVATE}\n\n${SAMPLE_PEM_EC}`;
    const r = sanitize({ msg: twoKeys });
    expect(r.msg.split('[CRYPTO]').length - 1).toBeGreaterThanOrEqual(2);
  });

  test('LS-CRY-07 crypto scanning disabled leaves PEM unchanged', () => {
    const c = cfg({ scanCrypto: false });
    const r = sanitize({ msg: SAMPLE_PEM_PRIVATE }, c);
    expect(r.msg).toContain('BEGIN RSA PRIVATE KEY');
  });

  test('LS-CRY-08 privateKey field by name is redacted (field gate)', () => {
    expect(sanitize({ privateKey: SAMPLE_PEM_PRIVATE }).privateKey).toBe('[REDACTED]');
  });

  test('LS-CRY-09 AES key field by name (encryptionKey) is redacted', () => {
    const aesKey = Buffer.from('0'.repeat(32)).toString('hex');
    expect(sanitize({ encryptionKey: aesKey }).encryptionKey).toBe('[REDACTED]');
  });

  test('LS-CRY-10 HMAC key field by name (signingKey) is redacted', () => {
    expect(sanitize({ signingKey: 'hmac-sha256-secret-key' }).signingKey).toBe('[REDACTED]');
  });

  test('LS-CRY-11 hsmKey field is redacted', () => {
    expect(sanitize({ hsmKey: 'hsm-key-ref-abc' }).hsmKey).toBe('[REDACTED]');
  });

  test('LS-CRY-12 PEM block in Error message is replaced', () => {
    const err = new Error(`Config error: ${SAMPLE_PEM_PRIVATE}`);
    const r = sanitize(err);
    expect(r.message).toContain('[CRYPTO]');
    expect(r.message).not.toContain('BEGIN RSA');
  });
});

// ── LS-STR: data structure handling ──────────────────────────────────────────

describe('LS-STR — sanitize: data structures', () => {
  test('LS-STR-01 plain object is returned as new plain object', () => {
    const original = { a: 1 };
    const result   = sanitize(original);
    expect(result).not.toBe(original);
    expect(result.a).toBe(1);
  });

  test('LS-STR-02 array of strings is sanitized element-by-element', () => {
    const r = sanitize(['hello', 'john@example.com', 42]);
    expect(r[0]).toBe('hello');
    expect(r[1]).toBe('[EMAIL]');
    expect(r[2]).toBe(42);
  });

  test('LS-STR-03 deeply nested object is sanitized at each level', () => {
    const r = sanitize({ a: { b: { c: { secret: 'val' } } } });
    expect(r.a.b.c.secret).toBe('[REDACTED]');
  });

  test('LS-STR-04 Map with sensitive key is sanitized', () => {
    const m = new Map([['password', 's3cr3t'], ['count', 5]]);
    const r = sanitize(m);
    expect(r.password).toBe('[REDACTED]');
    expect(r.count).toBe(5);
  });

  test('LS-STR-05 Map keys are converted to strings for field-name check', () => {
    const m = new Map([['apiKey', 'my-key']]);
    const r = sanitize(m);
    expect(r.apiKey).toBe('[REDACTED]');
  });

  test('LS-STR-06 Set is converted to an array', () => {
    const s = new Set(['hello', 'world']);
    const r = sanitize(s);
    expect(Array.isArray(r)).toBe(true);
    expect(r).toEqual(['hello', 'world']);
  });

  test('LS-STR-07 Set containing PII values is sanitized', () => {
    const s = new Set(['alice@example.com', 'bob@example.com']);
    const r = sanitize(s);
    expect(r).toEqual(['[EMAIL]', '[EMAIL]']);
  });

  test('LS-STR-08 Buffer is replaced with [BUFFER]', () => {
    expect(sanitize(Buffer.from('secret data'))).toBe('[BUFFER]');
  });

  test('LS-STR-09 Buffer in object field is replaced with [BUFFER]', () => {
    const r = sanitize({ data: Buffer.from('raw') });
    expect(r.data).toBe('[BUFFER]');
  });

  test('LS-STR-10 Error object is converted to plain object with name, message, stack', () => {
    const err = new Error('something went wrong');
    const r   = sanitize(err);
    expect(r.name).toBe('Error');
    expect(r.message).toBe('something went wrong');
    expect(typeof r.stack).toBe('string');
  });

  test('LS-STR-11 Error stack trace is sanitized for PII', () => {
    const err = new Error('Contact admin@corp.example at x');
    const r   = sanitize(err);
    expect(r.message).not.toContain('@');
    expect(r.message).toContain('[EMAIL]');
  });

  test('LS-STR-12 Error with custom properties sanitizes them', () => {
    const err = new Error('fail');
    err.statusCode = 500;
    err.token      = 'secret-token';
    const r = sanitize(err);
    expect(r.statusCode).toBe(500);
    expect(r.token).toBe('[REDACTED]');
  });

  test('LS-STR-13 null is returned as null', () => {
    expect(sanitize(null)).toBeNull();
  });

  test('LS-STR-14 undefined is returned as undefined', () => {
    expect(sanitize(undefined)).toBeUndefined();
  });

  test('LS-STR-15 number is returned unchanged', () => {
    expect(sanitize(42)).toBe(42);
    expect(sanitize(3.14)).toBe(3.14);
  });

  test('LS-STR-16 boolean is returned unchanged', () => {
    expect(sanitize(true)).toBe(true);
    expect(sanitize(false)).toBe(false);
  });

  test('LS-STR-17 Date is serialized to ISO string', () => {
    const d = new Date('2024-01-01T00:00:00Z');
    expect(sanitize(d)).toBe('2024-01-01T00:00:00.000Z');
  });

  test('LS-STR-18 RegExp is serialized to string', () => {
    expect(sanitize(/foo/gi)).toBe('/foo/gi');
  });

  test('LS-STR-19 Symbol is serialized to string', () => {
    const sym = Symbol('test');
    expect(sanitize(sym)).toBe('Symbol(test)');
  });

  test('LS-STR-20 BigInt is returned unchanged', () => {
    expect(sanitize(BigInt(9007199254740993))).toBe(BigInt(9007199254740993));
  });

  test('LS-STR-21 Function is replaced with [FUNCTION]', () => {
    expect(sanitize(() => {})).toBe('[FUNCTION]');
  });

  test('LS-STR-22 array of mixed types is handled correctly', () => {
    const r = sanitize([1, 'hello', null, true, { token: 'secret' }]);
    expect(r[0]).toBe(1);
    expect(r[1]).toBe('hello');
    expect(r[2]).toBeNull();
    expect(r[3]).toBe(true);
    expect(r[4].token).toBe('[REDACTED]');
  });

  test('LS-STR-23 nested array in object is sanitized', () => {
    const r = sanitize({ tags: ['a@b.com', 'normal'] });
    expect(r.tags[0]).toBe('[EMAIL]');
    expect(r.tags[1]).toBe('normal');
  });

  test('LS-STR-24 Map in nested object is sanitized', () => {
    const m = new Map([['password', 'secret']]);
    const r = sanitize({ info: m });
    expect(r.info.password).toBe('[REDACTED]');
  });

  test('LS-STR-25 TypeError (non-plain Error subclass) is sanitized', () => {
    const err = new TypeError('type mismatch at user@example.com');
    const r   = sanitize(err);
    expect(r.name).toBe('TypeError');
    expect(r.message).toContain('[EMAIL]');
  });
});

// ── LS-EDG: edge cases ────────────────────────────────────────────────────────

describe('LS-EDG — sanitize: edge cases', () => {
  test('LS-EDG-01 circular reference in object is replaced with [CIRCULAR]', () => {
    const a = { x: 1 };
    a.self = a;
    const r = sanitize(a);
    expect(r.x).toBe(1);
    expect(r.self).toBe('[CIRCULAR]');
  });

  test('LS-EDG-02 circular reference in array is replaced with [CIRCULAR]', () => {
    const arr = [1, 2];
    arr.push(arr);
    const r = sanitize(arr);
    expect(r[0]).toBe(1);
    expect(r[2]).toBe('[CIRCULAR]');
  });

  test('LS-EDG-03 mutual circular references are handled', () => {
    const a = { name: 'a' };
    const b = { name: 'b' };
    a.b = b;
    b.a = a;
    const r = sanitize(a);
    expect(r.name).toBe('a');
    expect(r.b.name).toBe('b');
    expect(r.b.a).toBe('[CIRCULAR]');
  });

  test('LS-EDG-04 max depth returns [MAX_DEPTH] placeholder', () => {
    const c = cfg({ maxDepth: 2 });
    const r = sanitize({ a: { b: { c: { deep: 'value' } } } }, c);
    expect(r.a.b.c).toBe('[MAX_DEPTH]');
  });

  test('LS-EDG-05 string exactly at maxStringLength is not truncated', () => {
    const c = cfg({ maxStringLength: 10 });
    const r = sanitize('1234567890', c);
    expect(r).toBe('1234567890');
  });

  test('LS-EDG-06 string exceeding maxStringLength is truncated', () => {
    const c = cfg({ maxStringLength: 5 });
    const r = sanitize('hello world', c);
    expect(r).toContain('hello');
    expect(r).toContain('[TRUNCATED]');
  });

  test('LS-EDG-07 empty string is returned as empty string', () => {
    expect(sanitize('')).toBe('');
  });

  test('LS-EDG-08 empty object is returned as empty object', () => {
    expect(sanitize({})).toEqual({});
  });

  test('LS-EDG-09 empty array is returned as empty array', () => {
    expect(sanitize([])).toEqual([]);
  });

  test('LS-EDG-10 sanitize never throws on malformed inputs', () => {
    expect(() => sanitize(undefined)).not.toThrow();
    expect(() => sanitize(null)).not.toThrow();
    expect(() => sanitize(NaN)).not.toThrow();
    expect(() => sanitize(Infinity)).not.toThrow();
  });

  test('LS-EDG-11 object with null prototype is handled', () => {
    const obj = Object.create(null);
    obj.email = 'test@example.com';
    // Object.keys works on null-prototype objects
    expect(() => sanitize(obj)).not.toThrow();
  });

  test('LS-EDG-12 very deeply nested object hits depth limit gracefully', () => {
    let obj = { leaf: 'value' };
    for (let i = 0; i < 20; i++) obj = { next: obj };
    expect(() => sanitize(obj)).not.toThrow();
    const r = sanitize(obj, cfg({ maxDepth: 5 }));
    expect(typeof r).toBe('object');
  });

  test('LS-EDG-13 large object (many keys) is sanitized without error', () => {
    const big = {};
    for (let i = 0; i < 500; i++) big[`key_${i}`] = `value_${i}`;
    expect(() => sanitize(big)).not.toThrow();
    expect(sanitize(big).key_0).toBe('value_0');
  });

  test('LS-EDG-14 object with non-enumerable properties does not expose them', () => {
    const obj = {};
    Object.defineProperty(obj, 'hidden', { value: 'secret', enumerable: false });
    const r = sanitize(obj);
    expect(r.hidden).toBeUndefined();
  });

  test('LS-EDG-15 NaN number is returned unchanged', () => {
    expect(sanitize(NaN)).toBeNaN();
  });

  test('LS-EDG-16 Infinity is returned unchanged', () => {
    expect(sanitize(Infinity)).toBe(Infinity);
  });

  test('LS-EDG-17 string with only whitespace is returned unchanged', () => {
    expect(sanitize('   ')).toBe('   ');
  });

  test('LS-EDG-18 parallel sanitize calls do not share WeakSet state', async () => {
    const a = { x: 1 };
    a.self = a;
    const results = await Promise.all(
      Array.from({ length: 50 }, () => Promise.resolve(sanitize(a)))
    );
    for (const r of results) {
      expect(r.x).toBe(1);
      expect(r.self).toBe('[CIRCULAR]');
    }
  });

  test('LS-EDG-19 sanitize does not mutate the original object', () => {
    const original = { password: 'mysecret', msg: 'hello' };
    sanitize(original);
    expect(original.password).toBe('mysecret');
    expect(original.msg).toBe('hello');
  });

  test('LS-EDG-20 config override is respected per-call', () => {
    const r1 = sanitize({ msg: 'john@example.com' }, cfg({ scanPii: false }));
    const r2 = sanitize({ msg: 'john@example.com' }, cfg({ scanPii: true }));
    expect(r1.msg).toContain('@');
    expect(r2.msg).not.toContain('@');
  });
});

// ── LS-ERR: Error object sanitization ────────────────────────────────────────
//
// Covers: error.message, error.stack, error.cause, chained causes,
// AggregateError.errors, serialized exceptions, custom properties.

describe('LS-ERR — sanitize: Error object sanitization', () => {
  // ── error.message ──────────────────────────────────────────────────────────

  test('LS-ERR-01 error.message is sanitized for PII', () => {
    const err = new Error('Login failed for admin@corp.example.com');
    const r   = sanitize(err);
    expect(r.message).toBe('Login failed for [EMAIL]');
  });

  test('LS-ERR-02 error.message is sanitized for tokens', () => {
    const err = new Error(`Invalid token: ${SAMPLE_JWT}`);
    const r   = sanitize(err);
    expect(r.message).toContain('[TOKEN]');
    expect(r.message).not.toContain('eyJ');
  });

  test('LS-ERR-03 error.message is sanitized for crypto material', () => {
    const err = new Error(`Bad config: ${SAMPLE_PEM_PRIVATE}`);
    const r   = sanitize(err);
    expect(r.message).toContain('[CRYPTO]');
    expect(r.message).not.toContain('BEGIN RSA');
  });

  test('LS-ERR-04 clean error.message passes through unchanged', () => {
    const err = new Error('Connection refused after 3 retries');
    expect(sanitize(err).message).toBe('Connection refused after 3 retries');
  });

  // ── error.stack ────────────────────────────────────────────────────────────

  test('LS-ERR-05 error.stack is present in sanitized output', () => {
    const err = new Error('test');
    const r   = sanitize(err);
    expect(typeof r.stack).toBe('string');
    expect(r.stack.length).toBeGreaterThan(0);
  });

  test('LS-ERR-06 error.stack is sanitized for PII', () => {
    const err     = new Error('failure');
    err.stack     = 'Error: failure\n    at /app/src/service.js:10\n  user: jane@acme.org';
    const r       = sanitize(err);
    expect(r.stack).toContain('[EMAIL]');
    expect(r.stack).not.toContain('jane@acme.org');
  });

  test('LS-ERR-07 error.stack is sanitized for tokens', () => {
    const err  = new Error('auth failure');
    err.stack  = `Error: auth failure\n  token=${SAMPLE_JWT}`;
    const r    = sanitize(err);
    expect(r.stack).toContain('[TOKEN]');
    expect(r.stack).not.toContain('eyJ');
  });

  // ── error.cause ────────────────────────────────────────────────────────────
  // cause is non-enumerable (Object.keys() never yields it) — must be read via
  // hasOwnProperty.

  test('LS-ERR-08 error.cause string is sanitized for PII', () => {
    const err = new Error('outer', { cause: 'root cause: alice@secret.org' });
    const r   = sanitize(err);
    expect(r.cause).toBeDefined();
    expect(r.cause).toContain('[EMAIL]');
    expect(r.cause).not.toContain('alice@secret.org');
  });

  test('LS-ERR-09 error.cause as Error is sanitized recursively', () => {
    const cause = new Error('inner error: bob@internal.io SSN 123-45-6789');
    const outer = new Error('outer failure', { cause });
    const r     = sanitize(outer);
    expect(r.cause).toBeDefined();
    expect(r.cause.message).toContain('[EMAIL]');
    expect(r.cause.message).toContain('[PII]');
    expect(r.cause.message).not.toContain('bob@internal.io');
  });

  test('LS-ERR-10 error.cause is present in sanitized output when set', () => {
    const err = new Error('wrapper', { cause: 'downstream timeout' });
    const r   = sanitize(err);
    expect(Object.prototype.hasOwnProperty.call(r, 'cause')).toBe(true);
    expect(r.cause).toBe('downstream timeout');
  });

  test('LS-ERR-11 error without cause does not produce a cause field', () => {
    const err = new Error('plain error');
    const r   = sanitize(err);
    expect(Object.prototype.hasOwnProperty.call(r, 'cause')).toBe(false);
  });

  test('LS-ERR-12 chained cause: three levels deep are all sanitized', () => {
    const lvl3 = new Error('deep: user3@deep.org');
    const lvl2 = new Error('mid: user2@mid.org',  { cause: lvl3 });
    const lvl1 = new Error('top: user1@top.org',  { cause: lvl2 });
    const r    = sanitize(lvl1);
    expect(r.message).toContain('[EMAIL]');
    expect(r.cause.message).toContain('[EMAIL]');
    expect(r.cause.cause.message).toContain('[EMAIL]');
    expect(r.cause.cause.message).not.toContain('@');
  });

  test('LS-ERR-13 error.cause containing sensitive object is sanitized', () => {
    const cause = { token: 'bearer-secret', reason: 'expired' };
    const err   = new Error('auth failed', { cause });
    const r     = sanitize(err);
    expect(r.cause.token).toBe('[REDACTED]');
    expect(r.cause.reason).toBe('expired');
  });

  // ── AggregateError.errors ──────────────────────────────────────────────────
  // errors is non-enumerable — must be read via instanceof + property access.

  test('LS-ERR-14 AggregateError.errors array is present in sanitized output', () => {
    const agg = new AggregateError([new Error('a'), new Error('b')], 'group');
    const r   = sanitize(agg);
    expect(Array.isArray(r.errors)).toBe(true);
    expect(r.errors.length).toBe(2);
  });

  test('LS-ERR-15 AggregateError.errors[n].message is sanitized for PII', () => {
    const sub1 = new Error('failed for carol@payments.io');
    const sub2 = new Error('failed for dave@payments.io');
    const agg  = new AggregateError([sub1, sub2], 'batch failure');
    const r    = sanitize(agg);
    expect(r.errors[0].message).toBe('failed for [EMAIL]');
    expect(r.errors[1].message).toBe('failed for [EMAIL]');
  });

  test('LS-ERR-16 AggregateError.errors[n].stack is sanitized', () => {
    const sub  = new Error('sub err');
    sub.stack  = 'Error: sub err\n  token=' + SAMPLE_JWT;
    const agg  = new AggregateError([sub], 'agg');
    const r    = sanitize(agg);
    expect(r.errors[0].stack).toContain('[TOKEN]');
    expect(r.errors[0].stack).not.toContain('eyJ');
  });

  test('LS-ERR-17 AggregateError.errors[n].cause is sanitized', () => {
    const cause = new Error('root: eve@corp.example');
    const sub   = new Error('sub', { cause });
    const agg   = new AggregateError([sub], 'agg');
    const r     = sanitize(agg);
    expect(r.errors[0].cause.message).toContain('[EMAIL]');
  });

  test('LS-ERR-18 non-Error items in AggregateError.errors are sanitized', () => {
    const agg = new AggregateError(['frank@example.com', 42], 'mixed');
    const r   = sanitize(agg);
    expect(r.errors[0]).toBe('[EMAIL]');
    expect(r.errors[1]).toBe(42);
  });

  test('LS-ERR-19 AggregateError outer message is sanitized', () => {
    const agg = new AggregateError([], 'Batch error for grace@org.example');
    const r   = sanitize(agg);
    expect(r.message).toContain('[EMAIL]');
  });

  // ── Serialized exceptions ──────────────────────────────────────────────────

  test('LS-ERR-20 plain-object representation of error is sanitized via _sanitizeObject', () => {
    // When an Error is JSON-serialized and reparsed, it becomes a plain object.
    const errObj = { name: 'Error', message: 'fail for henry@example.org', stack: '' };
    const r      = sanitize(errObj);
    expect(r.message).toContain('[EMAIL]');
  });

  test('LS-ERR-21 serialized error with sensitive field in extra is sanitized', () => {
    const errObj = { name: 'Error', message: 'fail', token: 'secret-value', code: 401 };
    const r      = sanitize(errObj);
    expect(r.token).toBe('[REDACTED]');
    expect(r.code).toBe(401);
  });

  // ── Custom enumerable properties ───────────────────────────────────────────

  test('LS-ERR-22 custom enumerable property with safe value is preserved', () => {
    const err      = new Error('fail');
    err.statusCode = 500;
    expect(sanitize(err).statusCode).toBe(500);
  });

  test('LS-ERR-23 custom enumerable property with sensitive name is redacted', () => {
    const err    = new Error('fail');
    err.password = 'hunter2';
    expect(sanitize(err).password).toBe('[REDACTED]');
  });

  test('LS-ERR-24 custom enumerable property with PII value is sanitized', () => {
    const err    = new Error('fail');
    err.details  = 'User: iris@example.net, code: 42';
    const r      = sanitize(err);
    expect(r.details).toContain('[EMAIL]');
    expect(r.details).not.toContain('iris@');
  });

  test('LS-ERR-25 custom enumerable property that is itself an Error is sanitized', () => {
    const inner    = new Error('inner: james@secret.io');
    const outer    = new Error('outer');
    outer.original = inner;
    const r        = sanitize(outer);
    expect(r.original.message).toContain('[EMAIL]');
  });
});

// ── LS-MET: metrics ───────────────────────────────────────────────────────────

describe('LS-MET — sanitize: metrics', () => {
  test('LS-MET-01 redactedFields increments for each field-name redaction', () => {
    reset();
    sanitize({ password: 'x', token: 'y', safe: 'z' });
    expect(snapshot().redactedFields).toBe(2);
  });

  test('LS-MET-02 piiDetections increments for each PII match', () => {
    reset();
    sanitize({ msg: 'a@b.com and c@d.org' });
    expect(snapshot().piiDetections).toBeGreaterThanOrEqual(2);
  });

  test('LS-MET-03 tokenDetections increments for JWT match', () => {
    reset();
    sanitize({ msg: `Token: ${SAMPLE_JWT}` });
    expect(snapshot().tokenDetections).toBeGreaterThanOrEqual(1);
  });

  test('LS-MET-04 cryptoDetections increments for PEM match', () => {
    reset();
    sanitize({ msg: SAMPLE_PEM_PRIVATE });
    expect(snapshot().cryptoDetections).toBeGreaterThanOrEqual(1);
  });

  test('LS-MET-05 truncations increments when string exceeds maxStringLength', () => {
    reset();
    const c = cfg({ maxStringLength: 5 });
    sanitize('hello world', c);
    expect(snapshot().truncations).toBe(1);
  });

  test('LS-MET-06 reset() zeroes all counters', () => {
    sanitize({ password: 'x' });
    reset();
    const s = snapshot();
    expect(s.redactedFields).toBe(0);
    expect(s.piiDetections).toBe(0);
    expect(s.tokenDetections).toBe(0);
    expect(s.cryptoDetections).toBe(0);
    expect(s.truncations).toBe(0);
  });

  test('LS-MET-07 snapshot() returns a copy (mutations do not affect counters)', () => {
    reset();
    sanitize({ password: 'x' });
    const s = snapshot();
    s.redactedFields = 9999;
    expect(snapshot().redactedFields).toBe(1);
  });

  test('LS-MET-08 metrics accumulate across multiple calls', () => {
    reset();
    sanitize({ token: 'a' });
    sanitize({ secret: 'b' });
    expect(snapshot().redactedFields).toBe(2);
  });
});

// ── LS-INT: logger integration ────────────────────────────────────────────────

describe('LS-INT — logger integration: emit() produces sanitized records', () => {
  let stdoutSpy;
  let stderrSpy;
  const written = [];

  beforeAll(() => {
    // A single write() call may contain multiple '\n'-joined records (batched
    // stdout flush — see services/logger.js) — split before parsing.
    const capture = data => {
      for (const line of String(data).split('\n')) {
        if (!line.trim()) continue;
        try { written.push(JSON.parse(line)); } catch {}
      }
    };
    stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(data => { capture(data); return true; });
    stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(data => { capture(data); return true; });
  });

  afterAll(() => {
    stdoutSpy.mockRestore();
    stderrSpy.mockRestore();
  });

  beforeEach(() => { written.length = 0; });

  function lastRecord() { return written[written.length - 1]; }

  // Re-require logger after module-level mocks (Jest caches modules in this run)
  const { emit, flush } = require('../logger');

  // THROUGHPUT-12: INFO/WARN/ERROR records are now batched onto stdout and
  // flushed asynchronously (see services/logger.js) instead of written
  // synchronously inside emit() — that's the whole point of the change (one
  // write() syscall per tick instead of one per record). These tests assert
  // on the exact written record, so they must await flush() to force the
  // pending batch out before inspecting `written`. This is the only change
  // in this file: every assertion below is identical to before, just
  // correctly synchronized with the new (intentional) async write contract.
  // CRITICAL/FATAL (LS-INT-06) still write synchronously to stderr and never
  // needed this, but awaiting flush() there too is harmless.

  test('LS-INT-01 emit() produces a record with ts, level, event, category', async () => {
    emit('INFO', 'TEST_EVENT', {});
    await flush();
    const r = lastRecord();
    expect(r.timestamp).toBeDefined();
    expect(r.severity).toBe('INFO');
    expect(r.eventType).toBe('TEST_EVENT');
    expect(['AUDIT', 'SECURITY', 'OPERATIONAL']).toContain(r.category);
  });

  test('LS-INT-02 emit() sanitizes password field in extra', async () => {
    emit('INFO', 'TEST_EVENT', { password: 'mysecret' });
    await flush();
    expect(lastRecord().password).toBe('[REDACTED]');
  });

  test('LS-INT-03 emit() sanitizes email value in extra string field', async () => {
    emit('INFO', 'TEST_EVENT', { msg: 'User bob@example.com logged in' });
    await flush();
    expect(lastRecord().msg).toContain('[EMAIL]');
    expect(lastRecord().msg).not.toContain('@');
  });

  test('LS-INT-04 emit() sanitizes JWT in string value', async () => {
    emit('INFO', 'TEST_EVENT', { header: `Bearer ${SAMPLE_JWT}` });
    await flush();
    expect(lastRecord().header).toContain('[TOKEN]');
    expect(lastRecord().header).not.toContain('eyJ');
  });

  test('LS-INT-05 emit() sanitizes PEM block in string value', async () => {
    emit('INFO', 'TEST_EVENT', { msg: SAMPLE_PEM_PRIVATE });
    await flush();
    expect(lastRecord().msg).toContain('[CRYPTO]');
    expect(lastRecord().msg).not.toContain('BEGIN RSA');
  });

  test('LS-INT-06 emit() adds category=SECURITY for CRITICAL level', async () => {
    emit('CRITICAL', 'EXECUTION_INVARIANT_VIOLATED', {});
    await flush();
    expect(lastRecord().category).toBe('SECURITY');
  });

  test('LS-INT-07 emit() adds category=AUDIT for GATEWAY_ALLOW', async () => {
    emit('INFO', 'GATEWAY_ALLOW', { requestId: 'r1' });
    await flush();
    expect(lastRecord().category).toBe('AUDIT');
  });

  test('LS-INT-08 emit() adds category=OPERATIONAL for startup events', async () => {
    emit('INFO', 'KEYSTORE_LOADED', { keys: 0 });
    await flush();
    expect(lastRecord().category).toBe('OPERATIONAL');
  });

  test('LS-INT-09 emit() is safe when extra is omitted', async () => {
    expect(() => emit('INFO', 'SAFE_TEST')).not.toThrow();
    await flush();
    expect(lastRecord().eventType).toBe('SAFE_TEST');
  });

  test('LS-INT-10 emit() does not mutate the original extra object', async () => {
    const extra = { token: 'secret', count: 3 };
    emit('INFO', 'TEST_EVENT', extra);
    await flush();
    expect(extra.token).toBe('secret');
    expect(extra.count).toBe(3);
  });
});
