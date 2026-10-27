'use strict';

/**
 * SSRF URL validator tests (Register #111 — merged from the former
 *, which duplicated and partially diverged
 * from this file: it covered a few extra IP-literal/hostname edge cases but
 * never exercised validateLocalProviderUrl at all).
 */

const { validateProviderUrl, validateLocalProviderUrl, ALLOWED_HOSTNAMES } = require('../ssrf');

// ── validateProviderUrl — allowed destinations ─────────────────────────────────

describe('validateProviderUrl — allowed destinations', () => {
  test('api.openai.com is valid', () => {
    expect(validateProviderUrl('https://api.openai.com/v1').valid).toBe(true);
  });

  test('api.openai.com without a path is valid', () => {
    expect(validateProviderUrl('https://api.openai.com')).toEqual({ valid: true, reason: null });
  });

  test('api.anthropic.com is valid', () => {
    expect(validateProviderUrl('https://api.anthropic.com').valid).toBe(true);
  });

  test('generativelanguage.googleapis.com is valid', () => {
    expect(validateProviderUrl('https://generativelanguage.googleapis.com').valid).toBe(true);
  });

  test('api.mistral.ai is valid', () => {
    expect(validateProviderUrl('https://api.mistral.ai/v1').valid).toBe(true);
  });

  test('every entry in ALLOWED_HOSTNAMES is itself valid over https://', () => {
    for (const hostname of ALLOWED_HOSTNAMES) {
      expect(validateProviderUrl(`https://${hostname}/v1`).valid).toBe(true);
    }
  });
});

// ── validateProviderUrl — protocol rejection ───────────────────────────────────

describe('validateProviderUrl — protocol rejection', () => {
  test('http:// rejected → NON_HTTPS_PROTOCOL', () => {
    expect(validateProviderUrl('http://api.openai.com/v1').reason).toBe('NON_HTTPS_PROTOCOL');
  });

  test('file:// rejected → NON_HTTPS_PROTOCOL', () => {
    expect(validateProviderUrl('file:///etc/passwd').reason).toBe('NON_HTTPS_PROTOCOL');
  });

  test('ftp:// rejected → NON_HTTPS_PROTOCOL', () => {
    expect(validateProviderUrl('ftp://api.openai.com/').reason).toBe('NON_HTTPS_PROTOCOL');
  });

  test('ws:// rejected → NON_HTTPS_PROTOCOL', () => {
    expect(validateProviderUrl('ws://api.openai.com/').reason).toBe('NON_HTTPS_PROTOCOL');
  });

  test('data: rejected → NON_HTTPS_PROTOCOL', () => {
    expect(validateProviderUrl('data:text/html,<script>').reason).toBe('NON_HTTPS_PROTOCOL');
  });
});

// ── validateProviderUrl — IP literal rejection ─────────────────────────────────

describe('validateProviderUrl — IP literal rejection', () => {
  test('generic IPv4 literal → IP_LITERAL_DESTINATION', () => {
    expect(validateProviderUrl('https://1.2.3.4/v1').reason).toBe('IP_LITERAL_DESTINATION');
  });

  test('IPv4 loopback 127.0.0.1 → IP_LITERAL_DESTINATION', () => {
    expect(validateProviderUrl('https://127.0.0.1/v1').reason).toBe('IP_LITERAL_DESTINATION');
  });

  test('IPv4 APIPA 169.254.169.254 → IP_LITERAL_DESTINATION', () => {
    expect(validateProviderUrl('https://169.254.169.254/latest/meta-data/').reason)
      .toBe('IP_LITERAL_DESTINATION');
  });

  test('IPv4 private class A 10.0.0.1 → IP_LITERAL_DESTINATION', () => {
    expect(validateProviderUrl('https://10.0.0.1/').reason).toBe('IP_LITERAL_DESTINATION');
  });

  test('IPv4 private class C 192.168.1.1 → IP_LITERAL_DESTINATION', () => {
    expect(validateProviderUrl('https://192.168.1.1/').reason).toBe('IP_LITERAL_DESTINATION');
  });

  test('IPv4 wildcard 0.0.0.0 → IP_LITERAL_DESTINATION', () => {
    expect(validateProviderUrl('https://0.0.0.0/').reason).toBe('IP_LITERAL_DESTINATION');
  });

  test('IPv4 broadcast-range 255.255.255.0 → IP_LITERAL_DESTINATION', () => {
    expect(validateProviderUrl('https://255.255.255.0/').reason).toBe('IP_LITERAL_DESTINATION');
  });

  test('IPv6 loopback [::1] → IP_LITERAL_DESTINATION', () => {
    expect(validateProviderUrl('https://[::1]/').reason).toBe('IP_LITERAL_DESTINATION');
  });

  test('IPv6 global unicast [2001:db8::1] → IP_LITERAL_DESTINATION', () => {
    expect(validateProviderUrl('https://[2001:db8::1]/').reason).toBe('IP_LITERAL_DESTINATION');
  });
});

// ── validateProviderUrl — private network hostname rejection ──────────────────

describe('validateProviderUrl — private network hostname rejection', () => {
  test('localhost → PRIVATE_NETWORK_DESTINATION', () => {
    expect(validateProviderUrl('https://localhost/').reason).toBe('PRIVATE_NETWORK_DESTINATION');
  });

  test('LOCALHOST (uppercase) → PRIVATE_NETWORK_DESTINATION', () => {
    expect(validateProviderUrl('https://LOCALHOST/').reason).toBe('PRIVATE_NETWORK_DESTINATION');
  });

  test('subdomain.localhost → PRIVATE_NETWORK_DESTINATION', () => {
    expect(validateProviderUrl('https://internal.localhost/').reason)
      .toBe('PRIVATE_NETWORK_DESTINATION');
  });
});

// ── validateProviderUrl — hostname not in allowlist ────────────────────────────

describe('validateProviderUrl — hostname not in allowlist', () => {
  test('external https host not in allowlist → HOSTNAME_NOT_ALLOWED', () => {
    expect(validateProviderUrl('https://some-other-ai-provider.com/v1').reason)
      .toBe('HOSTNAME_NOT_ALLOWED');
  });

  test('subdomain of api.openai.com not in allowlist → HOSTNAME_NOT_ALLOWED', () => {
    // Subdomain injection: evil.api.openai.com is NOT the same as api.openai.com
    expect(validateProviderUrl('https://evil.api.openai.com/').reason)
      .toBe('HOSTNAME_NOT_ALLOWED');
  });

  test('subdomain of api.anthropic.com not in allowlist → HOSTNAME_NOT_ALLOWED', () => {
    expect(validateProviderUrl('https://evil.api.anthropic.com/v1').reason)
      .toBe('HOSTNAME_NOT_ALLOWED');
  });
});

// ── validateProviderUrl — invalid input ────────────────────────────────────────

describe('validateProviderUrl — invalid input', () => {
  test('empty string → INVALID_URL', () => {
    expect(validateProviderUrl('').reason).toBe('INVALID_URL');
  });

  test('null → INVALID_URL', () => {
    expect(validateProviderUrl(null).reason).toBe('INVALID_URL');
  });

  test('undefined → INVALID_URL', () => {
    expect(validateProviderUrl(undefined).reason).toBe('INVALID_URL');
  });

  test('non-URL string → INVALID_URL', () => {
    expect(validateProviderUrl('not a url').reason).toBe('INVALID_URL');
  });

  test('bare hostname (no scheme) → INVALID_URL', () => {
    expect(validateProviderUrl('api.openai.com').reason).toBe('INVALID_URL');
  });
});

// ── validateLocalProviderUrl — self-hosted endpoints ───────────────────────────

describe('validateLocalProviderUrl — self-hosted endpoints', () => {
  test('http://localhost:11434 is valid', () => {
    expect(validateLocalProviderUrl('http://localhost:11434').valid).toBe(true);
  });

  test('http://127.0.0.1:8080 is valid', () => {
    expect(validateLocalProviderUrl('http://127.0.0.1:8080').valid).toBe(true);
  });

  test('http://192.168.1.10:8080 is valid', () => {
    expect(validateLocalProviderUrl('http://192.168.1.10:8080').valid).toBe(true);
  });

  test('https://localhost:11434 is valid', () => {
    expect(validateLocalProviderUrl('https://localhost:11434').valid).toBe(true);
  });

  test('https://my-gpu-server.internal is valid', () => {
    expect(validateLocalProviderUrl('https://my-gpu-server.internal').valid).toBe(true);
  });

  test('file:// is rejected → NON_HTTP_PROTOCOL', () => {
    const r = validateLocalProviderUrl('file:///etc/passwd');
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('NON_HTTP_PROTOCOL');
  });

  test('ftp:// is rejected → NON_HTTP_PROTOCOL', () => {
    const r = validateLocalProviderUrl('ftp://localhost');
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('NON_HTTP_PROTOCOL');
  });

  test('empty string is rejected', () => {
    expect(validateLocalProviderUrl('').valid).toBe(false);
  });

  test('null is rejected', () => {
    expect(validateLocalProviderUrl(null).valid).toBe(false);
  });

  test('unparseable URL is rejected', () => {
    expect(validateLocalProviderUrl('not a url').valid).toBe(false);
  });
});

// ── ALLOWED_HOSTNAMES export ───────────────────────────────────────────────────

describe('ALLOWED_HOSTNAMES', () => {
  test('is a Set', () => {
    expect(ALLOWED_HOSTNAMES).toBeInstanceOf(Set);
  });

  test('contains all required public provider hostnames', () => {
    expect(ALLOWED_HOSTNAMES.has('api.openai.com')).toBe(true);
    expect(ALLOWED_HOSTNAMES.has('api.anthropic.com')).toBe(true);
    expect(ALLOWED_HOSTNAMES.has('generativelanguage.googleapis.com')).toBe(true);
    expect(ALLOWED_HOSTNAMES.has('api.mistral.ai')).toBe(true);
  });
});
