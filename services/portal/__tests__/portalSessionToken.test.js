'use strict';

const SECRET = 'a'.repeat(64); // 256-bit hex, matches the doc-recommended generation shape

function freshModule() {
  jest.resetModules();
  return require('../portalSessionToken');
}

function withSecret(secret, fn) {
  const saved = process.env.QODIQA_PORTAL_SESSION_SECRET;
  process.env.QODIQA_PORTAL_SESSION_SECRET = secret;
  try {
    return fn();
  } finally {
    if (saved === undefined) delete process.env.QODIQA_PORTAL_SESSION_SECRET;
    else process.env.QODIQA_PORTAL_SESSION_SECRET = saved;
  }
}

describe('portalSessionToken — mint/verify round trip', () => {
  test('a freshly minted token verifies and returns the exact fields minted', () => {
    withSecret(SECRET, () => {
      const mod = freshModule();
      const token = mod.mintSessionToken({ portalUserId: 'pu_1', tenantId: 'acme', role: 'tenant' });
      expect(token.startsWith('pt_')).toBe(true);

      const claims = mod.verifySessionToken(token);
      expect(claims).not.toBeNull();
      expect(claims.portalUserId).toBe('pu_1');
      expect(claims.tenantId).toBe('acme');
      expect(claims.role).toBe('tenant');
      expect(Number.isFinite(claims.issuedAt)).toBe(true);
      expect(claims.expiresAt).toBeGreaterThan(claims.issuedAt);
    });
  });

  test('default TTL is 8 hours', () => {
    withSecret(SECRET, () => {
      const mod = freshModule();
      expect(mod.DEFAULT_TTL_MS).toBe(8 * 60 * 60 * 1000);
    });
  });

  test('QODIQA_PORTAL_SESSION_TTL_MS overrides the TTL', () => {
    const saved = process.env.QODIQA_PORTAL_SESSION_TTL_MS;
    process.env.QODIQA_PORTAL_SESSION_TTL_MS = '1000';
    try {
      withSecret(SECRET, () => {
        const mod = freshModule();
        const token = mod.mintSessionToken({ portalUserId: 'pu_1', tenantId: 'acme', role: 'tenant' });
        const claims = mod.verifySessionToken(token);
        expect(claims.expiresAt - claims.issuedAt).toBe(1000);
      });
    } finally {
      if (saved === undefined) delete process.env.QODIQA_PORTAL_SESSION_TTL_MS;
      else process.env.QODIQA_PORTAL_SESSION_TTL_MS = saved;
    }
  });
});

describe('portalSessionToken — negative / fail-closed cases', () => {
  test('mintSessionToken throws when the secret is unset', () => {
    withSecret(undefined, () => {
      delete process.env.QODIQA_PORTAL_SESSION_SECRET;
      const mod = freshModule();
      expect(() => mod.mintSessionToken({ portalUserId: 'pu_1', tenantId: 'acme', role: 'tenant' }))
        .toThrow(/QODIQA_PORTAL_SESSION_SECRET/);
    });
  });

  test('mintSessionToken rejects an invalid tenantId', () => {
    withSecret(SECRET, () => {
      const mod = freshModule();
      expect(() => mod.mintSessionToken({ portalUserId: 'pu_1', tenantId: 'not valid!', role: 'tenant' }))
        .toThrow(TypeError);
      expect(() => mod.mintSessionToken({ portalUserId: '', tenantId: 'acme', role: 'tenant' }))
        .toThrow(TypeError);
      expect(() => mod.mintSessionToken({ portalUserId: 'pu_1', tenantId: 'acme', role: '' }))
        .toThrow(TypeError);
    });
  });

  test('verifySessionToken returns null for a non-string / non-prefixed / malformed token', () => {
    withSecret(SECRET, () => {
      const mod = freshModule();
      expect(mod.verifySessionToken(undefined)).toBeNull();
      expect(mod.verifySessionToken(null)).toBeNull();
      expect(mod.verifySessionToken(123)).toBeNull();
      expect(mod.verifySessionToken('not-a-token')).toBeNull();
      expect(mod.verifySessionToken('pt_missing-dot-and-signature')).toBeNull();
      expect(mod.verifySessionToken('pt_abc.not-hex-signature')).toBeNull();
    });
  });

  test('verifySessionToken returns null when the signature is tampered', () => {
    withSecret(SECRET, () => {
      const mod = freshModule();
      const token = mod.mintSessionToken({ portalUserId: 'pu_1', tenantId: 'acme', role: 'tenant' });
      const [body] = token.slice(3).split('.');
      const tampered = `pt_${body}.${'0'.repeat(64)}`;
      expect(mod.verifySessionToken(tampered)).toBeNull();
    });
  });

  test('verifySessionToken returns null when the PAYLOAD is tampered (e.g. forged role/tenant) even if re-signed with a WRONG secret', () => {
    withSecret(SECRET, () => {
      const mod = freshModule();
      const token = mod.mintSessionToken({ portalUserId: 'pu_1', tenantId: 'acme', role: 'tenant' });
      const [body] = token.slice(3).split('.');
      const forgedPayload = Buffer.from(JSON.stringify({
        sub: 'pu_1', tenantId: 'acme', role: 'admin', // forged: role escalation attempt
        issuedAt: Date.now(), expiresAt: Date.now() + 60_000,
      })).toString('base64url');
      // Attacker does not know the real secret — signs with a guessed one.
      const crypto = require('crypto');
      const badSig = crypto.createHmac('sha256', 'guessed-secret').update(forgedPayload, 'utf8').digest('hex');
      expect(mod.verifySessionToken(`pt_${forgedPayload}.${badSig}`)).toBeNull();
      // Sanity: the ORIGINAL, untampered token from the same body is unaffected.
      expect(mod.verifySessionToken(token)).not.toBeNull();
    });
  });

  test('verifySessionToken returns null for an expired token', () => {
    withSecret(SECRET, () => {
      const mod = freshModule();
      const token = mod.mintSessionToken({ portalUserId: 'pu_1', tenantId: 'acme', role: 'tenant' });
      const claims = mod.verifySessionToken(token, { _now: Date.now() + mod.DEFAULT_TTL_MS + 1000 });
      expect(claims).toBeNull();
    });
  });

  test('verifySessionToken returns null for a token signed under a DIFFERENT secret (rotation invalidates old tokens)', () => {
    const token = withSecret(SECRET, () => {
      const mod = freshModule();
      return mod.mintSessionToken({ portalUserId: 'pu_1', tenantId: 'acme', role: 'tenant' });
    });
    withSecret('b'.repeat(64), () => {
      const mod = freshModule();
      expect(mod.verifySessionToken(token)).toBeNull();
    });
  });

  test('verifySessionToken never throws, whatever garbage is passed', () => {
    withSecret(SECRET, () => {
      const mod = freshModule();
      const garbage = [
        {}, [], () => {}, Symbol('x'), new Error('x'),
        'pt_' + 'x'.repeat(10000) + '.' + 'a'.repeat(64),
        `pt_${Buffer.from('not json').toString('base64url')}.${'a'.repeat(64)}`,
      ];
      for (const g of garbage) {
        expect(() => mod.verifySessionToken(g)).not.toThrow();
      }
    });
  });
});

// ── session version claim ─────────────────────────────────────
describe('portalSessionToken — session version', () => {
  const crypto = require('crypto');
  // Build a token exactly as the PRE-DD-095 minter did (payload without `sv`), signed with the same secret.
  function legacyToken(payload) {
    const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const sig = crypto.createHmac('sha256', Buffer.from(SECRET, 'utf8')).update(encoded, 'utf8').digest('hex');
    return `pt_${encoded}.${sig}`;
  }

  test('DD095-T1 minted token carries the session version and verify returns it', () => {
    withSecret(SECRET, () => {
      const mod = freshModule();
      const t = mod.mintSessionToken({ portalUserId: 'pu_1', tenantId: 'acme', role: 'tenant', sessionVersion: 4 });
      expect(mod.verifySessionToken(t).sessionVersion).toBe(4);
    });
  });

  test('DD095-T2 sessionVersion omitted at mint -> 0', () => {
    withSecret(SECRET, () => {
      const mod = freshModule();
      const t = mod.mintSessionToken({ portalUserId: 'pu_1', tenantId: 'acme', role: 'tenant' });
      expect(mod.verifySessionToken(t).sessionVersion).toBe(0);
    });
  });

  test('DD095-T3 an OLD-FORMAT token (no sv) still verifies, as session version 0, until it expires', () => {
    withSecret(SECRET, () => {
      const mod = freshModule();
      const now = Date.now();
      const t = legacyToken({ sub: 'pu_1', tenantId: 'acme', role: 'tenant', issuedAt: now, expiresAt: now + 60_000 });
      const claims = mod.verifySessionToken(t);
      expect(claims).not.toBeNull();
      expect(claims.sessionVersion).toBe(0);
      expect(mod.verifySessionToken(t, { _now: now + 60_000 })).toBeNull(); // expiry still applies
    });
  });

  test('DD095-T4 a malformed sv (negative / fractional / string) is refused even with a valid signature', () => {
    withSecret(SECRET, () => {
      const mod = freshModule();
      const now = Date.now();
      for (const sv of [-1, 1.5, '1', null]) {
        const t = legacyToken({ sub: 'pu_1', tenantId: 'acme', role: 'tenant', issuedAt: now, expiresAt: now + 60_000, sv });
        expect(mod.verifySessionToken(t)).toBeNull();
      }
    });
  });

  test('DD095-T5 mint rejects an invalid sessionVersion', () => {
    withSecret(SECRET, () => {
      const mod = freshModule();
      for (const sessionVersion of [-1, 1.5, '2', null]) {
        expect(() => mod.mintSessionToken({ portalUserId: 'pu_1', tenantId: 'acme', role: 'tenant', sessionVersion })).toThrow(TypeError);
      }
    });
  });
});
