'use strict';

// Tests for QODIQA_OPS_TOKEN startup strength validation (AUTH-1).
//
// QODIQA_OPS_TOKEN previously had no strength validation — only presence was
// checked (in opsConfig.js), unlike every other credential validated by this
// module. _checkOpsToken() closes that gap: same minimum length (32 chars),
// same weak/placeholder deny-list, same trim-before-validate behavior, same
// fail-fast-in-production wiring via runSecretValidation() this module has
// always applied to every other bearer credential it validates.

function withEnv(overrides, deletions = []) {
  const saved = {};
  for (const k of Object.keys(overrides)) {
    saved[k] = process.env[k];
    process.env[k] = overrides[k];
  }
  for (const k of deletions) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  return function restore() {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  };
}

describe('_checkOpsToken', () => {
  let check;

  beforeAll(() => {
    check = require('./secretValidation')._checkOpsToken;
  });

  test('absent QODIQA_OPS_TOKEN produces no findings (presence is optional/deprecated)', () => {
    const restore = withEnv({}, ['QODIQA_OPS_TOKEN']);
    try {
      expect(check()).toHaveLength(0);
    } finally {
      restore();
    }
  });

  test('a strong, randomly-generated token produces no findings', () => {
    const restore = withEnv({
      QODIQA_OPS_TOKEN: 'f3a1c9e7b2d4680125fe9a3c7d1b8e4f6a2c0d8e4f6b8a0c2d4e6f8a0b2c4d6e',
    });
    try {
      expect(check()).toHaveLength(0);
    } finally {
      restore();
    }
  });

  test('empty string is rejected', () => {
    const restore = withEnv({ QODIQA_OPS_TOKEN: '' });
    try {
      const findings = check();
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatch(/empty or contains only whitespace/);
    } finally {
      restore();
    }
  });

  test('whitespace-only string is rejected', () => {
    const restore = withEnv({ QODIQA_OPS_TOKEN: '   ' });
    try {
      const findings = check();
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatch(/empty or contains only whitespace/);
    } finally {
      restore();
    }
  });

  test('newline-only string is rejected', () => {
    const restore = withEnv({ QODIQA_OPS_TOKEN: '\n\n\n' });
    try {
      const findings = check();
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatch(/empty or contains only whitespace/);
    } finally {
      restore();
    }
  });

  test('value is trimmed before length validation — padded-but-short token is still rejected', () => {
    const restore = withEnv({ QODIQA_OPS_TOKEN: '   short   ' });
    try {
      const findings = check();
      expect(findings.some(f => /only \d+ character/.test(f))).toBe(true);
    } finally {
      restore();
    }
  });

  test('a single character is rejected (below minimum length)', () => {
    const restore = withEnv({ QODIQA_OPS_TOKEN: 'a' });
    try {
      const findings = check();
      expect(findings.some(f => /only 1 character/.test(f))).toBe(true);
    } finally {
      restore();
    }
  });

  test('a 31-character token (one below the minimum) is rejected', () => {
    const restore = withEnv({ QODIQA_OPS_TOKEN: 'x'.repeat(31) });
    try {
      const findings = check();
      expect(findings.some(f => /A minimum of 32 characters is required/.test(f))).toBe(true);
    } finally {
      restore();
    }
  });

  test('a 32-character random-looking token passes the length check', () => {
    const restore = withEnv({ QODIQA_OPS_TOKEN: '9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c' });
    try {
      expect(check()).toHaveLength(0);
    } finally {
      restore();
    }
  });

  test.each([
    'a',
    'abc',
    'test',
    'password',
    'admin',
    '123456',
    'qwerty',
    'changeme',
    'default',
    'token',
  ])('well-known weak value %j is rejected', (weakValue) => {
    const restore = withEnv({ QODIQA_OPS_TOKEN: weakValue });
    try {
      const findings = check();
      expect(findings.length).toBeGreaterThan(0);
    } finally {
      restore();
    }
  });

  test.each([
    'your-token',
    'replace-me',
    'example',
    'sample',
    'xxx',
    'todo',
    'fixme',
  ])('placeholder value %j is rejected', (placeholder) => {
    const restore = withEnv({ QODIQA_OPS_TOKEN: placeholder });
    try {
      const findings = check();
      expect(findings.length).toBeGreaterThan(0);
    } finally {
      restore();
    }
  });

  test('weak value is matched case-insensitively', () => {
    const restore = withEnv({ QODIQA_OPS_TOKEN: 'ChangeMe' });
    try {
      const findings = check();
      expect(findings.some(f => /known placeholder or example value/.test(f))).toBe(true);
    } finally {
      restore();
    }
  });

  test('never includes the raw token value in a finding message', () => {
    const restore = withEnv({ QODIQA_OPS_TOKEN: 'changeme' });
    try {
      const findings = check();
      expect(findings.join(' ')).not.toContain('changeme');
    } finally {
      restore();
    }
  });
});

// ── runSecretValidation — production fail-fast integration ──────────────────

describe('runSecretValidation — QODIQA_OPS_TOKEN production fail-fast', () => {
  let exitSpy;
  let emitMock;

  const PRODUCTION_BASELINE_ENV = {
    NODE_ENV:                  'production',
    QODIQA_SIGN_TOKEN:         'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
    QODIQA_KEY_ENCRYPTION_KEY: 'b1c2d3e4'.repeat(8),
    // a strong, non-repeating value distinct from the KEK above —
    // the global test-suite default (test/support/jest.setup.js) is a deliberately weak
    // fixed value and would otherwise trip _checkExecutionInvariantSecret's
    // low-entropy check in these production-mode assertions.
    QODIQA_EXECUTION_INVARIANT_SECRET: 'c4d3e2f1'.repeat(8),
    OPENAI_API_KEY:            'sk-realkey1234567890realkey12345678',
    QODIQA_CLIENT_ID:          'my-production-org',
    QODIQA_KEYS_PATH:          require('path').join(require('os').tmpdir(), 'qodiqa-ops-token-test', 'keys.json'),
  };

  beforeEach(() => {
    jest.resetModules();
    exitSpy = jest.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit called');
    });
    emitMock = jest.fn();
    jest.doMock('../../../services/logger', () => ({ emit: emitMock }));
  });

  afterEach(() => {
    exitSpy.mockRestore();
  });

  test('startup fails before serving requests when QODIQA_OPS_TOKEN is weak', () => {
    const restore = withEnv({
      ...PRODUCTION_BASELINE_ENV,
      QODIQA_OPS_TOKEN: 'admin123',
    });
    try {
      const { runSecretValidation } = require('./secretValidation');
      expect(() => runSecretValidation()).toThrow('process.exit called');
      expect(exitSpy).toHaveBeenCalledWith(1);

      const fatalCall = emitMock.mock.calls.find(c => c[1] === 'SECRET_VALIDATION_FATAL');
      expect(fatalCall).toBeTruthy();
      const [, , payload] = fatalCall;
      expect(payload.findings.some(f => f.includes('QODIQA_OPS_TOKEN'))).toBe(true);
      // Never log the raw secret value.
      expect(JSON.stringify(payload)).not.toContain('admin123');
    } finally {
      restore();
    }
  });

  test('startup fails when QODIQA_OPS_TOKEN is whitespace-only', () => {
    const restore = withEnv({
      ...PRODUCTION_BASELINE_ENV,
      QODIQA_OPS_TOKEN: '   \t  ',
    });
    try {
      const { runSecretValidation } = require('./secretValidation');
      expect(() => runSecretValidation()).toThrow('process.exit called');
      expect(exitSpy).toHaveBeenCalledWith(1);
    } finally {
      restore();
    }
  });

  test('startup succeeds with a strong QODIQA_OPS_TOKEN and no other findings', () => {
    const restore = withEnv({
      ...PRODUCTION_BASELINE_ENV,
      QODIQA_OPS_TOKEN: 'f3a1c9e7b2d4680125fe9a3c7d1b8e4f6a2c0d8e4f6b8a0c2d4e6f8a0b2c4d6e',
    });
    try {
      const { runSecretValidation } = require('./secretValidation');
      expect(() => runSecretValidation()).not.toThrow();
      expect(exitSpy).not.toHaveBeenCalled();

      const okCall = emitMock.mock.calls.find(c => c[1] === 'SECRET_VALIDATION_OK');
      expect(okCall).toBeTruthy();
    } finally {
      restore();
    }
  });

  test('startup does not fail on QODIQA_OPS_TOKEN when it is absent (optional credential)', () => {
    const restore = withEnv({
      ...PRODUCTION_BASELINE_ENV,
    }, ['QODIQA_OPS_TOKEN']);
    try {
      const { runSecretValidation } = require('./secretValidation');
      expect(() => runSecretValidation()).not.toThrow();
      expect(exitSpy).not.toHaveBeenCalled();
    } finally {
      restore();
    }
  });

  test('non-production environment only warns, does not exit, for a weak QODIQA_OPS_TOKEN', () => {
    const restore = withEnv({
      NODE_ENV:         'development',
      QODIQA_OPS_TOKEN: 'admin123',
    }, ['QODIQA_KEYS_PATH']);
    try {
      const { runSecretValidation } = require('./secretValidation');
      expect(() => runSecretValidation()).not.toThrow();
      expect(exitSpy).not.toHaveBeenCalled();

      const warnCall = emitMock.mock.calls.find(c => c[1] === 'SECRET_VALIDATION_FAILED');
      expect(warnCall).toBeTruthy();
    } finally {
      restore();
    }
  });
});
