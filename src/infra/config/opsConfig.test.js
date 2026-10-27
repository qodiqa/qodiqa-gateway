'use strict';

// Tests for opsConfig.js — centralized configuration loading.
// Uses jest environment variable injection to test config behaviour.

const { _isValidEntry, _parseAllowlist } = require('./opsConfig');

// ── Unit: _isValidEntry ───────────────────────────────────────────────────────

describe('_isValidEntry', () => {
  it('accepts a valid bare IPv4', () => {
    expect(_isValidEntry('10.0.0.1')).toBe(true);
  });

  it('accepts a valid CIDR /24', () => {
    expect(_isValidEntry('192.168.1.0/24')).toBe(true);
  });

  it('accepts /32 (host route)', () => {
    expect(_isValidEntry('10.0.0.5/32')).toBe(true);
  });

  it('accepts /0 (default route)', () => {
    expect(_isValidEntry('0.0.0.0/0')).toBe(true);
  });

  it('rejects hostname', () => {
    expect(_isValidEntry('example.com')).toBe(false);
  });

  it('accepts bare IPv6 loopback (::1)', () => {
    expect(_isValidEntry('::1')).toBe(true);
  });

  it('accepts bare IPv6 global unicast', () => {
    expect(_isValidEntry('2001:db8::1')).toBe(true);
  });

  it('accepts IPv6 CIDR /32', () => {
    expect(_isValidEntry('2001:db8::/32')).toBe(true);
  });

  it('accepts IPv6 CIDR /128 (host route)', () => {
    expect(_isValidEntry('2001:db8::1/128')).toBe(true);
  });

  it('accepts IPv6 CIDR /0 (default route)', () => {
    expect(_isValidEntry('::/0')).toBe(true);
  });

  it('accepts IPv6 ULA range', () => {
    expect(_isValidEntry('fd00::/8')).toBe(true);
  });

  it('rejects IPv6 CIDR prefix > 128', () => {
    expect(_isValidEntry('2001:db8::/129')).toBe(false);
  });

  it('rejects IPv4-mapped IPv6 (contains dots)', () => {
    expect(_isValidEntry('::ffff:192.168.1.1')).toBe(false);
  });

  it('rejects malformed IPv6 (triple colon)', () => {
    expect(_isValidEntry('2001:::1')).toBe(false);
  });

  it('rejects CIDR with prefix > 32', () => {
    expect(_isValidEntry('10.0.0.0/33')).toBe(false);
  });

  it('rejects octet > 255', () => {
    expect(_isValidEntry('256.0.0.0')).toBe(false);
  });

  it('rejects empty string', () => {
    expect(_isValidEntry('')).toBe(false);
  });
});

// ── Unit: _parseAllowlist ─────────────────────────────────────────────────────

describe('_parseAllowlist', () => {
  it('returns empty arrays for empty string', () => {
    expect(_parseAllowlist('')).toEqual({ valid: [], invalid: [] });
  });

  it('returns empty arrays for null', () => {
    expect(_parseAllowlist(null)).toEqual({ valid: [], invalid: [] });
  });

  it('parses single IP correctly', () => {
    const result = _parseAllowlist('10.0.0.1');
    expect(result.valid).toEqual(['10.0.0.1']);
    expect(result.invalid).toEqual([]);
  });

  it('parses multiple comma-separated entries', () => {
    const result = _parseAllowlist('10.0.0.1,192.168.0.0/16');
    expect(result.valid).toEqual(['10.0.0.1', '192.168.0.0/16']);
    expect(result.invalid).toEqual([]);
  });

  it('trims whitespace around entries', () => {
    const result = _parseAllowlist('  10.0.0.1  ,  192.168.1.0/24  ');
    expect(result.valid).toEqual(['10.0.0.1', '192.168.1.0/24']);
  });

  it('separates valid and invalid entries', () => {
    const result = _parseAllowlist('10.0.0.1,not-valid,192.168.1.0/24,bad');
    expect(result.valid).toEqual(['10.0.0.1', '192.168.1.0/24']);
    expect(result.invalid).toEqual(['not-valid', 'bad']);
  });

  it('filters out empty tokens from double-commas', () => {
    const result = _parseAllowlist('10.0.0.1,,192.168.1.0/24');
    expect(result.valid).toEqual(['10.0.0.1', '192.168.1.0/24']);
    expect(result.invalid).toEqual([]);
  });

  it('accepts mixed IPv4 and IPv6 entries', () => {
    const result = _parseAllowlist('10.0.0.1,2001:db8::/32,::1');
    expect(result.valid).toEqual(['10.0.0.1', '2001:db8::/32', '::1']);
    expect(result.invalid).toEqual([]);
  });

  it('rejects malformed IPv6 entries into invalid list', () => {
    const result = _parseAllowlist('10.0.0.1,2001:::1');
    expect(result.valid).toEqual(['10.0.0.1']);
    expect(result.invalid).toEqual(['2001:::1']);
  });
});

// ── loadOpsConfig: environment-driven defaults ────────────────────────────────

describe('loadOpsConfig — environment-driven defaults', () => {
  let savedEnv;

  beforeEach(() => {
    savedEnv = { ...process.env };
    // Clear all OPS env vars
    delete process.env.QODIQA_OPS_TOKEN;
    delete process.env.QODIQA_OPS_IP_ALLOWLIST_ENABLED;
    delete process.env.QODIQA_OPS_IP_ALLOWLIST;
    delete process.env.QODIQA_OPS_TRUST_PROXY;
    delete process.env.QODIQA_DIAGNOSTICS_ENABLED;
    delete process.env.QODIQA_ADMIN_ENABLED;
    delete process.env.QODIQA_HEALTH_PROBE_AUTH_REQUIRED;
    delete process.env.QODIQA_HEALTH_REQUIRE_LOOPBACK;
    delete process.env.QODIQA_HEALTH_RATE_LIMIT_MAX;
    delete process.env.QODIQA_HEALTH_RATE_LIMIT_WINDOW_MS;
    delete process.env.NODE_ENV;
    jest.resetModules();
  });

  afterEach(() => {
    Object.keys(process.env).forEach(k => {
      if (!(k in savedEnv)) delete process.env[k];
    });
    Object.assign(process.env, savedEnv);
    jest.resetModules();
  });

  it('token is null when QODIQA_OPS_TOKEN is not set', () => {
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.token).toBeNull();
  });

  it('token is set from QODIQA_OPS_TOKEN', () => {
    process.env.QODIQA_OPS_TOKEN = 'my-secret-token';
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.token).toBe('my-secret-token');
  });

  it('diagnosticsEnabled defaults to true in non-production', () => {
    process.env.NODE_ENV = 'test';
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.diagnosticsEnabled).toBe(true);
  });

  it('diagnosticsEnabled defaults to false in production', () => {
    process.env.NODE_ENV = 'production';
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.diagnosticsEnabled).toBe(false);
  });

  it('diagnosticsEnabled can be overridden to true in production', () => {
    process.env.NODE_ENV = 'production';
    process.env.QODIQA_DIAGNOSTICS_ENABLED = 'true';
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.diagnosticsEnabled).toBe(true);
  });

  it('diagnosticsEnabled can be overridden to false in non-production', () => {
    process.env.NODE_ENV = 'development';
    process.env.QODIQA_DIAGNOSTICS_ENABLED = 'false';
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.diagnosticsEnabled).toBe(false);
  });

  // the admin plane has its own switch, strict from
  // day one — the diagnostics switch never enables it.
  it('adminEnabled defaults to true in non-production', () => {
    process.env.NODE_ENV = 'development';
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().adminEnabled).toBe(true);
  });

  it('adminEnabled defaults to false in production', () => {
    process.env.NODE_ENV = 'production';
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().adminEnabled).toBe(false);
  });

  it('adminEnabled can be enabled in production only by QODIQA_ADMIN_ENABLED=true', () => {
    process.env.NODE_ENV = 'production';
    process.env.QODIQA_ADMIN_ENABLED = 'true';
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.adminEnabled).toBe(true);
    expect(cfg.diagnosticsEnabled).toBe(false);
  });

  it('QODIQA_DIAGNOSTICS_ENABLED=true does NOT enable the admin plane in production (strict split)', () => {
    process.env.NODE_ENV = 'production';
    process.env.QODIQA_DIAGNOSTICS_ENABLED = 'true';
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.diagnosticsEnabled).toBe(true);
    expect(cfg.adminEnabled).toBe(false);
  });

  it('adminEnabled can be disabled in non-production independently of diagnostics', () => {
    process.env.NODE_ENV = 'development';
    process.env.QODIQA_ADMIN_ENABLED = 'false';
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.adminEnabled).toBe(false);
    expect(cfg.diagnosticsEnabled).toBe(true);
  });

  // #4: unlike diagnosticsEnabled above, this defaults to false in
  // EVERY environment (no !isProduction default) — opt-in only, since
  // profiling carries more performance/disclosure risk than health-style
  // diagnostics.
  it('profilingDiagnosticsEnabled defaults to false in non-production', () => {
    process.env.NODE_ENV = 'test';
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.profilingDiagnosticsEnabled).toBe(false);
  });

  it('profilingDiagnosticsEnabled defaults to false in production', () => {
    process.env.NODE_ENV = 'production';
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.profilingDiagnosticsEnabled).toBe(false);
  });

  it('profilingDiagnosticsEnabled can be explicitly enabled via QODIQA_PROFILING_DIAGNOSTICS_ENABLED=true', () => {
    process.env.QODIQA_PROFILING_DIAGNOSTICS_ENABLED = 'true';
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.profilingDiagnosticsEnabled).toBe(true);
  });

  it('profilingDiagnosticsEnabled stays false when generic diagnosticsEnabled is true (independent flags)', () => {
    process.env.NODE_ENV = 'test';
    process.env.QODIQA_DIAGNOSTICS_ENABLED = 'true';
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.diagnosticsEnabled).toBe(true);
    expect(cfg.profilingDiagnosticsEnabled).toBe(false);
  });

  it('ipAllowlistEnabled is false by default', () => {
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.ipAllowlistEnabled).toBe(false);
  });

  it('ipAllowlistEnabled is set to true by QODIQA_OPS_IP_ALLOWLIST_ENABLED=true', () => {
    process.env.QODIQA_OPS_IP_ALLOWLIST_ENABLED = 'true';
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.ipAllowlistEnabled).toBe(true);
  });

  it('allowlistEntries is populated from QODIQA_OPS_IP_ALLOWLIST', () => {
    process.env.QODIQA_OPS_IP_ALLOWLIST = '10.0.0.1,192.168.0.0/16';
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.allowlistEntries).toEqual(['10.0.0.1', '192.168.0.0/16']);
  });

  it('invalid entries set allowlistConfigValid=false', () => {
    process.env.QODIQA_OPS_IP_ALLOWLIST = '10.0.0.1,bad-entry';
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.allowlistConfigValid).toBe(false);
    // Invalid entries should NOT be in the valid list
    expect(cfg.allowlistEntries).not.toContain('bad-entry');
  });

  it('trustProxy is false by default', () => {
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.trustProxy).toBe(false);
  });

  it('trustProxy is set by QODIQA_OPS_TRUST_PROXY=true', () => {
    process.env.QODIQA_OPS_TRUST_PROXY = 'true';
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.trustProxy).toBe(true);
  });

  it('returned config is frozen (immutable)', () => {
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(Object.isFrozen(cfg)).toBe(true);
    expect(Object.isFrozen(cfg.allowlistEntries)).toBe(true);
  });
});

// ── loadOpsConfig: /health and /ready probe hardening knobs ───────────────────

describe('loadOpsConfig — health probe configuration', () => {
  let savedEnv;

  beforeEach(() => {
    savedEnv = { ...process.env };
    delete process.env.QODIQA_HEALTH_PROBE_AUTH_REQUIRED;
    delete process.env.QODIQA_HEALTH_REQUIRE_LOOPBACK;
    delete process.env.QODIQA_HEALTH_RATE_LIMIT_MAX;
    delete process.env.QODIQA_HEALTH_RATE_LIMIT_WINDOW_MS;
    jest.resetModules();
  });

  afterEach(() => {
    Object.keys(process.env).forEach(k => {
      if (!(k in savedEnv)) delete process.env[k];
    });
    Object.assign(process.env, savedEnv);
    jest.resetModules();
  });

  it('healthAuthRequired defaults to false (orchestrator compatibility)', () => {
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().healthAuthRequired).toBe(false);
  });

  it('healthAuthRequired is true only when explicitly set to "true"', () => {
    process.env.QODIQA_HEALTH_PROBE_AUTH_REQUIRED = 'true';
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().healthAuthRequired).toBe(true);
  });

  it('healthAuthRequired stays false for any non-"true" value', () => {
    process.env.QODIQA_HEALTH_PROBE_AUTH_REQUIRED = 'yes';
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().healthAuthRequired).toBe(false);
  });

  it('healthRequireLoopback defaults to false (Kubernetes compatibility)', () => {
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().healthRequireLoopback).toBe(false);
  });

  it('healthRequireLoopback is true only when explicitly set to "true"', () => {
    process.env.QODIQA_HEALTH_REQUIRE_LOOPBACK = 'true';
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().healthRequireLoopback).toBe(true);
  });

  it('healthRateLimitMax defaults to 240', () => {
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().healthRateLimitMax).toBe(240);
  });

  it('healthRateLimitMax is overridden by a valid positive integer', () => {
    process.env.QODIQA_HEALTH_RATE_LIMIT_MAX = '500';
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().healthRateLimitMax).toBe(500);
  });

  it('healthRateLimitMax falls back to default on invalid input', () => {
    process.env.QODIQA_HEALTH_RATE_LIMIT_MAX = 'not-a-number';
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().healthRateLimitMax).toBe(240);
  });

  it('healthRateLimitMax falls back to default on non-positive input', () => {
    process.env.QODIQA_HEALTH_RATE_LIMIT_MAX = '-5';
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().healthRateLimitMax).toBe(240);
  });

  it('healthRateLimitWindowMs defaults to 60000', () => {
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().healthRateLimitWindowMs).toBe(60_000);
  });

  it('healthRateLimitWindowMs is overridden by a valid positive integer', () => {
    process.env.QODIQA_HEALTH_RATE_LIMIT_WINDOW_MS = '30000';
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().healthRateLimitWindowMs).toBe(30_000);
  });
});

// ── loadOpsConfig: auth-failure lockout knobs (AUTH-2) ─────────────────────────

describe('loadOpsConfig — auth-failure lockout configuration', () => {
  let savedEnv;

  beforeEach(() => {
    savedEnv = { ...process.env };
    delete process.env.QODIQA_OPS_AUTH_LOCKOUT_ENABLED;
    delete process.env.QODIQA_OPS_AUTH_LOCKOUT_MAX_FAILURES;
    delete process.env.QODIQA_OPS_AUTH_LOCKOUT_DURATION_MS;
    delete process.env.QODIQA_OPS_AUTH_LOCKOUT_BACKOFF_MIN_MS;
    delete process.env.QODIQA_OPS_AUTH_LOCKOUT_BACKOFF_MAX_MS;
    delete process.env.QODIQA_OPS_AUTH_LOCKOUT_FAILURE_WINDOW_MS;
    jest.resetModules();
  });

  afterEach(() => {
    Object.keys(process.env).forEach(k => {
      if (!(k in savedEnv)) delete process.env[k];
    });
    Object.assign(process.env, savedEnv);
    jest.resetModules();
  });

  it('authLockoutEnabled defaults to true', () => {
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().authLockoutEnabled).toBe(true);
  });

  it('authLockoutEnabled is false only when explicitly set to "false"', () => {
    process.env.QODIQA_OPS_AUTH_LOCKOUT_ENABLED = 'false';
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().authLockoutEnabled).toBe(false);
  });

  it('authLockoutEnabled stays true for any non-"false" value', () => {
    process.env.QODIQA_OPS_AUTH_LOCKOUT_ENABLED = 'no';
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().authLockoutEnabled).toBe(true);
  });

  it('authLockoutMaxFailures defaults to 5', () => {
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().authLockoutMaxFailures).toBe(5);
  });

  it('authLockoutMaxFailures is overridden by a valid positive integer', () => {
    process.env.QODIQA_OPS_AUTH_LOCKOUT_MAX_FAILURES = '10';
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().authLockoutMaxFailures).toBe(10);
  });

  it('authLockoutMaxFailures falls back to default on invalid input', () => {
    process.env.QODIQA_OPS_AUTH_LOCKOUT_MAX_FAILURES = 'nope';
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().authLockoutMaxFailures).toBe(5);
  });

  it('authLockoutDurationMs defaults to 900000 (15 minutes)', () => {
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().authLockoutDurationMs).toBe(900_000);
  });

  it('authLockoutDurationMs is overridden by a valid positive integer', () => {
    process.env.QODIQA_OPS_AUTH_LOCKOUT_DURATION_MS = '60000';
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().authLockoutDurationMs).toBe(60_000);
  });

  it('authLockoutBackoffMinMs defaults to 250', () => {
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().authLockoutBackoffMinMs).toBe(250);
  });

  it('authLockoutBackoffMaxMs defaults to 5000', () => {
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().authLockoutBackoffMaxMs).toBe(5_000);
  });

  it('authLockoutFailureWindowMs defaults to authLockoutDurationMs when unset', () => {
    process.env.QODIQA_OPS_AUTH_LOCKOUT_DURATION_MS = '120000';
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.authLockoutFailureWindowMs).toBe(120_000);
  });

  it('authLockoutFailureWindowMs is independently overridable', () => {
    process.env.QODIQA_OPS_AUTH_LOCKOUT_DURATION_MS = '120000';
    process.env.QODIQA_OPS_AUTH_LOCKOUT_FAILURE_WINDOW_MS = '30000';
    const { loadOpsConfig } = require('./opsConfig');
    expect(loadOpsConfig().authLockoutFailureWindowMs).toBe(30_000);
  });

  it('clamps authLockoutBackoffMinMs to authLockoutBackoffMaxMs when min > max, rather than leaving an unbounded delay', () => {
    process.env.QODIQA_OPS_AUTH_LOCKOUT_BACKOFF_MIN_MS = '9000';
    process.env.QODIQA_OPS_AUTH_LOCKOUT_BACKOFF_MAX_MS = '2000';
    const { loadOpsConfig } = require('./opsConfig');
    const cfg = loadOpsConfig();
    expect(cfg.authLockoutBackoffMinMs).toBe(2_000);
    expect(cfg.authLockoutBackoffMaxMs).toBe(2_000);
  });
});
