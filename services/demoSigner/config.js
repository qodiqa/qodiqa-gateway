'use strict';

/**
 * Demo signer configuration (launch plan R-02).
 *
 * The demo signer is a SEPARATE process from the gateway. It holds the
 * server-side `sk_` keys of the demo signing identities and signs one exact
 * `/v1/ai/chat` request per visitor action, so an anonymous visitor can exercise
 * the real enforcement path without a personal key. It is never mounted inside
 * the gateway: `/demo/*` on the gateway stays 404 (test/demo-route-hardening).
 *
 * loadConfig() is fail-closed: when DEMO_SIGNER_ENABLED=true, any invalid or
 * missing setting is collected and thrown together, and the process refuses to
 * start. Key material is read here and never logged; the returned config keeps
 * it in a non-enumerable property so an accidental JSON.stringify(config) or a
 * log of the config object cannot reveal it.
 */

const fs = require('fs');

const SCENARIOS = Object.freeze({
  allowed:         Object.freeze({ keyEnv: 'DEMO_KEY_FILE_ALLOWED', expected: 'EXECUTE' }),
  consent_revoked: Object.freeze({ keyEnv: 'DEMO_KEY_FILE_REVOKED', expected: 'BLOCK CONSENT_REVOKED' }),
  policy_denied:   Object.freeze({ keyEnv: 'DEMO_KEY_FILE_DENIED',  expected: 'BLOCK IP_BLOCKED' }),
});

// Gateway ceilings the shared demo identities run into (each one becomes a GLOBAL
// limit because every visitor shares the identity): /sign 60/min per identity,
// the anomaly gate 100 executions/min per key, the policy-template RATE_LIMIT
// 100/min. The signer's global budget must stay strictly below the lowest.
const MAX_GLOBAL_PER_MIN = 50;
const MAX_PROMPT_CHARS_CEILING = 8000;
const CHAT_PATH_RE = /^\/(v1\/)?ai\/chat$/;
const SK_RE = /^sk_[A-Za-z0-9_-]{16,256}$/;

class DemoSignerConfigError extends Error {
  constructor(problems) {
    super(`DEMO_SIGNER_CONFIG_INVALID: ${problems.join('; ')}`);
    this.name = 'DemoSignerConfigError';
    this.problems = problems;
  }
}

function _int(env, name, dflt, problems) {
  const raw = env[name];
  if (raw === undefined || raw === '') return dflt;
  if (!/^[0-9]+$/.test(String(raw))) { problems.push(`${name} must be a positive integer`); return dflt; }
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n <= 0) { problems.push(`${name} must be a positive integer`); return dflt; }
  return n;
}

function _readKey(env, name, fsImpl, platform, problems) {
  const file = env[name];
  if (!file) { problems.push(`${name} is required`); return null; }
  let stat;
  try { stat = fsImpl.statSync(file); } catch { problems.push(`${name}: key file not readable`); return null; }
  if (!stat.isFile()) { problems.push(`${name}: not a regular file`); return null; }
  // POSIX only: the key file must not be readable by group/other (0600 or tighter).
  // Windows has no POSIX mode bits; ACLs are the operator's responsibility there.
  if (platform !== 'win32' && (stat.mode & 0o077) !== 0) {
    problems.push(`${name}: key file permissions must be 0600 or tighter`);
    return null;
  }
  let content;
  try { content = String(fsImpl.readFileSync(file, 'utf8')).trim(); } catch { problems.push(`${name}: key file not readable`); return null; }
  if (!SK_RE.test(content)) { problems.push(`${name}: file does not contain a single sk_ signing key`); return null; }
  return content;
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 * @param {{ fsImpl?: typeof fs, platform?: string }} [opts]
 */
function loadConfig(env = process.env, { fsImpl = fs, platform = process.platform } = {}) {
  const problems = [];
  const enabled = env.DEMO_SIGNER_ENABLED === 'true';

  const cfg = {
    enabled,
    port:            _int(env, 'DEMO_SIGNER_PORT', 4620, problems),
    host:            env.DEMO_SIGNER_HOST || '127.0.0.1',
    gatewayUrl:      env.DEMO_GATEWAY_URL || '',
    chatPath:        env.DEMO_CHAT_PATH || '/v1/ai/chat',
    provider:        env.DEMO_PROVIDER || 'local',
    redisUrl:        env.DEMO_REDIS_URL || '',
    allowedOrigin:   env.DEMO_ALLOWED_ORIGIN || null,
    trustedProxy:    env.DEMO_TRUSTED_PROXY !== undefined ? env.DEMO_TRUSTED_PROXY : 'loopback',
    perIpPerMin:     _int(env, 'DEMO_PER_IP_PER_MIN', 10, problems),
    perIpPerDay:     _int(env, 'DEMO_PER_IP_PER_DAY', 50, problems),
    globalPerMin:    _int(env, 'DEMO_GLOBAL_PER_MIN', 30, problems),
    maxPromptChars:  _int(env, 'DEMO_MAX_PROMPT_CHARS', 2000, problems),
    gatewayTimeoutMs: _int(env, 'DEMO_GATEWAY_TIMEOUT_MS', 5000, problems),
    scenarios:       Object.keys(SCENARIOS),
  };

  if (!CHAT_PATH_RE.test(cfg.chatPath)) problems.push('DEMO_CHAT_PATH must be /v1/ai/chat or /ai/chat');
  if (!/^[a-z][a-z0-9_-]{0,31}$/.test(cfg.provider)) problems.push('DEMO_PROVIDER is not a valid provider name');
  if (cfg.globalPerMin > MAX_GLOBAL_PER_MIN) {
    problems.push(`DEMO_GLOBAL_PER_MIN must be <= ${MAX_GLOBAL_PER_MIN} (below the gateway's per-identity /sign, anomaly and policy ceilings)`);
  }
  if (cfg.perIpPerMin > cfg.globalPerMin) problems.push('DEMO_PER_IP_PER_MIN must not exceed DEMO_GLOBAL_PER_MIN');
  if (cfg.perIpPerDay < cfg.perIpPerMin) problems.push('DEMO_PER_IP_PER_DAY must be >= DEMO_PER_IP_PER_MIN');
  if (cfg.maxPromptChars > MAX_PROMPT_CHARS_CEILING) problems.push(`DEMO_MAX_PROMPT_CHARS must be <= ${MAX_PROMPT_CHARS_CEILING}`);
  if (cfg.allowedOrigin !== null && !/^https?:\/\/[^/\s*]+$/.test(cfg.allowedOrigin)) {
    problems.push('DEMO_ALLOWED_ORIGIN must be a single origin (scheme://host[:port]), no wildcard');
  }

  const keys = {};
  if (enabled) {
    if (!/^https?:\/\/[^\s]+$/.test(cfg.gatewayUrl)) problems.push('DEMO_GATEWAY_URL must be an http(s) URL');
    if (!/^rediss?:\/\/[^\s]+$/.test(cfg.redisUrl)) problems.push('DEMO_REDIS_URL must be a redis:// or rediss:// URL (quotas are fail-closed and need Redis)');
    const secret = env.DEMO_IP_HASH_SECRET || '';
    if (secret.length < 32) problems.push('DEMO_IP_HASH_SECRET must be at least 32 characters');
    for (const [name, sc] of Object.entries(SCENARIOS)) {
      const key = _readKey(env, sc.keyEnv, fsImpl, platform, problems);
      if (key) keys[name] = key;
    }
    const distinct = new Set(Object.values(keys));
    if (Object.keys(keys).length === Object.keys(SCENARIOS).length && distinct.size !== Object.keys(keys).length) {
      problems.push('each scenario must use a distinct signing identity (consent is keyed to the identity)');
    }
    Object.defineProperty(cfg, 'ipHashSecret', { value: secret, enumerable: false });
  }

  if (problems.length > 0) throw new DemoSignerConfigError(problems);

  Object.defineProperty(cfg, 'keys', { value: Object.freeze(keys), enumerable: false });
  return Object.freeze(cfg);
}

module.exports = { loadConfig, DemoSignerConfigError, SCENARIOS, MAX_GLOBAL_PER_MIN, MAX_PROMPT_CHARS_CEILING };
