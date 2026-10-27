'use strict';

/**
 * — test-environment isolation from the LIVE PostgreSQL / Redis endpoints.
 *
 * On the development machine the PostgreSQL cluster on 127.0.0.1:5432 and the Docker Redis `qodiqa-redis` on 6379
 * host LIVE / dev-live data. Three independent doors led a local test run there (incident INC-01 and this phase's
 * audit):
 *
 *   1. `.env` inheritance — a suite (or a child process: server.js / bootstrap-dev.js / scripts that call
 *      dotenv.config()) back-filled QODIQA_PG_HOST/PORT (and PG_ENABLED=true) from the repository's `.env`.
 *   2. Product defaults — src/infra/postgres/* falls back to localhost:5432 and src/infra/redis/clientConfig.js to
 *      redis://localhost:6379 when the variable is unset OR EMPTY, so blanking a key is not enough on its own.
 *   3. Env-less children — Jest's per-file `process.env` is a COPY; a child spawned without an `env` option inherits
 *      the worker's REAL environment, which never saw test/support/jest.setup.js's isolation.
 *
 * This module is the shared mechanism: a socket-level guard that refuses a connection to a loopback/own-host address on
 * a LIVE port (5432, 6379) in-process, a preload that installs the same guard in every Node child that inherits
 * NODE_OPTIONS, and helpers to build child environments in which `.env` cannot supply a PostgreSQL/Redis target.
 *
 * Exempt (the guard does nothing): CI=true (GitHub Actions' ephemeral service containers on localhost:5432/6379), or
 * QODIQA_TEST_ALLOW_LIVE_PORTS=true — a deliberate escape hatch for a machine where 5432/6379 are disposable. Never set
 * it on the development machine. Node core only (it is preloaded into arbitrary children).
 *
 * Other variables: QODIQA_LIVE_GUARD_LOG=<file> appends one line per blocked attempt (tripwire evidence);
 * QODIQA_LIVE_GUARD_EXTRA_PORTS=<p1,p2> ADDS ports to the refused set (never removes 5432/6379) — used only by the
 * guard's own negative-control tests (test/liveEndpointGuard.test.js) against listeners they own.
 */

const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

const LIVE_PORTS = Object.freeze([5432, 6379]);
const PG_TARGET_KEYS = Object.freeze(['QODIQA_PG_HOST', 'QODIQA_PG_PORT', 'QODIQA_PG_URL', 'DATABASE_URL', 'PGHOST', 'PGPORT']);
const REDIS_TARGET_KEYS = Object.freeze(['REDIS_URL', 'REDIS_HOST', 'REDIS_PORT']);
const TARGET_KEYS = Object.freeze([...PG_TARGET_KEYS, ...REDIS_TARGET_KEYS]);
const ALLOW_FLAG = 'QODIQA_TEST_ALLOW_LIVE_PORTS';
const LOG_FILE_VAR = 'QODIQA_LIVE_GUARD_LOG';
const EXTRA_PORTS_VAR = 'QODIQA_LIVE_GUARD_EXTRA_PORTS';
const REPO_ROOT = path.join(__dirname, '..', '..');
const PRELOAD_PATH = path.join(__dirname, 'liveEndpointGuard.preload.js');
const STATE = Symbol.for('qodiqa.liveEndpointGuard');

function isExempt(env = process.env) {
  return env.CI === 'true' || env[ALLOW_FLAG] === 'true';
}

function ownHostNames() {
  const names = new Set(['', 'localhost', '0.0.0.0', '::', '::1', '[::1]', '0:0:0:0:0:0:0:1']);
  try { names.add(os.hostname().toLowerCase()); } catch (_) { /* no hostname */ }
  try {
    for (const list of Object.values(os.networkInterfaces())) for (const i of list || []) names.add(String(i.address).toLowerCase());
  } catch (_) { /* no interfaces */ }
  return names;
}

/** True for any address that reaches THIS machine (where the LIVE services listen, 5432 on 0.0.0.0). */
function isOwnHost(host, names = ownHostNames()) {
  const h = String(host === undefined || host === null ? '' : host).trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (names.has(h)) return true;
  if (/^127\./.test(h) || /^::ffff:127\./.test(h) || h.endsWith('.localhost')) return true;
  return false;
}

/** Extracts {host, port} from any Socket#connect call shape; null for an IPC path. */
function connectTarget(args) {
  let a = args;
  if (Array.isArray(a[0])) a = a[0]; // net.connect() hands Socket#connect its normalized [options, cb] array
  const first = a[0];
  if (first && typeof first === 'object') {
    if (first.path) return null;
    return { host: first.host, port: Number(first.port) };
  }
  if (typeof first === 'number' || (typeof first === 'string' && /^\d+$/.test(first))) {
    return { host: typeof a[1] === 'string' ? a[1] : undefined, port: Number(first) };
  }
  return null;
}

function _record(state, host, port) {
  const key = `${host}:${port}`;
  state.blocked.push({ host, port, at: new Date().toISOString() });
  if (!state.warned.has(key)) {
    state.warned.add(key);
    try { process.stderr.write(`[liveEndpointGuard] BLOCKED connect to ${key} (pid ${process.pid}) — a LIVE port on this machine; ` +
      'give the test an explicit disposable target (a disposable PostgreSQL/Redis environment).\n'); } catch (_) { /* closed stderr */ }
  }
  const logFile = process.env[LOG_FILE_VAR];
  if (logFile) {
    try { fs.appendFileSync(logFile, `${new Date().toISOString()} pid=${process.pid} blocked=${key}\n`); } catch (_) { /* best effort */ }
  }
}

/**
 * The ports the guard refuses: always 5432 and 6379, plus any listed in QODIQA_LIVE_GUARD_EXTRA_PORTS (comma-separated).
 * The extra list can only ADD ports — it exists so the guard's own negative-control tests can prove a block against a
 * listener THEY own, without ever aiming a connection at the real LIVE services.
 */
function guardedPorts(env = process.env) {
  const extra = String(env[EXTRA_PORTS_VAR] || '').split(',').map((s) => Number(s.trim())).filter((n) => Number.isInteger(n) && n > 0 && n < 65536);
  return [...new Set([...LIVE_PORTS, ...extra])];
}

/**
 * Patches net.Socket.prototype.connect (idempotent) so a connection to an own-host address on one of `ports` fails
 * exactly like a refused connection (ECONNREFUSED, emitted asynchronously on the socket) without any packet leaving.
 * Every TCP client in this codebase (pg, @redis/client, ioredis, tls) goes through this method.
 * @returns {boolean} whether the guard is active in this process
 */
function installSocketGuard({ ports = guardedPorts(), env = process.env } = {}) {
  if (isExempt(env)) return false;
  const proto = net.Socket.prototype;
  if (proto[STATE]) {
    for (const p of ports) proto[STATE].ports.add(Number(p));
    return true;
  }
  const state = { original: proto.connect, ports: new Set(ports.map(Number)), blocked: [], warned: new Set(), names: ownHostNames() };
  Object.defineProperty(proto, STATE, { value: state, configurable: true });
  proto.connect = function liveEndpointGuardedConnect(...args) {
    const t = connectTarget(args);
    if (t && state.ports.has(t.port) && isOwnHost(t.host, state.names)) {
      const host = t.host || 'localhost';
      _record(state, host, t.port);
      const err = Object.assign(new Error(`connect ECONNREFUSED ${host}:${t.port} (refused by test/helpers/liveEndpointGuard.js: ` +
        `${t.port} on this machine is a LIVE endpoint; tests need an explicit disposable target)`), {
        code: 'ECONNREFUSED', errno: -4078, syscall: 'connect', address: host, port: t.port, liveEndpointGuard: true,
      });
      process.nextTick(() => this.destroy(err));
      return this;
    }
    return state.original.apply(this, args);
  };
  return true;
}

/** Restores the original Socket#connect (used only by the guard's own tests). */
function uninstallSocketGuard() {
  const proto = net.Socket.prototype;
  const state = proto[STATE];
  if (!state) return;
  proto.connect = state.original;
  delete proto[STATE];
}

function blockedAttempts() {
  const state = net.Socket.prototype[STATE];
  return state ? state.blocked.slice() : [];
}

/** The NODE_OPTIONS fragment that preloads the guard into a Node child. */
function preloadOption() {
  const p = PRELOAD_PATH.replace(/\\/g, '/');
  return /\s/.test(p) ? `--require "${p}"` : `--require ${p}`;
}

function withPreload(nodeOptions) {
  const current = String(nodeOptions || '').trim();
  if (current.includes('liveEndpointGuard.preload')) return current;
  return `${current} ${preloadOption()}`.trim();
}

function dotenvParsed(envPath = process.env.QODIQA_TEST_DOTENV_PATH || path.join(REPO_ROOT, '.env')) {
  try {
    if (!fs.existsSync(envPath)) return {};
    // eslint-disable-next-line global-require
    return require('dotenv').parse(fs.readFileSync(envPath));
  } catch (_) {
    return {};
  }
}

/**
 * Pre-sets, on `env`, every PostgreSQL/Redis connection-target key that `.env` defines but `env` does not: to '' (and
 * QODIQA_PG_ENABLED to 'false'). dotenv never overrides an existing key, so neither a later dotenv.config() in the same
 * process nor a child's own dotenv load can back-fill the `.env` cluster. Explicit values are untouched.
 * @returns {string[]} the keys it set
 */
function neutraliseDotenvTargets(env, { parsed = dotenvParsed() } = {}) {
  const set = [];
  for (const k of TARGET_KEYS) {
    if (Object.prototype.hasOwnProperty.call(parsed, k) && !Object.prototype.hasOwnProperty.call(env, k)) { env[k] = ''; set.push(k); }
  }
  if (Object.prototype.hasOwnProperty.call(parsed, 'QODIQA_PG_ENABLED') && !Object.prototype.hasOwnProperty.call(env, 'QODIQA_PG_ENABLED')) {
    env.QODIQA_PG_ENABLED = 'false'; set.push('QODIQA_PG_ENABLED');
  }
  return set;
}

/**
 * A child-process env derived from `base` (default: this process's env) in which `.env` cannot supply a
 * PostgreSQL/Redis target and the socket guard is preloaded (unless exempt). Prefer this over `{ ...process.env }`.
 */
function isolatedChildEnv(base = process.env, extra = {}) {
  const env = { ...base, ...extra };
  neutraliseDotenvTargets(env);
  if (!isExempt(env)) env.NODE_OPTIONS = withPreload(env.NODE_OPTIONS);
  return env;
}

function _nonEmpty(v) { return typeof v === 'string' && v.trim() !== ''; }

function _portOfUrl(u, dflt) {
  try { const x = new URL(u); return { host: x.hostname, port: Number(x.port || dflt) }; } catch (_) { return null; }
}

/** The explicit PostgreSQL target named by `env` ({host, port}), or null when it names none. */
function explicitPgTarget(env = process.env) {
  if (_nonEmpty(env.QODIQA_PG_URL)) return _portOfUrl(env.QODIQA_PG_URL, 5432);
  if (_nonEmpty(env.DATABASE_URL)) return _portOfUrl(env.DATABASE_URL, 5432);
  if (_nonEmpty(env.QODIQA_PG_HOST) && _nonEmpty(env.QODIQA_PG_PORT)) return { host: env.QODIQA_PG_HOST, port: Number(env.QODIQA_PG_PORT) };
  return null;
}

/** The explicit Redis target named by `env` ({host, port, url}), or null when REDIS_URL is unset/empty. */
function explicitRedisTarget(env = process.env) {
  if (!_nonEmpty(env.REDIS_URL)) return null;
  const t = _portOfUrl(env.REDIS_URL, 6379);
  return t ? { ...t, url: env.REDIS_URL } : null;
}

/** True when {host, port} is a LIVE endpoint on this machine (an own-host address on 5432/6379). Pure; no I/O. */
function isLiveEndpoint(host, port) {
  return LIVE_PORTS.includes(Number(port)) && isOwnHost(host);
}

/**
 * Why an opted-in local (non-CI) run's environment is unsafe, or [] when it is fine: it must name its PostgreSQL target
 * explicitly as QODIQA_PG_HOST + QODIQA_PG_PORT (the ~60 PostgreSQL suites build their connection from exactly those two
 * keys, falling back to localhost / 5432 when either is missing — a URL alone would leave them on that fallback), and
 * no explicit target (that pair, QODIQA_PG_URL, DATABASE_URL, PGHOST/PGPORT, REDIS_URL) may be a LIVE port on this
 * machine.
 */
function optInProblems(env = process.env) {
  if (isExempt(env)) return [];
  const problems = [];
  if (!_nonEmpty(env.QODIQA_PG_HOST) || !_nonEmpty(env.QODIQA_PG_PORT)) {
    problems.push('QODIQA_ALLOW_PG_INTEGRATION_TESTS=true but no explicit PostgreSQL target in the process environment ' +
      '(QODIQA_PG_HOST and QODIQA_PG_PORT must both be set); .env is never used as a test target');
  } else if (isLiveEndpoint(env.QODIQA_PG_HOST, env.QODIQA_PG_PORT)) {
    problems.push(`the explicit PostgreSQL target ${env.QODIQA_PG_HOST}:${env.QODIQA_PG_PORT} is a LIVE port on this machine`);
  }
  for (const k of ['QODIQA_PG_URL', 'DATABASE_URL']) {
    const t = _nonEmpty(env[k]) ? _portOfUrl(env[k], 5432) : null;
    if (t && isLiveEndpoint(t.host, t.port)) problems.push(`${k} names ${t.host}:${t.port}, a LIVE port on this machine`);
  }
  if (_nonEmpty(env.PGPORT) && isLiveEndpoint(_nonEmpty(env.PGHOST) ? env.PGHOST : 'localhost', env.PGPORT)) {
    problems.push(`PGHOST/PGPORT name a LIVE port on this machine (${env.PGPORT})`);
  }
  const r = explicitRedisTarget(env);
  if (r && isLiveEndpoint(r.host, r.port)) problems.push(`REDIS_URL ${r.host}:${r.port} is a LIVE port on this machine`);
  return problems;
}

module.exports = {
  LIVE_PORTS, PG_TARGET_KEYS, REDIS_TARGET_KEYS, TARGET_KEYS, ALLOW_FLAG, LOG_FILE_VAR, EXTRA_PORTS_VAR, PRELOAD_PATH,
  isExempt, isOwnHost, isLiveEndpoint, connectTarget, guardedPorts, installSocketGuard, uninstallSocketGuard, blockedAttempts,
  preloadOption, withPreload, dotenvParsed, neutraliseDotenvTargets, isolatedChildEnv,
  explicitPgTarget, explicitRedisTarget, optInProblems,
};
