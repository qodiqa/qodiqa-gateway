'use strict';

/**
 * — write-capable operator scripts must not reach the LIVE cluster by default.
 *
 * Several scripts defaulted to `localhost:5432` (host `QODIQA_PG_HOST || 'localhost'`, port `QODIQA_PG_PORT || '5432'`), and
 * the repository's .env names exactly that cluster, which hosts the LIVE `qodiqa` database. Now such a script:
 *   1. needs an EXPLICIT PostgreSQL host and port (QODIQA_PG_HOST and QODIQA_PG_PORT set — no built-in default), and
 *   2. refuses a target on the standard LIVE port (5432) / loopback unless QODIQA_ALLOW_LIVE_TARGET=true is passed INLINE for
 *      that single invocation (same pattern as QODIQA_PG_ALLOW_SHARED — never put it in .env).
 * CI (CI=true) is exempt: its services are disposable.
 */

class LiveTargetError extends Error {
  constructor(message, code) { super(message); this.name = 'LiveTargetError'; this.code = code; }
}

const LIVE_PORTS = new Set(['5432']);

function checkPgTarget(env = process.env) {
  if (env.CI === 'true') return { ok: true, reason: 'CI' };
  if (env.QODIQA_ALLOW_LIVE_TARGET === 'true') return { ok: true, reason: 'ALLOW_LIVE_TARGET' };
  const host = env.QODIQA_PG_HOST;
  const port = env.QODIQA_PG_PORT;
  if (!host || !port) return { ok: false, code: 'PG_TARGET_NOT_EXPLICIT', message: 'QODIQA_PG_HOST and QODIQA_PG_PORT must both be set explicitly (no default to localhost:5432)' };
  if (LIVE_PORTS.has(String(port))) return { ok: false, code: 'PG_TARGET_IS_LIVE_PORT', message: `QODIQA_PG_PORT=${port} is the standard cluster port, which hosts the LIVE database` };
  return { ok: true, reason: 'EXPLICIT_NON_LIVE' };
}

/** Throws LiveTargetError when `script` would write to an implicit or LIVE PostgreSQL target. */
function assertExplicitNonLiveTarget(script, env = process.env) {
  const r = checkPgTarget(env);
  if (!r.ok) {
    throw new LiveTargetError(`${script}: refusing to run — ${r.message}. Point it at a disposable database via QODIQA_PG_HOST/QODIQA_PG_PORT, or, for a deliberate operation on the live cluster, pass QODIQA_ALLOW_LIVE_TARGET=true inline for this one invocation.`, r.code);
  }
}

/** CLI convenience: print the refusal and exit 2. */
function assertOrExit(script, env = process.env) {
  try { assertExplicitNonLiveTarget(script, env); } catch (e) { console.error(e.message); process.exit(2); }
}

module.exports = { assertExplicitNonLiveTarget, assertOrExit, checkPgTarget, LiveTargetError };
