'use strict';

/**
 * RBAC operator API key bootstrap for tests that need to call an
 * RBAC-gated admin endpoint (e.g. POST /consent, needed to reach a
 * genuine decision:EXECUTE from /verify under this repo's default
 * REQUIRE_CONSENT policy — see services/policy/evaluators/requireConsent.js).
 *
 * There is deliberately no HTTP-reachable path to mint the very first
 * operator API key (see scripts/rbac-bootstrap-key.js's own module
 * comment) — it must be provisioned out-of-band, with direct filesystem
 * access to the same RBAC store file the server reads
 * (QODIQA_RBAC_STORE_PATH). The RBAC store also only reads that file once
 * per process (src/core/rbac/store.js's _ensureLoaded() guard) and is
 * never re-read afterward, so the key MUST be provisioned into the store
 * file BEFORE the server process starts and takes its own first read —
 * provisioning it afterward would be invisible to the already-running
 * server.
 */

const path = require('path');
const { spawnSync } = require('child_process');

const { REPO_ROOT } = require('./server');
const { baseOsEnv } = require('./environment');

/**
 * Runs scripts/rbac-bootstrap-key.js against an isolated RBAC store file,
 * creating the bootstrap admin and issuing its API key. Must be called
 * BEFORE the server that will read the same store path is started.
 *
 * @param {string} rbacStorePath  an isolated, not-yet-existing file path
 * @returns {{ status: string, userId: string, apiKey?: string }}
 */
function bootstrapOperatorApiKey(rbacStorePath) {
  const res = spawnSync(process.execPath, ['scripts/rbac-bootstrap-key.js'], {
    cwd: REPO_ROOT,
    env: { ...baseOsEnv(), QODIQA_RBAC_STORE_PATH: rbacStorePath },
    encoding: 'utf8',
  });

  if (res.status !== 0) {
    throw new Error(`rbac-bootstrap-key.js exited ${res.status}: ${res.stderr || res.stdout}`);
  }

  // stdout is a mix of single-line NDJSON log events (services/logger.js)
  // followed by the script's own final result, pretty-printed via
  // console.log(JSON.stringify(x, null, 2)) — which always starts with a
  // lone "{" on its own line. Take everything from the last such line to
  // isolate that final block from the log lines preceding it.
  const lines = res.stdout.split('\n');
  const startIdx = lines.lastIndexOf('{');
  if (startIdx === -1) {
    throw new Error(`rbac-bootstrap-key.js produced no parseable result block: ${res.stdout}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(lines.slice(startIdx).join('\n'));
  } catch (err) {
    throw new Error(`rbac-bootstrap-key.js result block was not valid JSON: ${res.stdout}`);
  }

  if (!parsed.apiKey) {
    throw new Error(`rbac-bootstrap-key.js did not issue an API key: ${res.stdout}`);
  }

  return parsed;
}

/**
 * REL-01 /: the HTTP admin API no longer hands one admin a working key for a
 * peer (403 PEER_CREDENTIAL_FORBIDDEN) — that let one person act as author, reviewer and approver in maker-checker.
 * A second operator is provisioned the way a real deployment does it: out of band, with host access, before the
 * server reads the store (memory-mode control plane: the seed file; scripts/rbac-bootstrap-key.js uses the same
 * store functions). Must run after bootstrapOperatorApiKey() and before the server starts.
 *
 * @returns {{ userId: string, username: string, apiKey: string }}
 */
function provisionOperatorOutOfBand(rbacStorePath, username, role = 'admin') {
  const script = [
    "const s = require('./src/core/rbac/store');",
    "const u = s.createUser({ username: process.argv[1], role: process.argv[2], createdBy: 'out-of-band' });",
    "const k = s.issueApiKey(u.id, { issuedBy: 'out-of-band' });",
    "s.exportSeedFixture();",
    "process.stdout.write('\\nREL01_RESULT ' + JSON.stringify({ userId: u.id, username: u.username, apiKey: k.plaintext }) + '\\n');",
  ].join(' ');
  const res = spawnSync(process.execPath, ['-e', script, username, role], {
    cwd: REPO_ROOT,
    env: { ...baseOsEnv(), QODIQA_RBAC_STORE_PATH: rbacStorePath },
    encoding: 'utf8',
  });
  const line = (res.stdout || '').split(/\r?\n/).find((l) => l.startsWith('REL01_RESULT '));
  if (res.status !== 0 || !line) {
    throw new Error(`out-of-band operator provisioning failed (exit ${res.status}): ${res.stderr || res.stdout}`);
  }
  const parsed = JSON.parse(line.slice('REL01_RESULT '.length));
  if (typeof parsed.apiKey !== 'string') throw new Error('out-of-band operator provisioning returned no API key');
  return parsed;
}

module.exports = { bootstrapOperatorApiKey, provisionOperatorOutOfBand };
