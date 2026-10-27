#!/usr/bin/env node
'use strict';

/**
 * Smoke test for the Docker Compose sandbox (docker-compose.quickstart.yml), run against a clean checkout.
 * It follows the quick start and times every step:
 *   1 /health answers after `docker compose up`        2 the throwaway signing key is in the log
 *   3 sign + /ai/chat -> EXECUTE with the sandbox answer
 *   4 sign + /ai/chat with a prompt the sandbox content rule refuses -> BLOCK
 *   5 the signed artifact of step 3 is verified OFFLINE with the standalone verifier (tools/verify/verify.external.js) and the published key set
 *   6 the same artifact against a request with a changed body is rejected offline
 * The two decisions are written to the session record (--record <file>): request, signed artifact, response and the offline verdicts.
 * The signing key is never printed. Timings go to the log and, when GITHUB_STEP_SUMMARY is set, to the job summary.
 *
 *   docker compose -f docker-compose.quickstart.yml up -d
 *   node scripts/ci/quickstart-smoke.js [--base http://127.0.0.1:3000] [--wait-seconds 600] [--record quickstart-session.json] [--up-seconds <n>]
 */

const { execSync, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const arg = (n, d) => { const i = process.argv.indexOf('--' + n); return i > 0 ? process.argv[i + 1] : d; };
const BASE = arg('base', 'http://127.0.0.1:3000');
const WAIT_MS = Number(arg('wait-seconds', '600')) * 1000;
const RECORD = arg('record', null);
const UP_SECONDS = arg('up-seconds', null);
const COMPOSE = ['docker', 'compose', '-f', 'docker-compose.quickstart.yml'];
const VERIFIER = ['tools/verify/verify.external.js', 'scripts/verify.external.js'].map((f) => path.resolve(f)).find((f) => fs.existsSync(f)) || path.resolve('tools/verify/verify.external.js');   // run from the repository root

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
const timings = [];
const T0 = Date.now();
const check = (ok, label, detail) => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ' - ' + detail : ''}`); if (!ok) failures++; };
async function timed(step, fn) {
  const t = Date.now();
  const r = await fn();
  const s = (Date.now() - t) / 1000;
  timings.push([step, s]);
  console.log(`TIME  ${step}: ${s.toFixed(1)} s`);
  return r;
}

async function call(p, opts) {
  const r = await fetch(BASE + p, opts);
  const text = await r.text();
  let body; try { body = JSON.parse(text); } catch { body = text; }
  return { status: r.status, body };
}

async function waitForHealth() {
  const until = Date.now() + WAIT_MS;
  while (Date.now() < until) {
    try { const h = await call('/health'); if (h.status === 200) return h; } catch { /* not up yet */ }
    await sleep(2000);
  }
  return null;
}

function summary() {
  const total = (Date.now() - T0) / 1000;
  const rows = [];
  if (UP_SECONDS) rows.push(['docker compose up -d (image build and start)', Number(UP_SECONDS)]);
  rows.push(...timings);
  const md = ['### Quickstart smoke: timings', '', '| Step | Seconds |', '|---|---|', ...rows.map(([s, t]) => `| ${s} | ${t.toFixed(1)} |`),
    `| smoke script total | ${total.toFixed(1)} |`, '', failures ? `**${failures} check(s) failed.**` : 'All checks passed.', ''].join('\n');
  console.log(md);
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md + '\n');
}

(async () => {
  const health = await timed('gateway healthy (after up)', waitForHealth);
  check(!!health, 'GET /health answers 200 after start', health ? JSON.stringify(health.body).slice(0, 60) : `no answer within ${WAIT_MS / 1000}s`);
  if (!health) { try { console.log(execSync(COMPOSE.join(' ') + ' logs --tail 80 gateway', { encoding: 'utf8' })); } catch { /* ignore */ } summary(); process.exit(1); }

  const logs = execSync(COMPOSE.join(' ') + ' logs gateway', { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const key = /Authorization: Bearer (\S+)/.exec(logs);
  check(!!key, 'the sandbox prints a signing key');
  if (!key) { summary(); process.exit(1); }

  const run = async (prompt) => {
    const request = { method: 'POST', path: '/ai/chat', body: { prompt } };
    const s = await call('/sign', { method: 'POST', headers: { Authorization: 'Bearer ' + key[1], 'content-type': 'application/json' },
      body: JSON.stringify({ request, payload: { userId: 'me' }, ttl: 60000 }) });
    if (s.status !== 200) return { request, sign: s };
    const artifact = s.body.artifact || s.body;
    const c = await call('/ai/chat', { method: 'POST', headers: { 'content-type': 'application/json', 'x-qodiqa-artifact': Buffer.from(JSON.stringify(artifact)).toString('base64') }, body: JSON.stringify({ prompt }) });
    return { request, artifact, sign: s, chat: c };
  };

  const ok = await timed('sign + execute request', () => run('hello'));
  check(ok.sign.status === 200, 'POST /sign returns an artifact');
  check(ok.chat && ok.chat.body.decision === 'EXECUTE' && ok.chat.body.response === '[sandbox] hello', 'POST /ai/chat executes with the sandbox provider',
    ok.chat ? `${ok.chat.body.decision} ${ok.chat.body.response}` : 'no chat call');

  const blocked = await timed('sign + blocked request', () => run('sandbox-block-me please'));
  check(blocked.chat && blocked.chat.body.decision === 'BLOCK', 'a request the sandbox content rule refuses is blocked',
    blocked.chat ? `${blocked.chat.body.decision} ${blocked.chat.body.reason}` : 'no chat call');

  // offline verification with the standalone verifier and the published key set (nothing from the running gateway except its public keys)
  const keys = await call('/.well-known/qodiqa/keys');
  check(keys.status === 200 && keys.body && Array.isArray(keys.body.keys), 'the public key set is published');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'qs-'));
  fs.writeFileSync(path.join(tmp, 'keys.json'), JSON.stringify(keys.body));
  const verify = (artifact, request) => spawnSync(process.execPath, [VERIFIER, '--offline', '--historical', '--key-file', path.join(tmp, 'keys.json'), JSON.stringify(artifact), JSON.stringify(request)], { encoding: 'utf8' });
  const v1 = await timed('offline verification of the executed request', async () => verify(ok.artifact, ok.request));
  let verdict1 = {}; try { verdict1 = JSON.parse(v1.stdout); } catch { /* not JSON */ }
  check(v1.status === 0 && verdict1.valid === true, 'the executed request verifies offline', `exit ${v1.status} valid=${verdict1.valid} ${(v1.stdout + v1.stderr).replace(/\s+/g, ' ').slice(0, 300)}`);
  const changed = { ...ok.request, body: { prompt: 'goodbye' } };
  const v2 = verify(ok.artifact, changed);
  check(v2.status !== 0, 'the same artifact with a changed request body is rejected offline', `exit ${v2.status}`);

  if (RECORD) {
    const rec = { recordedAt: new Date().toISOString(), profile: 'quickstart sandbox (built-in sandbox model, no AI provider)',
      sessions: [
        { name: 'execute', request: ok.request, artifact: ok.artifact, response: ok.chat && ok.chat.body, offlineVerdict: verdict1 },
        { name: 'block', request: blocked.request, artifact: blocked.artifact, response: blocked.chat && blocked.chat.body },
        { name: 'changed-body', request: changed, artifact: ok.artifact, offlineExit: v2.status },
      ] };
    fs.writeFileSync(RECORD, JSON.stringify(rec, null, 2) + '\n');
    console.log('recorded ' + RECORD);
  }
  summary();
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error('FAIL  smoke test crashed:', e.message); summary(); process.exit(1); });
