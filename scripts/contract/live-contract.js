#!/usr/bin/env node
'use strict';

/**
 * LIVE response-contract check: real server responses vs the committed OpenAPI (docs/api/openapi.json), and the
 * real JavaScript and Python SDKs run against the same live server.
 *
 * Boots the REAL server once (test/harness/server.js startBootstrapped: fresh per-boot PostgreSQL database,
 * isolated stores, Redis), with the zero-latency stub provider (no paid calls) and an operator key from the same RBAC
 * bootstrap the acceptance suite uses. Then:
 *   1. drives the SDK-facing flows (sign → /ai/chat EXECUTE and BLOCK → transparency entries/entry/proof/verify/roots/
 *      root → admin root generation/stats/chain validate → verify/verify v2 → public keys → the standard error classes)
 *      and validates every response body against the OpenAPI response schema for that operation and HTTP status;
 *   2. runs the SDK contract probes (sdk/javascript built dist via scripts/contract/sdk-probe.mjs; sdk/python via its
 *      venv and scripts/contract/sdk_probe.py) against the same server, each asserting the parsed shapes.
 * Teardown ends processes only: the per-boot database is kept.
 *
 *   W8_SCRATCH=<abs dir outside repo> node scripts/contract/live-contract.js <out.json> [--no-sdk]
 * Exit 1 when any response violates its documented schema, any operation/status is undocumented, or an SDK probe fails.
 */

const fs = require('fs'); const net = require('net'); const path = require('path'); const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const { validate, findOperation, resolve } = require('./lib/schemaValidate');

const REPO = path.join(__dirname, '..', '..');
const OUT = path.resolve(process.argv[2] || path.join(REPO, 'evidence', 'w12', 'contract', 'live-contract.json'));
const NO_SDK = process.argv.includes('--no-sdk');
const SCRATCH = process.env.W8_SCRATCH;
const KEY_RE = /Authorization: Bearer (\S+)/;
const DEV_DB_RE = /using a fresh, isolated per-boot database "(qodiqa_dev_[0-9a-f]+)"/;
const redact = (s) => String(s).replace(/sk_[0-9a-f]{16,}/g, '<redacted-sign-key>').replace(/ok_[0-9a-f]{16,}/g, '<redacted-ops-key>');
const freePort = () => new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64');

(async () => {
  const { insideRepo } = require(path.join(REPO, 'scripts/audit-repro/lib/signKey'));
  if (!SCRATCH || !path.isAbsolute(SCRATCH) || insideRepo(SCRATCH)) throw new Error('W8_SCRATCH must be an absolute dir outside the repo');
  const doc = JSON.parse(fs.readFileSync(path.join(REPO, 'docs', 'api', 'openapi.json'), 'utf8'));
  const result = { generatedAt: new Date().toISOString(), head: spawnSync('git', ['rev-parse', 'HEAD'], { cwd: REPO, encoding: 'utf8' }).stdout.trim(),
    contractSha256: crypto.createHash('sha256').update(fs.readFileSync(path.join(REPO, 'docs', 'api', 'openapi.json'))).digest('hex'), checks: [], sdk: {} };

  const stubPort = await freePort();
  const stub = spawn(process.execPath, ['scripts/e2e/stub.js', String(stubPort)], { cwd: REPO, stdio: 'ignore' });
  await sleep(300);
  const { startBootstrapped } = require(path.join(REPO, 'test/harness/server.js'));
  const { prepareRigStores } = require(path.join(REPO, 'scripts/e2e/lib/rig'));
  const { killProcessTree } = require(path.join(REPO, 'test/harness/process'));
  const rig = prepareRigStores(path.join(SCRATCH, `w12-contract-rig-${process.pid}`));
  const rbacStore = path.join(SCRATCH, `w12-contract-rbac-${process.pid}.json`);
  const OPS = require(path.join(REPO, 'test/harness/rbac.js')).bootstrapOperatorApiKey(rbacStore).apiKey;
  const srv = await startBootstrapped({ env: { LLAMA_BASE_URL: `http://127.0.0.1:${stubPort}/v1`, ...rig.env, QODIQA_RBAC_STORE_PATH: rbacStore } });
  let failed = false;
  try {
    const out = srv.startupResult.output || '';
    const SIGN = (out.match(KEY_RE) || [])[1];
    result.db = (out.match(DEV_DB_RE) || [])[1] || null;
    const B = srv.baseUrl;
    if (!SIGN) throw new Error('dev signing key not found in boot output');

    /** One HTTP call, validated against the contract. */
    async function call(name, method, p, { headers = {}, body, expectStatus } = {}) {
      const r = await fetch(B + p, { method: method.toUpperCase(), headers: { ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...headers }, body: body !== undefined ? JSON.stringify(body) : undefined });
      const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch { /* non-JSON */ }
      const c = { name, method, path: p.replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, '{uuid}'), status: r.status, errors: [] };
      if (expectStatus && r.status !== expectStatus) c.errors.push(`expected HTTP ${expectStatus}, got ${r.status}: ${redact(text.slice(0, 300))}`);
      const op = findOperation(doc, method, p);
      if (!op) c.errors.push('operation not documented in docs/api/openapi.json');
      else {
        c.operation = `${method} ${op.tpl}`;
        const resp = op.op.responses[String(r.status)] || op.op.responses.default;
        if (!resp) c.errors.push(`HTTP ${r.status} not documented for ${method} ${op.tpl} (documented: ${Object.keys(op.op.responses).join(',')})`);
        else {
          const rr = resolve(resp, doc);
          const media = rr.content && (rr.content['application/json'] || null);
          if (media && media.schema) {
            if (json === null) c.errors.push(`documented JSON body but got non-JSON: ${redact(text.slice(0, 120))}`);
            else c.errors.push(...validate(media.schema, json, doc).map((e) => `body${e}`));
          }
        }
      }
      c.body = json === null ? redact(text.slice(0, 400)) : JSON.parse(redact(JSON.stringify(json)).slice(0, 1_000_000));
      c.ok = c.errors.length === 0;
      if (!c.ok) failed = true;
      result.checks.push(c);
      return { status: r.status, json, headers: r.headers };
    }
    const signFor = async (chatBody) => (await call('sign (ai/chat artifact)', 'post', '/sign', { headers: { Authorization: `Bearer ${SIGN}` }, body: { request: { method: 'POST', path: '/ai/chat', body: chatBody }, payload: { provider: 'llama' } }, expectStatus: 200 })).json;
    const ops = { Authorization: `Bearer ${OPS}` };

    // ── protocol surface ────────────────────────────────────────────────────────
    await call('health', 'get', '/health', { expectStatus: 200 });
    await call('ready', 'get', '/ready');
    await call('public keys', 'get', '/public-keys', { expectStatus: 200 });
    await call('sign without credentials → 401', 'post', '/sign', { body: { request: { method: 'POST', path: '/ai/chat', body: {} } }, expectStatus: 401 });
    await call('sign invalid body → 400', 'post', '/sign', { headers: { Authorization: `Bearer ${SIGN}` }, body: { request: 'nope' }, expectStatus: 400 });
    const chatBody = { prompt: 'What is the capital of France?', provider: 'llama', model: 'stub-model' };
    const s1 = await signFor(chatBody);
    const ex = await call('ai/chat EXECUTE', 'post', '/ai/chat', { headers: { 'x-qodiqa-artifact': b64(s1.artifact) }, body: chatBody, expectStatus: 200 });
    await call('ai/chat replay → BLOCK 200', 'post', '/ai/chat', { headers: { 'x-qodiqa-artifact': b64(s1.artifact) }, body: chatBody, expectStatus: 200 });
    await call('ai/chat missing artifact → BLOCK 200', 'post', '/ai/chat', { body: chatBody, expectStatus: 200 });
    const s2 = await signFor(chatBody);
    await call('verify (dry run)', 'post', '/verify', { body: { artifact: s2.artifact, request: { method: 'POST', path: '/ai/chat', body: chatBody } } });

    // ── transparency ────────────────────────────────────────────────────────────
    await sleep(1500);   // transparency leaf registration is post-response
    const ents = await call('transparency entries', 'get', '/v1/transparency/entries?pageSize=5', { expectStatus: 200 });
    const entryList = (ents.json && (ents.json.data ? ents.json.data.entries : ents.json.entries)) || [];
    const tid = entryList[0] && (entryList[0].transparencyId || entryList[0].transparency_id);
    result.transparencyEntrySample = tid ? 'present' : 'none';
    await call('transparency admin root generate', 'post', '/v1/transparency/admin/roots/generate', { headers: ops, expectStatus: 201 });
    const roots = await call('transparency roots (paginated list)', 'get', '/v1/transparency/roots?page=1&pageSize=5', { expectStatus: 200 });
    const rootList = (roots.json && (roots.json.data ? roots.json.data.roots : roots.json.roots)) || [];
    await call('transparency latest root', 'get', '/v1/transparency/root', { expectStatus: 200 });
    if (rootList[0]) await call('transparency root by id', 'get', `/v1/transparency/root?rootId=${encodeURIComponent(rootList[0].root_id || rootList[0].rootId)}`, { expectStatus: 200 });
    if (tid) {
      await call('transparency entry', 'get', `/v1/transparency/entry/${tid}`, { expectStatus: 200 });
      await call('transparency proof', 'get', `/v1/transparency/proof/${tid}`, { expectStatus: 200 });
      await call('transparency verify', 'get', `/v1/transparency/verify/${tid}`, { expectStatus: 200 });
    }
    await call('transparency entry unknown → 404', 'get', `/v1/transparency/entry/${crypto.randomUUID()}`, { expectStatus: 404 });
    await call('transparency admin stats', 'get', '/v1/transparency/admin/stats', { headers: ops, expectStatus: 200 });
    await call('transparency admin chain validate', 'get', '/v1/transparency/admin/chain/validate', { headers: ops, expectStatus: 200 });
    await call('transparency admin stats without auth → 401', 'get', '/v1/transparency/admin/stats', { expectStatus: 401 });
    // ── auth requirements the SDKs must honour ──────────────────────────────────
    await call('certification evaluate without auth → 401', 'post', '/v1/certification/evaluate', { body: {}, expectStatus: 401 });
    await call('attestation chain verify without auth → 401', 'post', '/v1/attestation/chain/verify', { body: {}, expectStatus: 401 });
    await call('audit chain integrity without auth → 401', 'get', '/audit/chain/integrity', { expectStatus: 401 });
    result.executeDecision = ex.json && ex.json.decision;

    // ── SDK probes against the same live server ─────────────────────────────────
    if (!NO_SDK) {
      await sleep(6000);   // let the transparency bucket's 5 s burst window reset after the checks above
      const env = { ...process.env, QODIQA_CONTRACT_BASE: B, QODIQA_CONTRACT_SIGN_KEY: SIGN, QODIQA_CONTRACT_OPS_KEY: OPS };
      const js = spawnSync(process.execPath, [path.join(__dirname, 'sdk-probe.mjs')], { cwd: REPO, env, encoding: 'utf8', timeout: 180_000 });
      result.sdk.javascript = { exit: js.status, report: (() => { try { return JSON.parse(js.stdout.trim().split('\n').pop()); } catch { return { raw: redact(js.stdout.slice(-2000)), stderr: redact(js.stderr.slice(-2000)) }; } })() };
      await sleep(6000);
      const py = spawnSync(path.join(REPO, 'sdk', 'python', '.venv', 'Scripts', 'python.exe'), [path.join(__dirname, 'sdk_probe.py')], { cwd: REPO, env, encoding: 'utf8', timeout: 180_000 });
      result.sdk.python = { exit: py.status, report: (() => { try { return JSON.parse(py.stdout.trim().split('\n').pop()); } catch { return { raw: redact((py.stdout || '').slice(-2000)), stderr: redact((py.stderr || '').slice(-2000)) }; } })() };
      if (js.status !== 0 || py.status !== 0) failed = true;
    }
  } finally {
    await killProcessTree(srv.handle.child);   // processes only — the per-boot database is kept
    stub.kill();
  }
  result.summary = { checks: result.checks.length, ok: result.checks.filter((c) => c.ok).length, failed: result.checks.filter((c) => !c.ok).map((c) => c.name),
    sdkJs: result.sdk.javascript && result.sdk.javascript.exit, sdkPy: result.sdk.python && result.sdk.python.exit, verdict: failed ? 'FAIL' : 'PASS' };
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(result, null, 1));
  process.stdout.write(`${JSON.stringify(result.summary)}\n`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error('live-contract error:', redact(e.stack || e.message)); process.exit(1); });
