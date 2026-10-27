#!/usr/bin/env node
'use strict';

/**
 * `qodiqa dev` - a local sandbox for developers: the REAL gateway (scripts/bootstrap-dev.js -> server.js, full enforcement pipeline) in an isolated temporary environment, with
 *   - a built-in sandbox AI provider, so /ai/chat works without any provider account (scripts/dev/sandboxProvider.js; a stand-in for the model only),
 *   - sandbox policies (policies.sandbox.json: no consent registry needed, a demo content rule that refuses the phrase "sandbox-block-me"),
 *   - a disposable Redis and a disposable PostgreSQL container when none is configured (needs Docker; both are tmpfs-backed, `--rm`, stopped on exit). PostgreSQL holds the consent registry:
 *     the sandbox grants consent to its own dev identity, through the same API production uses, so REQUIRE_CONSENT still runs on every request.
 * Nothing is written outside a fresh temp directory; the production data/ is never touched. NOT a production configuration.
 *
 *   npm run dev:sandbox            or      node bin/qodiqa.js dev [--port 3000] [--redis-url redis://127.0.0.1:6379] [--no-docker-redis]
 */

const path = require('path');
const net = require('net');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const sandboxProvider = require('./sandboxProvider');

const REPO = path.join(__dirname, '..', '..');
const PG_IMAGE = 'postgres:16-alpine@sha256:f4610795587492cd4fb887c2dc3de301b813278bb6f616992061141b5f15ac36';

function parseArgs(argv) {
  const o = { port: process.env.PORT || '3000', redisUrl: process.env.REDIS_URL || 'redis://127.0.0.1:6379', dockerRedis: true, dockerPg: true };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--port') o.port = String(argv[++i]);
    else if (a === '--redis-url') o.redisUrl = String(argv[++i]);
    else if (a === '--no-docker-redis') o.dockerRedis = false;
    else if (a === '--no-docker-pg') o.dockerPg = false;
    else if (a === '--help' || a === '-h') o.help = true;
    else throw new Error(`unknown option ${a}`);
  }
  if (!/^\d{1,5}$/.test(o.port) || Number(o.port) < 1 || Number(o.port) > 65535) throw new Error('--port must be 1..65535');
  return o;
}

function reachable(url) {
  return new Promise((resolve) => {
    let u; try { u = new URL(url); } catch { return resolve(false); }
    const s = net.connect({ host: u.hostname, port: Number(u.port || 6379), timeout: 1500 });
    s.on('connect', () => { s.destroy(); resolve(true); });
    s.on('error', () => resolve(false));
    s.on('timeout', () => { s.destroy(); resolve(false); });
  });
}

function freePort() {
  return new Promise((resolve, reject) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); s.on('error', reject); });
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  if (o.help) {
    process.stdout.write('qodiqa dev - local sandbox: the real gateway with a built-in sandbox provider and sandbox policies.\n  --port <n>            port of the gateway (default 3000)\n  --redis-url <url>     Redis to use (default redis://127.0.0.1:6379)\n  --no-docker-redis     do not start a disposable Redis container when none is reachable\n');
    return;
  }
  let redisContainer = null;
  if (!(await reachable(o.redisUrl))) {
    if (!o.dockerRedis) throw new Error(`Redis is not reachable at ${o.redisUrl} (start one, or drop --no-docker-redis to let the sandbox start a disposable container)`);
    const p = await freePort();
    const name = `qodiqa-sandbox-redis-${process.pid}`;
    const r = spawnSync('docker', ['run', '-d', '--rm', '--name', name, '-p', `127.0.0.1:${p}:6379`, 'redis:7-alpine'], { encoding: 'utf8' });
    if (r.status !== 0) throw new Error(`Redis is not reachable at ${o.redisUrl} and a disposable container could not be started (${(r.stderr || r.stdout || 'docker not available').trim().slice(0, 200)})`);
    redisContainer = name;
    o.redisUrl = `redis://127.0.0.1:${p}`;
    for (let i = 0; i < 30 && !(await reachable(o.redisUrl)); i++) await new Promise((r2) => setTimeout(r2, 500));
    process.stdout.write(`[qodiqa dev] disposable Redis container ${name} on ${o.redisUrl}\n`);
  }

  // PostgreSQL for the consent registry: the one the developer configured (QODIQA_PG_ENABLED=true), else a disposable container
  let pgContainer = null; const pgEnv = {};
  if (process.env.QODIQA_PG_ENABLED !== 'true' && o.dockerPg) {
    const p = await freePort();
    const name = `qodiqa-sandbox-pg-${process.pid}`;
    const pw = crypto.randomBytes(16).toString('hex');
    const r = spawnSync('docker', ['run', '-d', '--rm', '--name', name, '-p', `127.0.0.1:${p}:5432`, '--tmpfs', '/var/lib/postgresql/data:rw,size=1g', '-e', 'POSTGRES_USER=qodiqa', '-e', `POSTGRES_PASSWORD=${pw}`, '-e', 'POSTGRES_DB=postgres', PG_IMAGE], { encoding: 'utf8' });
    if (r.status !== 0) throw new Error(`a disposable PostgreSQL container could not be started (${(r.stderr || r.stdout || 'docker not available').trim().slice(0, 200)}); use --no-docker-pg to run without consent`);
    pgContainer = name;
    for (let i = 0; i < 60; i++) { const q = spawnSync('docker', ['exec', name, 'pg_isready', '-U', 'qodiqa'], { encoding: 'utf8' }); if (q.status === 0) break; await new Promise((r2) => setTimeout(r2, 1000)); }
    // The migrations create the runtime roles with their PUBLISHED placeholder passwords (src/infra/postgres/roleCredentials.js); on this loopback-only, tmpfs-backed, throw-away database the sandbox simply uses them.
    Object.assign(pgEnv, {
      QODIQA_PG_ENABLED: 'true', QODIQA_PG_HOST: '127.0.0.1', QODIQA_PG_PORT: String(p), QODIQA_PG_SSL: 'false', QODIQA_PG_DATABASE: '',
      QODIQA_PG_TEST_USER: 'qodiqa', QODIQA_PG_TEST_PASSWORD: pw, QODIQA_PG_MIG_USER: 'qodiqa', QODIQA_PG_MIG_PASSWORD: pw,
      QODIQA_PG_USER: 'qodiqa_app', QODIQA_PG_PASSWORD: 'REPLACE_WITH_VAULT_SECRET_APP', QODIQA_PG_RETENTION_PASSWORD: 'REPLACE_WITH_VAULT_SECRET_RETENTION',
      QODIQA_PG_SYSTEM_PASSWORD: 'REPLACE_WITH_VAULT_SECRET_SYSTEM', QODIQA_PG_REPORTING_PASSWORD: 'REPLACE_WITH_VAULT_SECRET_REPORTING', QODIQA_PG_CONTROL_PASSWORD: 'REPLACE_WITH_VAULT_SECRET_CONTROL', QODIQA_PG_BACKUP_PASSWORD: 'REPLACE_WITH_VAULT_SECRET_BACKUP',
    });
    process.stdout.write(`[qodiqa dev] disposable PostgreSQL container ${name} on 127.0.0.1:${p}
`);
  }

  const provider = await sandboxProvider.start();
  process.stdout.write(`[qodiqa dev] sandbox provider at ${provider.url} (model ${provider.model})\n`);

  const env = {
    ...process.env,
    PORT: o.port,
    REDIS_URL: o.redisUrl,
    POLICY_FILE: undefined,                       // bootstrap-dev copies the file named below into its temp directory
    LOCAL_BASE_URL: provider.url,
    PROVIDER_DEFAULT_MODEL_LOCAL: provider.model,
    QODIQA_SANDBOX: 'true',
    ...pgEnv,
  };
  delete env.POLICY_FILE;
  for (const k of ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY', 'MISTRAL_API_KEY', 'LLAMA_BASE_URL', 'AZURE_OPENAI_API_KEY']) delete env[k];
  env.QODIQA_DEV_POLICY_SOURCE = path.join(REPO, 'scripts', 'dev', 'policies.sandbox.json');

  process.stdout.write(`[qodiqa dev] gateway on http://127.0.0.1:${o.port} - the keys it generates are printed below\n`);
  const child = spawn(process.execPath, [path.join(REPO, 'scripts', 'bootstrap-dev.js')], { cwd: REPO, env, stdio: 'inherit' });

  let stopping = false;
  const cleanup = async () => {
    if (stopping) return; stopping = true;
    try { await provider.close(); } catch { /* closing */ }
    for (const c of [redisContainer, pgContainer]) if (c) spawnSync('docker', ['stop', c], { stdio: 'ignore' });
  };
  const forward = (sig) => { if (!child.killed) child.kill(sig); };
  process.on('SIGINT', () => forward('SIGINT'));
  process.on('SIGTERM', () => forward('SIGTERM'));
  child.on('exit', async (code) => { await cleanup(); process.exit(code ?? 0); });
  child.on('error', async (e) => { process.stderr.write(`[qodiqa dev] cannot start the gateway: ${e.message}\n`); await cleanup(); process.exit(1); });
}

main().catch((e) => { process.stderr.write(`[qodiqa dev] ${e.message}\n`); process.exit(1); });
