#!/usr/bin/env node
'use strict';

/**
 *boot the BUILT IMAGE in the PRODUCTION profile, on real TLS
 * dependencies, and require it to pass its own production boot validator, reach /ready and decide a real request.
 *
 * The previous CI "Docker Build + Boot" job booted NODE_ENV=production with plaintext PostgreSQL/Redis, placeholder
 * role passwords and no MAC keyring — an environment the product's own validator refuses with 11 fatal errors, i.e.
 * the job could not pass on the code it was meant to gate. This gate builds the environment the product requires:
 *
 *   network     a private docker network qodiqa-cbg-<run>
 *   PKI         throwaway CA + server cert (SAN DNS:pg, DNS:redis), openssl, in a temp dir
 *   PostgreSQL  postgres container with ssl=on (the server itself terminates TLS — no front-end)
 *   migrations  run by the IMAGE (src/infra/postgres/migrate.js) over verified TLS as a bootstrap superuser
 *   roles       every migration-created login role gets a fresh random password (scripts/db/role-credentials.js
 * --rotate, SCRAM verifier); the unused qodiqa_read is disabled (harden-unused) —'s gate
 *   Redis       redis container, TLS-only (port 0, tls-port 6379), password, AOF (STRICT_REPLAY_PROTECTION)
 *   secrets     fresh random KEK / invariant secret / DSR pepper; keystore + MAC keyring provisioned by the image's
 *               own operator tools into a docker volume
 *   boot        NODE_ENV=production, rediss://, QODIQA_PG_SSL=true with the CA; deploy/env/production.policies.example
 *   checks      the boot's BOOT_REPORT has 0 fatal violations; /ready 200 within the bound; /health 200; one signed
 *               request returns an enforcement decision
 *
 * Everything it creates is its own disposable fixture (containers --rm, the network and volume it named), removed
 * on exit. The temp PKI directory is left in the OS temp dir (it holds only a 1-day throwaway CA).
 *
 *   node scripts/ci/container-boot-gate.js <image> [--json out.json] [--pg-image postgres:17-alpine] [--redis-image redis:7]
 *   exit 0 = PASS, 1 = FAIL, 2 = infrastructure error
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const REPO = path.join(__dirname, '..', '..');
const args = process.argv.slice(2);
const opt = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
const IMAGE = args.find((a, i) => !a.startsWith('--') && !(i > 0 && args[i - 1].startsWith('--')));
if (!IMAGE) { console.error('usage: container-boot-gate.js <image> [--json out.json]'); process.exit(64); }
const PG_IMAGE = opt('--pg-image', 'postgres:17-alpine');
const REDIS_IMAGE = opt('--redis-image', 'redis:7');
const JSON_OUT = opt('--json', null);
const RUN = crypto.randomBytes(4).toString('hex');
const NET = `qodiqa-cbg-${RUN}`; const PG = `cbg-pg-${RUN}`; const REDIS = `cbg-redis-${RUN}`; const APP = `cbg-app-${RUN}`; const VOL = `cbg-data-${RUN}`;
const rand = (n = 32) => crypto.randomBytes(n).toString('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const steps = [];

function docker(a, { input, allowFail = false, timeout = 600000 } = {}) {
  const r = spawnSync('docker', a, { encoding: 'utf8', input, timeout, maxBuffer: 64 << 20, env: { ...process.env, MSYS_NO_PATHCONV: '1' } });
  if (r.status !== 0 && !allowFail) throw new Error(`docker ${a.slice(0, 3).join(' ')} … exit ${r.status}: ${(r.stderr || r.stdout || '').trim().slice(-800)}`);
  return r;
}
function step(name, fn) {
  const t0 = Date.now();
  try { const detail = fn(); steps.push({ name, ok: true, ms: Date.now() - t0, ...(detail ? { detail } : {}) }); return detail; } catch (e) { steps.push({ name, ok: false, ms: Date.now() - t0, error: e.message }); throw e; }
}
async function stepA(name, fn) {
  const t0 = Date.now();
  try { const detail = await fn(); steps.push({ name, ok: true, ms: Date.now() - t0, ...(detail ? { detail } : {}) }); return detail; } catch (e) { steps.push({ name, ok: false, ms: Date.now() - t0, error: e.message }); throw e; }
}
const envArgs = (env) => Object.entries(env).flatMap(([k, v]) => ['-e', `${k}=${v}`]);
// docker bind-mount source: forward slashes work for Docker Desktop on Windows
const hostPath = (p) => p.replace(/\\/g, '/');

function makePki(dir) {
  const ossl = (a) => { const r = spawnSync('openssl', a, { cwd: dir, encoding: 'utf8' }); if (r.status !== 0) throw new Error(`openssl ${a[0]}: ${(r.stderr || '').trim().slice(0, 300)}`); };
  const ec = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes'];
  ossl(['req', '-x509', ...ec, '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '1', '-subj', '/CN=qodiqa-cbg-ca']);
  ossl(['req', ...ec, '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=pg']);
  fs.writeFileSync(path.join(dir, 'ext.cnf'), `basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:${PG},DNS:${REDIS}\n`);
  ossl(['x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'server.crt', '-days', '1', '-extfile', 'ext.cnf']);
}

async function main() {
  const pki = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-cbg-pki-'));
  const S = { super: rand(16), redis: rand(16), kek: rand(), invariant: rand(), pepper: rand() };
  const ROLE_PW = { QODIQA_PG_PASSWORD: rand(16), QODIQA_PG_MIG_PASSWORD: rand(16), QODIQA_PG_RETENTION_PASSWORD: rand(16), QODIQA_PG_SYSTEM_PASSWORD: rand(16),
    QODIQA_PG_REPORTING_PASSWORD: rand(16), QODIQA_PG_CONTROL_PASSWORD: rand(16), QODIQA_PG_BACKUP_PASSWORD: rand(16) };
  const ROLES = { qodiqa_app: 'QODIQA_PG_PASSWORD', qodiqa_mig: 'QODIQA_PG_MIG_PASSWORD', qodiqa_retention: 'QODIQA_PG_RETENTION_PASSWORD', qodiqa_system: 'QODIQA_PG_SYSTEM_PASSWORD',
    qodiqa_reporting: 'QODIQA_PG_REPORTING_PASSWORD', qodiqa_control: 'QODIQA_PG_CONTROL_PASSWORD', qodiqa_backup: 'QODIQA_PG_BACKUP_PASSWORD' };
  const CERTS = ['-v', `${hostPath(pki)}:/certs:ro`];
  const PG_TLS = { QODIQA_PG_HOST: PG, QODIQA_PG_PORT: '5432', QODIQA_PG_DATABASE: 'qodiqa', QODIQA_PG_SSL: 'true', QODIQA_PG_SSL_CA: '/certs/ca.crt' };
  const DATA = { QODIQA_KEYS_PATH: '/opt/qodiqa/data/keys.json', QODIQA_MAC_KEYS_PATH: '/opt/qodiqa/data/mac-keys.json', QODIQA_KEY_ENCRYPTION_KEY: S.kek };
  let result = 'FAIL';
  try {
    step('pki', () => { makePki(pki); return { dir: pki }; });
    // production requires audit anchoring — provision a witness exactly as the k8s overlay documents
    // (scripts/anchor/witness-cosign.js --public-key creates the key and prints its public trust record).
    step('audit witness (anchoring)', () => {
      const wdir = path.join(pki, 'witness'); fs.mkdirSync(wdir, { recursive: true });
      const r = spawnSync(process.execPath, [path.join(REPO, 'scripts/anchor/witness-cosign.js'), '--public-key'], { encoding: 'utf8',
        env: { ...process.env, WITNESS_ID: 'cbg-witness', WITNESS_KEY_PATH: path.join(wdir, 'witness-key.json'), WITNESS_LOG_PATH: path.join(wdir, 'unused.jsonl') } });
      if (r.status !== 0) throw new Error(`witness provisioning failed: ${r.stderr}`);
      fs.writeFileSync(path.join(wdir, 'witness-public-keys.json'), JSON.stringify([JSON.parse(r.stdout)]));
      return { witnessId: 'cbg-witness' };
    });
    step('network', () => { docker(['network', 'create', NET]); });
    step('volume', () => { docker(['volume', 'create', VOL]); });
    step('postgres (ssl=on)', () => {
      docker(['run', '-d', '--rm', '--name', PG, '--network', NET, ...CERTS, '-e', 'POSTGRES_USER=cbg_super', '-e', `POSTGRES_PASSWORD=${S.super}`, '-e', 'POSTGRES_DB=qodiqa',
        '--entrypoint', 'sh', PG_IMAGE, '-c',
        'mkdir -p /tls && cp /certs/server.crt /certs/server.key /tls/ && chown -R postgres /tls && chmod 600 /tls/server.key && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tls/server.crt -c ssl_key_file=/tls/server.key']);
    });
    step('redis (TLS-only, AOF, password)', () => {
      docker(['run', '-d', '--rm', '--name', REDIS, '--network', NET, ...CERTS, REDIS_IMAGE, 'redis-server', '--port', '0', '--tls-port', '6379',
        '--tls-cert-file', '/certs/server.crt', '--tls-key-file', '/certs/server.key', '--tls-ca-cert-file', '/certs/ca.crt', '--tls-auth-clients', 'no',
        '--appendonly', 'yes', '--appendfsync', 'everysec', '--requirepass', S.redis]);
    });
    await stepA('postgres ready', async () => {
      for (let i = 0; i < 60; i++) {
        // the init phase restarts the server once; require two consecutive successes over TCP
        if (docker(['exec', PG, 'pg_isready', '-h', '127.0.0.1', '-U', 'cbg_super', '-d', 'qodiqa'], { allowFail: true }).status === 0
          && (await sleep(1000), docker(['exec', PG, 'pg_isready', '-h', '127.0.0.1', '-U', 'cbg_super', '-d', 'qodiqa'], { allowFail: true }).status === 0)) return { seconds: i + 1 };
        await sleep(1000);
      }
      throw new Error('postgres not ready in 60 s');
    });
    const inImage = (env, cmd, extra = []) => docker(['run', '--rm', '--network', NET, ...CERTS, '-v', `${VOL}:/opt/qodiqa/data`, ...extra, ...envArgs(env), '--entrypoint', 'node', IMAGE, ...cmd]);
    step('migrations (by the image, over TLS)', () => {
      const r = inImage({ ...PG_TLS, QODIQA_PG_MIG_USER: 'cbg_super', QODIQA_PG_MIG_PASSWORD: S.super }, ['src/infra/postgres/migrate.js']);
      return { tail: r.stdout.trim().split('\n').slice(-2).join(' | ').slice(0, 300) };
    });
    step('rotate migration role passwords', () => {
      const admin = { ...PG_TLS, QODIQA_PG_ADMIN_USER: 'cbg_super', QODIQA_PG_ADMIN_PASSWORD: S.super };
      for (const [role, v] of Object.entries(ROLES)) inImage({ ...admin, NEWPW: ROLE_PW[v] }, ['scripts/db/role-credentials.js', '--rotate', role, '--password-env', 'NEWPW', '--confirm']);
      inImage(admin, ['scripts/db/role-credentials.js', '--harden-unused', '--confirm']);
      const chk = inImage(admin, ['scripts/db/role-credentials.js', '--check'], ['-e', 'X=1']);
      return { check: chk.stdout.trim().split('\n').slice(-1)[0].slice(0, 200) };
    });
    step('keystore + MAC keyring (image operator tools)', () => {
      inImage(DATA, ['scripts/security/macKeyring.js', 'init'], ['--user', '1000:1000']);
      docker(['run', '--rm', '--user', '1000:1000', '-v', `${VOL}:/opt/qodiqa/data`, ...envArgs(DATA), '--entrypoint', 'node', IMAGE, '-e',
        "const { validateKeyStore, rotateKey } = require('/app/services/artifact/keyStore'); const s = validateKeyStore(); if (!s.clients['cbg-client']) rotateKey('cbg-client'); console.log('keystore ok');"]);
    });
    const appEnv = {
      NODE_ENV: 'production', PORT: '3000', STRICT_REPLAY_PROTECTION: 'true',
      REDIS_URL: `rediss://${REDIS}:6379`, REDIS_PASSWORD: S.redis, REDIS_TLS_CA: '/certs/ca.crt',
      // the migration credential is never part of the gateway's environment (production refuses it)
      ...PG_TLS, QODIQA_PG_ENABLED: 'true', QODIQA_PG_USER: 'qodiqa_app',
      ...Object.fromEntries(Object.entries(ROLE_PW).filter(([k]) => k !== 'QODIQA_PG_MIG_PASSWORD')),
      ...DATA, QODIQA_CLIENT_ID: 'cbg-client', QODIQA_EXECUTION_INVARIANT_SECRET: S.invariant, QODIQA_DSR_PSEUDONYM_PEPPER: S.pepper,
      QODIQA_AUDIT_LOG: '/opt/qodiqa/data/audit.log', QODIQA_TRANSPARENCY_KEYS_PATH: '/opt/qodiqa/data/transparency-keys.json',
      QODIQA_PRQ_JOURNAL_DIR: '/opt/qodiqa/data/prq-journal', POLICY_FILE: '/opt/qodiqa/config/policies.json',
      LOCAL_BASE_URL: 'http://127.0.0.1:1/v1',
      // anchoring on — witness key/public keys from the read-only /certs mount, export + witness log on the volume
      QODIQA_WITNESS_MODE: 'local', QODIQA_WITNESS_ID: 'cbg-witness',
      QODIQA_WITNESS_KEY_PATH: '/certs/witness/witness-key.json', QODIQA_WITNESS_PUBLIC_KEYS: '/certs/witness/witness-public-keys.json',
      QODIQA_WITNESS_LOG_PATH: '/opt/qodiqa/data/anchors/witness-log.jsonl', QODIQA_ANCHOR_EXPORT_PATH: '/opt/qodiqa/data/anchors/anchors.jsonl',
    };
    step('boot (NODE_ENV=production)', () => {
      docker(['run', '-d', '--name', APP, '--network', NET, '--user', '1000:1000', '-p', '127.0.0.1::3000', ...CERTS, '-v', `${VOL}:/opt/qodiqa/data`,
        '-v', `${hostPath(path.join(REPO, 'deploy/env/production.policies.example'))}:/opt/qodiqa/config/policies.json:ro`, '--tmpfs', '/tmp:rw', ...envArgs(appEnv), IMAGE]);
    });
    const port = step('published port', () => docker(['port', APP, '3000']).stdout.trim().split('\n')[0].split(':').pop());
    await stepA('/ready', async () => {
      for (let i = 0; i < 90; i++) {
        try { const r = await fetch(`http://127.0.0.1:${port}/ready`); if (r.status === 200) return { seconds: i * 2, body: (await r.text()).slice(0, 300) }; } catch { /* not up yet */ }
        if (docker(['inspect', '-f', '{{.State.Running}}', APP], { allowFail: true }).stdout.trim() !== 'true') throw new Error('container exited before /ready');
        await sleep(2000);
      }
      throw new Error('/ready not 200 within 180 s');
    });
    await stepA('/health', async () => { const r = await fetch(`http://127.0.0.1:${port}/health`); if (r.status !== 200) throw new Error(`health ${r.status}`); });
    step('BOOT_REPORT: production profile, validator passed, TLS established', () => {
      // A fatal validator violation aborts the boot before BOOT_REPORT is emitted (server/startup.js), so the report's
      // presence plus 0 FATAL events is the validator's pass; the report's own facts are then checked.
      const r = docker(['logs', APP]); const logs = r.stdout + r.stderr;
      const fatal = (logs.match(/"severity":"FATAL"/g) || []).length;
      const line = logs.split(/\r?\n/).find((l) => l.includes('"eventType":"BOOT_REPORT"'));
      if (!line) throw new Error('no BOOT_REPORT in the boot output');
      const rep = JSON.parse(line.slice(line.indexOf('{'))).report || {};
      const pgTls = rep.postgres && rep.postgres.tls;
      const facts = { profile: rep.profile, nodeEnv: rep.nodeEnv, fatalEvents: fatal, warnings: (rep.config && rep.config.warnings) || [],
        postgresTls: pgTls, redisTlsEstablished: rep.redis && rep.redis.tlsEstablished, redisAuth: rep.redis && rep.redis.authConfigured };
      const bad = [];
      if (fatal) bad.push(`${fatal} FATAL events`);
      if (rep.profile !== 'prod') bad.push(`profile ${rep.profile}`);
      if (rep.nodeEnv !== 'production') bad.push(`nodeEnv ${rep.nodeEnv}`);
      if (!pgTls || pgTls.configured !== true || (pgTls.observed && pgTls.server && pgTls.server.ssl !== true)) bad.push(`postgres tls ${JSON.stringify(pgTls)}`);
      if (facts.redisTlsEstablished !== true) bad.push('redis tls not established');
      if (bad.length) throw new Error(`${bad.join('; ')} :: ${JSON.stringify(facts).slice(0, 600)}`);
      return facts;
    });
    step('signed request decided', () => {
      const r = docker(['exec', APP, 'node', '-e', `
        const { getActiveKey } = require('/app/services/artifact/keyStore');
        const { signBoundArtifact } = require('/app/src/validation/signBoundArtifact');
        const KEY = getActiveKey('cbg-client'); const body = { prompt: 'container boot gate', model: 'bench' }; const now = Date.now();
        const art = signBoundArtifact({ method: 'POST', path: '/ai/chat', body }, { payload: { provider: 'local' }, timestamp: now, expiry: now + 60000, publicKeyId: KEY.keyId }, KEY.privDer);
        fetch('http://127.0.0.1:3000/ai/chat', { method: 'POST', headers: { 'x-qodiqa-artifact': Buffer.from(JSON.stringify(art)).toString('base64'), 'content-type': 'application/json' }, body: JSON.stringify(body) })
          .then(async (res) => { const t = await res.text(); console.log(JSON.stringify({ status: res.status, body: t.slice(0, 300) })); })
          .catch((e) => { console.log(JSON.stringify({ error: e.message })); process.exit(1); });`]);
      const o = JSON.parse(r.stdout.trim().split('\n').pop());
      let d = null; try { d = JSON.parse(o.body); } catch { /* non-JSON */ }
      if (!d || !d.decision) throw new Error(`no enforcement decision: ${JSON.stringify(o)}`);
      return { status: o.status, decision: d.decision, reason: d.reason };
    });
    result = 'PASS';
  } catch (e) {
    if (!steps.length || steps[steps.length - 1].ok) steps.push({ name: 'error', ok: false, error: e.message });
    const logs = docker(['logs', '--tail', '60', APP], { allowFail: true });
    if (logs.status === 0) steps.push({ name: 'app log tail', ok: false, detail: (logs.stdout + logs.stderr).split('\n').filter((l) => /FATAL|ERROR|BOOT/.test(l)).slice(-12).map((l) => l.slice(0, 400)) });
  } finally {
    docker(['rm', '-f', APP], { allowFail: true });
    docker(['stop', PG, REDIS], { allowFail: true });
    docker(['volume', 'rm', VOL], { allowFail: true });
    docker(['network', 'rm', NET], { allowFail: true });
  }
  const out = { gate: 'container-boot-gate', image: IMAGE, pgImage: PG_IMAGE, redisImage: REDIS_IMAGE, run: RUN, result, at: new Date().toISOString(), steps };
  if (JSON_OUT) { fs.mkdirSync(path.dirname(path.resolve(JSON_OUT)), { recursive: true }); fs.writeFileSync(JSON_OUT, `${JSON.stringify(out, null, 1)}\n`); }
  console.log(JSON.stringify({ result, failed: steps.filter((s) => !s.ok).map((s) => s.name) }));
  process.exit(result === 'PASS' ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(2); });
