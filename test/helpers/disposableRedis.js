'use strict';

// step 5: a throwaway Redis with PRODUCTION persistence (appendonly yes,
// appendfsync everysec) for the production-profile boot test. The production
// profile forces STRICT_REPLAY_PROTECTION, which (correctly) refuses to start
// on a Redis without AOF — and the shared dev container qodiqa-redis runs
// appendonly no by design. Its configuration is never touched; instead this
// starts a separate container from the already-local redis:7 image
// (`--pull never`: never downloads anything), bound to 127.0.0.1 on an
// ephemeral port, auto-removed on stop (`--rm`).
//
// (D5) adds a CRASH-restartable variant ({ restartable: true }): a fixed
// host port and no `--rm`, so `docker kill` (SIGKILL — no graceful AOF flush,
// no RDB save) followed by `docker start` models a real crash and the port
// survives; stop removes this helper's own container. { appendonly: 'no' }
// starts one without persistence. Names are prefix-restricted (qodiqa-w2-/w6-).
//
// The caller persists `name` (e.g. to its ledger) BEFORE calling start(), and
// after stop() verifies it is gone with exists().

const net = require('net');
const { spawnSync } = require('child_process');
const { probeRedisReachable } = require('../../scripts/lib/redisProbe');

const IMAGE = 'redis:7';
const NAME_RE = /^qodiqa-w[26]-[a-z0-9-]+$/;

function docker(args) {
  const r = spawnSync('docker', args, { encoding: 'utf8', timeout: 60_000 });
  if (r.error) throw new Error(`docker not runnable (${r.error.code})`);
  return r;
}

function exists(name) {
  const r = docker(['ps', '-a', '--filter', `name=^${name}$`, '--format', '{{.Names}}']);
  return r.stdout.split(/\r?\n/).includes(name);
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  });
}

async function waitReachable(name, port) {
  const deadline = Date.now() + 30_000;
  while (!(await probeRedisReachable(`redis://127.0.0.1:${port}`))) {
    if (Date.now() > deadline) throw new Error(`disposable redis ${name} not reachable on ${port}`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

async function startDisposableRedis(name, { appendonly = 'yes', restartable = false } = {}) {
  if (!NAME_RE.test(name)) throw new Error(`refusing container name ${name}`);
  const persistence = appendonly === 'no' ? ['--appendonly', 'no'] : ['--appendonly', 'yes', '--appendfsync', 'everysec'];
  const hostPort = restartable ? await freePort() : null;
  const run = docker(['run', '-d', ...(restartable ? [] : ['--rm']), '--pull', 'never', '--name', name,
    '-p', restartable ? `127.0.0.1:${hostPort}:6379` : '127.0.0.1::6379', IMAGE, 'redis-server', ...persistence]);
  if (run.status !== 0) throw new Error(`docker run failed: ${(run.stderr || '').trim().slice(0, 500)}`);
  let port = hostPort;
  if (!port) {
    const portOut = docker(['port', name, '6379/tcp']);
    const m = /:(\d+)\s*$/m.exec(portOut.stdout || '');
    if (!m) throw new Error(`could not read mapped port for ${name}: ${portOut.stdout} ${portOut.stderr}`);
    port = parseInt(m[1], 10);
  }
  await waitReachable(name, port);
  return { name, port };
}

function stopDisposableRedis(name) {
  if (!exists(name)) return true;
  docker(['stop', '-t', '2', name]);
  // A restartable container has no --rm: remove this helper's own container.
  if (exists(name)) docker(['rm', '-f', name]);
  const deadline = Date.now() + 20_000;
  while (exists(name) && Date.now() < deadline) spawnSync(process.execPath, ['-e', 'setTimeout(()=>{},250)']);
  return !exists(name);
}

/** (D5): crash (SIGKILL) and start again — same container, same port, same data dir. */
async function crashRestartDisposableRedis(name, port) {
  if (!NAME_RE.test(name)) throw new Error(`refusing container name ${name}`);
  const k = docker(['kill', name]);
  if (k.status !== 0) throw new Error(`docker kill failed: ${(k.stderr || '').trim().slice(0, 300)}`);
  const s = docker(['start', name]);
  if (s.status !== 0) throw new Error(`docker start failed: ${(s.stderr || '').trim().slice(0, 300)}`);
  await waitReachable(name, port);
}

module.exports = { startDisposableRedis, stopDisposableRedis, crashRestartDisposableRedis, exists, IMAGE };
