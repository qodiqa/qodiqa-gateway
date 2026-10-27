'use strict';

/**
 * Disposable, test-owned Redis instance manager.
 *
 * No helper anywhere in this repository starts or stops a Redis process —
 * scripts/bootstrap-dev.js and the existing CI workflows both assume Redis
 * is already running (a developer's local service, or a CI service
 * container) and fail fast/skip if it isn't (see scripts/lib/redisProbe.js).
 *
 * Acceptance tests that simulate a Redis outage (AT-005, AT-008, ...) need
 * something they fully own: their own instance, on its own port, that they
 * can start and kill without touching the developer's real Redis/Memurai
 * service or any ambient CI service container. This module provides that,
 * trying (in order) a local Memurai install (Windows), a `redis-server`
 * binary on PATH (Linux/CI), then Docker — and reports itself as
 * unavailable, rather than guessing, if none of those exist.
 */

const fs = require('fs');
const os = require('os');
const { spawnSync } = require('child_process');

const { getFreePort, spawnCapturing, waitForCondition, killProcessTree } = require('./process');
const { probeRedisReachable } = require('../../scripts/lib/redisProbe');

const WINDOWS_MEMURAI_PATH = 'C:\\Program Files\\Memurai\\memurai.exe';

function commandExists(cmd) {
  try {
    const probe = os.platform() === 'win32' ? spawnSync('where', [cmd]) : spawnSync('which', [cmd]);
    return probe.status === 0;
  } catch {
    return false;
  }
}

function detectBackend() {
  if (os.platform() === 'win32' && fs.existsSync(WINDOWS_MEMURAI_PATH)) {
    return { kind: 'memurai', command: WINDOWS_MEMURAI_PATH };
  }
  if (commandExists('redis-server')) {
    return { kind: 'redis-server', command: 'redis-server' };
  }
  if (commandExists('docker')) {
    return { kind: 'docker', command: 'docker' };
  }
  return null;
}

/**
 * Starts a disposable Redis-compatible instance on a free local port.
 *
 * @param {object} [opts]
 * @param {number} [opts.port]
 * @param {boolean} [opts.appendonly]  Enable AOF persistence (appendfsync
 *   everysec) instead of the default disposable-instance `--appendonly no`.
 *   Only AT-100 (production checklist's REDIS_PERSISTENCE_STATUS item) needs
 *   this — every other test wants the default fast, non-durable disposable
 *   instance.
 * @returns {Promise<{ available: true, url: string, port: number, stop: () => Promise<void> } | { available: false, reason: string }>}
 */
// REL-01 — the restart barrier: an artifact whose signed
// timestamp is at or before the Redis server's start (+5 s future-skew tolerance, start rounded up to the second) is
// refused REPLAY_STATE_UNPROVABLE. A production Redis is not started seconds before each request; every acceptance
// case starts a fresh one. Record each start so helpers/artifacts.js#callSign can let the barrier pass first.
const BARRIER_CLEAR_MS = 7_000; // 5 s skew tolerance + 1 s uptime rounding + clock/latency margin
let _lastRedisStartMs = 0;
async function waitForReplayBarrier() {
  const wait = _lastRedisStartMs + BARRIER_CLEAR_MS - Date.now();
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
}

async function startDisposableRedis({ port: requestedPort, appendonly = false } = {}) {
  const backend = detectBackend();
  if (!backend) {
    return {
      available: false,
      reason: 'No controllable Redis backend found (no C:\\Program Files\\Memurai\\memurai.exe, ' +
        'no redis-server on PATH, no docker on PATH).',
    };
  }

  const port = requestedPort || (await getFreePort());
  const url = `redis://127.0.0.1:${port}`;
  let handle;

  if (backend.kind === 'memurai' || backend.kind === 'redis-server') {
    handle = spawnCapturing(backend.command, [
      '--port', String(port),
      '--daemonize', 'no',
      '--save', '',
      '--appendonly', appendonly ? 'yes' : 'no',
      ...(appendonly ? ['--appendfsync', 'everysec'] : []),
      '--bind', '127.0.0.1',
    ]);
  } else {
    // Docker fallback — mirrors the redis:7-alpine image already used by
    // .github/workflows/backup-restore.yml, run disposably and removed on stop.
    const containerName = `qodiqa-acceptance-redis-${port}`;
    handle = spawnCapturing('docker', [
      'run', '--rm', '--name', containerName,
      '-p', `127.0.0.1:${port}:6379`,
      'redis:7-alpine',
      ...(appendonly ? ['redis-server', '--appendonly', 'yes', '--appendfsync', 'everysec'] : []),
    ]);
    handle.containerName = containerName;
  }

  const ready = await waitForCondition(() => probeRedisReachable(url, 500), {
    timeoutMs: 15000,
    intervalMs: 200,
  });

  if (!ready) {
    await stopHandle(backend, handle);
    return {
      available: false,
      reason: `Disposable Redis backend "${backend.kind}" did not become reachable at ${url} ` +
        `within 15s.\nOutput:\n${handle.getOutput()}`,
    };
  }

  // Stamp AFTER the server answers: its real start is never later than this (a container backend starts the
  // process seconds after the spawn, so a pre-spawn stamp under-waits — observed with the docker backend).
  _lastRedisStartMs = Date.now();
  return {
    available: true,
    url,
    port,
    backend: backend.kind,
    stop: () => stopHandle(backend, handle),
  };
}

async function stopHandle(backend, handle) {
  if (backend.kind === 'docker' && handle.containerName) {
    // `docker run --rm` removes the container on exit; killing the CLI
    // process alone would leave the daemon-managed container running, so
    // stop it by name instead. -t 0 kills immediately: `docker stop`'s
    // default 10s SIGTERM grace made a Redis-outage case's own outage begin
    // up to 10s AFTER stop() returned, so outage-reaction assertions with
    // ~10s windows (AT-008/AT-096's /ready polls) timed out against the
    // still-running instance. A disposable, per-test instance holds nothing
    // worth a graceful flush — instant death IS the simulated outage.
    spawnSync('docker', ['stop', '-t', '0', handle.containerName]);
  }
  await killProcessTree(handle.child);
}

module.exports = { startDisposableRedis, detectBackend, waitForReplayBarrier };
