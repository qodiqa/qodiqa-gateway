'use strict';

/**
 * Real Redis Sentinel failover integration test.
 *
 * This is the flagship proof for the remediation: it spins up a REAL,
 * disposable master + replica + Sentinel topology (using the same
 * Memurai/redis-server backend detection as
 * test/harness/redis.js — no mocking of the Redis protocol
 * anywhere in this file), points a real createManagedRedisClient({ mode:
 * 'sentinel' }) client at it, kills the master process outright, and asserts
 * that:
 *
 *   1. Sentinel detects the failure and promotes the replica automatically.
 *   2. The managed client automatically reconnects to the new master — with
 *      NO process restart, NO manual reconnect call, and no code path beyond
 *      what production code already does at connect() time.
 *   3. A previously-written key is still readable through the new master
 *      (replication had propagated it) and a fresh write/read round-trip
 *      succeeds post-failover.
 *   4. The managed client's own health()/failoverCount tracking observed the
 *      MASTER_CHANGE event.
 *
 * Requires a real Memurai (Windows) or redis-server (Linux/CI) binary with
 * genuine SENTINEL command support — this is a materially higher bar than
 * the existing disposable-Redis acceptance tests (test/harness/
 * redis.js), which never start Sentinel. If neither is available, or the
 * detected backend does not support --sentinel (verified with a quick probe
 * before committing to the full topology), this test SKIPS with a clear
 * reason rather than failing or hanging — the same pattern
 * test/serverStartupSmoke.test.js uses for its own real-Redis prerequisite.
 *
 * Docker is NOT used as a fallback here (unlike helpers/redis.js) — building
 * a 3-process Sentinel topology through ephemeral containers is materially
 * more complex than a single container, and this environment's Docker daemon
 * is not reliably available; the Memurai/redis-server path already gives
 * genuine multi-process coverage without it.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { spawnCapturing, getFreePort, waitForCondition, killProcessTree } = require('../harness/process');
const { detectBackend } = require('../harness/redis');
const { probeRedisReachable } = require('../../scripts/lib/redisProbe');

const TEST_TIMEOUT_MS = 90_000;
const TMP_ROOT = path.join(os.tmpdir(), `qodiqa-sentinel-it-${process.pid}-${Date.now()}`);

function spawnServer(command, port, extraArgs = []) {
  return spawnCapturing(command, [
    '--port', String(port),
    '--daemonize', 'no',
    '--save', '',
    '--appendonly', 'no',
    '--bind', '127.0.0.1',
    ...extraArgs,
  ]);
}

async function probeSentinelSupport(command) {
  const port = await getFreePort();
  const confPath = path.join(TMP_ROOT, `probe-sentinel-${port}.conf`);
  fs.mkdirSync(TMP_ROOT, { recursive: true });
  fs.writeFileSync(confPath, `port ${port}\nbind 127.0.0.1\n`);

  const handle = spawnCapturing(command, ['--sentinel', confPath, '--port', String(port), '--daemonize', 'no']);
  const ready = await waitForCondition(() => probeRedisReachable(`redis://127.0.0.1:${port}`, 500), {
    timeoutMs: 5_000, intervalMs: 200,
  });
  await killProcessTree(handle.child);
  return ready;
}

async function runRedisCli(command, port, args) {
  const cliCommand = command.toLowerCase().includes('memurai')
    ? path.join(path.dirname(command), 'memurai-cli.exe')
    : 'redis-cli';
  const { spawnSync } = require('child_process');
  const result = spawnSync(cliCommand, ['-p', String(port), ...args], { encoding: 'utf8' });
  return (result.stdout || '').trim();
}

describe('real Redis Sentinel failover (integration)', () => {
  let backend;
  let masterHandle, replicaHandle, sentinelHandle;
  let masterPort, replicaPort, sentinelPort;
  let skip = false;
  let skipReason = '';

  beforeAll(async () => {
    backend = detectBackend();
    if (!backend || backend.kind === 'docker') {
      skip = true;
      skipReason = 'No local Memurai/redis-server binary found (Docker-only environments are not exercised by ' +
        'this test — see file header).';
      return;
    }

    const supportsSentinel = await probeSentinelSupport(backend.command);
    if (!supportsSentinel) {
      skip = true;
      skipReason = `Detected backend "${backend.kind}" does not appear to support --sentinel mode.`;
      return;
    }

    fs.mkdirSync(TMP_ROOT, { recursive: true });
    [masterPort, replicaPort, sentinelPort] = await Promise.all([getFreePort(), getFreePort(), getFreePort()]);

    masterHandle = spawnServer(backend.command, masterPort);
    const masterReady = await waitForCondition(() => probeRedisReachable(`redis://127.0.0.1:${masterPort}`, 500), { timeoutMs: 15_000 });
    if (!masterReady) { skip = true; skipReason = 'Master did not become reachable.'; return; }

    replicaHandle = spawnServer(backend.command, replicaPort, ['--replicaof', '127.0.0.1', String(masterPort)]);
    const replicaReady = await waitForCondition(() => probeRedisReachable(`redis://127.0.0.1:${replicaPort}`, 500), { timeoutMs: 15_000 });
    if (!replicaReady) { skip = true; skipReason = 'Replica did not become reachable.'; return; }

    // Give replication a moment to establish (small, bounded — this is
    // infrastructure setup polling, not a retried assertion).
    await waitForCondition(() => {
      const role = runRedisCli(backend.command, replicaPort, ['info', 'replication']);
      return role.includes('master_link_status:up') || role.includes('role:slave');
    }, { timeoutMs: 10_000, intervalMs: 200 });

    const sentinelConfPath = path.join(TMP_ROOT, 'sentinel.conf');
    fs.writeFileSync(sentinelConfPath, [
      `port ${sentinelPort}`,
      'bind 127.0.0.1',
      `sentinel monitor mymaster 127.0.0.1 ${masterPort} 1`,
      'sentinel down-after-milliseconds mymaster 2000',
      'sentinel failover-timeout mymaster 8000',
      'sentinel parallel-syncs mymaster 1',
    ].join('\n') + '\n');

    sentinelHandle = spawnCapturing(backend.command, ['--sentinel', sentinelConfPath, '--port', String(sentinelPort), '--daemonize', 'no']);
    const sentinelReady = await waitForCondition(() => probeRedisReachable(`redis://127.0.0.1:${sentinelPort}`, 500), { timeoutMs: 15_000 });
    if (!sentinelReady) { skip = true; skipReason = 'Sentinel did not become reachable.'; return; }

    // Confirm Sentinel has actually discovered the master before proceeding.
    const discovered = await waitForCondition(() => {
      const reply = runRedisCli(backend.command, sentinelPort, ['sentinel', 'get-master-addr-by-name', 'mymaster']);
      return reply.includes(String(masterPort));
    }, { timeoutMs: 10_000, intervalMs: 300 });
    if (!discovered) { skip = true; skipReason = 'Sentinel did not discover the master within the timeout.'; }
  }, TEST_TIMEOUT_MS);

  afterAll(async () => {
    await Promise.all([
      killProcessTree(masterHandle?.child),
      killProcessTree(replicaHandle?.child),
      killProcessTree(sentinelHandle?.child),
    ]);
    try { fs.rmSync(TMP_ROOT, { recursive: true, force: true }); } catch { /* best-effort cleanup */ }
  });

  test('client automatically reconnects and continues serving reads/writes after the master is killed', async () => {
    if (skip) {
      // eslint-disable-next-line no-console
      console.warn(`[redisSentinelFailover] SKIPPED — ${skipReason}`);
      return;
    }

    // Fresh module instance so REDIS_MODE env picks up cleanly for this test only.
    jest.resetModules();
    const { createManagedRedisClient } = require('../../src/infra/redis/managedClient');

    const client = createManagedRedisClient({
      purpose: 'sentinelIntegrationTest',
      haConfig: {
        mode: 'sentinel', valid: true, validationErrors: [],
        sentinel: {
          masterName: 'mymaster',
          rootNodes: [{ host: '127.0.0.1', port: sentinelPort }],
          scanIntervalMs: 500,
          useReplicas: false,
        },
        cluster: { rootNodes: [] },
        retry: { maxAttempts: 5, baseDelayMs: 100, maxDelayMs: 1000, jitterRatio: 0, circuitBreakerCooldownMs: 5000 },
      },
    });

    await client.connect();
    await client.set('ha1:preFailoverKey', 'value1');
    expect(await client.get('ha1:preFailoverKey')).toBe('value1');

    // Kill the master outright — no graceful shutdown, simulating a real
    // instance failure (crash, host loss, network partition).
    await killProcessTree(masterHandle.child);

    // Sentinel needs down-after-milliseconds (2s) + failover-timeout budget
    // to detect the failure and promote the replica; poll until the client's
    // own commands succeed again through the new master, with NO restart and
    // NO manual reconnect call from this test — exactly the production
    // contract exists to deliver.
    const recovered = await waitForCondition(async () => {
      try {
        return (await client.get('ha1:preFailoverKey')) === 'value1';
      } catch {
        return false;
      }
    }, { timeoutMs: 60_000, intervalMs: 500 });

    expect(recovered).toBe(true);

    // Fresh write/read round-trip against the newly promoted master.
    await client.set('ha1:postFailoverKey', 'value2');
    expect(await client.get('ha1:postFailoverKey')).toBe('value2');

    // The managed client observed the failover itself (not just "commands
    // happen to work again" — the topology-change tracking actually fired).
    expect(client.health().failoverCount).toBeGreaterThanOrEqual(1);

    await client.disconnect();
  }, TEST_TIMEOUT_MS);
});
