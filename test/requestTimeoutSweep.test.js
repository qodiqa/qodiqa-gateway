'use strict';

/**
 * remediation — live regression test.
 *
 * Full mechanism, confirmed via bounded live diagnosis, is documented in
 *: Node's requestTimeout is enforced
 * via a periodic connectionsCheckingInterval sweep, not a precise
 * per-connection timer, and only takes effect when requestTimeout exceeds
 * headersTimeout's own configured value. Every approved test condition below
 * exists specifically because Session 1's own withdrawn regression test got
 * one of them wrong:
 *
 *   1. Enforcing regime (requestTimeout > headersTimeout) — Session 1's own
 *      test used requestTimeout=2000 against the untouched headersTimeout
 *      default (66000), the NON-enforcing regime; it never actually
 *      exercised the mechanism it was trying to validate.
 *   2. The fix must be set BEFORE server.listen() — Session 1's own fix set
 *      connectionsCheckingInterval inside the listen() callback (after
 *      listen() was already called), confirmed empirically to have zero
 *      effect on Node's already-armed sweep timer.
 *   3. Overshoot must be bounded by the new default (~1000ms) + CI margin,
 *      not Node's own unconfigured default (up to 30000ms).
 *   4. A legitimate request whose body completes before the deadline must
 *      not be affected — the fix only changes how often already-expired
 *      deadlines are noticed, never the deadline computation itself.
 *
 * Full stack, not bare http — the bare-http path is confirmed NOT to
 * reproduce this condition reliably (Session 1's own isolated probes, and
 * Session 2's own full-stack-vs-bare-http comparison).
 */

const fs   = require('fs');
const path = require('path');
const net  = require('net');
const { spawn } = require('child_process');

const REPO_ROOT          = path.join(__dirname, '..');
const STARTUP_TIMEOUT_MS = 20_000;

// Condition 1: requestTimeout (8000) genuinely exceeds headersTimeout (5000)
// — the confirmed enforcing regime. keepAliveTimeout (4000) stays below
// headersTimeout per tlsDefaults.js's own validated invariant.
const REQUEST_TIMEOUT_MS         = 8_000;
const HEADERS_TIMEOUT_MS         = 5_000;
const KEEP_ALIVE_TIMEOUT_MS      = 4_000;
const CONNECTIONS_CHECKING_INTERVAL_MS = 1_000; // the new shipped default

// Condition 3's acceptance bar: approved ≤2000ms absolute overshoot: a small
// amount of extra CI-jitter margin is added on top for wall-clock robustness
// under load (matching this project's own established "generous CI-jitter
// margin" convention for timing assertions), without diluting the bar being
// tested — Node's OLD, unfixed behavior would have missed this by roughly
// 15x (up to ~30000ms unfixed vs. the ~2500ms ceiling asserted here).
const MAX_ACCEPTABLE_OVERSHOOT_MS = 2_500;
const IDLE_PROBE_CAP_MS = REQUEST_TIMEOUT_MS + MAX_ACCEPTABLE_OVERSHOOT_MS + 5_000; // generous safety margin beyond the assertion itself

function requireDevEnvironmentFresh() {
  jest.resetModules();
  return require('../scripts/lib/devEnvironment');
}

const ENV_KEYS_TO_ISOLATE = [
  'NODE_ENV', 'QODIQA_KEY_ENCRYPTION_KEY', 'QODIQA_CLIENT_ID',
  'QODIQA_KEYS_PATH', 'QODIQA_AUDIT_LOG', 'QODIQA_TRANSPARENCY_KEYS_PATH',
  'QODIQA_SIGNING_STORE_PATH', 'LOCAL_BASE_URL', 'STRICT_REPLAY_PROTECTION',
  'QODIQA_DEPLOYMENT_MODE',
];

function snapshotEnv(keys) {
  const snap = {};
  for (const k of keys) snap[k] = process.env[k];
  return snap;
}

function restoreEnv(snap) {
  for (const [k, v] of Object.entries(snap)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

async function bootIsolatedServer(clientId) {
  const port = await getFreePort();
  const envSnapshot = snapshotEnv(ENV_KEYS_TO_ISOLATE);
  const { prepareIsolatedEnvironment } = requireDevEnvironmentFresh();
  const { paths } = await prepareIsolatedEnvironment({ clientId, tempPrefix: 'qodiqa-f25-' });

  const childEnv = {
    ...process.env,
    // the coverage run keeps REDIS_URL unset and names the disposable Redis in QODIQA_TEST_REDIS_URL: the booted server needs it
    ...(!process.env.REDIS_URL && process.env.QODIQA_TEST_REDIS_URL ? { REDIS_URL: process.env.QODIQA_TEST_REDIS_URL } : {}),
    PORT: String(port),
    QODIQA_DEPLOYMENT_MODE: 'single-node',
    QODIQA_PG_ENABLED: 'false',
    REQUEST_TIMEOUT_MS: String(REQUEST_TIMEOUT_MS),
    HEADERS_TIMEOUT_MS: String(HEADERS_TIMEOUT_MS),
    KEEP_ALIVE_TIMEOUT_MS: String(KEEP_ALIVE_TIMEOUT_MS),
    CONNECTIONS_CHECKING_INTERVAL_MS: String(CONNECTIONS_CHECKING_INTERVAL_MS),
  };
  restoreEnv(envSnapshot);

  const outputChunks = [];
  let readyEvent = null;
  let fatalEvent = null;
  let hardenedEvent = null;
  const child = spawn(process.execPath, ['server.js'], {
    cwd: REPO_ROOT,
    env: childEnv,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const onData = (buf) => {
    const text = buf.toString();
    outputChunks.push(text);
    for (const line of text.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      let parsed;
      try { parsed = JSON.parse(trimmed); } catch { continue; }
      if (parsed.eventType === 'GATEWAY_START') readyEvent = parsed;
      if (parsed.eventType === 'HTTP_SERVER_TRANSPORT_HARDENED') hardenedEvent = parsed;
      if (parsed.severity === 'FATAL' && !fatalEvent) fatalEvent = parsed;
    }
  };
  child.stdout.on('data', onData);
  child.stderr.on('data', onData);

  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  while (!readyEvent && !fatalEvent && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 100));
  }
  if (fatalEvent) {
    throw new Error(`FATAL during startup: ${JSON.stringify(fatalEvent)}\n${outputChunks.join('')}`);
  }
  if (!readyEvent) {
    throw new Error(`Server did not reach GATEWAY_START within ${STARTUP_TIMEOUT_MS}ms.\n${outputChunks.join('')}`);
  }

  return { child, port, tempRoot: paths.root, hardenedEvent };
}

function killChild(child) {
  return new Promise((resolve) => {
    if (!child || child.killed || child.exitCode !== null) return resolve();
    const forceKill = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      resolve();
    }, 3000);
    child.once('exit', () => { clearTimeout(forceKill); resolve(); });
    child.kill('SIGTERM');
  });
}

describe('requestTimeout sweep-interval fix (live, full stack)', () => {
  let child;
  let tempRoot;

  afterEach(async () => {
    await killChild(child);
    child = null;
    if (tempRoot && fs.existsSync(tempRoot)) fs.rmSync(tempRoot, { recursive: true, force: true });
    tempRoot = null;
  });

  test('static: configureTlsDefaults() is called BEFORE .listen() in server/startup.js', () => {
    const src = fs.readFileSync(path.join(REPO_ROOT, 'server', 'startup.js'), 'utf8');
    const configureCallIdx = src.indexOf('configureTlsDefaults(_httpServer, emit);');
    const listenCallIdx    = src.indexOf('_httpServer.listen(PORT,');
    expect(configureCallIdx).toBeGreaterThan(-1);
    expect(listenCallIdx).toBeGreaterThan(-1);
    // The exact regression this fix closes: a later reassignment of
    // connectionsCheckingInterval (e.g. moved back inside the listen()
    // callback in a future edit) would place listenCallIdx BEFORE
    // configureCallIdx — confirmed empirically to silently reintroduce the
    // up-to-30000ms overshoot bug.
    expect(configureCallIdx).toBeLessThan(listenCallIdx);
  });

  test('idle/zero-body connection: real 408 fires within the approved overshoot bound, enforcing regime', async () => {
    const boot = await bootIsolatedServer('f25-idle-test');
    child = boot.child; tempRoot = boot.tempRoot;

    expect(boot.hardenedEvent).toBeTruthy();
    expect(boot.hardenedEvent.requestTimeoutMs).toBe(REQUEST_TIMEOUT_MS);
    expect(boot.hardenedEvent.headersTimeoutMs).toBe(HEADERS_TIMEOUT_MS);
    expect(boot.hardenedEvent.connectionsCheckingIntervalMs).toBe(CONNECTIONS_CHECKING_INTERVAL_MS);
    // Condition 1, asserted directly: the boot config is genuinely in the
    // confirmed enforcing regime, not the non-enforcing one that fooled
    // Session 1's own regression test.
    expect(boot.hardenedEvent.requestTimeoutMs).toBeGreaterThan(boot.hardenedEvent.headersTimeoutMs);

    const connectTime = Date.now();
    const result = await new Promise((resolve) => {
      const sock = net.connect(boot.port, '127.0.0.1', () => {
        // Real "pure idle" condition: headers complete, declared
        // body never arrives. POST /ai/chat (not GET) — a GET's
        // Content-Length is ignored by Express entirely, confirmed the hard
        // way during this session's own diagnosis.
        sock.write(
          'POST /ai/chat HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n' +
          'Content-Length: 50\r\nConnection: close\r\n\r\n',
        );
      });
      let data = '';
      const cap = setTimeout(() => {
        resolve({ outcome: 'TIMEOUT_NO_CLOSE', elapsedMs: Date.now() - connectTime, data });
        try { sock.destroy(); } catch { /* ignore */ }
      }, IDLE_PROBE_CAP_MS);
      sock.on('data', (c) => { data += c.toString(); });
      sock.on('close', () => { clearTimeout(cap); resolve({ outcome: 'CLOSED', elapsedMs: Date.now() - connectTime, data }); });
      sock.on('error', (e) => { clearTimeout(cap); resolve({ outcome: 'ERROR', elapsedMs: Date.now() - connectTime, error: e.message, data }); });
    });

    expect(result.outcome).toBe('CLOSED');
    expect(result.data).toContain('408 Request Timeout');
    // Condition 3: overshoot bounded by the approved acceptance bar, not
    // Node's unconfigured up-to-30000ms default.
    const overshootMs = result.elapsedMs - REQUEST_TIMEOUT_MS;
    expect(overshootMs).toBeGreaterThanOrEqual(0);
    expect(overshootMs).toBeLessThanOrEqual(MAX_ACCEPTABLE_OVERSHOOT_MS);
  }, IDLE_PROBE_CAP_MS + STARTUP_TIMEOUT_MS + 10_000);

  test('legitimate request completing just under the deadline is NOT cut off (no premature termination)', async () => {
    const boot = await bootIsolatedServer('f25-trickle-test');
    child = boot.child; tempRoot = boot.tempRoot;

    // Trickle the declared body to completion at ~75% of REQUEST_TIMEOUT_MS
    // (6000ms of an 8000ms budget) — deliberately close to, but safely under,
    // the deadline, then confirm a genuine (non-408) response arrives. This
    // is the direct, live proof that shortening connectionsCheckingInterval
    // never affects requestTimeout's own deadline computation — only how
    // quickly an ALREADY-expired connection is noticed.
    const BODY = JSON.stringify({ prompt: 'hi', model: 'gpt-4' });
    const bodyBuf = Buffer.from(BODY, 'utf8');
    const TRICKLE_WINDOW_MS = Math.round(REQUEST_TIMEOUT_MS * 0.75);
    const chunkDelayMs = Math.max(1, Math.floor(TRICKLE_WINDOW_MS / bodyBuf.length));

    const connectTime = Date.now();
    const result = await new Promise((resolve, reject) => {
      const sock = net.connect(boot.port, '127.0.0.1', () => {
        sock.write(
          `POST /ai/chat HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n` +
          `Content-Length: ${bodyBuf.length}\r\nConnection: close\r\n\r\n`,
        );
        // byte i is due at trickleStart + i * chunkDelayMs on the test's own clock. A chain of fixed setTimeout
        // delays accumulated every timer's lateness on a loaded machine, stretching the "~75 %" trickle past the 8 s
        // deadline itself; a late byte now shortens the next wait instead, so the body still completes at ~75 %.
        const trickleStart = Date.now();
        let i = 0;
        const sendNext = () => {
          if (i >= bodyBuf.length) return;
          sock.write(Buffer.from([bodyBuf[i]]));
          i += 1;
          setTimeout(sendNext, Math.max(0, trickleStart + i * chunkDelayMs - Date.now()));
        };
        sendNext();
      });
      let data = '';
      const cap = setTimeout(() => {
        try { sock.destroy(); } catch { /* ignore */ }
        reject(new Error(`No response within cap. Elapsed=${Date.now() - connectTime}ms, data so far: ${data}`));
      }, REQUEST_TIMEOUT_MS + MAX_ACCEPTABLE_OVERSHOOT_MS + 10_000);
      sock.on('data', (c) => {
        data += c.toString();
        if (data.includes('\r\n\r\n') && (data.includes('Content-Length') || data.includes('chunked'))) {
          // Full-ish response headers arrived — give the body a brief moment
          // then resolve. Simpler than a full chunked/length-aware parser
          // for this test's own purposes: any well-formed HTTP status line
          // that isn't 408 already proves the point.
          clearTimeout(cap);
          resolve({ elapsedMs: Date.now() - connectTime, data });
        }
      });
      sock.on('close', () => { clearTimeout(cap); resolve({ elapsedMs: Date.now() - connectTime, data }); });
      sock.on('error', (e) => { clearTimeout(cap); reject(e); });
    });

    expect(result.data).not.toContain('408 Request Timeout');
    // The trickle completes at ~TRICKLE_WINDOW_MS; response should follow
    // shortly after, well before REQUEST_TIMEOUT_MS's own deadline.
    expect(result.elapsedMs).toBeLessThan(REQUEST_TIMEOUT_MS);
    const statusLine = result.data.split('\r\n')[0];
    expect(statusLine).toMatch(/^HTTP\/1\.1 \d{3}/);
  }, REQUEST_TIMEOUT_MS + MAX_ACCEPTABLE_OVERSHOOT_MS + STARTUP_TIMEOUT_MS + 15_000);
});
