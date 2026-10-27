'use strict';

/**
 * webhooks end to end on real PostgreSQL (disposable DB).
 *
 * Real: endpoint store (AES-GCM secret, RLS), a REAL signed artifact attested by
 * attestor.generateAttestation(), the dispatcher's tenant fan-out, the PG
 * recovery queue, the worker, webhookDelivery.retryHandler/deliver/post, the
 * SSRF guard's validateDestination() and its connection-time DNS re-validation
 * (createSecureLookup), the retry policy, the circuit breaker and the delivery
 * log. The receiver side verifies with the published JS SDK
 * (sdk/javascript verifyWebhookSignature).
 *
 * Doubles, at the network edge only:
 *   dns.promises.lookup — test hostnames resolve to fixed addresses (a public
 *     address for the receiver; a metadata/loopback address for the SSRF
 *     cases); every other name uses the real resolver;
 *   https.request       — the receiver. It CALLS the request's own `lookup`
 *     option (the SSRF guard's secure lookup) before "connecting", exactly as
 *     Node's socket layer would, so the connection-time re-validation runs for
 *     real. A genuine local HTTPS receiver is unreachable by design: the guard
 *     refuses loopback/private destinations and verifies certificates, and it is
 *     not loosened for this test.
 *
 * WH-01  delivered: one signed POST; SDK verification passes; body is the event;
 *        TLS verification on; connected to the validated public address; log row
 * WH-02  retry: 503 then 200 → two attempts, delivered, queue empty
 * WH-03  DLQ: always 503 → five attempts, then the operation is in the DLQ
 * WH-04  SSRF refusal: endpoint resolving to 169.254.169.254 → no request ever
 *        reaches the network; the operation ends in the DLQ, not delivered
 * WH-05  DNS rebinding (public at validation, loopback at connect) → refused at
 *        connection time, nothing sent
 * WH-06  tenant isolation: another tenant's endpoint gets nothing; a forged
 *        artifact naming the tenant's key produces no delivery at all
 *
 * DB qodiqa_w3wh_<pid>_<hex>, name appended to %TEMP%/qodiqa-w3-ledger.jsonl
 * BEFORE creation, dropped and verified gone in afterAll.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Pool, Client } = require('pg');

// ── network-edge doubles ─────────────────────────────────────────────────────
const mockDnsTable = new Map();       // hostname → [addresses] or function(callNo) → [addresses]
const mockDnsCalls = new Map();
jest.mock('dns', () => {
  const actual = jest.requireActual('dns');
  return {
    ...actual,
    promises: {
      ...actual.promises,
      lookup: async (host, opts) => {
        if (!mockDnsTable.has(host)) return actual.promises.lookup(host, opts);
        const n = (mockDnsCalls.get(host) || 0) + 1; mockDnsCalls.set(host, n);
        const v = mockDnsTable.get(host);
        return (typeof v === 'function' ? v(n) : v).map((address) => ({ address, family: 4 }));
      },
    },
  };
});
const mockReceiver = { received: [], connects: [], respond: () => 200 };
jest.mock('https', () => {
  const actual = jest.requireActual('https');
  return {
    ...actual,
    request: (options, onResponse) => {
      const req = new (require('events').EventEmitter)();
      let body = '';
      req.write = (c) => { body += c; };
      req.destroy = (err) => { if (err) req.emit('error', err); };
      req.end = () => {
        options.lookup(options.hostname, {}, (err, address) => {
          if (err) { mockReceiver.connects.push({ hostname: options.hostname, refused: err.code }); req.emit('error', err); return; }
          mockReceiver.connects.push({ hostname: options.hostname, address });
          const rec = { hostname: options.hostname, address, path: options.path, method: options.method, headers: options.headers, body,
            rejectUnauthorized: options.rejectUnauthorized, minVersion: options.minVersion };
          mockReceiver.received.push(rec);
          const res = new (require('stream').PassThrough)();
          res.statusCode = mockReceiver.respond(rec);
          onResponse(res);
          res.end();
        });
      };
      return req;
    },
  };
});

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
const DB = `qodiqa_w3wh_${process.pid}_${crypto.randomBytes(4).toString('hex')}`;
const LEDGER = path.join(os.tmpdir(), 'qodiqa-w3-ledger.jsonl');
const APP_USER = process.env.QODIQA_PG_USER;
const APP_PASSWORD = process.env.QODIQA_PG_PASSWORD;
const asTest = (database) => ({
  host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  database, user: process.env.QODIQA_PG_TEST_USER, password: process.env.QODIQA_PG_TEST_PASSWORD, ssl: false,
});
const ledger = (event) => fs.appendFileSync(LEDGER, JSON.stringify({ at: new Date().toISOString(), db: DB, event, by: 'test/integration/webhookDelivery.integration.test.js' }) + '\n');

const PUBLIC_ADDR = '93.184.216.34';
jest.setTimeout(120_000);

describeOrSkip('D6 — webhooks delivered end to end (real PostgreSQL)', () => {
  let created = false; const saved = {}; let tmpDir; let verify;
  let pgPool, store, attestor, queue, worker, recoveryManager, getActiveKey, signArtifact, parseKeyId, verifyWebhookSignature;
  let TENANT; let KEY;

  beforeAll(async () => {
    if (!/^[a-z][a-z0-9_]{0,62}$/.test(DB)) throw new Error('unsafe db name');
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w3wh-'));
    ledger('planned');
    const m = new Client(asTest('postgres')); await m.connect();
    try { await m.query(`CREATE DATABASE "${DB}"`); } finally { await m.end(); }
    created = true; ledger('created');
    const mp = new Pool(asTest(DB));
    try { jest.resetModules(); await require('../../src/infra/postgres/migrate').runMigrations({ pool: mp }); } finally { await mp.end(); }

    for (const k of ['QODIQA_PG_ENABLED', 'QODIQA_PG_DATABASE', 'QODIQA_PG_USER', 'QODIQA_PG_PASSWORD', 'QODIQA_PRQ_JOURNAL_DIR', 'PRQ_ENABLED']) saved[k] = process.env[k];
    Object.assign(process.env, { QODIQA_PG_ENABLED: 'true', QODIQA_PG_DATABASE: DB, QODIQA_PG_USER: APP_USER,
      QODIQA_PRQ_JOURNAL_DIR: path.join(tmpDir, 'prq'), PRQ_ENABLED: 'true' });
    process.env['QODIQA_PG_PASSWORD'] = APP_PASSWORD;
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool'); pgPool.initialize();
    store = require('../../src/core/webhooks/webhookStore');
    attestor = require('../../src/core/attestation/attestor');
    queue = require('../../src/core/persistenceRecovery/queue');
    worker = require('../../src/core/persistenceRecovery/worker');
    recoveryManager = require('../../src/core/persistenceRecovery/recoveryManager');
    ({ getActiveKey } = require('../../services/artifact/keyStore'));
    ({ signArtifact } = require('../../src/validation/signArtifact'));
    ({ parseKeyId } = require('../../services/artifact/keyId'));
    ({ verifyWebhookSignature } = require('../helpers/jsSdkDist').ensureJsSdkDist()); // dist/ is untracked build output
    const T = recoveryManager.OPERATION_TYPES.WEBHOOK_DELIVERY;
    worker.registerHandler(T, recoveryManager._builtinHandlers[T]);
    KEY = getActiveKey('default');
    TENANT = parseKeyId(KEY.keyId).tenantId;
    verify = new Pool(asTest(DB));
  });

  afterAll(async () => {
    if (verify) await verify.end().catch(() => {});
    if (pgPool) await pgPool.shutdown().catch(() => {});
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (created) {
      const m = new Client(asTest('postgres')); await m.connect();
      try {
        try { await m.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`); } catch { await m.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`); }
        ledger((await m.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0 ? 'dropped' : 'DROP-FAILED');
      } finally { await m.end(); }
    }
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  beforeEach(() => { mockReceiver.received = []; mockReceiver.connects = []; mockReceiver.respond = () => 200; });

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const artifact = (key = KEY) => { const now = Date.now(); return signArtifact({ payload: { action: 'w3wh', requestId: crypto.randomUUID(), tenantId: TENANT }, timestamp: now, expiry: now + 600_000, publicKeyId: key.keyId }, key.privDer); };
  async function endpoint(host, tenantId = TENANT) {
    mockDnsTable.set(host, [PUBLIC_ADDR]);
    return store.createEndpoint({ tenantId, url: `https://${host}/qodiqa/hook`, eventTypes: ['attestation.completed'], createdBy: 'w3-test' });
  }
  async function opsFor(endpointId, wait = 5000) {
    const t0 = Date.now();
    for (;;) {
      const r = (await verify.query("SELECT operation_id, status, retry_count FROM persistence_recovery_queue WHERE operation_type = 'WEBHOOK_DELIVERY' AND payload->>'endpointId' = $1", [endpointId])).rows;
      if (r.length || Date.now() - t0 > wait) return r;
      await sleep(50);
    }
  }
  // Drain exactly this operation through the real worker, making each backoff eligible at once.
  async function drain(operationId, maxRounds = 10) {
    for (let i = 0; i < maxRounds; i++) {
      const row = (await verify.query('SELECT status FROM persistence_recovery_queue WHERE operation_id = $1', [operationId])).rows[0];
      if (!row || row.status !== 'PENDING') return row ? row.status : 'COMPLETE';
      await verify.query("UPDATE persistence_recovery_queue SET eligible_at = now() - interval '1 second' WHERE operation_id = $1", [operationId]);
      const op = await queue.claimNext();
      expect(op && op.operationId).toBe(operationId);
      await worker._processOne(op);
    }
    return 'STILL_PENDING';
  }
  const log = async (endpointId) => (await verify.query('SELECT attempt, http_status, success FROM webhook_delivery_log WHERE endpoint_id = $1 ORDER BY attempt', [endpointId])).rows;

  test('WH-01 a completed attestation is delivered once, signed, and verifies with the SDK', async () => {
    const { endpoint: ep, secret } = await endpoint('wh01.receiver.w3.test');
    const att = await attestor.generateAttestation(artifact());
    expect(att.attestationDecision).toMatch(/^ATTESTED/);
    const [op] = await opsFor(ep.id);
    expect(op).toBeDefined();
    expect(await drain(op.operation_id)).toBe('COMPLETE');

    expect(mockReceiver.received).toHaveLength(1);
    const rec = mockReceiver.received[0];
    expect(rec).toEqual(expect.objectContaining({ hostname: 'wh01.receiver.w3.test', address: PUBLIC_ADDR, method: 'POST', path: '/qodiqa/hook', rejectUnauthorized: true, minVersion: 'TLSv1.2' }));
    expect(rec.headers['X-QODIQA-Event']).toBe('attestation.completed');
    expect(() => verifyWebhookSignature({ body: rec.body, signature: rec.headers['X-QODIQA-Signature'], timestamp: rec.headers['X-QODIQA-Timestamp'], secret })).not.toThrow();
    expect(() => verifyWebhookSignature({ body: rec.body, signature: rec.headers['X-QODIQA-Signature'], timestamp: rec.headers['X-QODIQA-Timestamp'], secret: 'whsec_wrong' })).toThrow();
    const body = JSON.parse(rec.body);
    expect(body).toEqual(expect.objectContaining({ eventType: 'attestation.completed', attestationId: att.attestationId, tenantId: TENANT, decision: att.attestationDecision }));
    expect(rec.headers['X-QODIQA-Event-ID']).toBe(body.eventId);
    expect(await log(ep.id)).toEqual([{ attempt: 1, http_status: 200, success: true }]);
  });

  test('WH-02 a transient failure is retried and then delivered', async () => {
    const { endpoint: ep } = await endpoint('wh02.receiver.w3.test');
    let n = 0; mockReceiver.respond = () => (++n === 1 ? 503 : 200);
    await attestor.generateAttestation(artifact());
    const [op] = await opsFor(ep.id);
    expect(await drain(op.operation_id)).toBe('COMPLETE');
    expect(mockReceiver.received).toHaveLength(2);
    expect(await log(ep.id)).toEqual([{ attempt: 1, http_status: 503, success: false }, { attempt: 2, http_status: 200, success: true }]);
  });

  test('WH-03 an event that keeps failing ends in the DLQ after five attempts', async () => {
    const { endpoint: ep } = await endpoint('wh03.receiver.w3.test');
    mockReceiver.respond = () => 503;
    await attestor.generateAttestation(artifact());
    const [op] = await opsFor(ep.id);
    expect(await drain(op.operation_id)).toBe('DLQ');
    expect(mockReceiver.received).toHaveLength(5);
    const rows = await log(ep.id);
    expect(rows.map((r) => r.attempt)).toEqual([1, 2, 3, 4, 5]);
    expect(rows.every((r) => r.http_status === 503 && r.success === false)).toBe(true);
    const dlq = (await verify.query('SELECT status, last_error FROM persistence_recovery_queue WHERE operation_id = $1', [op.operation_id])).rows[0];
    expect(dlq.status).toBe('DLQ');
    expect(dlq.last_error).toMatch(/^non-retryable: webhook delivery abandoned/);
  });

  test('WH-04 an endpoint that resolves to the metadata address is refused before any connection', async () => {
    const { endpoint: ep } = await endpoint('wh04.metadata.w3.test');
    mockDnsTable.set('wh04.metadata.w3.test', ['169.254.169.254']);
    await attestor.generateAttestation(artifact());
    const [op] = await opsFor(ep.id);
    const final = await drain(op.operation_id);
    expect(final).toBe('DLQ');
    expect(mockReceiver.connects.filter((c) => c.hostname === 'wh04.metadata.w3.test')).toEqual([]);
    expect(mockReceiver.received).toEqual([]);
    const rows = await log(ep.id);
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((r) => r.success === false && r.http_status === null)).toBe(true);
  });

  test('WH-05 DNS rebinding to loopback at connect time is refused; nothing is sent', async () => {
    const { endpoint: ep } = await endpoint('wh05.rebind.w3.test');
    mockDnsCalls.delete('wh05.rebind.w3.test');
    mockDnsTable.set('wh05.rebind.w3.test', (n) => (n % 2 === 1 ? [PUBLIC_ADDR] : ['127.0.0.1']));
    await attestor.generateAttestation(artifact());
    const [op] = await opsFor(ep.id);
    await verify.query("UPDATE persistence_recovery_queue SET eligible_at = now() - interval '1 second' WHERE operation_id = $1", [op.operation_id]);
    await worker._processOne(await queue.claimNext());
    expect(mockReceiver.connects).toEqual([{ hostname: 'wh05.rebind.w3.test', refused: 'WEBHOOK_DNS_REVALIDATION_BLOCKED' }]);
    expect(mockReceiver.received).toEqual([]);
  });

  test('WH-06 tenant isolation: other tenants get nothing; a forged artifact triggers nothing', async () => {
    const { endpoint: mine } = await endpoint('wh06a.receiver.w3.test');
    const { endpoint: theirs } = await endpoint('wh06b.receiver.w3.test', 'w3-other-tenant');
    await attestor.generateAttestation(artifact());
    expect(await opsFor(mine.id)).toHaveLength(1);
    expect(await opsFor(theirs.id, 1000)).toHaveLength(0);

    const forged = { ...artifact(), signature: Buffer.alloc(64, 7).toString('base64') };
    const before = (await verify.query("SELECT count(*)::int AS n FROM persistence_recovery_queue WHERE operation_type = 'WEBHOOK_DELIVERY'")).rows[0].n;
    const r = await attestor.generateAttestation(forged);
    expect(r.attestationDecision).toBe('NOT_ATTESTED');
    await sleep(500);
    const after = (await verify.query("SELECT count(*)::int AS n FROM persistence_recovery_queue WHERE operation_type = 'WEBHOOK_DELIVERY'")).rows[0].n;
    expect(after).toBe(before);
  });
});
