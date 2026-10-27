'use strict';

/**
 * step 9 — three real server.js replicas (A, B, C), ONE PostgreSQL database,
 * ONE Redis (AOF, crash-restartable), shared keystore volume
 * (test/helpers/cluster.js). Every propagation check is held to the
 * approved guarantee and its measured time is recorded
 *.
 *
 *   CL-01  signing key revoked on A → B and C reject it (/sign 401) within 5 s
 *   CL-02  a new key issued on A works everywhere; the revoked one never comes back
 *   CL-03  RBAC user removed on A → B and C reject the operator key within 5 s
 *   CL-04  tenant suspended on A → artifacts blocked (TENANT_SUSPENDED) on B and C within 5 s
 *   CL-05  graceful key rotation on A: B signs with the new key within 5 s; an artifact
 * signed before the rotation still verifies on C inside the window
 * CL-06 a non-canonical signature spelling is INVALID_SIGNATURE on every replica
 * CL-07 /sign clamps an over-long ttl to 60 s on every replica
 * CL-08 an artifact used before a Redis crash is REPLAY_DETECTED after it
 * Failover authorization runs through the real /ai/chat route and router in
 * src/api/routes/__tests__/aiChat.failover.test.js.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).
const fs = require('fs');
const path = require('path');
const { startCluster, REPO_ROOT } = require('../helpers/cluster');

const REAL = process.env.QODIQA_PG_ENABLED === 'true' && !!process.env.QODIQA_PG_CONTROL_PASSWORD
  && require('child_process').spawnSync('docker', ['info'], { timeout: 20_000 }).status === 0;
const describeOrSkip = REAL ? describe : describe.skip;
jest.setTimeout(600_000);

const BOUND_MS = 5000;
const EVIDENCE = path.join(process.env.W6_EVIDENCE_DIR || path.join(REPO_ROOT, 'evidence', 'w6', 'tests', 'runs') /* C-11: default is git-ignored; the tracked *-latest.json files are historical */, `cluster-${process.env.W6_EVIDENCE_TAG || 'latest'}.json`);
const measured = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

describeOrSkip('3 replicas, one PostgreSQL, one Redis', () => {
  let c;
  const ALL = ['A', 'B', 'C'];
  const http = async (node, method, p, { body, token, headers = {} } = {}) => {
    const res = await fetch(`${c.url(node)}${p}`, {
      method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let json = null; try { json = await res.json(); } catch (_) { /* no body */ }
    return { status: res.status, body: json };
  };
  const admin = (node, method, p, body) => http(node, method, p, { body, token: c.operatorKey });
  const signOn = (node, key, request, extra = {}) => http(node, 'POST', '/sign', { token: key, body: { request, ...extra } });
  const artifactHeader = (a) => ({ 'x-qodiqa-artifact': Buffer.from(JSON.stringify(a)).toString('base64') });
  const ORDER = { method: 'POST', path: '/orders/create', body: { sku: 'SKU-1' } };
  const CHAT_BODY = { prompt: 'Hello from the cluster test' };
  const CHAT = { method: 'POST', path: '/ai/chat', body: CHAT_BODY };

  async function within(label, probe, ok) {
    const t0 = Date.now();
    for (;;) {
      let v; let err = null;
      try { v = await probe(); } catch (e) { err = e; }
      const elapsed = Date.now() - t0;
      if (!err && ok(v)) { measured.push({ label, elapsedMs: elapsed }); return elapsed; }
      if (elapsed > BOUND_MS) throw new Error(`${label}: not in force after ${elapsed} ms (bound ${BOUND_MS}); last=${err ? err.message : JSON.stringify(v).slice(0, 400)}`);
      await sleep(25);
    }
  }

  beforeAll(async () => { c = await startCluster({ replicas: 3, tag: 'w6cl' }); }, 600_000);
  afterAll(async () => {
    fs.mkdirSync(path.dirname(EVIDENCE), { recursive: true });
    fs.writeFileSync(EVIDENCE, JSON.stringify({ boundMs: BOUND_MS, replicas: 3, measured }, null, 2));
    if (c) {
      await c.stop();
      expect({ dbGone: c.dbGone, redisGone: c.redisGone }).toEqual({ dbGone: true, redisGone: true });
    }
  }, 120_000);

  test('CL-01/02 a signing key revoked on A is rejected by B and C within 5 s; a new key works everywhere, the old never returns', async () => {
    const key = c.signing.apiKey; const id = c.signing.identityId;
    for (const n of ALL) expect((await signOn(n, key, ORDER)).status).toBe(200);
    expect((await admin('A', 'DELETE', `/signing-identities/${id}/api-key`, { reason: 'w6 cluster test' })).status).toBe(200);
    for (const n of ['B', 'C']) await within(`CL-01 revocation on ${n}`, () => signOn(n, key, ORDER), (r) => r.status === 401);
    expect((await signOn('A', key, ORDER)).status).toBe(401);
    const issued = await admin('A', 'POST', `/signing-identities/${id}/api-key`);
    expect(issued.status).toBe(201);
    const fresh = issued.body.data ? issued.body.data.apiKey || issued.body.data.plaintext : (issued.body.apiKey || issued.body.plaintext);
    expect(typeof fresh).toBe('string');
    for (const n of ['B', 'C']) await within(`CL-02 new key on ${n}`, () => signOn(n, fresh, ORDER), (r) => r.status === 200);
    for (const n of ALL) expect((await signOn(n, key, ORDER)).status).toBe(401);
    c.signing.apiKey = fresh;
  });

  test('CL-03 an RBAC user removed on A is rejected by B and C within 5 s', async () => {
    const created = await admin('A', 'POST', '/rbac/users', { username: `w6-cl-${Date.now()}`, role: 'auditor' });
    expect(created.status).toBe(201);
    const userId = (created.body.data || created.body).user.id;
    const k = await admin('A', 'POST', `/rbac/users/${userId}/api-key`);
    const opKey = (k.body.data || k.body).apiKey || (k.body.data || k.body).plaintext;
    // authenticated on B/C = anything but 401 (an auditor may get 403 on this route: known, not permitted)
    for (const n of ['B', 'C']) await within(`CL-03 user known on ${n}`, () => http(n, 'GET', '/rbac/permissions', { token: opKey }), (r) => r.status !== 401);
    expect((await admin('A', 'DELETE', `/rbac/users/${userId}`)).status).toBe(200);
    for (const n of ['B', 'C']) await within(`CL-03 removal on ${n}`, () => http(n, 'GET', '/rbac/permissions', { token: opKey }), (r) => r.status === 401);
  });

  test('CL-04 a tenant suspended on A is blocked on B and C within 5 s', async () => {
    const probe = (n) => async () => {
      const s = await signOn('A', c.signing.apiKey, CHAT, { payload: { provider: 'local' } });
      return http(n, 'POST', '/ai/chat', { body: CHAT_BODY, headers: artifactHeader(s.body.artifact) });
    };
    expect((await admin('A', 'PATCH', `/v1/admin/tenants/${c.clientId}`, { status: 'suspended' })).status).toBe(200);
    for (const n of ['B', 'C']) await within(`CL-04 suspension on ${n}`, probe(n), (r) => r.body && r.body.reason === 'TENANT_SUSPENDED');
    expect((await admin('A', 'PATCH', `/v1/admin/tenants/${c.clientId}`, { status: 'active' })).status).toBe(200);
    for (const n of ['B', 'C']) await within(`CL-04 reactivation on ${n}`, probe(n), (r) => r.body && r.body.reason !== 'TENANT_SUSPENDED');
  });

  test('CL-05 graceful rotation on A: B signs with the new key within 5 s; a pre-rotation artifact still verifies on C (in-flight window)', async () => {
    const before = await signOn('B', c.signing.apiKey, ORDER);
    expect(before.body.artifact.publicKeyId).toBe(c.firstKeyId);
    const rot = await admin('A', 'POST', `/key-admin/${c.clientId}/rotate-graceful`);
    expect(rot.status).toBe(200);
    const newKeyId = (rot.body.data || rot.body).keyId;
    expect(newKeyId).not.toBe(c.firstKeyId);
    await within('CL-05 B signs with the new key', () => signOn('B', c.signing.apiKey, ORDER), (r) => r.status === 200 && r.body.artifact.publicKeyId === newKeyId);
    const v = await http('C', 'POST', '/verify/v2', { body: { artifact: before.body.artifact, request: ORDER } });
    // Validation (signature, time, key-lifecycle timeline) runs BEFORE policy: reaching the
    // policy stage's consent check proves the deprecated key was accepted for this in-flight
    // artifact on C. (No consent grant exists in this cluster — the policy stage is not under test.)
    // Diagnostics only: the criterion is unchanged — the same comparison
    // as the expect() below — but a failure now reports the COMPLETE response (reason, details.issue = which
    // keyLifecycle branch refused, keyStatus) and the artifact's timestamp, which the bare reason assertion discarded.
    if (!v.body || v.body.reason !== 'CONSENT_CONTEXT_INCOMPLETE') {
      const failure = { status: v.status, body: v.body, artifactTimestamp: before.body.artifact.timestamp, artifactIso: new Date(before.body.artifact.timestamp).toISOString(), oldKeyId: c.firstKeyId, newKeyId };
      // Failure path only: keep the replicas' state before afterAll's c.stop() removes the database, Redis and keystore.
      const evidenceDir = await c.captureEvidence('CL-05', { failure, rotation: rot.body, verifiedOn: 'C', signedOn: 'B', rotatedOn: 'A' });
      throw new Error(`CL-05: expected reason CONSENT_CONTEXT_INCOMPLETE; complete response: ${JSON.stringify(failure)}; evidence: ${evidenceDir}`);
    }
    expect(v.body.reason).toBe('CONSENT_CONTEXT_INCOMPLETE');
  });

  test('CL-06 a non-canonical signature spelling is INVALID_SIGNATURE on every replica', async () => {
    for (const n of ALL) {
      const s = await signOn('A', c.signing.apiKey, ORDER);
      const bad = { ...s.body.artifact, signature: s.body.artifact.signature.replace(/=+$/, '') };
      const v = await http(n, 'POST', '/verify/v2', { body: { artifact: bad, request: ORDER } });
      expect({ n, reason: v.body.reason }).toEqual({ n, reason: 'INVALID_SIGNATURE' });
    }
  });

  test('CL-07 /sign clamps an over-long ttl to 60 s on every replica', async () => {
    for (const n of ALL) {
      const s = await signOn(n, c.signing.apiKey, ORDER, { ttl: 600_000 });
      expect(s.body.meta).toMatchObject({ ttlClamped: true, effectiveTtlMs: 60_000 });
      expect(s.body.artifact.expiry - s.body.artifact.timestamp).toBe(60_000);
    }
  });

  test('CL-08 an artifact used before a Redis crash is still REPLAY_DETECTED after it (AOF), on another replica', async () => {
    const s = await signOn('A', c.signing.apiKey, CHAT, { payload: { provider: 'local' } });
    const first = await http('A', 'POST', '/ai/chat', { body: CHAT_BODY, headers: artifactHeader(s.body.artifact) });
    expect(first.body.reason).not.toBe('REPLAY_DETECTED'); // first use (consent/provider outcome is irrelevant: the nonce is burned)
    await sleep(1500);                                      // past the AOF everysec fsync
    await c.crashRestartRedis();
    const replay = await within('CL-08 replay refused after the crash (B)', async () => http('B', 'POST', '/ai/chat', { body: CHAT_BODY, headers: artifactHeader(s.body.artifact) }),
      (r) => r.body && (r.body.reason === 'REPLAY_DETECTED' || r.body.reason === 'REPLAY_STATE_UNPROVABLE'));
    void replay;
    // C's Redis client may still be reconnecting (NONCE_STORE_ERROR: fail closed) — poll it like B
    await within('CL-08 replay refused after the crash (C)', async () => http('C', 'POST', '/ai/chat', { body: CHAT_BODY, headers: artifactHeader(s.body.artifact) }),
      (r) => r.body && r.body.reason === 'REPLAY_DETECTED');
  });
});
