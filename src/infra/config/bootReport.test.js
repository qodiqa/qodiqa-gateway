'use strict';

// step 4 — BOOT_REPORT must be truthful: observed facts, with a failed
// probe reported as such (never replaced by the configured intent), and no
// secret value. The real-server production-profile boot is covered end to end
// by; this pins the builder's
// own derivations with injected dependencies.

const fs = require('fs');
const os = require('os');
const path = require('path');

const { buildBootReport, emitBootReport, canonical } = require('./bootReport');
const semanticConfig = require('../../core/semantic/embeddingSimilarity/config');

function deps(over = {}) {
  return {
    validation: () => ({ profile: 'prod', nodeEnv: 'production', fingerprint: { sha256: 'f'.repeat(64), variableCount: 3 },
      warnings: [{ variable: 'QODIQA_KMS_PROVIDER' }] }),
    pg: () => ({ isEnabled: () => false }),
    pgSsl: () => true,
    listKeys: () => () => [
      { keyId: 'b:key_v1', status: 'active', publicKeyB64: 'PUBLIC' },
      { keyId: 'a:key_v2', status: 'active' },
      { keyId: 'a:key_v1', status: 'deprecated' },
    ],
    providers: () => ['local'],
    redisSummary: () => ({ urlRedacted: 'rediss://***@r:6380', tlsEnabled: true, tlsVerified: true, authConfigured: true }),
    semanticConfig: () => semanticConfig,
    semanticStatus: () => ({ model: 'm', status: 'READY', anchorCount: 76 }),
    opsConfig: () => ({ adminEnabled: false, diagnosticsEnabled: true, profilingDiagnosticsEnabled: false, token: 't'.repeat(40) }),
    ...over,
  };
}
const FACTS = { nonceReady: true, anomalyReady: true, rlReady: true, requestRateLimitEnabled: true,
  requestRateLimitStorageReady: true, executionIntegrity: 'FULL' };

describe('buildBootReport', () => {
  test('reports profile, fingerprint, keys (ids only), providers, planes', async () => {
    const r = await buildBootReport(FACTS, deps());
    expect(r).toMatchObject({ schemaVersion: 1, profile: 'prod', nodeEnv: 'production',
      config: { fingerprint: { sha256: 'f'.repeat(64) }, warnings: ['QODIQA_KMS_PROVIDER'] },
      keys: { observed: true, count: 3, active: ['a:key_v2', 'b:key_v1'], byStatus: { active: 2, deprecated: 1 } },
      providers: ['local'],
      planes: { admin: false, diagnostics: true, profiling: false, opsTokenConfigured: true },
      postgres: { enabled: false }, executionIntegrity: 'FULL' });
    expect(JSON.stringify(r)).not.toContain('PUBLIC');
    expect(JSON.stringify(r)).not.toContain('t'.repeat(40));
  });

  test.each([
    [true, true, true], [true, false, false], [false, true, false], [false, false, false],
  ])('rate limit: limiter enabled=%s, storage ready=%s → protectionActive=%s', async (enabled, ready, active) => {
    const r = await buildBootReport({ ...FACTS, requestRateLimitEnabled: enabled, requestRateLimitStorageReady: ready }, deps());
    // the report also states the limiter's real mode in words.
    const mode = !enabled ? 'off (RL_ENABLED=false)' : ready ? 'on (Redis)'
      : 'on, backend not ready: failMode=closed buckets return 429, failMode=degrade buckets use the per-process fallback';
    expect(r.rateLimit).toEqual({ requestLimiterEnabled: enabled, requestLimiterStorageReady: ready,
      protectionActive: active, policyRateLimitStoreReady: true, mode, failModes: null });
  });

  test('the fail-mode tiers supplied at boot are reported as given', async () => {
    const failModes = { closed: ['sign', 'ops_admin'], degrade: ['ai_chat_ip'] };
    const r = await buildBootReport({ ...FACTS, requestRateLimitFailModes: failModes }, deps());
    expect(r.rateLimit.failModes).toEqual(failModes);
  });

  test('policy-store readiness never stands in for request limiting (the earlier bug)', async () => {
    const r = await buildBootReport({ ...FACTS, requestRateLimitEnabled: false, rlReady: true }, deps());
    expect(r.rateLimit.policyRateLimitStoreReady).toBe(true);
    expect(r.rateLimit.protectionActive).toBe(false);
  });

  test('Redis TLS is "established" only when configured AND a store is ready over it', async () => {
    expect((await buildBootReport(FACTS, deps())).redis.tlsEstablished).toBe(true);
    const none = { ...FACTS, nonceReady: false, anomalyReady: false, rlReady: false };
    expect((await buildBootReport(none, deps())).redis.tlsEstablished).toBe(false);
    const plain = deps({ redisSummary: () => ({ urlRedacted: 'redis://r', tlsEnabled: false, tlsVerified: false, authConfigured: false }) });
    expect((await buildBootReport(FACTS, plain)).redis.tlsEstablished).toBe(false);
  });

  test('PostgreSQL: both ends of the connection and the migration state are observed', async () => {
    const pg = { isEnabled: () => true,
      connectionSecurity: async () => ({ client: { tls: true, protocol: 'TLSv1.3', cipher: 'X', authorized: true },
        server: { ssl: false, protocol: null, cipher: null } }),
      query: async () => ({ rows: [{ version: '002', name: 'b' }, { version: '001', name: 'a' }] }) };
    const r = await buildBootReport(FACTS, deps({ pg: () => pg }));
    expect(r.postgres.tls).toEqual({ observed: true, configured: true,
      client: { tls: true, protocol: 'TLSv1.3', cipher: 'X', authorized: true }, server: { ssl: false, protocol: null, cipher: null } });
    const onDisk = fs.readdirSync(path.join(__dirname, '..', 'postgres', 'migrations')).filter((f) => /^\d+.*\.sql$/.test(f)).length;
    expect(r.postgres.migrations).toEqual({ observed: true, applied: 2, latest: { version: '002', name: 'b' }, onDisk, pending: onDisk - 2 });
  });

  test('a failing probe is reported as unobserved with its error — never as the configured intent', async () => {
    const pg = { isEnabled: () => true,
      connectionSecurity: async () => { const e = new Error('permission denied'); e.code = '42501'; throw e; },
      query: async () => { throw new Error('relation "qodiqa_migrations" does not exist'); } };
    const r = await buildBootReport(FACTS, deps({ pg: () => pg }));
    expect(r.postgres.tls).toEqual({ observed: false, configured: true, error: '42501: permission denied' });
    expect(r.postgres.migrations).toEqual({ observed: false, error: 'relation "qodiqa_migrations" does not exist' });
    expect(r.postgres.tls.client).toBeUndefined();
  });

  test('semantic fingerprint is stable, independent of key order, and matches the shipped defaults here', async () => {
    const r1 = await buildBootReport(FACTS, deps());
    const r2 = await buildBootReport(FACTS, deps());
    expect(r1.semantic.fingerprint).toBe(r2.semantic.fingerprint);
    expect(r1.semantic.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(canonical({ b: 1, a: { d: 1, c: 2 } }))).toBe('{"a":{"c":2,"d":1},"b":1}');
    expect(r1.semantic.deviations).toEqual(semanticConfig.getDeviations().map((d) => d.key));
  });
});

test('services-layer accessors must be injected (infra never imports services)', async () => {
  const { listKeys, ...noKeys } = deps();
  await expect(buildBootReport(FACTS, noKeys)).rejects.toThrow('deps.listKeys is required');
  const { providers, ...noProviders } = deps();
  await expect(buildBootReport(FACTS, noProviders)).rejects.toThrow('deps.providers is required');
  expect(fs.readFileSync(path.join(__dirname, 'bootReport.js'), 'utf8')).not.toMatch(/require\([^)]*services\//);
});

describe('emitBootReport', () => {
  test('emits BOOT_REPORT and writes the file when QODIQA_BOOT_REPORT_PATH is set', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w2-bootreport-'));
    try {
      const file = path.join(dir, 'r.json');
      const events = [];
      const r = await emitBootReport(FACTS, { emit: (s, t, f) => events.push({ s, t, f }), env: { QODIQA_BOOT_REPORT_PATH: file }, deps: deps() });
      expect(events).toEqual([{ s: 'INFO', t: 'BOOT_REPORT', f: { report: r } }]);
      expect(JSON.parse(fs.readFileSync(file, 'utf8'))).toEqual(r);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('never throws: a builder failure becomes BOOT_REPORT_FAILED', async () => {
    const events = [];
    const r = await emitBootReport(FACTS, { emit: (s, t, f) => events.push({ s, t, f }), env: {},
      deps: deps({ providers: () => { throw new Error('boom'); } }) });
    expect(r).toBeNull();
    expect(events).toEqual([{ s: 'ERROR', t: 'BOOT_REPORT_FAILED', f: { error: 'boom' } }]);
  });
});
