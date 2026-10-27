'use strict';

const path = require('path');
const { seedDemo, SeedError, DENY_POLICY_ID, createOtpProvider, _hotp } = require('../seedDemoLib');

const OPS = { maker: 'ok_maker000000000000000', reviewer: 'ok_reviewer0000000000000', approver: 'ok_approver0000000000000' };
const OUT = path.join('/tmp', 'demo-keys');

// A stateful fake of the admin API surface the seed uses, enforcing the same separation-of-duties the real
// governance service does (review/approve/publish by someone other than the drafter).
function fakeGateway() {
  const state = { identities: [], consents: [], tenantKeys: new Set(), policies: {}, crs: {}, n: 0, keysIssued: 0 };
  const calls = [];
  const id = (p) => `${p}-${++state.n}`;
  async function call(method, url, { key, body } = {}) {
    calls.push({ method, url, key, body });
    const u = new URL(url, 'http://gw');
    const p = u.pathname;
    if (method === 'GET' && p === '/signing-identities') return ok(200, { identities: state.identities });
    if (method === 'POST' && p === '/signing-identities') {
      const identity = { id: id('sid'), ...body };
      state.identities.push(identity);
      return ok(201, { identity });
    }
    let m;
    if (method === 'POST' && (m = p.match(/^\/signing-identities\/([^/]+)\/api-key$/))) {
      state.keysIssued += 1;
      return ok(201, { apiKey: `sk_${String(state.keysIssued).padStart(32, '0')}` });
    }
    if ((m = p.match(/^\/key-admin\/([^/]+)\/status$/))) return state.tenantKeys.has(m[1]) ? ok(200, { keyCount: 1 }) : ok(404, {});
    if (method === 'POST' && (m = p.match(/^\/key-admin\/([^/]+)\/rotate$/))) { state.tenantKeys.add(m[1]); return ok(200, {}); }
    if (method === 'GET' && p === '/consent') {
      const q = Object.fromEntries(u.searchParams);
      return ok(200, { records: state.consents.filter((c) => c.actor_id === q.actorId && c.action === q.action && c.tenant_id === q.tenantId) });
    }
    if (method === 'POST' && p === '/consent') { const rec = { id: id('c'), state: 'ACTIVE', ...body }; state.consents.push(rec); return ok(201, { record: rec }); }
    if (method === 'POST' && (m = p.match(/^\/consent\/([^/]+)\/revoke$/))) { state.consents.find((c) => c.id === m[1]).state = 'REVOKED'; return ok(200, {}); }
    if ((m = p.match(/^\/v1\/admin\/tenants\/([^/]+)\/policy-config$/))) {
      const pol = state.policies[m[1]];
      return pol ? ok(200, { policySet: { source: 'TENANT', policies: pol } }) : ok(404, {});
    }
    if (method === 'POST' && p === '/v1/policy/governance/draft') { const cr = { id: id('cr'), maker: key, body, steps: [] }; state.crs[cr.id] = cr; return ok(201, cr); }
    if (method === 'POST' && (m = p.match(/^\/v1\/policy\/governance\/([^/]+)\/(submit|review|approve|publish)$/))) {
      const cr = state.crs[m[1]];
      if (m[2] !== 'submit' && key === cr.maker) return ok(403, { error: 'SELF_APPROVAL_FORBIDDEN' });
      cr.steps.push(m[2]);
      if (m[2] === 'publish') state.policies[cr.body.tenantId] = [{ id: cr.body.policyId, ...cr.body.payload }];
      return ok(200, {});
    }
    return ok(500, { error: `unexpected ${method} ${p}` });
  }
  function ok(status, data) { return { status, json: { data }, text: JSON.stringify({ data }) }; }
  return { api: { call }, state, calls };
}

function fakeFs() {
  const files = new Map();
  return {
    files,
    existsSync: (f) => files.has(f),
    readFileSync: (f) => { if (!files.has(f)) throw new Error('ENOENT'); return files.get(f).data; },
    mkdirSync: () => {},
    writeFileSync: (f, data, opts) => {
      if (opts.flag === 'wx' && files.has(f)) throw new Error('EEXIST');
      files.set(f, { data, mode: opts.mode });
    },
  };
}

describe('public demo seed (R-03)', () => {
  test('first run provisions 3 identities, 2 tenant keys, consent ACTIVE/REVOKED/ACTIVE and the governed deny-all policy', async () => {
    const gw = fakeGateway();
    const fs = fakeFs();
    const report = [];
    const out = await seedDemo({ api: gw.api, operators: OPS, outDir: OUT, environment: 'production', fsImpl: fs, report: (l) => report.push(l) });

    expect(gw.state.identities.map((i) => [i.name, i.tenantId, i.allowedProviders])).toEqual([
      ['demo-allowed', 'demo', ['local']], ['demo-revoked', 'demo', ['local']], ['demo-denied', 'demo-denied', ['local']]]);
    expect([...gw.state.tenantKeys].sort()).toEqual(['demo', 'demo-denied']);
    const stateOf = (name) => gw.state.consents.filter((c) => c.actor_id === out.identities[name]).map((c) => c.state);
    expect(stateOf('demo-allowed')).toEqual(['ACTIVE']);
    expect(stateOf('demo-revoked')).toEqual(['REVOKED']);
    expect(stateOf('demo-denied')).toEqual(['ACTIVE']);
    expect(gw.state.policies['demo-denied']).toEqual([{ id: DENY_POLICY_ID, type: 'BLOCK_IP', priority: 5, config: { blocklist: [], cidrs: ['0.0.0.0/0', '::/0'] } }]);
    expect(Object.values(gw.state.crs)[0].steps).toEqual(['submit', 'review', 'approve', 'publish']);

    // key files: 0600, exclusive create, sk_ content; nothing secret in the report
    expect([...fs.files.keys()].sort()).toEqual(['demo-allowed', 'demo-denied', 'demo-revoked'].map((n) => path.join(OUT, `${n}.key`)));
    for (const { data, mode } of fs.files.values()) { expect(mode).toBe(0o600); expect(data).toMatch(/^sk_[0-9]{32}\n$/); }
    expect(JSON.stringify(report) + JSON.stringify(out)).not.toMatch(/sk_|ok_/);
  });

  test('re-running is a no-op: no new identity, key, consent, rotation or change request', async () => {
    const gw = fakeGateway();
    const fs = fakeFs();
    await seedDemo({ api: gw.api, operators: OPS, outDir: OUT, environment: 'production', fsImpl: fs });
    const before = JSON.stringify({ ...gw.state, tenantKeys: [...gw.state.tenantKeys] });
    const second = await seedDemo({ api: gw.api, operators: OPS, outDir: OUT, environment: 'production', fsImpl: fs });
    expect(second.actions).toEqual([]);
    expect(JSON.stringify({ ...gw.state, tenantKeys: [...gw.state.tenantKeys] })).toBe(before);
    expect(gw.calls.filter((c) => c.method !== 'GET').length).toBeGreaterThan(0); // only the first run wrote
  });

  test('a stray ACTIVE consent on the revoked identity is revoked again on the next run', async () => {
    const gw = fakeGateway();
    const fs = fakeFs();
    const first = await seedDemo({ api: gw.api, operators: OPS, outDir: OUT, environment: 'production', fsImpl: fs });
    gw.state.consents.push({ id: 'stray', state: 'ACTIVE', actor_id: first.identities['demo-revoked'], action: 'local', tenant_id: 'demo' });
    await seedDemo({ api: gw.api, operators: OPS, outDir: OUT, environment: 'production', fsImpl: fs });
    expect(gw.state.consents.find((c) => c.id === 'stray').state).toBe('REVOKED');
  });

  test('dry run writes nothing', async () => {
    const gw = fakeGateway();
    const fs = fakeFs();
    const out = await seedDemo({ api: gw.api, operators: OPS, outDir: OUT, environment: 'production', fsImpl: fs, dryRun: true });
    expect(out.actions.length).toBeGreaterThan(0);
    expect(gw.calls.filter((c) => c.method !== 'GET')).toEqual([]);
    expect(fs.files.size).toBe(0);
  });

  test('refuses: non-distinct operators, a foreign-tenant identity with a demo name, a corrupt key file', async () => {
    await expect(seedDemo({ api: fakeGateway().api, operators: { ...OPS, approver: OPS.maker }, outDir: OUT, environment: 'production', fsImpl: fakeFs() }))
      .rejects.toThrow(/three distinct operators/);

    const gw = fakeGateway();
    gw.state.identities.push({ id: 'x', name: 'demo-allowed', tenantId: 'acme' });
    await expect(seedDemo({ api: gw.api, operators: OPS, outDir: OUT, environment: 'production', fsImpl: fakeFs() }))
      .rejects.toThrow(/belongs to tenant acme/);

    const fs = fakeFs();
    fs.files.set(path.join(OUT, 'demo-allowed.key'), { data: 'garbage', mode: 0o600 });
    await expect(seedDemo({ api: fakeGateway().api, operators: OPS, outDir: OUT, environment: 'production', fsImpl: fs }))
      .rejects.toBeInstanceOf(SeedError);
    expect(fs.files.get(path.join(OUT, 'demo-allowed.key')).data).toBe('garbage'); // never overwritten
  });

  test('MFA step-up: every mutating call carries the right operator code; GETs carry none', async () => {
    const gw = fakeGateway();
    let n = 0;
    const prov = (role) => ({ getCode: async () => `${role}-${++n}` });
    await seedDemo({ api: gw.api, operators: OPS, otp: { maker: prov('m'), reviewer: prov('r'), approver: prov('a') }, outDir: OUT, environment: 'production', fsImpl: fakeFs() });
    // the fake API ignores otp, so capture via a wrapper
    const gw2 = fakeGateway();
    const seen = [];
    const inner = gw2.api.call;
    gw2.api.call = async (m, u, o = {}) => { seen.push({ m, u, otp: o.otp, key: o.key }); return inner(m, u, o); };
    await seedDemo({ api: gw2.api, operators: OPS, otp: { maker: prov('m'), reviewer: prov('r'), approver: prov('a') }, outDir: OUT, environment: 'production', fsImpl: fakeFs() });
    for (const c of seen) {
      if (c.m === 'GET') expect(c.otp).toBeUndefined();
      else expect(c.otp).toMatch(c.key === OPS.maker ? /^m-/ : c.key === OPS.reviewer ? /^r-/ : /^a-/);
    }
    expect(seen.filter((c) => c.m !== 'GET').length).toBe(17);
  });

  test('OTP provider: recovery codes first, then strictly increasing TOTP steps (±1 window), waiting only when needed', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    let t = 1_000_000 * 30000 + 5000; // 5 s into step 1,000,000
    const sleeps = [];
    const p = createOtpProvider({ totpSecret: secret, recoveryCodes: ['rc1'], now: () => t, sleep: async (ms) => { sleeps.push(ms); t += ms; } });
    expect(await p.getCode()).toBe('rc1');
    expect(await p.getCode()).toBe(_hotp(secret, 999_999));
    expect(await p.getCode()).toBe(_hotp(secret, 1_000_000));
    expect(await p.getCode()).toBe(_hotp(secret, 1_000_001));
    expect(sleeps).toEqual([]);
    expect(await p.getCode()).toBe(_hotp(secret, 1_000_002)); // needs the clock to reach step 1,000,001
    expect(sleeps.length).toBe(1);
    // RFC 6238 test vector (SHA-1, T=59 s → step 1): 287082 for the ASCII secret "12345678901234567890"
    expect(_hotp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 1)).toBe('287082');
  });

  test('OTP provider with nothing left fails loudly instead of sending an empty code', async () => {
    await expect(createOtpProvider({}).getCode()).rejects.toThrow(/no recovery code or TOTP secret/);
  });

  test('a failing API call aborts with a redacted error (no key material)', async () => {
    const gw = fakeGateway();
    const orig = gw.api.call;
    gw.api.call = async (m, u, o) => (u === '/consent' && m === 'POST' ? { status: 500, json: null, text: 'boom sk_secretsecretsecret00 ok_operatorkey0000000' } : orig(m, u, o));
    const err = await seedDemo({ api: gw.api, operators: OPS, outDir: OUT, environment: 'production', fsImpl: fakeFs() }).catch((e) => e);
    expect(err).toBeInstanceOf(SeedError);
    expect(err.message).not.toMatch(/sk_secret|ok_operator/);
  });
});
