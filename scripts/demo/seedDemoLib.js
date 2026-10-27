'use strict';

/**
 * Deterministic public-demo seed (launch plan R-03). Library half; CLI: scripts/demo/seed-demo.js.
 *
 * Provisions, through the gateway's OWN admin HTTP API (never a direct database or store write, so every RBAC,
 * MFA step-up, audit and maker-checker control still applies), exactly:
 *
 *   tenant `demo`        identity `demo-allowed`  consent ACTIVE  for action <provider>   -> EXECUTE
 *                        identity `demo-revoked`  consent REVOKED for action <provider>   -> BLOCK CONSENT_REVOKED
 *   tenant `demo-denied` identity `demo-denied`   consent ACTIVE  for action <provider>
 *                        + governed tenant policy DEMO-DENY-ALL (BLOCK_IP 0.0.0.0/0 + ::/0) -> BLOCK IP_BLOCKED
 *
 * Consent is keyed to the signing identity (callerContext.callerId = identity id) and the provider name
 * (services/policy/evaluators/requireConsent.js), which is why each scenario needs its own identity, and why the
 * policy scenario needs its own tenant (tenant policy sets replace the global set for that tenant only).
 *
 * Idempotent: every step reads current state first and changes only what is missing. Re-running is a no-op.
 * It never deletes anything and never re-issues a key whose key file already exists.
 *
 * Secrets: issued sk_ keys are written to <outDir>/<identity>.key with mode 0600 using the exclusive-create flag
 * (an existing file is never overwritten) and are never written to stdout/stderr. Only identity ids are reported.
 *
 * Scope guard: the tenant ids, identity names and policy id are constants. The library refuses to act on anything
 * else, so a mistaken invocation cannot alter a real tenant's policy set.
 */

const path = require('path');

const DEMO_TENANT = 'demo';
const DENIED_TENANT = 'demo-denied';
const DENY_POLICY_ID = 'DEMO-DENY-ALL';
const IDENTITIES = Object.freeze([
  Object.freeze({ name: 'demo-allowed', tenantId: DEMO_TENANT, consent: 'ACTIVE', scenario: 'allowed' }),
  Object.freeze({ name: 'demo-revoked', tenantId: DEMO_TENANT, consent: 'REVOKED', scenario: 'consent_revoked' }),
  Object.freeze({ name: 'demo-denied', tenantId: DENIED_TENANT, consent: 'ACTIVE', scenario: 'policy_denied' }),
]);
const DENY_POLICY = Object.freeze({
  type: 'BLOCK_IP',
  priority: 5,
  config: Object.freeze({ blocklist: [], cidrs: ['0.0.0.0/0', '::/0'] }),
});
const SK_RE = /^sk_[A-Za-z0-9_-]{16,256}$/;

class SeedError extends Error {
  constructor(step, detail) {
    super(`DEMO_SEED_FAILED at ${step}: ${detail}`);
    this.name = 'SeedError';
    this.step = step;
  }
}

function _redact(text) {
  return String(text || '').replace(/(sk|ok)_[A-Za-z0-9_-]+/g, '$1_[REDACTED]').slice(0, 300);
}

// ── Operator MFA step-up (src/middleware/mfaStepUp.js): every MUTATING admin call needs X-QODIQA-OTP. ──────────────
// A code is a single-use recovery code or a TOTP (RFC 6238: SHA-1, 30 s, 6 digits, the server accepts ±1 step and
// never the same or an earlier step twice per operator — src/core/rbac/mfa.js). The provider spends recovery codes
// first, then TOTP steps in strictly increasing order, waiting for the next step only when the ±1 window is used up.
function _base32Decode(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0; let v = 0; const out = [];
  for (const ch of String(s).toUpperCase().replace(/=+$/, '').replace(/\s+/g, '')) {
    const i = A.indexOf(ch);
    if (i < 0) throw new SeedError('otp', 'TOTP secret is not base32');
    v = (v << 5) | i; bits += 5;
    if (bits >= 8) { out.push((v >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
function _hotp(secret, step) {
  const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(step));
  const h = require('crypto').createHmac('sha1', _base32Decode(secret)).update(buf).digest();
  const o = h[h.length - 1] & 0x0f;
  return String((((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1e6).padStart(6, '0');
}
function createOtpProvider({ totpSecret = null, recoveryCodes = [], afterStep = null, now = Date.now, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  const codes = [...recoveryCodes];
  let lastStep = afterStep; // a step already spent elsewhere (e.g. the enrolment confirm) is never reused
  return {
    get lastStep() { return lastStep; },
    async getCode() {
      if (codes.length > 0) return codes.shift();
      if (!totpSecret) throw new SeedError('otp', 'MFA step-up needed but no recovery code or TOTP secret is left for this operator');
      for (;;) {
        const cur = Math.floor(now() / 30000);
        const next = lastStep === null ? cur - 1 : Math.max(lastStep + 1, cur - 1);
        if (next <= cur + 1) { lastStep = next; return _hotp(totpSecret, next); }
        await sleep((cur + 1) * 30000 - now() + 50);
      }
    },
  };
}

function createApi({ gatewayUrl, fetchImpl = globalThis.fetch }) {
  async function call(method, urlPath, { key, body, otp } = {}) {
    const res = await fetchImpl(new URL(urlPath, gatewayUrl).toString(), {
      method,
      headers: { authorization: `Bearer ${key}`, ...(otp ? { 'x-qodiqa-otp': otp } : {}), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    let json = null;
    let text = '';
    try { text = await res.text(); json = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
    return { status: res.status, json, text };
  }
  return { call };
}

/**
 * @param {object} opts
 * @param {{ call: Function }} opts.api
 * @param {{ maker: string, reviewer: string, approver: string }} opts.operators  ok_ operator keys (3 distinct)
 * @param {string} opts.outDir
 * @param {string} opts.environment  signing-identity environment
 * @param {string} [opts.provider]   consent action / allowed provider (default 'local')
 * @param {boolean} [opts.dryRun]
 * @param {object} [opts.fsImpl]
 * @param {(line: object) => void} [opts.report]
 */
async function seedDemo({ api, operators, otp = null, outDir, environment, provider = 'local', lawfulBasis = 'consent',
  purpose = 'Public QODIQA demonstration: execution-control scenario identity (no personal data)', dryRun = false, fsImpl = require('fs'), report = () => {} }) {
  const { maker, reviewer, approver } = operators || {};
  const keyOf = { maker, reviewer, approver };
  // Mutating admin calls carry the operator's MFA step-up code when an OTP provider is configured (production).
  const mcall = async (role, method, url, opts = {}) => {
    const code = otp && otp[role] ? await otp[role].getCode() : undefined;
    return api.call(method, url, { ...opts, key: keyOf[role], otp: code });
  };
  if (!maker || !reviewer || !approver) throw new SeedError('args', 'three operator keys are required (maker, reviewer, approver)');
  if (new Set([maker, reviewer, approver]).size !== 3) throw new SeedError('args', 'maker, reviewer and approver must be three distinct operators');
  if (!/^[a-z][a-z0-9_-]{0,31}$/.test(provider)) throw new SeedError('args', 'invalid provider name');
  const actions = [];
  const step = (s) => { actions.push(s); report({ step: s, dryRun }); };
  const must = (res, expected, label) => {
    if (!expected.includes(res.status)) throw new SeedError(label, `HTTP ${res.status}: ${_redact(res.text)}`);
    return res;
  };

  // ── 1. Identities + key files ───────────────────────────────────────────────
  const list = must(await api.call('GET', '/signing-identities', { key: maker }), [200], 'list-identities');
  const existing = new Map(((list.json && list.json.data && list.json.data.identities) || []).map((i) => [i.name, i]));
  const ids = {};
  for (const spec of IDENTITIES) {
    let identity = existing.get(spec.name);
    if (identity && identity.tenantId !== spec.tenantId) {
      throw new SeedError('identity', `existing identity ${spec.name} belongs to tenant ${identity.tenantId}, expected ${spec.tenantId}; refusing to reuse it`);
    }
    if (!identity) {
      step(`create identity ${spec.name} (tenant ${spec.tenantId})`);
      if (!dryRun) {
        const res = must(await mcall('maker', 'POST', '/signing-identities', { body: {
          name: spec.name, tenantId: spec.tenantId, environment, permissions: ['SIGN_ARTIFACT'], allowedProviders: [provider],
        } }), [201], `create-identity-${spec.name}`);
        identity = res.json.data.identity;
      } else {
        identity = { id: `<new:${spec.name}>`, name: spec.name, tenantId: spec.tenantId };
      }
    }
    ids[spec.name] = identity.id;

    const keyFile = path.join(outDir, `${spec.name}.key`);
    if (fsImpl.existsSync(keyFile)) {
      const content = String(fsImpl.readFileSync(keyFile, 'utf8')).trim();
      if (!SK_RE.test(content)) throw new SeedError('key-file', `${keyFile} exists but does not hold a single sk_ key; refusing to overwrite it`);
    } else {
      step(`issue key for ${spec.name} -> ${keyFile} (0600)`);
      if (!dryRun) {
        const res = must(await mcall('maker', 'POST', `/signing-identities/${encodeURIComponent(identity.id)}/api-key`), [201], `issue-key-${spec.name}`);
        const apiKey = res.json && res.json.data && res.json.data.apiKey;
        if (!SK_RE.test(String(apiKey || ''))) throw new SeedError(`issue-key-${spec.name}`, 'response carried no sk_ key');
        fsImpl.mkdirSync(outDir, { recursive: true, mode: 0o700 });
        fsImpl.writeFileSync(keyFile, `${apiKey}\n`, { mode: 0o600, flag: 'wx' });
      }
    }
  }

  // ── 2. Tenant artifact-signing keys (ONB-1: a tenant has none until one is rotated in) ──
  for (const tenantId of [DEMO_TENANT, DENIED_TENANT]) {
    const st = await api.call('GET', `/key-admin/${tenantId}/status`, { key: maker });
    if (st.status === 200) continue;
    must(st, [404], `key-status-${tenantId}`);
    step(`rotate in first artifact key for tenant ${tenantId}`);
    if (!dryRun) must(await mcall('maker', 'POST', `/key-admin/${tenantId}/rotate`, { body: {} }), [200], `key-rotate-${tenantId}`);
  }

  // ── 3. Consent states ───────────────────────────────────────────────────────
  for (const spec of IDENTITIES) {
    const actorId = ids[spec.name];
    const q = new URLSearchParams({ actorId, action: provider, tenantId: spec.tenantId }).toString();
    const listed = dryRun && actorId.startsWith('<new:') ? { json: { data: { records: [] } } }
      : must(await api.call('GET', `/consent?${q}`, { key: maker }), [200], `list-consent-${spec.name}`);
    const records = (listed.json && listed.json.data && listed.json.data.records) || [];
    const active = records.filter((r) => r.state === 'ACTIVE');
    const revoked = records.filter((r) => r.state === 'REVOKED');
    const grant = async () => {
      step(`grant consent ${spec.name} -> ${provider}`);
      if (dryRun) return { id: '<new-consent>' };
      const res = must(await mcall('maker', 'POST', '/consent', { body: {
        actor_id: actorId, action: provider, scope: 'standard', required_scope: 'standard', tenant_id: spec.tenantId,
        subject_name: `Public demo identity ${spec.name}`, action_display: `Public demo (${provider})`, duration_days: 365,
        lawfulBasis, purpose,
      } }), [201], `grant-consent-${spec.name}`);
      return (res.json && res.json.data && (res.json.data.record || res.json.data.consent || res.json.data)) || {};
    };
    if (spec.consent === 'ACTIVE') {
      if (active.length === 0) await grant();
    } else {
      // REVOKED scenario: no ACTIVE record may remain, and at least one REVOKED record must exist.
      let toRevoke = active;
      if (active.length === 0 && revoked.length === 0) toRevoke = [await grant()];
      for (const rec of toRevoke) {
        step(`revoke consent ${spec.name} (${rec.id})`);
        if (!dryRun) must(await mcall('maker', 'POST', `/consent/${encodeURIComponent(rec.id)}/revoke`, { body: { tenantId: spec.tenantId, revocationReason: 'Public demo: consent-revoked scenario' } }), [200], `revoke-consent-${spec.name}`);
      }
    }
  }

  // ── 4. Governed deny-all policy set for tenant demo-denied (maker != reviewer != approver) ──
  const cfg = await api.call('GET', `/v1/admin/tenants/${DENIED_TENANT}/policy-config`, { key: maker });
  if (cfg.status !== 200 && cfg.status !== 404) must(cfg, [200, 404], 'policy-config');
  const policies = (cfg.status === 200 && cfg.json && cfg.json.data && cfg.json.data.policySet && cfg.json.data.policySet.policies) || [];
  if (!policies.some((p) => p && (p.id === DENY_POLICY_ID || p.policyId === DENY_POLICY_ID))) {
    step(`governed publish ${DENY_POLICY_ID} for tenant ${DENIED_TENANT}`);
    if (!dryRun) {
      const draft = must(await mcall('maker', 'POST', '/v1/policy/governance/draft', { body: {
        policyId: DENY_POLICY_ID, tenantId: DENIED_TENANT, requestType: 'CREATE',
        payload: { type: DENY_POLICY.type, priority: DENY_POLICY.priority, config: { blocklist: [], cidrs: [...DENY_POLICY.config.cidrs] } },
        changeReason: 'Public demo: deterministic policy-denied scenario (deny every client IP, IPv4 and IPv6)',
      } }), [201], 'governance-draft');
      const requestId = draft.json && draft.json.data && draft.json.data.id;
      if (!requestId) throw new SeedError('governance-draft', 'no change-request id returned');
      for (const [s, role, body] of [
        ['submit', 'maker', {}],
        ['review', 'reviewer', { decision: 'APPROVED', notes: 'Public demo deny-all policy' }],
        ['approve', 'approver', { notes: 'Public demo deny-all policy' }],
        ['publish', 'approver', {}],
      ]) {
        must(await mcall(role, 'POST', `/v1/policy/governance/${encodeURIComponent(requestId)}/${s}`, { body }), [200], `governance-${s}`);
      }
    }
  }

  return { identities: ids, actions, keyFiles: IDENTITIES.map((s) => path.join(outDir, `${s.name}.key`)) };
}

module.exports = { seedDemo, createApi, createOtpProvider, _hotp, SeedError, IDENTITIES, DEMO_TENANT, DENIED_TENANT, DENY_POLICY_ID, DENY_POLICY };
