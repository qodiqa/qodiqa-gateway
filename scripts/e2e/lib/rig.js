'use strict';
// the measurement rig's store preparation.
//
// The audit rig (QODIQA-INDEPENDENT-AUDIT-2026-09-28 §5, "policy rate limits and anomaly quotas raised so
// they don't throttle") did this by hand and never scripted it; makes it explicit and reproducible.
// Every enforcement stage stays ACTIVE — the rate-limit policies stay enabled and the anomaly check still
// runs on every request — only the ceilings are lifted so a measurement run of n requests is not itself
// rejected by the throttles it passes through:
//   • org quotas: an isolated organization store whose one org owns the dev tenant, with
//     maxRequestsPerKeyPerMin / maxRequestsPerMinute raised (default 100/min per key trips at n>100)
//   • policies: an isolated copy of the repository policies.json with every RATE_LIMIT rule's maxRequests
//     raised, and the BLOCK_IP policy's blocklist gains the harness-only address POLICY_BLOCK_SOURCE
// The files go to a caller-given directory OUTSIDE the repository (the boot reads them; they are not
// evidence). The repository's policies.json and data/ are only read, never written.
const fs = require('fs');
const path = require('path');

const REPO = path.join(__dirname, '..', '..', '..');
const RAISED = 1_000_000;
const POLICY_BLOCK_SOURCE = '127.0.0.2';

function prepareRigStores(dir, { tenantId = 'dev-local' } = {}) {
  fs.mkdirSync(dir, { recursive: true });
  const now = new Date().toISOString();
  const orgPath = path.join(dir, 'rig-organizations.json');
  fs.writeFileSync(orgPath, JSON.stringify({ version: 1, organizations: [{
    organizationId: 'w8-bench-org', organizationName: 'bench rig', status: 'active', createdAt: now, updatedAt: now,
    metadata: { purpose: 'measurement rig — quotas raised so the harness is not throttled' },
    quotas: { maxRequestsPerMinute: RAISED, maxRequestsPerKeyPerMin: RAISED, maxStreamingSessions: 500, retentionDays: 365 },
    tenantIds: [tenantId],
  }] }, null, 1));

  const pol = JSON.parse(fs.readFileSync(path.join(REPO, 'policies.json'), 'utf8'));
  const raised = [];
  for (const p of pol.policies) {
    if (p.type === 'RATE_LIMIT' && p.config && typeof p.config.maxRequests === 'number') {
      raised.push({ id: p.id, enabled: p.enabled, from: p.config.maxRequests, to: RAISED, windowSeconds: p.config.windowSeconds });
      p.config.maxRequests = RAISED;
    }
  }
  // Policy-class BLOCK recipe: the existing, enabled BLOCK_IP policy gets one harness-only source address.
  // Only the policy scenario's requests leave from it (http localAddress); every other request comes from
  // 127.0.0.1 and evaluates the same policy set to a pass, exactly as before.
  const blockIp = pol.policies.find((p) => p.type === 'BLOCK_IP' && p.enabled);
  if (!blockIp) throw new Error('rig: repository policies.json has no enabled BLOCK_IP policy to carry the policy-class recipe');
  blockIp.config.blocklist = [...(blockIp.config.blocklist || []), POLICY_BLOCK_SOURCE];
  const policyPath = path.join(dir, 'rig-policies.json');
  fs.writeFileSync(policyPath, JSON.stringify(pol, null, 1));
  // request limiter: stays ON (S11r/S21r execute on every request, backed by Redis); only the ceilings
  // of the surfaces the harness drives are raised, through the limiter's own per-surface env overrides
  // (src/core/rateLimit/config.js). This replaces the runner's RL_ENABLED=false deviation.
  const rlEnv = {};
  for (const k of ['RL_SIGN_MAX', 'RL_SIGN_BURST', 'RL_SIGN_AUTH_MAX', 'RL_SIGN_AUTH_BURST',
    'RL_AI_CHAT_IP_MAX', 'RL_AI_CHAT_IP_BURST', 'RL_AI_CHAT_IDENTITY_MAX']) rlEnv[k] = String(RAISED);
  return {
    env: { ORG_STORE_PATH: orgPath, POLICY_FILE: policyPath, ...rlEnv },
    record: { orgQuotas: { tenantId, maxRequestsPerKeyPerMin: RAISED, maxRequestsPerMinute: RAISED, default: '100/min per key, 5,000/min per tenant' },
      rateLimitPolicies: raised, policyBlockSource: { policy: blockIp.id, address: POLICY_BLOCK_SOURCE }, requestLimiter: { enabled: true, raised: Object.keys(rlEnv), to: RAISED }, everyStageActive: true },
  };
}

module.exports = { prepareRigStores, RAISED, POLICY_BLOCK_SOURCE };
