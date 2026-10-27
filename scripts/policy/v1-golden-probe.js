'use strict';

/**
 * v1 policy golden probe.
 *
 *   node scripts/policy/v1-golden-probe.js [--root <tree>]
 *
 * Loads the frozen v1 policy document (the four original rule types: REQUIRE_CONSENT, BLOCK_IP, TIME_WINDOW, RATE_LIMIT) from services/policy/__tests__/fixtures/v1-policies.json
 * and runs it through the policy loader, the policy hash and the engine over a fixed matrix of contexts, with an in-memory rate-limit store and a deterministic consent stub.
 * It prints one JSON document: the policy-set hash, the per-rule hashes, and for every context the decision, reason, deciding rule and evaluation path.
 *
 * `--root` points at another checkout of the repository (for example the tree BEFORE the extended policy engine), so the same probe can produce the golden output from the
 * old engine and the test can compare the current engine against it byte for byte. The probe reads only the engine, loader and hash modules; it needs no services.
 */

const path = require('path');

const argRoot = process.argv.indexOf('--root');
const ROOT = argRoot > 0 ? path.resolve(process.argv[argRoot + 1]) : path.resolve(__dirname, '..', '..');
const FIXTURE = path.resolve(__dirname, '..', '..', 'services', 'policy', '__tests__', 'fixtures', 'v1-policies.json');

// Deterministic consent stub (the real verifier reads the consent store): users whose id ends in "-noconsent" have none.
const consentPath = require.resolve(path.join(ROOT, 'src', 'core', 'consent'));
require.cache[consentPath] = { id: consentPath, filename: consentPath, loaded: true, exports: {
  verify: async (ctx) => (String(ctx.userId || '').endsWith('-noconsent') ? { pass: false, reason: 'CONSENT_NOT_FOUND' } : { pass: true, reason: 'ACTIVE' }),
} };

const logger = require(path.join(ROOT, 'services', 'logger'));
for (const k of ['emit', 'blocked']) if (typeof logger[k] === 'function') logger[k] = () => {};

const { validateAndPrepare } = require(path.join(ROOT, 'services', 'policy', 'loader'));
const { evaluate } = require(path.join(ROOT, 'services', 'policy', 'engine'));
const { createStore } = require(path.join(ROOT, 'services', 'policy', 'store'));
const { computePolicyHash, computeRuleHash } = require(path.join(ROOT, 'services', 'policyHash'));

const doc = JSON.parse(require('fs').readFileSync(FIXTURE, 'utf8'));
const set = validateAndPrepare(doc);

const T0 = Date.UTC(2026, 9, 22, 0, 0) / 1000;                          // a Thursday
const contexts = [];
for (const userId of ['alice', 'bob-noconsent', 'carol']) {
  for (const ip of ['198.51.100.7', '10.1.2.3', '192.0.2.50', '203.0.113.9']) {
    for (const hour of [3, 9, 13, 22]) {
      for (const day of [0, 2]) contexts.push({ artifact: { valid: true }, userId, callerId: null, action: 'openai', tenantId: 'acme', requestId: 'r', ip, timestamp: T0 + day * 86400 + hour * 3600 });
    }
  }
}
contexts.push({ artifact: { valid: false }, userId: 'alice', callerId: null, action: 'openai', tenantId: 'acme', requestId: 'r', ip: '198.51.100.7', timestamp: T0 + 9 * 3600 });
contexts.push({ artifact: { valid: true }, userId: null, callerId: null, action: null, tenantId: null, requestId: 'r', ip: '198.51.100.7', timestamp: T0 + 9 * 3600 });

(async () => {
  const store = createStore();
  const decisions = [];
  for (const c of contexts) {
    const d = await evaluate(c, set, store, { requestId: 'r' });
    decisions.push({ u: c.userId, ip: c.ip, ts: c.timestamp, valid: c.artifact.valid, decision: d.decision, reason: d.reason, policyId: d.policyId, policyVersion: d.policyVersion, policyRuleHash: d.policyRuleHash, consent: d.consentProvenance,
      path: d.evaluationPath.map((e) => [e.policyId, e.type, e.result, e.reason, e.ruleHash]) });
  }
  process.stdout.write(JSON.stringify({ probe: 'v1-golden', policyHash: computePolicyHash(set), rules: set.map((p) => [p.id, p.type, computeRuleHash(p)]), count: decisions.length, decisions }, null, 1));
})().catch((e) => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });
