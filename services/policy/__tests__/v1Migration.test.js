'use strict';

/**
 * the extended engine keeps every v1 policy working, and the governed store accepts the new rule types.
 * VM-01 golden: the four original rule types decide, hash and trace exactly as the earlier engine did (golden produced by the tree at f89ef366)
 *   VM-02  the v1 document simulates unchanged and with the extended types added
 *   VM-03  governance: the store (and so draft/four-eyes) validates every evaluator type, not only the original four
 *   VM-04  the tenant floor: a floor policy of a new type cannot be altered per tenant
 */

const path = require('path');
const { execFileSync } = require('child_process');

jest.mock('../../logger', () => { const a = jest.requireActual('../../logger'); return { ...a, emit: jest.fn(), blocked: jest.fn() }; });

const REGISTRY = require('../evaluators');
const { validateAndPrepare } = require('../loader');
const { runSimulation } = require('../../../src/core/simulation/simulationEngine');
const store = require('../../../src/core/policy/store');
const { computePolicyHash } = require('../../policyHash');

const FIX = path.join(__dirname, 'fixtures');
const v1 = require('./fixtures/v1-policies.json');
const golden = require('./fixtures/v1-golden.json');

describe('v1 policies on the extended engine', () => {
  test('VM-01 golden: decisions, reasons, evaluation paths, rule hashes and the policy-set hash are identical to the earlier engine', () => {
    const out = JSON.parse(execFileSync(process.execPath, [path.join(__dirname, '..', '..', '..', 'scripts', 'policy', 'v1-golden-probe.js')], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }));
    expect(out.count).toBe(golden.count);
    expect(out.policyHash).toBe(golden.policyHash);
    expect(out.rules).toEqual(golden.rules);
    expect(out.decisions).toEqual(golden.decisions);
    const reasons = new Set(golden.decisions.map((d) => d.reason));
    for (const r of ['ALL_CHECKS_PASSED', 'IP_BLOCKED', 'OUTSIDE_TIME_WINDOW', 'RATE_LIMIT_EXCEEDED', 'CONSENT_MISSING']) expect(reasons.has(r)).toBe(true);
  });

  test('VM-02 the v1 document simulates, and adding extended rule types does not change what the v1 rules decide', async () => {
    const consent = { id: 'C', type: 'REQUIRE_CONSENT', priority: 1, enabled: true, config: { requireValidArtifact: true } };
    const base = v1.policies.filter((p) => p.type !== 'REQUIRE_CONSENT' && p.type !== 'RATE_LIMIT');
    const extra = [
      { id: 'X-ABAC', type: 'ABAC', priority: 40, enabled: true, config: { abacFormat: 1, effect: 'DENY', reason: 'X_DENY', when: { attr: 'tenant.id', op: 'eq', value: 'nobody' } } },
      { id: 'X-DLP', type: 'DLP', priority: 41, enabled: true, config: { dlpFormat: 1, direction: 'input', action: 'BLOCK', rules: ['EMAIL'] } },
      { id: 'X-CR', type: 'CONTENT_RULE', priority: 42, enabled: true, config: { contentFormat: 1, direction: 'input', action: 'BLOCK', items: [{ id: 'a', kind: 'word', value: 'zzz' }] } },
    ];
    const nc = (set) => set.filter((p) => p.type !== 'REQUIRE_CONSENT');     // simulation here tests rule logic; the real consent verifier needs the consent store
    const oldSet = nc(validateAndPrepare({ policies: [consent, ...base] }));
    const newSet = nc(validateAndPrepare({ policies: [consent, ...base, ...extra] }));
    expect(computePolicyHash(oldSet)).not.toBe(computePolicyHash(newSet));
    for (const ip of ['198.51.100.7', '192.0.2.50', '10.2.3.4']) for (const ts of [Date.UTC(2026, 9, 22, 9) / 1000, Date.UTC(2026, 9, 24, 23) / 1000]) {
      const ctx = { userId: 'alice', action: 'openai', tenantId: 'acme', ip, timestamp: ts };
      const a = await runSimulation({ context: ctx, policies: oldSet }, () => oldSet, null);
      const b = await runSimulation({ context: ctx, policies: newSet }, () => newSet, null);
      expect({ d: b.decision, r: b.reason }).toEqual({ d: a.decision, r: a.reason });
      expect(a.executionPrevented).toBe(true); expect(b.executionPrevented).toBe(true);
    }
  });

  test('VM-03 the governed store validates every rule type the engine can evaluate (four-eyes drafts go through this)', () => {
    const samples = {
      REQUIRE_CONSENT: { requireValidArtifact: true }, BLOCK_IP: { blocklist: ['203.0.113.77'], cidrs: [] },
      TIME_WINDOW: { allowedWindows: [{ days: ['MON'], start: '09:00', end: '17:00' }] }, RATE_LIMIT: { windowSeconds: 60, maxRequests: 10, keyBy: 'userId' },
      ABAC: { abacFormat: 1, effect: 'DENY', reason: 'X_DENY', when: { attr: 'tenant.id', op: 'eq', value: 'nobody' } },
      DLP: { dlpFormat: 1, direction: 'input', action: 'BLOCK', rules: ['EMAIL'] },
      BUDGET: { budgetFormat: 1, scope: 'tenant', period: 'day', limits: { requests: 100 } },
      CONTENT_RULE: { contentFormat: 1, direction: 'input', action: 'BLOCK', items: [{ id: 'a', kind: 'word', value: 'zzz' }] },
    };
    for (const type of Object.keys(REGISTRY)) {
      if (!samples[type]) continue;            // DATA_RESIDENCY / DATA_RETENTION have their own format tests; here the point is the list, not each config
      const r = store.validatePolicyCandidate({ id: `V-${type}`, type, priority: 500, enabled: true, config: samples[type] });
      expect({ type, errors: r.errors }).toEqual({ type, errors: [] });
    }
    expect(store.validatePolicyCandidate({ id: 'V-BAD', type: 'NOPE', priority: 5, enabled: true, config: {} }).valid).toBe(false);
    expect(store.validatePolicyCandidate({ id: 'V-ABAC', type: 'ABAC', priority: 5, enabled: true, config: { abacFormat: 1, effect: 'DENY', reason: 'lower', when: {} } }).valid).toBe(false);
  });

  test('VM-04 tenant floor: a floor policy of a new type must keep exactly its configuration', () => {
    jest.resetModules();
    const cfg = { dlpFormat: 1, direction: 'input', action: 'BLOCK', rules: ['EMAIL'] };
    jest.doMock('../../../src/core/policy/store', () => ({ listEnabledPolicies: () => [{ id: 'FLOOR-DLP', type: 'DLP', priority: 10, config: cfg }] }));
    const floor = require('../../../src/core/tenancy/tenantPolicyFloor');
    expect(floor.checkEntryAgainstFloor({ id: 'FLOOR-DLP', type: 'DLP', enabled: true, config: { ...cfg } })).toEqual({ ok: true });
    expect(floor.checkEntryAgainstFloor({ id: 'FLOOR-DLP', type: 'DLP', enabled: true, config: { ...cfg, action: 'DETECT' } }).ok).toBe(false);
    expect(floor.checkEntryAgainstFloor({ id: 'FLOOR-DLP', type: 'DLP', enabled: false, config: cfg }).ok).toBe(false);
    expect(floor.checkEntryAgainstFloor({ id: 'FLOOR-DLP', type: 'ABAC', enabled: true, config: cfg }).ok).toBe(false);
    jest.dontMock('../../../src/core/policy/store'); jest.resetModules();
  });
});
