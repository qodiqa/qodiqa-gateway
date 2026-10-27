'use strict';

/**
 * /sign must bind the artifact's policyHash to the SAME policy set the execution path
 * evaluates for that tenant: the tenant-effective set (tenant set + floor, via
 * tenantPolicyRegistry.getEffectivePoliciesForTenant), falling back to the global set only when the tenant has no
 * stored set (GLOBAL_FALLBACK — exactly aiChat.js's and verify.js's rule). Before the fix /sign always hashed the
 * GLOBAL set, so for every tenant with tenant policies the execution path (which hashes the tenant-effective set,
 * services/policy/evaluatePolicyDecision.js) saw a different hash and emitted POLICY_DRIFT_DETECTED on every request.
 *
 * The signing tenant is the authenticated identity's tenantId, which is also the artifact key id's clientId — the
 * very value aiChat.js resolves as the execution tenant (validateBoundRequest → details.clientId).
 */

const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');

const TENANT = 'default';
const { apiKey: SIGN_TOKEN } = provisionTestSigningIdentity({ tenantId: TENANT });

afterEach(() => {
  jest.dontMock('../../../../services/providers');
  jest.dontMock('../../../../services/providers/config');
  jest.resetModules();
});

function load() {
  jest.resetModules();
  process.env.QODIQA_CLIENT_ID = TENANT;
  jest.doMock('../../../../services/providers', () => ({
    resolveProvider: jest.fn(() => true),
    listEnabledProviders: jest.fn(() => ['local']),
    listProviders: jest.fn(() => ['local']),
  }));
  jest.doMock('../../../../services/providers/config', () => ({
    getProviderConfig: jest.fn(() => ({ enabled: true })),
    getEnabledProviders: jest.fn(() => []),
  }));

  const express = require('express');
  const request = require('supertest');
  const createSignRouter = require('../sign');
  const { validateAndPrepare } = require('../../../../services/policy/loader');
  const { computePolicyHash } = require('../../../../services/policyHash');
  const tenantPolicyRegistry = require('../../../core/tenancy/tenantPolicyRegistry');
  tenantPolicyRegistry._reset();

  const globalPolicies = validateAndPrepare({ policies: [{
    id: 'POL-GLOBAL', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
    config: { requireValidArtifact: true },
  }] });

  const app = express();
  app.use(express.json());
  app.use('/sign', createSignRouter(() => globalPolicies));
  return { app, request, computePolicyHash, tenantPolicyRegistry, globalPolicies };
}

async function sign(ctx) {
  const res = await ctx.request(ctx.app)
    .post('/sign')
    .set('Content-Type', 'application/json')
    .set('Authorization', `Bearer ${SIGN_TOKEN}`)
    .send({ request: { method: 'POST', path: '/ai/chat', body: { prompt: 'hi' } } });
  expect(res.status).toBe(200);
  return res.body.artifact.payload.policyHash;
}

describe('/sign policyHash = hash of the tenant-effective set the execution path evaluates', () => {
  test('SPH-01 tenant WITH tenant policies → artifact policyHash equals the execution-side (tenant-effective) hash, not the global one', async () => {
    const ctx = load();
    ctx.tenantPolicyRegistry.setPolicies(TENANT, [
      { id: 'TENANT-BLOCK', type: 'BLOCK_IP', priority: 5, enabled: true, config: { blocklist: ['10.9.9.9'], cidrs: [] } },
    ]);
    // What aiChat.js / verify.js evaluate (and evaluatePolicyDecision.js hashes) for this tenant:
    const executionHash = ctx.computePolicyHash(ctx.tenantPolicyRegistry.getEffectivePoliciesForTenant(TENANT));
    const globalHash    = ctx.computePolicyHash(ctx.globalPolicies);
    expect(executionHash).not.toBe(globalHash);

    const signed = await sign(ctx);
    expect(signed).toBe(executionHash); // no POLICY_DRIFT_DETECTED at execution
    expect(signed).not.toBe(globalHash);
    ctx.tenantPolicyRegistry._reset();
  });

  test('SPH-02 control: tenant with NO stored set → GLOBAL_FALLBACK, artifact policyHash is the global hash (unchanged)', async () => {
    const ctx = load();
    const signed = await sign(ctx);
    expect(signed).toBe(ctx.computePolicyHash(ctx.globalPolicies));
  });

  test('SPH-03 another tenant\'s policies never affect this tenant\'s artifact hash', async () => {
    const ctx = load();
    ctx.tenantPolicyRegistry.setPolicies('some-other-tenant', [
      { id: 'OTHER', type: 'BLOCK_IP', priority: 5, enabled: true, config: { blocklist: ['10.1.1.1'], cidrs: [] } },
    ]);
    const signed = await sign(ctx);
    expect(signed).toBe(ctx.computePolicyHash(ctx.globalPolicies));
    ctx.tenantPolicyRegistry._reset();
  });
});
