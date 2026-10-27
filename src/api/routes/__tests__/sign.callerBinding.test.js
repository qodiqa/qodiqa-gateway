'use strict';

/**
 * POST /sign — caller-identity binding.
 *
 * Root cause: TRUST-1 authenticated WHO may call /sign (req.signingIdentity)
 * but that identity was discarded after the authz check — every artifact
 * /sign minted carried only the shared tenant signing key (publicKeyId),
 * making two different signing identities under the same tenant
 * cryptographically indistinguishable at the artifact layer.
 *
 * Fix: /sign now embeds an immutable callerContext snapshot of the
 * authenticated identity directly into payload, so the existing Ed25519
 * envelope signature protects it "for free" — see src/api/routes/sign.js.
 *
 * This suite proves:
 *   1. callerContext is embedded and matches the authenticated identity.
 *   2. Two different identities under the SAME tenant produce artifacts
 *      with distinct, correctly-attributed callerContext (the actual
 * cryptographic distinguishability requires).
 *   3. A client cannot spoof callerContext via payload — the authenticated
 *      value always wins (anti-spoofing).
 */

const request = require('supertest');
const express  = require('express');

const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');

function loadApp() {
  jest.resetModules();
  process.env.QODIQA_CLIENT_ID = 'default';

  const createSignRouter       = require('../sign');
  const { validateAndPrepare } = require('../../../../services/policy/loader');

  const policies = validateAndPrepare({ policies: [{
    id: 'POL-TEST', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
    config: { requireValidArtifact: true },
  }] });

  const app = express();
  app.use(express.json());
  app.use('/sign', createSignRouter(() => policies));
  return app;
}

function post(app, token, body) {
  return request(app)
    .post('/sign')
    .set('Content-Type', 'application/json')
    .set('Authorization', `Bearer ${token}`)
    .send(body);
}

function nonAiChatBody(payload) {
  return {
    request: { method: 'POST', path: '/orders/create', body: { sku: 'SKU-1' } },
    ...(payload !== undefined ? { payload } : {}),
  };
}

describe('POST /sign — caller-identity binding', () => {
  test('SIGN-CALLER-01 embeds callerContext matching the authenticated signing identity', async () => {
    const app = loadApp();
    const { apiKey, identityId } = provisionTestSigningIdentity({ tenantId: 'default' });

    const res = await post(app, apiKey, nonAiChatBody());

    expect(res.status).toBe(200);
    const { callerContext } = res.body.artifact.payload;
    expect(callerContext).toBeDefined();
    expect(callerContext.callerId).toBe(identityId);
    expect(typeof callerContext.callerName).toBe('string');
    expect(callerContext.environment).toBe('test');
    expect(callerContext.credentialType).toBe('api-key');
    // Also echoed in the response meta for convenience.
    expect(res.body.meta.callerId).toBe(identityId);
  });

  test('SIGN-CALLER-02 two identities sharing the same tenant produce artifacts with distinct callerContext.callerId', async () => {
    const app = loadApp();
    const a = provisionTestSigningIdentity({ tenantId: 'default' });
    const b = provisionTestSigningIdentity({ tenantId: 'default' });
    expect(a.identityId).not.toBe(b.identityId);

    const resA = await post(app, a.apiKey, nonAiChatBody());
    const resB = await post(app, b.apiKey, nonAiChatBody());

    expect(resA.status).toBe(200);
    expect(resB.status).toBe(200);
    expect(resA.body.artifact.payload.callerContext.callerId).toBe(a.identityId);
    expect(resB.body.artifact.payload.callerContext.callerId).toBe(b.identityId);
    expect(resA.body.artifact.payload.callerContext.callerId)
      .not.toBe(resB.body.artifact.payload.callerContext.callerId);
    // Same tenant signing key for both — this is exactly the scenario
    // describes as "indistinguishable at the cryptographic layer"
    // prior to this remediation.
    expect(resA.body.meta.keyId).toBe(resB.body.meta.keyId);
  });

  test('SIGN-CALLER-03 anti-spoofing: a client-supplied payload.callerContext is silently overridden by the authenticated identity', async () => {
    const app = loadApp();
    const { apiKey, identityId } = provisionTestSigningIdentity({ tenantId: 'default' });

    const res = await post(app, apiKey, nonAiChatBody({
      callerContext: {
        callerId: 'attacker-controlled-id',
        callerName: 'not-the-real-caller',
        environment: 'production',
        credentialType: 'forged',
      },
    }));

    expect(res.status).toBe(200);
    const { callerContext } = res.body.artifact.payload;
    expect(callerContext.callerId).toBe(identityId);
    expect(callerContext.callerId).not.toBe('attacker-controlled-id');
    expect(callerContext.environment).toBe('test');
    expect(callerContext.credentialType).toBe('api-key');
  });

  test('SIGN-CALLER-04 multi-tenant isolation: identities in different tenants each get correctly attributed callerContext and tenantId, with no cross-contamination', async () => {
    const app = loadApp();
    // rotate() provisions a fresh signing key for a client id that has none
    // yet ('s `km.rotate('km-test')`
    // usage) — 'default' is pre-provisioned by test/support/jest.setup.js, these are not.
    const keyManager = require('../../../../services/artifact/keyManager');
    keyManager.rotate('tenant-alpha');
    keyManager.rotate('tenant-beta');
    const a = provisionTestSigningIdentity({ tenantId: 'tenant-alpha' });
    const b = provisionTestSigningIdentity({ tenantId: 'tenant-beta' });

    const resA = await post(app, a.apiKey, nonAiChatBody());
    const resB = await post(app, b.apiKey, nonAiChatBody());

    expect(resA.status).toBe(200);
    expect(resB.status).toBe(200);
    expect(resA.body.artifact.payload.tenantId).toBe('tenant-alpha');
    expect(resB.body.artifact.payload.tenantId).toBe('tenant-beta');
    expect(resA.body.artifact.payload.callerContext.callerId).toBe(a.identityId);
    expect(resB.body.artifact.payload.callerContext.callerId).toBe(b.identityId);
    // Different tenants also sign under different keys — key AND caller
    // attribution must both be tenant-scoped correctly, never swapped.
    expect(resA.body.meta.keyId).not.toBe(resB.body.meta.keyId);
    expect(resA.body.meta.keyId.startsWith('tenant-alpha:')).toBe(true);
    expect(resB.body.meta.keyId.startsWith('tenant-beta:')).toBe(true);
  });

  test('SIGN-CALLER-05 signer rotation: callerContext is identity-derived, not key-derived — it is unchanged across a signing-key rotation for the same identity', async () => {
    const app = loadApp();
    const { apiKey, identityId } = provisionTestSigningIdentity({ tenantId: 'default' });
    const keyManager = require('../../../../services/artifact/keyManager');

    const before = await post(app, apiKey, nonAiChatBody());
    expect(before.status).toBe(200);
    const keyIdBefore = before.body.meta.keyId;

    keyManager.rotate('default', { mode: 'emergency' });

    const after = await post(app, apiKey, nonAiChatBody());
    expect(after.status).toBe(200);
    const keyIdAfter = after.body.meta.keyId;

    // The signing key changed (rotation happened)...
    expect(keyIdAfter).not.toBe(keyIdBefore);
    // ...but the SAME authenticated identity still produces the SAME
    // callerId on both sides of the rotation — caller attribution survives
    // key rotation because it is bound to the credential, not the key.
    expect(before.body.artifact.payload.callerContext.callerId).toBe(identityId);
    expect(after.body.artifact.payload.callerContext.callerId).toBe(identityId);
  });
});

// ── opt-in strict payload (QODIQA_SIGN_PAYLOAD_STRICT) ───────────────────────────────────
describe('POST /sign — caller payload hardening (audit 3.12)', () => {
  const OLD = process.env.QODIQA_SIGN_PAYLOAD_STRICT;
  afterEach(() => { if (OLD === undefined) delete process.env.QODIQA_SIGN_PAYLOAD_STRICT; else process.env.QODIQA_SIGN_PAYLOAD_STRICT = OLD; });

  test('SIGN-PAYLOAD-01 default: free-form application context is still signed (documented API)', async () => {
    const app = loadApp();
    const { apiKey } = provisionTestSigningIdentity({ tenantId: 'default' });
    const res = await post(app, apiKey, nonAiChatBody({ userId: 'u-1' }));
    expect(res.status).toBe(200);
    expect(res.body.artifact.payload.userId).toBe('u-1');
  });

  test('SIGN-PAYLOAD-02 QODIQA_SIGN_PAYLOAD_STRICT=true: any caller key other than provider is refused (400), nothing is signed', async () => {
    process.env.QODIQA_SIGN_PAYLOAD_STRICT = 'true';
    const app = loadApp();
    const { apiKey } = provisionTestSigningIdentity({ tenantId: 'default' });
    const res = await post(app, apiKey, nonAiChatBody({ userId: 'u-1' }));
    expect(res.status).toBe(400);
    expect(res.body.decision).toBe('BLOCK');
    expect(res.body.artifact).toBeUndefined();
  });

  test('SIGN-PAYLOAD-03 an oversized payload is refused at the schema', async () => {
    const app = loadApp();
    const { apiKey } = provisionTestSigningIdentity({ tenantId: 'default' });
    const res = await post(app, apiKey, nonAiChatBody({ blob: 'a'.repeat(9000) }));
    expect(res.status).toBe(400);
  });
});
