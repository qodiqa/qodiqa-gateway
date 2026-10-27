'use strict';

/**
 * CRYPTO-6 remediation — legacy (colon-less) key IDs must still be
 * tenant-scoped in the nonce namespace.
 *
 * Previously validateBoundRequest.js derived tenantId by re-parsing the raw
 * publicKeyId string via parseKeyId(), which throws (→ tenantId=null) for
 * any legacy key ID — even though services/artifact/keyStore.js's own
 * _legacyMap already knows the real owning clientId for that exact key. This
 * suite constructs a real legacy-mapped key fixture and proves the nonce
 * ends up in that key's real tenant namespace, not the global one.
 */

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');

const TEST_KEK = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

function makeTempPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-legacy-key-'));
  return path.join(dir, 'keys.json');
}

// Writes a keys.json fixture where a bare, colon-less legacy ID
// ("legacy-client") maps via _legacyMap to a real, modern-format record
// ("legacy-client:key_v1") — reproducing exactly the on-disk shape a
// pre-migration deployment's key store would have.
function writeLegacyMappedFile(keysPath, legacyId, clientId) {
  const { privateKey: priv, publicKey: pub } = crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
  });
  const resolvedKeyId = `${clientId}:key_v1`;
  const file = {
    version: 1,
    clients: {
      [clientId]: {
        [resolvedKeyId]: {
          clientId,
          keyId:         resolvedKeyId,
          version:       1,
          algorithm:     'ed25519',
          privateKeyDer: Buffer.from(priv).toString('base64'),
          publicKeyDer:  Buffer.from(pub).toString('base64'),
          status:        'active',
          createdAt:     new Date().toISOString(),
        },
      },
    },
    legacyMap: { [legacyId]: resolvedKeyId },
  };
  fs.mkdirSync(path.dirname(keysPath), { recursive: true });
  fs.writeFileSync(keysPath, JSON.stringify(file, null, 2), 'utf8');
  return { privDer: Buffer.from(priv), pubDer: Buffer.from(pub), resolvedKeyId };
}

function loadFreshModules(keysPath) {
  jest.resetModules();
  process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
  process.env.QODIQA_KEYS_PATH = keysPath;
  require('../../../services/secrets/secretsProvider')._clearCache();
  const keyStore = require('../../../services/artifact/keyStore');
  const { validateBoundRequest } = require('../validateBoundRequest');
  const { signBoundArtifact }    = require('../signBoundArtifact');
  const { makeNonceStore, makeOpenAnomalyStore } = require('../../testing/stores');
  const { buildNonceKey } = require('../nonceStore');
  // CRYPTO-6 fix side effect (correct, not incidental): since tenantId now
  // resolves correctly for legacy keys too, Step 1b/1c of
  // validateBoundRequest also runs the tenant/org active-status gate for
  // them — previously skipped entirely because tenantId always came back
  // null. A real deployment's legacy-mapped clientId would already be a
  // registered tenant (registration is a separate onboarding flow, not tied
  // to key format), so tests must register it too to reflect that.
  const { registerTenant } = require('../../core/tenancy/tenantRegistry');
  return { keyStore, validateBoundRequest, signBoundArtifact, makeNonceStore, makeOpenAnomalyStore, buildNonceKey, registerTenant };
}

describe('CRYPTO-6 — legacy colon-less key IDs are tenant-scoped', () => {
  test('getPublicKey() resolves the real clientId for a legacy bare-id lookup', () => {
    const keysPath = makeTempPath();
    const { keyStore } = loadFreshModules(keysPath);
    writeLegacyMappedFile(keysPath, 'legacy-bare-id', 'legacy-real-client');
    keyStore.reloadFromDisk();

    const resolved = keyStore.getPublicKey('legacy-bare-id');
    expect(resolved.clientId).toBe('legacy-real-client');
  });

  test('validateBoundRequest derives tenantId from the resolved clientId, not null, for a legacy key ID', async () => {
    const keysPath = makeTempPath();
    const { keyStore, validateBoundRequest, signBoundArtifact, makeNonceStore, makeOpenAnomalyStore, registerTenant } = loadFreshModules(keysPath);
    const { privDer, resolvedKeyId } = writeLegacyMappedFile(keysPath, 'legacy-bare-id-2', 'legacy-real-client-2');
    keyStore.reloadFromDisk();
    registerTenant('legacy-real-client-2');

    const request = { method: 'POST', path: '/ai/chat', body: { prompt: 'hi', model: 'gpt-4' } };
    const now = Date.now();
    const artifact = signBoundArtifact(
      request,
      { payload: { provider: 'openai' }, timestamp: now, expiry: now + 60_000, publicKeyId: 'legacy-bare-id-2' },
      privDer,
    );

    const result = await validateBoundRequest(artifact, request, {
      _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(),
    });

    expect(result.allowed).toBe(true);
    expect(result.tenantId).toBe('legacy-real-client-2');
    // publicKeyId on the result is the raw value from the artifact payload
    // (the legacy bare id, unchanged) — clientId is the separately-resolved
    // field this fix adds; resolvedKeyId is asserted via the getPublicKey()
    // test above.
    expect(result.publicKeyId).toBe('legacy-bare-id-2');
    expect(resolvedKeyId).toBe('legacy-real-client-2:key_v1');
  });

  test('the nonce for a legacy key ends up in that key\'s real tenant namespace, not the global/un-scoped one', async () => {
    const keysPath = makeTempPath();
    const { keyStore, validateBoundRequest, signBoundArtifact, makeNonceStore, makeOpenAnomalyStore, buildNonceKey, registerTenant } = loadFreshModules(keysPath);
    const { privDer } = writeLegacyMappedFile(keysPath, 'legacy-bare-id-3', 'legacy-real-client-3');
    keyStore.reloadFromDisk();
    registerTenant('legacy-real-client-3');

    const request = { method: 'POST', path: '/ai/chat', body: { prompt: 'hi', model: 'gpt-4' } };
    const now = Date.now();
    const artifact = signBoundArtifact(
      request,
      { payload: { provider: 'openai' }, timestamp: now, expiry: now + 60_000, publicKeyId: 'legacy-bare-id-3' },
      privDer,
    );

    const store = makeNonceStore();
    const result = await validateBoundRequest(artifact, request, { _store: store, _anomalyStore: makeOpenAnomalyStore() });
    expect(result.allowed).toBe(true);

    // Tenant-scoped key must be present...
    const tenantScopedKey = buildNonceKey(result.requestId, 'legacy-real-client-3');
    expect(store._map.has(tenantScopedKey)).toBe(true);
    // ...and the un-scoped (global-namespace) key must NOT be, proving the
    // nonce was not silently placed outside its tenant's namespace.
    const globalKey = buildNonceKey(result.requestId, null);
    expect(store._map.has(globalKey)).toBe(false);
  });

  test('two different legacy-mapped clients never collide in the nonce namespace even with the same requestId shape', async () => {
    const keysPath = makeTempPath();
    const { keyStore, validateBoundRequest, signBoundArtifact, makeNonceStore, makeOpenAnomalyStore, buildNonceKey, registerTenant } = loadFreshModules(keysPath);

    // Two legacy clients in the same file.
    const { privateKey: priv1, publicKey: pub1 } = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'der' }, publicKeyEncoding: { type: 'spki', format: 'der' },
    });
    const { privateKey: priv2, publicKey: pub2 } = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'der' }, publicKeyEncoding: { type: 'spki', format: 'der' },
    });
    const file = {
      version: 1,
      clients: {
        'client-a': { 'client-a:key_v1': { clientId: 'client-a', keyId: 'client-a:key_v1', version: 1, algorithm: 'ed25519', privateKeyDer: Buffer.from(priv1).toString('base64'), publicKeyDer: Buffer.from(pub1).toString('base64'), status: 'active', createdAt: new Date().toISOString() } },
        'client-b': { 'client-b:key_v1': { clientId: 'client-b', keyId: 'client-b:key_v1', version: 1, algorithm: 'ed25519', privateKeyDer: Buffer.from(priv2).toString('base64'), publicKeyDer: Buffer.from(pub2).toString('base64'), status: 'active', createdAt: new Date().toISOString() } },
      },
      legacyMap: { 'legacy-a': 'client-a:key_v1', 'legacy-b': 'client-b:key_v1' },
    };
    fs.mkdirSync(path.dirname(keysPath), { recursive: true });
    fs.writeFileSync(keysPath, JSON.stringify(file, null, 2), 'utf8');
    keyStore.reloadFromDisk();
    registerTenant('client-a');
    registerTenant('client-b');

    const store = makeNonceStore();
    const request = { method: 'POST', path: '/ai/chat', body: { prompt: 'hi', model: 'gpt-4' } };
    const now = Date.now();

    const artifactA = signBoundArtifact(request, { payload: { provider: 'openai' }, timestamp: now, expiry: now + 60_000, publicKeyId: 'legacy-a' }, Buffer.from(priv1));
    const artifactB = signBoundArtifact(request, { payload: { provider: 'openai' }, timestamp: now, expiry: now + 60_000, publicKeyId: 'legacy-b' }, Buffer.from(priv2));

    const resultA = await validateBoundRequest(artifactA, request, { _store: store, _anomalyStore: makeOpenAnomalyStore() });
    const resultB = await validateBoundRequest(artifactB, request, { _store: store, _anomalyStore: makeOpenAnomalyStore() });

    expect(resultA.allowed).toBe(true);
    expect(resultB.allowed).toBe(true);
    expect(resultA.tenantId).toBe('client-a');
    expect(resultB.tenantId).toBe('client-b');
    expect(buildNonceKey(resultA.requestId, 'client-a')).not.toBe(buildNonceKey(resultB.requestId, 'client-b'));
  });
});
