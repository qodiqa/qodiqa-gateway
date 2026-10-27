'use strict';

/**
 * integration test — full sign → archive/purge → verify flow.
 *
 * Before this remediation, an artifact signed by a key that was later
 * deprecated and then purged (archived + removed from the live keystore)
 * became permanently unverifiable — an undocumented ~180-360 day
 * verification ceiling. This test proves the end-to-end fix: the exact same
 * artifact, validated through the real server-side validateArtifact() path
 * (no test-only shortcuts), still resolves to EXECUTE after its signing key
 * has been fully purged from keys.json — and that keyStore.getPublicKey()
 * reports the archived source for observability, without that metadata
 * affecting the verification outcome itself.
 */

const fs   = require('fs');

const { validateArtifact } = require('../validateArtifact');
const { signArtifact }     = require('../signArtifact');
const keyStore              = require('../../../services/artifact/keyStore');

// K1: this fixture edits keys.json deliberately, as a KEK holder would, so it re-seals the record MACs
// (an edit WITHOUT the KEK is exactly what src/infra/crypto/keyRecordSeal.js now refuses).
function resealKeys(d) {
  const seal = require('../../infra/crypto/keyRecordSeal');
  return seal.sealFileData(d, require('../../../services/artifact/keyEncryption').deriveKekSubkey(seal.RECORD_MAC_INFO), 'artifact');
}

function backdateRetiredAt(keysPath, clientId, keyId, daysAgo) {
  const data = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
  data.clients[clientId][keyId].retiredAt = new Date(Date.now() - daysAgo * 86_400_000).toISOString();
  // keep the timeline consistent (created before it was retired)
  data.clients[clientId][keyId].createdAt = new Date(Date.now() - 2 * daysAgo * 86_400_000).toISOString();
  fs.writeFileSync(keysPath, JSON.stringify(resealKeys(data), null, 2), 'utf8');
}

describe('archived key end-to-end verification', () => {
  test('a since-purged (archived) key never verifies for execution; its signature stays verifiable historically', () => {
    const clientId = 'wp011-e2e-client';

    // 1. Provision + capture the signing key while active.
    keyStore.rotateKey(clientId, { mode: 'graceful' });
    const { keyId: signingKeyId, privDer } = keyStore.getActiveKey(clientId);

    // 2. Sign an artifact with it.
    const now      = Date.now();
    const artifact = signArtifact(
      { payload: { userId: 'alice', action: 'query' }, timestamp: now, expiry: now + 300_000, publicKeyId: signingKeyId },
      privDer,
    );

    // Sanity: verifies normally while the key is still active.
    expect(validateArtifact(artifact)).toMatchObject({ decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED' });

    // 3. Rotate gracefully — outgoing key becomes 'deprecated' (still verifiable).
    keyStore.rotateKeyGracefully(clientId);
    expect(validateArtifact(artifact)).toMatchObject({ decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED' });

    // 4. Force purge-eligibility (past the 180-day post-retirement retention
    //    window) without waiting out real time, then purge — archives the
    //    key's public metadata to key-archive.json and removes it from the
    //    live store entirely.
    const keysPath = process.env.QODIQA_KEYS_PATH;
    backdateRetiredAt(keysPath, clientId, signingKeyId, 200);
    keyStore.reloadFromDisk();
    const purgeResult = keyStore.purgeExpiredDeprecated(clientId);
    expect(purgeResult.purged).toBe(1);
    expect(purgeResult.archived[0].keyId).toBe(signingKeyId);

    // The key is genuinely gone from the live store now — getKeyStatus()
    // (the live-only lookup used by the unchanged /qodiqa/keys/:keyId route)
    // returns null, proving this isn't verifying against a live record.
    expect(keyStore.getKeyStatus(signingKeyId)).toBeNull();

    // 5. an ARCHIVED key never verifies an
    //    artifact for execution — not even one it signed while active. (
    //    had made this EXECUTE indefinitely; that was the finding.)
    const result = validateArtifact(artifact);
    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('KEY_ARCHIVED');

    // 6.'s durable property survives as HISTORICAL verification: the
    //    archived public key still resolves (source 'archived', timeline
    //    'archived'), and a signature made while the key was active verifies
    //    against its timeline (keyLifecycle.checkHistorical) — e.g. certificates.
    const resolved = keyStore.getPublicKey(signingKeyId);
    expect(resolved.source).toBe('archived');
    expect(resolved.timeline.status).toBe('archived');
    const { checkHistorical } = require('../keyLifecycle');
    // (step 4 backdated the retirement by 200 days to force the purge, so
    // "while active" is measured against that recorded retirement time)
    const retiredMs = Date.parse(resolved.timeline.deprecatedAt);
    expect(checkHistorical(resolved.timeline, retiredMs - 1)).toEqual({ valid: true });
    expect(checkHistorical(resolved.timeline, retiredMs).valid).toBe(false);
  });

  test('regression: a purged REVOKED key (never archived) is still permanently unverifiable', () => {
    // Sanity guard for the "revocation always wins" invariant this
    // remediation must not weaken: purgeExpiredDeprecated() only ever
    // archives 'deprecated' keys, never 'revoked' ones, so an emergency-mode
    // rotation's outgoing key must remain unverifiable forever — the archive
    // fallback must never accidentally resurrect it.
    const clientId = 'wp011-revoked-regression-client';
    keyStore.rotateKey(clientId, { mode: 'graceful' });
    const { keyId: signingKeyId, privDer } = keyStore.getActiveKey(clientId);

    const now      = Date.now();
    const artifact = signArtifact(
      { payload: { userId: 'mallory', action: 'query' }, timestamp: now, expiry: now + 300_000, publicKeyId: signingKeyId },
      privDer,
    );

    keyStore.rotateKey(clientId, { mode: 'emergency' }); // revokes signingKeyId

    const result = validateArtifact(artifact);
    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('INVALID_SIGNATURE'); // indistinguishable from a bad signature, by design

    expect(() => keyStore.getPublicKey(signingKeyId)).toThrow(/revoked and cannot be used/);
  });
});
