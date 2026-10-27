'use strict';

/**
 * Evidence Package Generator — test suite
 *
 * EV-01…EV-05   Input validation
 * EV-06…EV-12   JSON package generation
 * EV-13…EV-18   PDF package generation
 * EV-19…EV-23   Audit chain export
 * EV-24…EV-30   Cryptographic verification output
 * EV-31…EV-36   Edge cases: expired, invalid sig, replay, corrupted chain, no policies
 */

// v7 (R-12 / R-14): audit appends pseudonymize consentProvenance.subject / callerContext.callerId, which needs PostgreSQL
// in production (fail-closed without it). This suite runs without a database, so it opts in to the EXPLICIT test-only stand-in.
jest.mock('../../../core/dsr/subjectPseudonym', () => require('../../../../test/helpers/subjectPseudonymMock'));
const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../../core/audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
const request       = require('supertest');
const express       = require('express');
const { randomUUID: uuidv4 } = require('crypto');

// ── Load modules AFTER test/support/jest.setup.js has redirected env vars ──────────────────
const {
  append,
  getAuditChain,
} = require('../../../core/audit/audit-log.js');
const { getActiveKey } = require('../../../../services/artifact/keyStore');
const { signArtifact } = require('../../../validation/signArtifact');
const { computePolicyHash } = require('../../../../services/policyHash');
const createEvidenceRouter  = require('../evidence');

// ── Test app factory ──────────────────────────────────────────────────────────

let _testPolicies = [];

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use((req, res, next) => { req.requestId = `test-${Date.now()}`; res.locals.requestId = req.requestId; next(); });
  app.use('/evidence', createEvidenceRouter({ _getPolicies: () => _testPolicies }));
  return app;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

let KEY;
// the external verifiers need the instance's published key set as a trust anchor
// (the out-of-band /.well-known/qodiqa/keys body) — never the key embedded in the package.
const TRUST = () => ({ trustedKeys: [{ keyId: KEY.keyId, publicKey: KEY.pubDer.toString('base64'), status: 'active' }] });
beforeAll(() => {
  KEY = getActiveKey('default');
  _testPolicies = [
    { id: 'test-policy-1', type: 'REQUIRE_CONSENT', priority: 1, enabled: true, config: {} },
  ];
});

function makeArtifact(overrides = {}) {
  const now    = Date.now();
  const expiry = now + 60_000;
  return signArtifact(
    {
      payload:     { action: 'test', data: 'evidence-test' },
      timestamp:   now,
      expiry,
      publicKeyId: KEY.keyId,
      ...overrides,
    },
    KEY.privDer
  );
}

function appendAllow(artifactId, extra = {}) {
  const artifact   = makeArtifact();
  const inputHash  = require('crypto').createHash('sha256').update(JSON.stringify(artifact.payload)).digest('hex');
  const policyHash = computePolicyHash(_testPolicies);
  return append({
    artifactId,
    inputHash,
    decision:          'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
    signature:         Buffer.from(artifact.signature, 'base64').toString('hex'),
    requestHash:       require('crypto').createHash('sha256').update('test-req').digest('hex'),
    policyHash,
    verificationResult: true,
    // real writers set the hash-protected top-level publicKeyId AND the legacy
    // executionContext copy (aiChat.js _writeAuditBlock); the evidence generator now reads only the
    // protected one for schemaVersion >= 2, so the fixture carries it as production does.
    publicKeyId:       KEY.keyId,
    executionContext:  { stage: 'ENFORCE', reason: 'ALL_CHECKS_PASSED', publicKeyId: KEY.keyId },
    ...extra,
  });
}

function appendBlock(artifactId, extra = {}) {
  return append({
    artifactId,
    decision:         'BLOCK',
    publicKeyId:      KEY.keyId, // as real writers do (see appendAllow)
    executionContext: { stage: 'ENFORCE', reason: 'INVALID_SIGNATURE', publicKeyId: KEY.keyId },
    ...extra,
  });
}

function appendReplay(originalId, replayId) {
  return append({
    artifactId:       replayId,
    decision:         'BLOCK',
    executionContext: { stage: 'ENFORCE', reason: 'REPLAY_DETECTED', replayOf: originalId },
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// EV-01…EV-05  Input validation
// ─────────────────────────────────────────────────────────────────────────────

describe('EV-01…EV-05  Input validation', () => {
  const app = makeApp();

  test('EV-01  rejects non-UUID artifactId on /json', async () => {
    const r = await request(app).get('/evidence/package/not-a-uuid/json');
    expect(r.status).toBe(400);
    expect(r.body.error.code).toBe('INVALID_ARTIFACT_ID');
  });

  test('EV-02  rejects non-UUID artifactId on /pdf', async () => {
    const r = await request(app).get('/evidence/package/bad/pdf');
    expect(r.status).toBe(400);
  });

  test('EV-03  rejects non-UUID artifactId on /audit', async () => {
    const r = await request(app).get('/evidence/package/BAD/audit');
    expect(r.status).toBe(400);
    expect(r.body.error.code).toBe('INVALID_ARTIFACT_ID');
  });

  test('EV-04  rejects non-UUID artifactId on /verify', async () => {
    const r = await request(app).get('/evidence/package/123/verify');
    expect(r.status).toBe(400);
  });

  test('EV-05  returns 404 for valid UUID not in chain', async () => {
    const r = await request(app).get(`/evidence/package/${uuidv4()}/json`);
    expect(r.status).toBe(404);
    expect(r.body.error.code).toBe('ARTIFACT_NOT_FOUND');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// EV-06…EV-12  JSON package generation
// ─────────────────────────────────────────────────────────────────────────────

describe('EV-06…EV-12  JSON package generation', () => {
  const app = makeApp();
  let artifactId;
  let pkg;

  beforeAll(async () => {
    artifactId = uuidv4();
    await appendAllow(artifactId);
    const r = await request(app).get(`/evidence/package/${artifactId}/json`);
    expect(r.status).toBe(200);
    pkg = r.body.data;
  });

  test('EV-06  package has correct schema and version fields', () => {
    expect(pkg.schema).toBe('QODIQA::EVIDENCE::V1');
    expect(typeof pkg.version).toBe('string');
    expect(pkg.artifactId).toBe(artifactId);
    expect(pkg.found).toBe(true);
  });

  test('EV-07  artifact section has required fields', () => {
    const { artifact } = pkg.sections;
    expect(artifact.artifactId).toBe(artifactId);
    expect(artifact.decision).toBe('ALLOW');
    expect(typeof artifact.timestamp).toBe('string');
    expect(typeof artifact.inputHash).toBe('string');
    expect(typeof artifact.policyHash).toBe('string');
  });

  test('EV-08  policy section compares hashes', () => {
    const { policy } = pkg.sections;
    expect(policy.policyHashAtExecution).toBeTruthy();
    expect(typeof policy.hashIntegrity).toBe('string');
    // hashIntegrity should be MATCH since policies haven't changed
    expect(['MATCH', 'MISMATCH', 'UNKNOWN']).toContain(policy.hashIntegrity);
  });

  test('EV-09  key section exposes the full public key but never private key material', () => {
    const { key } = pkg.sections;
    // Full, untruncated public key — required for offline verification.
    expect(key.publicKey).toBe(KEY.pubDer.toString('base64'));
    expect(key.publicKey).not.toMatch(/…|\.\.\.$/);
    expect(key.publicKeyEncoding).toBe('base64-der-spki');
    // Never the private key.
    expect(key.publicKey).not.toContain(KEY.privDer?.toString('base64') ?? ' never-empty ');
    expect(key.publicKeyId).toBe(KEY.keyId);
    expect(key.keyStatus).toBeTruthy();
  });

  test('EV-10  verification section reflects VALID outcome', () => {
    const { verification } = pkg.sections;
    expect(verification.outcome).toBe('VALID');
    expect(verification.decisionAtExecution).toBe('ALLOW');
  });

  test('EV-11  audit section shows chain integrity and artifact position', () => {
    const { audit } = pkg.sections;
    expect(typeof audit.chainIntegrity.valid).toBe('boolean');
    expect(typeof audit.chainIntegrity.entriesVerified).toBe('number');
    expect(audit.artifactPosition.found).toBe(true);
    expect(typeof audit.artifactPosition.index).toBe('number');
    expect(audit.replayAnalysis.replayCount).toBe(0);
    expect(audit.replayAnalysis.replayRiskLevel).toBe('NONE');
  });

  test('EV-12  package has integrity seal (SHA-256 hash)', () => {
    expect(pkg.integrity).toBeDefined();
    expect(typeof pkg.integrity.packageHash).toBe('string');
    expect(pkg.integrity.packageHash).toMatch(/^[a-f0-9]{64}$/);
    expect(pkg.integrity.algorithm).toBe('SHA-256');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// EV-13…EV-18  Root endpoint alias + PDF
// ─────────────────────────────────────────────────────────────────────────────

describe('EV-13…EV-18  PDF and root alias', () => {
  const app = makeApp();
  let artifactId;

  beforeAll(async () => {
    artifactId = uuidv4();
    await appendAllow(artifactId);
  });

  test('EV-13  GET /package/:id returns same structure as /json', async () => {
    const [r1, r2] = await Promise.all([
      request(app).get(`/evidence/package/${artifactId}`),
      request(app).get(`/evidence/package/${artifactId}/json`),
    ]);
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    // Both should agree on stable, non-time-sensitive fields
    expect(r1.body.data.artifactId).toBe(r2.body.data.artifactId);
    expect(r1.body.data.schema).toBe(r2.body.data.schema);
    expect(r1.body.data.sections.artifact.decision).toBe(r2.body.data.sections.artifact.decision);
    // Both have integrity seals (packageHash changes per request due to generatedAt)
    expect(r1.body.data.integrity.algorithm).toBe(r2.body.data.integrity.algorithm);
  });

  test('EV-14  GET /package/:id/pdf returns application/pdf', async () => {
    const r = await request(app).get(`/evidence/package/${artifactId}/pdf`);
    expect(r.status).toBe(200);
    expect(r.headers['content-type']).toMatch(/application\/pdf/);
  });

  test('EV-15  PDF response has Content-Disposition attachment', async () => {
    const r = await request(app).get(`/evidence/package/${artifactId}/pdf`);
    expect(r.headers['content-disposition']).toMatch(/attachment/);
    expect(r.headers['content-disposition']).toContain(artifactId);
  });

  test('EV-16  PDF response is non-empty binary', async () => {
    const r = await request(app)
      .get(`/evidence/package/${artifactId}/pdf`)
      .buffer(true)
      .parse((res, cb) => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => cb(null, Buffer.concat(chunks)));
      });
    expect(r.body.length).toBeGreaterThan(1000);
    // PDF magic bytes: %PDF
    expect(r.body.slice(0, 4).toString()).toBe('%PDF');
  });

  test('EV-17  PDF 404 for unknown artifactId', async () => {
    const r = await request(app).get(`/evidence/package/${uuidv4()}/pdf`);
    expect(r.status).toBe(404);
  });

  test('EV-18  PDF sets X-Content-Type-Options nosniff', async () => {
    const r = await request(app).get(`/evidence/package/${artifactId}/pdf`);
    expect(r.headers['x-content-type-options']).toBe('nosniff');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// EV-19…EV-23  Audit chain export
// ─────────────────────────────────────────────────────────────────────────────

describe('EV-19…EV-23  Audit chain export', () => {
  const app = makeApp();
  let artifactId;

  beforeAll(async () => {
    artifactId = uuidv4();
    await appendAllow(artifactId);
    // Add a replay attempt
    const replayId = uuidv4();
    await appendReplay(artifactId, replayId);
  });

  test('EV-19  filtered export includes artifact entry and its replay entries', async () => {
    const r = await request(app).get(`/evidence/package/${artifactId}/audit`);
    expect(r.status).toBe(200);
    const { entries, meta } = r.body.data;
    expect(meta.filtered).toBe(true);
    const ids = entries.map(e => e.artifactId);
    expect(ids).toContain(artifactId);
    // replay entry should reference this artifact
    const replays = entries.filter(e => e.executionContext?.replayOf === artifactId);
    expect(replays.length).toBeGreaterThanOrEqual(1);
  });

  test('EV-20  unfiltered export returns full chain', async () => {
    const r = await request(app).get(`/evidence/package/${artifactId}/audit?filtered=false`);
    expect(r.status).toBe(200);
    const { meta } = r.body.data;
    expect(meta.filtered).toBe(false);
    expect(meta.totalChain).toBe(meta.exportedCount);
  });

  test('EV-21  audit export includes chain integrity metadata', async () => {
    const r = await request(app).get(`/evidence/package/${artifactId}/audit`);
    const { meta } = r.body.data;
    expect(typeof meta.chainIntegrity.valid).toBe('boolean');
    expect(typeof meta.chainIntegrity.entriesVerified).toBe('number');
    expect(typeof meta.chainIntegrity.tamperingDetected).toBe('boolean');
    expect(meta.exportedAt).toBeTruthy();
  });

  test('EV-22  filtered export 404 for unknown artifact', async () => {
    const r = await request(app).get(`/evidence/package/${uuidv4()}/audit`);
    expect(r.status).toBe(404);
  });

  test('EV-23  entries in export have expected audit chain fields', async () => {
    const r = await request(app).get(`/evidence/package/${artifactId}/audit`);
    const entry = r.body.data.entries.find(e => e.artifactId === artifactId);
    expect(entry).toBeDefined();
    expect(entry.decision).toBe('ALLOW');
    expect(entry.hash).toBeTruthy();
    expect(entry.prevHash).toBeTruthy();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// EV-24…EV-30  Cryptographic verification output
// ─────────────────────────────────────────────────────────────────────────────

describe('EV-24…EV-30  Cryptographic verification output', () => {
  const app = makeApp();
  let artifactId;
  let verifyData;

  beforeAll(async () => {
    artifactId = uuidv4();
    await appendAllow(artifactId);
    const r = await request(app).get(`/evidence/package/${artifactId}/verify`);
    expect(r.status).toBe(200);
    verifyData = r.body.data;
  });

  test('EV-24  verify output has schema and generatedAt', () => {
    expect(verifyData.schema).toBe('QODIQA::EVIDENCE::V1');
    expect(verifyData.generatedAt).toBeTruthy();
    expect(verifyData.artifactId).toBe(artifactId);
    expect(verifyData.found).toBe(true);
  });

  test('EV-25  verify output has chain verification section', () => {
    const { chain } = verifyData.verifications;
    expect(typeof chain.valid).toBe('boolean');
    expect(typeof chain.tamperingDetected).toBe('boolean');
    expect(typeof chain.entriesVerified).toBe('number');
    expect(['VALID', 'INVALID']).toContain(chain.status);
  });

  test('EV-26  verify output has signature verification section', () => {
    const { signature } = verifyData.verifications;
    expect(['VALID', 'INVALID', 'UNAVAILABLE', 'UNKNOWN']).toContain(signature.status);
  });

  test('EV-27  verify output has policy verification section', () => {
    const { policy } = verifyData.verifications;
    expect(['MATCH', 'MISMATCH', 'UNKNOWN']).toContain(policy.status);
  });

  test('EV-28  verify output has replay verification section', () => {
    const { replay } = verifyData.verifications;
    expect(['CLEAN', 'REPLAYS_DETECTED']).toContain(replay.status);
    expect(typeof replay.replayCount).toBe('number');
  });

  test('EV-29  overallStatus is set and is a known value', () => {
    const valid = ['VERIFIED', 'INVALID', 'COMPROMISED', 'REPLAYED', 'PARTIAL', 'UNKNOWN'];
    expect(valid).toContain(verifyData.overallStatus);
  });

  test('EV-30  verify 404 for unknown artifactId', async () => {
    const r = await request(app).get(`/evidence/package/${uuidv4()}/verify`);
    expect(r.status).toBe(404);
    expect(r.body.error.code).toBe('ARTIFACT_NOT_FOUND');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// EV-31…EV-36  Edge cases
// ─────────────────────────────────────────────────────────────────────────────

describe('EV-31…EV-36  Edge cases', () => {
  const app = makeApp();

  test('EV-31  BLOCK entry verification shows UNAVAILABLE for missing signature', async () => {
    const artifactId = uuidv4();
    await appendBlock(artifactId);

    const r = await request(app).get(`/evidence/package/${artifactId}/json`);
    expect(r.status).toBe(200);
    const { verification } = r.body.data.sections;
    // BLOCK with no signature should be UNAVAILABLE or UNKNOWN (not VALID)
    expect(['UNAVAILABLE', 'UNKNOWN', 'INVALID']).toContain(verification.outcome);
  });

  test('EV-32  replay detection is reflected in JSON package and verify output', async () => {
    const originalId = uuidv4();
    await appendAllow(originalId);

    const replayId1 = uuidv4();
    const replayId2 = uuidv4();
    await appendReplay(originalId, replayId1);
    await appendReplay(originalId, replayId2);

    const [pkgRes, verifyRes] = await Promise.all([
      request(app).get(`/evidence/package/${originalId}/json`),
      request(app).get(`/evidence/package/${originalId}/verify`),
    ]);

    expect(pkgRes.status).toBe(200);
    const { replayAnalysis } = pkgRes.body.data.sections.audit;
    expect(replayAnalysis.replayCount).toBe(2);
    expect(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(replayAnalysis.replayRiskLevel);

    expect(verifyRes.status).toBe(200);
    const { replay } = verifyRes.body.data.verifications;
    expect(replay.status).toBe('REPLAYS_DETECTED');
    expect(replay.replayCount).toBe(2);
  });

  test('EV-33  policy hash comparison shows MISMATCH when policies change', async () => {
    const artifactId = uuidv4();
    // Append with current policy hash
    await appendAllow(artifactId);

    // Temporarily change _testPolicies so computePolicyHash gives a different result
    const savedPolicies = _testPolicies;
    _testPolicies = [
      { id: 'policy-changed', type: 'REQUIRE_CONSENT', priority: 1, enabled: true, config: {} },
      { id: 'policy-extra', type: 'BLOCK_IP', priority: 2, enabled: true, config: { blockedIPs: ['1.2.3.4'] } },
    ];

    try {
      const r = await request(app).get(`/evidence/package/${artifactId}/json`);
      expect(r.status).toBe(200);
      const { policy } = r.body.data.sections;
      // With different policies, hash should mismatch
      expect(policy.hashIntegrity).toBe('MISMATCH');
    } finally {
      _testPolicies = savedPolicies;
    }
  });

  test('EV-34  evidence package works with no policies (_getPolicies returns [])', async () => {
    // App with no policies provider
    const appNoPolicies = express();
    appNoPolicies.use(express.json());
    appNoPolicies.use((req, _res, next) => { req.requestId = 'test'; next(); });
    appNoPolicies.use('/evidence', createEvidenceRouter());

    const artifactId = uuidv4();
    await appendAllow(artifactId);

    const r = await request(appNoPolicies).get(`/evidence/package/${artifactId}/json`);
    expect(r.status).toBe(200);
    const { policy } = r.body.data.sections;
    expect(policy.hashIntegrity).toBe('UNKNOWN');
  });

  test('EV-35  response envelope matches standard format', async () => {
    const artifactId = uuidv4();
    await appendAllow(artifactId);
    const r = await request(app).get(`/evidence/package/${artifactId}/json`);
    expect(r.body.status).toBe('success');
    expect(r.body.timestamp).toBeTruthy();
    expect(r.body.requestId).toBeTruthy();
    expect(r.body.data).toBeDefined();
  });

  test('EV-36  PDF for BLOCK entry still generates valid PDF', async () => {
    const artifactId = uuidv4();
    await appendBlock(artifactId);

    const r = await request(app)
      .get(`/evidence/package/${artifactId}/pdf`)
      .buffer(true)
      .parse((res, cb) => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => cb(null, Buffer.concat(chunks)));
      });

    expect(r.status).toBe(200);
    expect(r.headers['content-type']).toMatch(/application\/pdf/);
    expect(r.body.slice(0, 4).toString()).toBe('%PDF');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// remediation — full signature/public key export + offline verification
// ─────────────────────────────────────────────────────────────────────────────

describe('Full crypto material export + independent offline verification', () => {
  const app = makeApp();
  const crypto = require('crypto');
  const { verifyEvidencePackage } = require('../../../core/evidence/generator');
  const externalVerifier = require('../../../../tools/verify/verify.evidence.external.js');

  let artifactId;
  let entry;
  let pkg;

  beforeAll(async () => {
    artifactId = uuidv4();
    entry = await appendAllow(artifactId);
    const r = await request(app).get(`/evidence/package/${artifactId}/json`);
    expect(r.status).toBe(200);
    pkg = r.body.data;
  });

  test('EVID2-01  exported signature is the full, untruncated value — no ellipsis', () => {
    expect(pkg.sections.artifact.signature).toBe(entry.signature);
    expect(pkg.sections.verification.signature).toBe(entry.signature);
    expect(pkg.sections.artifact.signature).not.toMatch(/…/);
    expect(pkg.sections.verification.signature).not.toMatch(/…/);
  });

  test('EVID2-02  exported public key is the full, untruncated base64 DER — no ellipsis', () => {
    const fullKeyB64 = KEY.pubDer.toString('base64');
    expect(pkg.sections.key.publicKey).toBe(fullKeyB64);
    expect(pkg.sections.verification.publicKey).toBe(fullKeyB64);
    expect(pkg.sections.key.publicKey).not.toMatch(/…/);
    // The full key must actually load as a valid Ed25519 SPKI public key.
    expect(() => crypto.createPublicKey({
      key: Buffer.from(pkg.sections.key.publicKey, 'base64'), format: 'der', type: 'spki',
    })).not.toThrow();
  });

  test('EVID2-03  canonical payload and chain hash domain are exported for offline chain verification', () => {
    expect(typeof pkg.sections.artifact.canonical).toBe('string');
    expect(pkg.sections.artifact.canonical.length).toBeGreaterThan(0);
    expect(pkg.sections.artifact.chainHashDomain).toBe('QODIQA::AUDIT::V1');
  });

  test('EVID2-04  package is sealed with a genuine Ed25519 signature over the full content', () => {
    expect(typeof pkg.integrity.signature).toBe('string');
    expect(pkg.integrity.signature.length).toBeGreaterThan(0);
    expect(pkg.integrity.signingAlgorithm).toBe('Ed25519');
    expect(pkg.integrity.publicKey).toBe(KEY.pubDer.toString('base64'));
    expect(pkg.integrity.keyId).toBe(KEY.keyId);
  });

  test('EVID2-05  offline verification succeeds using only the exported bundle (internal verifier)', () => {
    const result = verifyEvidencePackage(pkg);
    expect(result.packageHashValid).toBe(true);
    expect(result.signatureValid).toBe(true);
    expect(result.chainHashValid).toBe(true);
    expect(result.valid).toBe(true);
  });

  test('EVID2-05b a package resealed with an attacker key is rejected by the server-side verifier (trusted key store, never the embedded key)', () => {
    const forged = JSON.parse(JSON.stringify(pkg));
    const att = crypto.generateKeyPairSync('ed25519');
    const content = externalVerifier.packageContent(forged);
    const hash = externalVerifier.domainSeparatedHash('QODIQA::EVIDENCE::V1', externalVerifier.stableStringify(content));
    forged.integrity.signature = crypto.sign(null, hash, att.privateKey).toString('base64');
    forged.integrity.publicKey = att.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    const internal = verifyEvidencePackage(forged);
    expect(internal.valid).toBe(false);
    expect(internal.reasons.join(' ')).toMatch(/KEY_MISMATCH/);
    // and the embedded-key-only "self-consistent" view is exactly what is no longer trusted:
    expect(externalVerifier.verifyEvidencePackage(forged).selfConsistentSignature).toBe(true);
    expect(externalVerifier.verifyEvidencePackage(forged, TRUST()).valid).toBe(false);
  });

  test('EVID2-06  offline verification succeeds via the standalone external verifier (no QODIQA source imports)', () => {
    const result = externalVerifier.verifyEvidencePackage(pkg, TRUST());
    expect(result.packageHashValid).toBe(true);
    expect(result.signatureValid).toBe(true);
    expect(result.chainHashValid).toBe(true);
    expect(result.valid).toBe(true);
  });

  test('EVID2-07  tampering with the payload (decision) is detected offline', () => {
    const tampered = JSON.parse(JSON.stringify(pkg));
    tampered.sections.artifact.decision = 'BLOCK';
    const internal = verifyEvidencePackage(tampered);
    const external = externalVerifier.verifyEvidencePackage(tampered, TRUST());
    expect(internal.valid).toBe(false);
    expect(internal.packageHashValid).toBe(false);
    expect(external.valid).toBe(false);
  });

  test('EVID2-08  tampering with the signature is detected offline', () => {
    const tampered = JSON.parse(JSON.stringify(pkg));
    // Flip the first character of the sealed signature — guaranteed to be
    // significant base64 data (unlike the last character, which may be
    // padding that Node's lenient base64 decoder can absorb unchanged).
    const sig = tampered.integrity.signature;
    tampered.integrity.signature = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
    const internal = verifyEvidencePackage(tampered);
    const external = externalVerifier.verifyEvidencePackage(tampered, TRUST());
    expect(internal.signatureValid).toBe(false);
    expect(internal.valid).toBe(false);
    expect(external.signatureValid).toBe(false);
    expect(external.valid).toBe(false);
  });

  test('EVID2-09  tampering with the public key is detected offline', () => {
    const otherKeyPair = crypto.generateKeyPairSync('ed25519');
    const otherPubDer  = otherKeyPair.publicKey.export({ type: 'spki', format: 'der' });

    const tampered = JSON.parse(JSON.stringify(pkg));
    tampered.integrity.publicKey = otherPubDer.toString('base64');

    const internal = verifyEvidencePackage(tampered);
    const external = externalVerifier.verifyEvidencePackage(tampered, TRUST());
    expect(internal.signatureValid).toBe(false);
    expect(internal.valid).toBe(false);
    expect(external.signatureValid).toBe(false);
    expect(external.valid).toBe(false);
  });

  test('EVID2-10  no preview/truncation formatting leaks into exported cryptographic fields', () => {
    // Regression guard: nothing named like a display-preview helper, and no
    // ellipsis character, appears anywhere in the exported JSON evidence
    // package. Catches any future accidental reuse of UI-only formatting.
    const serialized = JSON.stringify(pkg);
    expect(serialized).not.toMatch(/…/);
    expect(pkg.sections.key.publicFingerprint).toBeUndefined();
    expect(pkg.sections.verification.signatureField).toBeUndefined();
  });

  test('EVID2-11  BLOCK entries with no signature still produce a validly sealed package', async () => {
    const blockId = uuidv4();
    await appendBlock(blockId);
    const r = await request(app).get(`/evidence/package/${blockId}/json`);
    expect(r.status).toBe(200);
    const blockPkg = r.body.data;

    expect(blockPkg.sections.artifact.signature).toBe('UNAVAILABLE');
    // The package-level seal covers the whole package regardless of whether
    // the underlying decision had a signature — still independently verifiable.
    const result = verifyEvidencePackage(blockPkg);
    expect(result.packageHashValid).toBe(true);
    expect(result.signatureValid).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// TRACE-2 remediation — consent-record + policy-rule provenance is embedded
// in the evidence package, cryptographically bound, and independently
// provable by an external, offline verifier from the exported file alone.
// ─────────────────────────────────────────────────────────────────────────────

describe('TRACE-2  Consent + policy-rule provenance in the evidence package', () => {
  const app = makeApp();
  const externalVerifier = require('../../../../tools/verify/verify.evidence.external.js');

  const CONSENT_PROVENANCE = Object.freeze({
    consentId:         uuidv4(),
    consentVersion:    2,
    consentCreatedAt:  '2026-01-01T00:00:00.000Z',
    consentApprovedAt: '2026-01-02T00:00:00.000Z',
    consentIssuer:     'admin@example.com',
    tenantId:           'tenant-trace2',
    subject:            'default:key_v1',
    scope:              'basic',
    requiredScope:      'basic',
    expiresAt:          null,
    revocationStatus:   'ACTIVE',
    recordHash:         'r'.repeat(64),
  });

  const POLICY_DECISION = Object.freeze({
    policyId:      'POL-REQUIRE-CONSENT-1',
    policyVersion: 3,
    engineVersion: '1.0.0',
    evaluatedAt:   '2026-01-02T00:00:01.000Z',
    evaluationPath: [
      { policyId: 'POL-REQUIRE-CONSENT-1', policyVersion: 3, type: 'REQUIRE_CONSENT', result: 'PASS', reason: 'CONSENT_VERIFIED' },
    ],
  });

  test('EV-TRACE2-01  ALLOW entry with consent+policy provenance produces a self-contained consent section', async () => {
    const artifactId = uuidv4();
    await appendAllow(artifactId, { consentProvenance: CONSENT_PROVENANCE, policyDecision: POLICY_DECISION });

    const r = await request(app).get(`/evidence/package/${artifactId}/json`);
    expect(r.status).toBe(200);
    const pkg = r.body.data;

    expect(pkg.sections.consent.available).toBe(true);
    expect(pkg.sections.consent.consentId).toBe(CONSENT_PROVENANCE.consentId);
    expect(pkg.sections.consent.consentVersion).toBe(CONSENT_PROVENANCE.consentVersion);
    expect(pkg.sections.consent.revocationStatus).toBe('ACTIVE');
    // v7 (R-12/R-13): the audit entry carries the subject PSEUDONYM, never the raw identifier (no tenant in this fixture)
    expect(pkg.sections.consent.subject).toBe(require('../../../../test/helpers/subjectPseudonymMock').expectedPseudonym(null, CONSENT_PROVENANCE.subject));
    expect(JSON.stringify(pkg)).not.toContain(`"subject":"${CONSENT_PROVENANCE.subject}"`);

    expect(pkg.sections.policy.matchedRuleId).toBe(POLICY_DECISION.policyId);
    expect(pkg.sections.policy.matchedRuleVersion).toBe(POLICY_DECISION.policyVersion);
    expect(pkg.sections.policy.engineVersion).toBe(POLICY_DECISION.engineVersion);
    expect(pkg.sections.policy.evaluationPath).toEqual(POLICY_DECISION.evaluationPath);
  });

  test('EV-TRACE2-02  an entry with no consent policy applied reports available:false, distinct from "predates TRACE-2"', async () => {
    const artifactId = uuidv4();
    await appendAllow(artifactId); // no consentProvenance/policyDecision passed

    const r = await request(app).get(`/evidence/package/${artifactId}/json`);
    const pkg = r.body.data;

    expect(pkg.sections.consent.available).toBe(false);
    expect(pkg.sections.consent.note).toMatch(/no consent policy applied/i);
  });

  test('EV-TRACE2-03  external, dependency-free offline verifier independently proves consentId, version, revocation status, and matched rule from the file alone', async () => {
    const artifactId = uuidv4();
    await appendAllow(artifactId, { consentProvenance: CONSENT_PROVENANCE, policyDecision: POLICY_DECISION });

    const r = await request(app).get(`/evidence/package/${artifactId}/json`);
    const pkg = r.body.data;

    // Round-trip through JSON exactly as an external auditor downloading the
    // file would receive it — no live object references, no repo imports
    // beyond the standalone verifier script itself.
    const downloaded = JSON.parse(JSON.stringify(pkg));
    const result = externalVerifier.verifyEvidencePackage(downloaded, TRUST());

    expect(result.valid).toBe(true);
    expect(result.packageHashValid).toBe(true);
    expect(result.signatureValid).toBe(true);
    expect(result.chainHashValid).not.toBe(false);

    // No database, no API, no live QODIQA instance — the answer to "which
    // consent, which version, was it revoked, which rule, why" comes only
    // from the downloaded JSON.
    expect(result.provenance.consent.consentId).toBe(CONSENT_PROVENANCE.consentId);
    expect(result.provenance.consent.consentVersion).toBe(CONSENT_PROVENANCE.consentVersion);
    expect(result.provenance.consent.revocationStatus).toBe('ACTIVE');
    expect(result.provenance.policyRule.matchedRuleId).toBe(POLICY_DECISION.policyId);
    expect(result.provenance.policyRule.matchedRuleVersion).toBe(POLICY_DECISION.policyVersion);
  });

  test('EV-TRACE2-04  tampering with the consent section after export is detected offline (signature covers it)', async () => {
    const artifactId = uuidv4();
    await appendAllow(artifactId, { consentProvenance: CONSENT_PROVENANCE, policyDecision: POLICY_DECISION });

    const r = await request(app).get(`/evidence/package/${artifactId}/json`);
    const pkg = JSON.parse(JSON.stringify(r.body.data));

    // A forger swaps in a different consentId, hoping to claim a different
    // (perhaps still-active) consent authorized this execution.
    const tampered = JSON.parse(JSON.stringify(pkg));
    tampered.sections.consent.consentId = uuidv4();

    const genuine  = externalVerifier.verifyEvidencePackage(pkg, TRUST());
    const forged   = externalVerifier.verifyEvidencePackage(tampered, TRUST());

    expect(genuine.valid).toBe(true);
    expect(forged.valid).toBe(false);
    expect(forged.packageHashValid).toBe(false);
    expect(forged.reasons).toEqual(expect.arrayContaining([expect.stringContaining('PACKAGE_HASH_MISMATCH')]));
  });

  test('EV-TRACE2-05  audit chain entry itself hash-protects consentProvenance/policyDecision — tampering breaks chain verification, not just the package seal', async () => {
    const artifactId = uuidv4();
    const entry = await appendAllow(artifactId, { consentProvenance: CONSENT_PROVENANCE, policyDecision: POLICY_DECISION });
    // bumped CURRENT_SCHEMA_VERSION 3 -> 4 (adds callerContext),
    // bumped it again to 5 (adds provider + model), and bumped
    // it again to 6 (adds stage/reason/semantic/tokenUsage/responseId);
    // consentProvenance/policyDecision protection (this test's subject) is
    // unaffected.
    expect(entry.schemaVersion).toBe(7); // CURRENT_SCHEMA_VERSION 6 -> 7 (audit schema v7)

    // Verify against the real chain position (this suite's audit-log module
    // is shared across the whole file, so `entry` is not necessarily
    // genesis — a single-entry array would spuriously fail on prevHash
    // continuity rather than the hash tamper this test targets).
    const chain = await getAuditChain();
    const idx   = chain.findIndex(e => e.artifactId === artifactId);
    expect(idx).toBeGreaterThanOrEqual(0);

    const tamperedChain = chain.slice();
    tamperedChain[idx] = { ...entry, consentProvenance: { ...entry.consentProvenance, consentId: 'forged-id' } };

    const { verifyAuditChainDetailed } = require('../../../core/audit/audit-log.js');
    const result = verifyAuditChainDetailed(tamperedChain);

    expect(result.valid).toBe(false);
    expect(result.tamperingDetected).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// EV-BUNDLE Self-contained offline evidence bundle
// ─────────────────────────────────────────────────────────────────────────────

describe('EV-BUNDLE  self-contained offline evidence bundle', () => {
  const app = makeApp();
  const externalBundleVerifier = require('../../../../tools/verify/verify.bundle.external.js');

  test('EV-BUNDLE-01  rejects non-UUID artifactId', async () => {
    const r = await request(app).get('/evidence/package/not-a-uuid/bundle');
    expect(r.status).toBe(400);
    expect(r.body.error.code).toBe('INVALID_ARTIFACT_ID');
  });

  test('EV-BUNDLE-02  returns 404 for a valid UUID not in the audit chain', async () => {
    const r = await request(app).get(`/evidence/package/${uuidv4()}/bundle`);
    expect(r.status).toBe(404);
    expect(r.body.error.code).toBe('ARTIFACT_NOT_FOUND');
  });

  test('EV-BUNDLE-03  generates a bundle with the correct schema, an embedded evidence package, and a signed envelope seal', async () => {
    const artifactId = uuidv4();
    await appendAllow(artifactId);

    const r = await request(app).get(`/evidence/package/${artifactId}/bundle`);
    expect(r.status).toBe(200);

    const bundle = r.body.data;
    expect(bundle.schema).toBe('QODIQA::EVIDENCE_BUNDLE::V1');
    expect(bundle.artifactId).toBe(artifactId);
    expect(bundle.evidencePackage.schema).toBe('QODIQA::EVIDENCE::V1');
    expect(bundle.evidencePackage.artifactId).toBe(artifactId);
    expect(typeof bundle.integrity.bundleHash).toBe('string');
    expect(bundle.integrity.signingAlgorithm).toBe('Ed25519');
    // No transparency root has been published in this test process — the
    // bundle must still generate, just with the section marked unavailable
    // rather than failing the whole request.
    expect(bundle.transparency.available).toBe(false);
    expect(typeof bundle.transparency.note).toBe('string');
  });

  test('EV-BUNDLE-04  the standalone offline verifier (tools/verify/verify.bundle.external.js) verifies a downloaded bundle with zero repo imports beyond itself', async () => {
    const artifactId = uuidv4();
    await appendAllow(artifactId);

    const r = await request(app).get(`/evidence/package/${artifactId}/bundle`);
    // Round-trip through JSON exactly as an external auditor downloading the
    // file would receive it.
    const downloaded = JSON.parse(JSON.stringify(r.body.data));

    const result = externalBundleVerifier.verifyEvidenceBundle(downloaded, TRUST());
    expect(result.bundleHashValid).toBe(true);
    expect(result.bundleSignatureValid).toBe(true);
    expect(result.packageValid).toBe(true);
    // No published root in this test process — nothing to check, must not
    // fail the bundle.
    expect(result.transparencyProofValid).toBeNull();
    expect(result.valid).toBe(true);
  });

  test('EV-BUNDLE-05  tampering with the downloaded bundle after export is detected offline', async () => {
    const artifactId = uuidv4();
    await appendAllow(artifactId);

    const r = await request(app).get(`/evidence/package/${artifactId}/bundle`);
    const genuine  = JSON.parse(JSON.stringify(r.body.data));
    const tampered = JSON.parse(JSON.stringify(r.body.data));
    tampered.evidencePackage.sections.artifact.decision = 'BLOCK';

    expect(externalBundleVerifier.verifyEvidenceBundle(genuine, TRUST()).valid).toBe(true);
    const forged = externalBundleVerifier.verifyEvidenceBundle(tampered, TRUST());
    expect(forged.valid).toBe(false);
    expect(forged.bundleHashValid).toBe(false);
  });

  test('EV-BUNDLE-06  tools/verify/verify.bundle.external.js runs as a standalone child process with no repo/network/DB access and reaches the same verdict', async () => {
    const { spawnSync } = require('child_process');
    const fs   = require('fs');
    const path = require('path');
    const os   = require('os');

    const artifactId = uuidv4();
    await appendAllow(artifactId);
    const r = await request(app).get(`/evidence/package/${artifactId}/bundle`);

    const tmpFile = path.join(os.tmpdir(), `qodiqa-bundle-${uuidv4()}.json`);
    fs.writeFileSync(tmpFile, JSON.stringify(r.body));
    try {
      const keysFile = path.join(os.tmpdir(), `qodiqa-keys-${uuidv4()}.json`);
      fs.writeFileSync(keysFile, JSON.stringify({ keys: TRUST().trustedKeys }));
      const proc = spawnSync(process.execPath, [
        path.join(__dirname, '..', '..', '..', '..', 'tools/verify/verify.bundle.external.js'),
        '--keys', keysFile, tmpFile,
      ], { encoding: 'utf8' });
      fs.unlinkSync(keysFile);

      expect(proc.status).toBe(0);
      const output = JSON.parse(proc.stdout);
      expect(output.valid).toBe(true);
      expect(output.bundleHashValid).toBe(true);
      expect(output.bundleSignatureValid).toBe(true);
      expect(output.packageValid).toBe(true);
    } finally {
      fs.unlinkSync(tmpFile);
    }
  });
});
