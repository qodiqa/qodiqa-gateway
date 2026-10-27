'use strict';

/**
 * QODIQA SDK — Local (offline) artifact verification example
 *
 * Demonstrates verifying a signed artifact's Ed25519 signature, canonical
 * JSON, and key validity entirely on the client — WITHOUT ever calling the
 * server's `/verify` endpoint or trusting its response. Also demonstrates
 * verifying an attached transparency inclusion proof.
 *
 * Prerequisites:
 *   npm install  (inside sdk/javascript)
 *   npm run build
 *
 * Run:
 *   QODIQA_BASE_URL=http://localhost:3000 node examples/node/verify-artifact-offline.js
 */

const { QodiqaClient, ArtifactVerifier, RemoteKeyProvider } = require('@qodiqa/sdk');

const baseUrl = process.env.QODIQA_BASE_URL || 'http://localhost:3000';

async function main() {
  const client = new QodiqaClient({ signToken: process.env.QODIQA_SIGN_TOKEN, baseUrl });

  // 1. Obtain a signed artifact the normal way (server-side signing is not
  //    part of this remediation — only verification moves client-side).
  const signed = await client.sign.sign({
    request: { method: 'POST', path: '/ai/chat', body: { prompt: 'Hello' } },
    payload: { userId: 'user_123' },
    ttl: 300_000,
  });

  // 2. Configure two SEPARATE key providers — one for artifact-signing keys,
  //    one for transparency-signing keys. These are cryptographically
  //    distinct trust domains server-side; never point both at the same
  //    source, or that separation is silently defeated.
  const artifactKeys = new RemoteKeyProvider({ discoveryUrl: `${baseUrl}/.well-known/qodiqa/keys` });
  const transparencyKeys = new RemoteKeyProvider({ discoveryUrl: `${baseUrl}/.well-known/qodiqa/transparency-keys` });

  const verifier = new ArtifactVerifier({ keys: artifactKeys, transparencyKeys });

  // 3. Verify entirely locally. No network call happens here beyond the
  //    one-time (cached) key-list fetch above.
  const result = await verifier.verify(signed.artifact);

  console.log('\n--- Local verification result ---');
  console.log('verificationStatus:  ', result.verificationStatus);
  console.log('signatureValid:      ', result.signatureValid);
  console.log('canonicalizationValid:', result.canonicalizationValid);
  console.log('keyValid:            ', result.keyValid, `(${result.keyId}, ${result.keyStatus})`);
  console.log('timestampValid:      ', result.timestampValid);
  console.log('expiryValid:         ', result.expiryValid);
  console.log('transparencyVerified:', result.transparencyVerified); // 'unavailable' — no proof supplied above

  if (result.verificationStatus !== 'valid') {
    console.log('failedStage:  ', result.failedStage);
    console.log('errors:       ', result.verificationErrors);
    return;
  }

  // 4. Optional: fetch and locally verify a transparency inclusion proof for
  //    an artifact already registered in the transparency log.
  //
  // const proofResponse = await client.transparency.getProof(someTransparencyId);
  // const resultWithProof = await verifier.verify(signed.artifact, {
  //   transparencyProof: proofResponse.data.proof,
  // });
  // console.log('transparencyVerified:', resultWithProof.transparencyVerified); // 'verified' | 'failed'
}

main().catch((err) => {
  console.error('Error:', err.message);
  process.exitCode = 1;
});
