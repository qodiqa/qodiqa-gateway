'use strict';

/**
 * QODIQA SDK — Node.js basic usage example
 *
 * Prerequisites:
 *   npm install  (inside sdk/javascript)
 *   npm run build
 *
 * Run:
 *   QODIQA_API_KEY=ok_<64hex> QODIQA_BASE_URL=http://localhost:3000 node examples/node/basic.js
 */

const { QodiqaClient } = require('@qodiqa/sdk');

const client = new QodiqaClient({
  apiKey: process.env.QODIQA_API_KEY,
  signToken: process.env.QODIQA_SIGN_TOKEN,
  baseUrl: process.env.QODIQA_BASE_URL || 'http://localhost:3000',
  timeout: 30_000,
  maxRetries: 2,
});

async function main() {
  // -------------------------------------------------------------------------
  // 1. Health check
  // -------------------------------------------------------------------------
  console.log('\n--- Health check ---');
  const health = await client.healthCheck();
  console.log('Health:', health);

  // -------------------------------------------------------------------------
  // 2. Readiness check
  // -------------------------------------------------------------------------
  console.log('\n--- Readiness check ---');
  const ready = await client.readinessCheck();
  console.log('Ready:', ready.ready);
  console.log('Components:', ready.components);

  // -------------------------------------------------------------------------
  // 3. Get public keys
  // -------------------------------------------------------------------------
  console.log('\n--- Public keys ---');
  const keys = await client.getPublicKeys();
  console.log('Active keys:', keys.keys.length);
  if (keys.keys[0]) {
    console.log('First key ID:', keys.keys[0].keyId);
    console.log('Algorithm:', keys.keys[0].algorithm);
    console.log('Status:', keys.keys[0].status);
  }

  // -------------------------------------------------------------------------
  // 4. Sign a request (requires signToken)
  // -------------------------------------------------------------------------
  if (!process.env.QODIQA_SIGN_TOKEN) {
    console.log('\n--- Skipping sign/chat (QODIQA_SIGN_TOKEN not set) ---');
    return;
  }

  console.log('\n--- Signing a request ---');
  // `payload.provider` is not set here — /sign auto-resolves it to the
  // single enabled AI provider. With more than one provider configured,
  // /sign returns 400 PROVIDER_REQUIRED and payload.provider must be set
  // explicitly (e.g. payload: { provider: 'openai' }). See api.md#sign.
  //
  // CHAT_BODY MUST be byte-identical to what is actually sent to
  // /ai/chat below — the artifact's requestHash binds the exact signed
  // body, so signing one shape (e.g. missing `model`) and then executing
  // a different one fails closed with REQUEST_MISMATCH. Defining it once
  // and reusing it for both calls, rather than re-typing the body
  // literal twice, makes that class of mistake structurally impossible.
  const CHAT_BODY = { prompt: 'Explain quantum computing in simple terms.', model: 'gpt-4' };
  const signed = await client.sign.sign({
    request: {
      method: 'POST',
      path: '/ai/chat',
      body: CHAT_BODY,
    },
    payload: {
      userId: 'user_123',
      sessionId: 'session_abc',
    },
    ttl: 300_000, // 5 minutes
  });

  console.log('Artifact ID:', signed.artifactId);
  console.log('Key ID:', signed.meta.keyId);
  console.log('Expires at:', new Date(signed.meta.expiresAt).toISOString());

  // -------------------------------------------------------------------------
  // 5. Execute AI chat with enforcement
  // -------------------------------------------------------------------------
  console.log('\n--- AI Chat ---');
  const artifactB64 = Buffer.from(JSON.stringify(signed.artifact)).toString('base64');

  const chat = await client.chat.create(artifactB64, CHAT_BODY);

  console.log('Decision:', chat.decision);
  console.log('Reason:', chat.reason);

  if (chat.decision === 'EXECUTE' && chat.aiText) {
    console.log('\nAI Response:');
    console.log(chat.aiText);
    if (chat.tokenUsage) {
      console.log('\nTokens used:', chat.tokenUsage.total_tokens);
    }
  } else {
    console.log('Request was blocked:', chat.reason);
  }

  // -------------------------------------------------------------------------
  // 6. Verify an artifact
  // -------------------------------------------------------------------------
  // This reuses the SAME artifact the /ai/chat call above already executed,
  // whose one-time nonce is now consumed — so a correctly-working replay
  // guard will report BLOCK/REPLAY_DETECTED here, not a clean pass. That is
  // expected and is itself a real demonstration of replay protection, not
  // a failure of this example. Verifying a not-yet-executed artifact would
  // instead need a second, freshly signed artifact never sent to /ai/chat.
  console.log('\n--- Verify artifact ---');
  const verification = await client.verify.verify(artifactB64, {
    artifact: signed.artifact,
    request: {
      method: 'POST',
      path: '/ai/chat',
      body: CHAT_BODY,
    },
  });

  console.log('Verify decision:', verification.decision);
  console.log('Verify reason:', verification.reason);

  // -------------------------------------------------------------------------
  // 7. Audit chain
  // -------------------------------------------------------------------------
  console.log('\n--- Audit chain ---');
  try {
    // Needs QODIQA_API_KEY (ops key with READ_AUDIT). The route answers the standard
    // success envelope, so the audit record is `.data`.
    const { data: audit } = await client.getAuditChain(signed.artifactId);
    console.log('Artifact:', audit.artifactId);
    console.log('Decision:', audit.decision);
    console.log('Chain length:', audit.chain.length);
  } catch (err) {
    console.log('Audit chain not available yet:', err.message);
  }

  // -------------------------------------------------------------------------
  // 8. Transparency log
  // -------------------------------------------------------------------------
  console.log('\n--- Transparency log entries ---');
  try {
    const entries = await client.transparency.listEntries({ page: 1, pageSize: 5 });
    console.log('Total entries:', entries.data.total);
    console.log('Returned:', entries.data.entries.length);
  } catch (err) {
    console.log('Transparency log unavailable:', err.message);
  }

  // -------------------------------------------------------------------------
  // 9. Portal verification — synchronous, no polling
  // -------------------------------------------------------------------------
  console.log('\n--- Portal verification ---');
  try {
    const verifyRes = await client.portal.verify(signed.artifact);
    console.log('Verification ID:', verifyRes.data.verificationId);
    console.log('Overall result:', verifyRes.data.overallResult);
    if (verifyRes.data.warnings.length > 0) {
      console.log('Warnings:', verifyRes.data.warnings);
    }

    // getResult() only succeeds if PostgreSQL is enabled server-side — the
    // portal's history store is Postgres-only, and a disabled deployment
    // never persists the record verify() just returned.
    try {
      const resultRes = await client.portal.getResult(verifyRes.data.verificationId);
      console.log('Persisted record found:', resultRes.data.verification.overall_result);
    } catch (err) {
      console.log('getResult() unavailable (likely PostgreSQL disabled):', err.message);
    }
  } catch (err) {
    console.log('Portal verification failed:', err.message);
  }
}

main().catch((err) => {
  console.error('\nError:', err.message);
  if (err.status) console.error('HTTP Status:', err.status);
  if (err.requestId) console.error('Request ID:', err.requestId);
  if (err.details) console.error('Details:', err.details);
  process.exit(1);
});
