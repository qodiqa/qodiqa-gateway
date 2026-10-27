/**
 * QODIQA SDK — TypeScript basic usage example
 *
 * Run (after build):
 *   npx ts-node examples/typescript/basic.ts
 */

import {
  QodiqaClient,
  QodiqaError,
  AuthenticationError,
  RateLimitError,
  type SignResponse,
  type ChatResponse,
  type VerifyResponse,
  type HealthResponse,
  type KeysResponse,
} from '@qodiqa/sdk';

// ---------------------------------------------------------------------------
// Client setup
// ---------------------------------------------------------------------------

const client = new QodiqaClient({
  apiKey: process.env['QODIQA_API_KEY'],
  signToken: process.env['QODIQA_SIGN_TOKEN'],
  baseUrl: process.env['QODIQA_BASE_URL'] ?? 'http://localhost:3000',
  timeout: 30_000,
  maxRetries: 2,
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function artifactToBase64(artifact: SignResponse['artifact']): string {
  return Buffer.from(JSON.stringify(artifact)).toString('base64');
}

function printSection(title: string): void {
  const bar = '='.repeat(50);
  console.log(`\n${bar}\n${title}\n${bar}`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  // -------------------------------------------------------------------------
  // Health and readiness
  // -------------------------------------------------------------------------
  printSection('Health and Readiness');

  const health: HealthResponse = await client.healthCheck();
  console.log(`Server status: ${health.status} | Uptime: ${health.uptime}s`);

  const ready = await client.readinessCheck();
  console.log(`Ready: ${ready.ready}`);
  console.log(`  nonceStore: ${ready.components.nonceStore}`);
  console.log(`  anomalyStore: ${ready.components.anomalyStore}`);
  console.log(`  rateLimitStore: ${ready.components.rateLimitStore}`);

  // -------------------------------------------------------------------------
  // Public key discovery
  // -------------------------------------------------------------------------
  printSection('Key Discovery');

  const keysResponse: KeysResponse = await client.getPublicKeys();
  console.log(`Total active keys: ${keysResponse.keys.length}`);
  for (const key of keysResponse.keys) {
    console.log(`  - ${key.keyId} [${key.algorithm}] -- ${key.status}`);
  }

  // -------------------------------------------------------------------------
  // Sign a request
  // -------------------------------------------------------------------------
  if (!process.env['QODIQA_SIGN_TOKEN']) {
    console.log('\nSkipping sign/chat/verify -- QODIQA_SIGN_TOKEN not set');
    return;
  }

  printSection('Signing');

  // `payload.provider` is not set here — /sign auto-resolves it to the
  // single enabled AI provider. With more than one provider configured,
  // /sign returns 400 PROVIDER_REQUIRED and payload.provider must be set
  // explicitly (e.g. payload: { provider: 'openai' }). See api.md#sign.
  const signed: SignResponse = await client.sign.sign({
    request: {
      method: 'POST',
      path: '/ai/chat',
      body: { prompt: 'What is the speed of light?' },
    },
    payload: {
      userId: 'user_42',
      role: 'researcher',
    },
    ttl: 300_000,
  });

  console.log(`Artifact ID: ${signed.artifactId}`);
  console.log(`Key ID: ${signed.meta.keyId}`);
  console.log(`Tenant: ${signed.meta.tenantId}`);
  console.log(`Expires: ${new Date(signed.meta.expiresAt).toISOString()}`);

  const artifactB64 = artifactToBase64(signed.artifact);

  // -------------------------------------------------------------------------
  // AI Chat with enforcement
  // -------------------------------------------------------------------------
  printSection('AI Chat (enforced)');

  const chat: ChatResponse = await client.chat.create(artifactB64, {
    prompt: 'What is the speed of light?',
    model: 'gpt-4',
  });

  console.log(`Decision: ${chat.decision}`);
  console.log(`Reason: ${chat.reason}`);

  if (chat.decision === 'EXECUTE') {
    console.log(`\nAI Response: ${chat.aiText ?? '(no text)'}`);
    if (chat.tokenUsage) {
      const { prompt_tokens, completion_tokens, total_tokens } = chat.tokenUsage;
      console.log(`Tokens: ${prompt_tokens} prompt + ${completion_tokens} completion = ${total_tokens} total`);
    }
  }

  // -------------------------------------------------------------------------
  // Verify artifact
  // -------------------------------------------------------------------------
  printSection('Verification');

  const verification: VerifyResponse = await client.verify.verify(artifactB64, {
    artifact: signed.artifact,
    request: {
      method: 'POST',
      path: '/ai/chat',
      body: { prompt: 'What is the speed of light?' },
    },
  });

  console.log(`Decision: ${verification.decision}`);
  console.log(`Reason: ${verification.reason}`);

  // -------------------------------------------------------------------------
  // Dry-run verify
  // -------------------------------------------------------------------------
  printSection('Dry-run Verification');

  const dryRun: VerifyResponse = await client.verify.dryRun({
    artifact: signed.artifact,
    request: {
      method: 'POST',
      path: '/ai/chat',
      body: { prompt: 'What is the speed of light?' },
    },
  });

  console.log(`Dry-run decision: ${dryRun.decision}`);

  // -------------------------------------------------------------------------
  // Transparency log
  // -------------------------------------------------------------------------
  printSection('Transparency Log');

  try {
    const root = await client.transparency.getRoot();
    // `root` is null on a log that has no signed root yet (see TransparencyLatestRoot).
    console.log(`Log root: ${root.data.root ? root.data.root.root_id : '(none yet)'}`);
    console.log(`Entries: ${root.data.root ? root.data.root.entry_count : 0}`);

    const entries = await client.transparency.listEntries({ page: 1, pageSize: 3 });
    console.log(`Recent entries (${entries.data.entries.length} of ${entries.data.total}):`);
    for (const entry of entries.data.entries) {
      console.log(`  - [${entry.id}] ${entry.transparency_id} -- ${entry.created_at}`);
    }
  } catch (err: unknown) {
    if (err instanceof QodiqaError) {
      console.log(`Transparency log unavailable: ${err.message}`);
    }
  }

  // -------------------------------------------------------------------------
  // Attestation
  // -------------------------------------------------------------------------
  printSection('Attestation');

  try {
    const attestation = await client.attestation.verify({ artifact: signed.artifact });
    console.log(`Attestation ID: ${attestation.data.attestationId}`);
    console.log(`Status: ${attestation.data.status}`);
  } catch (err: unknown) {
    if (err instanceof QodiqaError) {
      console.log(`Attestation failed: ${err.message}`);
    }
  }

  // -------------------------------------------------------------------------
  // Certification evaluation
  // -------------------------------------------------------------------------
  printSection('Certification Evaluation');

  try {
    const certification = await client.certification.evaluate({
      artifacts: [signed.artifact as unknown as Record<string, unknown>],
    });
    console.log(`Certification ID: ${certification.data.id}`);
    console.log(`Status: ${certification.data.status}`);
    if (certification.data.score !== undefined) {
      console.log(`Score: ${certification.data.score}`);
    }
  } catch (err: unknown) {
    if (err instanceof QodiqaError) {
      console.log(`Certification failed: ${err.message}`);
    }
  }

  console.log('\nDone.');
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

main().catch((err: unknown) => {
  if (err instanceof AuthenticationError) {
    console.error('\nAuthentication failed. Check your API key / sign token.');
    console.error('Message:', err.message);
  } else if (err instanceof RateLimitError) {
    console.error('\nRate limited.');
    if (err.retryAfter !== undefined) {
      console.error(`Retry after: ${err.retryAfter}s`);
    }
  } else if (err instanceof QodiqaError) {
    console.error('\nQODIQA error:', err.message);
    if (err.status) console.error('HTTP status:', err.status);
    if (err.requestId) console.error('Request ID:', err.requestId);
    if (Object.keys(err.details).length > 0) {
      console.error('Details:', JSON.stringify(err.details, null, 2));
    }
  } else {
    console.error('\nUnexpected error:', err);
  }
  process.exit(1);
});
