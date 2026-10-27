'use strict';

/**
 * QODIQA SDK — Node.js streaming usage example
 *
 * Prerequisites:
 *   npm install  (inside sdk/javascript)
 *   npm run build
 *
 * Run:
 *   QODIQA_SIGN_TOKEN=<printed-signing-key> QODIQA_BASE_URL=http://localhost:3000 node examples/node/streaming.js
 */

const { QodiqaClient, QodiqaError, TimeoutError, VerificationError } = require('@qodiqa/sdk');

const client = new QodiqaClient({
  signToken: process.env.QODIQA_SIGN_TOKEN,
  baseUrl: process.env.QODIQA_BASE_URL || 'http://localhost:3000',
  timeout: 30_000,
});

async function main() {
  if (!process.env.QODIQA_SIGN_TOKEN) {
    console.log('QODIQA_SIGN_TOKEN not set — start the server and copy the printed signing key.');
    return;
  }

  // `stream: true` must be part of the exact body signed below — the server
  // binds the artifact to this body via requestHash, so the same object is
  // reused for both the sign call and the stream call rather than
  // reconstructed.
  const CHAT_BODY = {
    prompt: 'Explain how QODIQA enforces AI execution, in three sentences.',
    model: 'gpt-4',
    stream: true,
  };

  console.log('--- Signing ---');
  // payload.provider is omitted here — /sign auto-resolves it to the single
  // enabled AI provider. With more than one provider configured, pass
  // payload: { provider: 'openai' } explicitly (400 PROVIDER_REQUIRED
  // otherwise). See README.md "sign" under Resources.
  const signed = await client.sign.sign({
    request: { method: 'POST', path: '/ai/chat', body: CHAT_BODY },
    payload: { userId: 'streaming-example' },
    ttl: 300_000,
  });
  const artifactB64 = Buffer.from(JSON.stringify(signed.artifact)).toString('base64');
  console.log('Artifact ID:', signed.artifactId);

  // Cancellation: an AbortController tied to a caller-side deadline. Ctrl+C
  // (SIGINT) also aborts cleanly — see the process.on('SIGINT', ...) below —
  // demonstrating that breaking a `for await` loop, an explicit signal
  // abort, and process interruption all release the connection the same way.
  const controller = new AbortController();
  const onSigint = () => controller.abort();
  process.on('SIGINT', onSigint);

  console.log('\n--- Streaming ---');
  try {
    for await (const event of client.chat.stream(artifactB64, CHAT_BODY, { signal: controller.signal })) {
      switch (event.event) {
        case 'stream_started':
          console.log(`[${event.provider}/${event.model}]`);
          break;
        case 'chunk_forwarded':
          process.stdout.write(event.delta);
          break;
        case 'stream_completed':
          console.log(`\n\ndone — ${event.chunksTotal} chunks, ${event.bytesTotal} bytes, ${event.durationMs}ms`);
          break;
        case 'stream_cancelled':
          console.log(`\n\ncancelled: ${event.reason}`);
          break;
      }
    }
  } catch (err) {
    if (err instanceof VerificationError) {
      // Most common cause: the body signed above didn't include `stream: true`.
      console.error('\nartifact/request mismatch:', err.message);
    } else if (err instanceof TimeoutError) {
      console.error('\nstream exceeded its timeout budget');
    } else if (err instanceof QodiqaError) {
      console.error(`\n[${err.status ?? 'n/a'}] ${err.message}`, err.details);
    } else {
      throw err;
    }
  } finally {
    process.off('SIGINT', onSigint);
  }
}

main().catch((err) => {
  console.error('\nError:', err.message);
  process.exit(1);
});
