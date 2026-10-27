#!/usr/bin/env node
'use strict';

/**
 * QODIQA SDK — Node.js CLI example
 *
 * A minimal command-line tool demonstrating QODIQA SDK usage in a CLI context.
 *
 * Usage:
 *   node examples/node/cli.js health
 *   node examples/node/cli.js keys
 *   node examples/node/cli.js sign   --prompt "Hello world" --user user_123
 *   node examples/node/cli.js chat   --prompt "Explain quantum computing" --user user_123
 *   node examples/node/cli.js verify --artifact <base64> --prompt "Hello world"
 *   node examples/node/cli.js audit  --artifact-id art_abc123
 *
 * Environment:
 *   QODIQA_API_KEY      — ops key (ok_<64hex>), required for ops commands
 *   QODIQA_SIGN_TOKEN   — sign token, required for sign/chat commands
 *   QODIQA_BASE_URL     — API base URL (default: http://localhost:3000)
 */

const {
  QodiqaClient,
  QodiqaError,
  AuthenticationError,
  ValidationError,
  RateLimitError,
  NetworkError,
  TimeoutError,
} = require('@qodiqa/sdk');

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

const client = new QodiqaClient({
  apiKey: process.env.QODIQA_API_KEY,
  signToken: process.env.QODIQA_SIGN_TOKEN,
  baseUrl: process.env.QODIQA_BASE_URL || 'http://localhost:3000',
  timeout: 30_000,
  maxRetries: 2,
});

// ---------------------------------------------------------------------------
// Arg parsing (minimal, no external deps)
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      args[key] = next && !next.startsWith('--') ? (i++, next) : true;
    }
  }
  return args;
}

const [, , command, ...rest] = process.argv;
const flags = parseArgs(rest);

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

const commands = {
  async health() {
    const result = await client.healthCheck();
    console.log('Status:', result.status);
    console.log('Uptime:', result.uptime, 'seconds');
  },

  async keys() {
    const result = await client.getPublicKeys();
    console.log(`${result.keys.length} key(s):`);
    for (const key of result.keys) {
      console.log(`  ${key.keyId}  algorithm=${key.algorithm}  status=${key.status}`);
    }
  },

  async sign() {
    const prompt = flags.prompt;
    if (!prompt) throw new ValidationError('--prompt is required');

    // --provider is optional: /sign auto-resolves payload.provider to the
    // single enabled AI provider. It only needs to be passed explicitly
    // once more than one provider is enabled server-side (otherwise /sign
    // returns 400 PROVIDER_REQUIRED).
    const signed = await client.sign.sign({
      request: {
        method: 'POST',
        path: '/ai/chat',
        body: { prompt },
      },
      payload: {
        userId: flags.user || 'cli-user',
        ...(flags.provider ? { provider: flags.provider } : {}),
      },
      ttl: 300_000,
    });

    console.log('Artifact ID :', signed.artifactId);
    console.log('Key ID      :', signed.meta.keyId);
    console.log('Tenant      :', signed.meta.tenantId);
    console.log('Expires at  :', new Date(signed.meta.expiresAt).toISOString());
    console.log('');
    console.log('Artifact (base64):');
    console.log(Buffer.from(JSON.stringify(signed.artifact)).toString('base64'));
  },

  async chat() {
    const prompt = flags.prompt;
    if (!prompt) throw new ValidationError('--prompt is required');

    // Step 1: Sign (--provider optional — see sign() above for when it's required)
    const signed = await client.sign.sign({
      request: { method: 'POST', path: '/ai/chat', body: { prompt } },
      payload: {
        userId: flags.user || 'cli-user',
        ...(flags.provider ? { provider: flags.provider } : {}),
      },
      ttl: 300_000,
    });

    const artifactB64 = Buffer.from(JSON.stringify(signed.artifact)).toString('base64');

    // Step 2: Chat
    const chat = await client.chat.create(artifactB64, {
      prompt,
      model: flags.model,
    });

    console.log('Decision  :', chat.decision);
    console.log('Reason    :', chat.reason);
    console.log('Request ID:', chat.requestId);

    if (chat.decision === 'EXECUTE' && chat.aiText) {
      console.log('');
      console.log('Response:');
      console.log(chat.aiText);
      if (chat.tokenUsage) {
        console.log('');
        console.log(`Tokens: ${chat.tokenUsage.total_tokens} total (${chat.tokenUsage.prompt_tokens} prompt + ${chat.tokenUsage.completion_tokens} completion)`);
      }
    } else {
      console.error('Request was blocked:', chat.reason);
      process.exitCode = 1;
    }
  },

  async verify() {
    const artifactB64 = flags.artifact;
    if (!artifactB64) throw new ValidationError('--artifact is required (base64 string)');
    const prompt = flags.prompt || '';

    let artifact;
    try {
      artifact = JSON.parse(Buffer.from(artifactB64, 'base64').toString('utf8'));
    } catch {
      throw new ValidationError('--artifact is not valid base64-encoded JSON');
    }

    const result = await client.verify.verify(artifactB64, {
      artifact,
      request: {
        method: 'POST',
        path: '/ai/chat',
        body: { prompt },
      },
    });

    console.log('Decision   :', result.decision);
    console.log('Reason     :', result.reason);
    console.log('Artifact ID:', result.artifactId || 'n/a');
    console.log('Key ID     :', result.keyId || 'n/a');
    console.log('Request ID :', result.requestId);

    if (result.decision === 'BLOCK') {
      process.exitCode = 1;
    }
  },

  async audit() {
    const artifactId = flags['artifact-id'];
    if (!artifactId) throw new ValidationError('--artifact-id is required');

    // Needs QODIQA_API_KEY (ops key with READ_AUDIT); the record is the envelope's `data`.
    const { data: result } = await client.getAuditChain(artifactId);
    console.log('Artifact ID :', result.artifactId);
    console.log('Decision    :', result.decision);
    console.log('Reason      :', result.reason);
    console.log('Timestamp   :', result.timestamp);
    console.log('Chain length:', result.chain.length);
    console.log('Request ID  :', result.requestId);
  },
};

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

function printUsage() {
  console.error('Usage: node cli.js <command> [--flag value ...]');
  console.error('');
  console.error('Commands:');
  console.error('  health                              Liveness check');
  console.error('  keys                                List public signing keys');
  console.error('  sign   --prompt <text> [--user id] [--provider name]  Sign a request');
  console.error('  chat   --prompt <text> [--user id] [--provider name] [--model name]  Enforced AI chat');
  console.error('  verify --artifact <b64> [--prompt <text>]          Verify artifact');
  console.error('  audit  --artifact-id <id>           Fetch audit chain');
  console.error('');
  console.error('Environment:');
  console.error('  QODIQA_SIGN_TOKEN   Sign token (required for sign/chat)');
  console.error('  QODIQA_API_KEY      Ops API key (required for admin commands)');
  console.error('  QODIQA_BASE_URL     Server base URL (default: http://localhost:3000)');
  process.exit(1);
}

if (!command || !commands[command]) {
  printUsage();
}

commands[command]().catch((err) => {
  if (err instanceof AuthenticationError) {
    console.error('Authentication failed:', err.message);
    console.error('Ensure QODIQA_SIGN_TOKEN and/or QODIQA_API_KEY are set correctly.');
  } else if (err instanceof ValidationError) {
    console.error('Validation error:', err.message);
    if (Object.keys(err.details).length > 0) console.error('Details:', err.details);
  } else if (err instanceof RateLimitError) {
    console.error('Rate limited.', err.retryAfter ? `Retry after ${err.retryAfter}s.` : '');
  } else if (err instanceof TimeoutError) {
    console.error('Request timed out. Check QODIQA_BASE_URL and server availability.');
  } else if (err instanceof NetworkError) {
    console.error('Network error:', err.message);
  } else if (err instanceof QodiqaError) {
    console.error(`Error (HTTP ${err.status ?? 'unknown'}):`, err.message);
    if (err.requestId) console.error('Request ID:', err.requestId);
    if (Object.keys(err.details).length > 0) console.error('Details:', err.details);
  } else {
    console.error('Unexpected error:', err instanceof Error ? err.message : String(err));
  }
  process.exit(1);
});
