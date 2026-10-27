'use strict';

/**
 * QODIQA end-to-end example — uses the maintained JavaScript SDK
 * (sdk/javascript, required here via a relative path since this demo
 * repository does not publish it to npm; see README.md "Quick start").
 *
 * Prerequisites:
 *   1. Build the SDK once:      npm run sdk:build
 *   2. Start the server:        npm run dev
 *      (prints a per-identity "Signing API Key" to the console on startup —
 *      TRUST-1 remediation: there is no more shared QODIQA_SIGN_TOKEN)
 *   3. Run this example with that key:
 *        QODIQA_SIGN_TOKEN=<printed-key> node examples/quickstart.js
 *
 * See docs/guides/quickstart.md for the full walkthrough, including provisioning
 * PostgreSQL-backed consent (required for a genuine EXECUTE decision).
 */

const { QodiqaClient } = require('../sdk/javascript/dist/index.js');

const BASE_URL   = process.env.QODIQA_BASE_URL || 'http://localhost:3000';
const SIGN_TOKEN = process.env.QODIQA_SIGN_TOKEN;
const PROVIDER   = process.env.QODIQA_PROVIDER; // optional — only needed if more than one provider is configured
const MODEL      = process.env.QODIQA_MODEL;     // optional — e.g. a model name pulled in a local Ollama instance
const PROMPT     = 'Hello, what is 2 + 2?';
const CHAT_BODY  = MODEL ? { prompt: PROMPT, model: MODEL } : { prompt: PROMPT };

if (!SIGN_TOKEN) {
  console.error(
    'QODIQA_SIGN_TOKEN is not set.\n\n' +
    'Start the server first, in another terminal:\n' +
    '  npm run dev\n\n' +
    'Copy the "Signing API Key" it prints on startup, then re-run this example:\n' +
    '  QODIQA_SIGN_TOKEN=<printed-key> node examples/quickstart.js\n',
  );
  process.exit(1);
}

const client = new QodiqaClient({ baseUrl: BASE_URL, signToken: SIGN_TOKEN });

async function main() {
  console.log('── Without enforcement ──────────────────────────────');
  try {
    const raw = await fetch(`${BASE_URL}/ai/chat`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(CHAT_BODY),
    });
    const data = await raw.json();
    console.log('decision:', data.decision);
    console.log('reason:  ', data.reason);
  } catch (e) {
    console.log('error:', e.message);
  }

  console.log();
  console.log('── With the QODIQA SDK ──────────────────────────────');
  try {
    const signed = await client.sign.sign({
      request: { method: 'POST', path: '/ai/chat', body: CHAT_BODY },
      ...(PROVIDER ? { payload: { provider: PROVIDER } } : {}),
    });

    const artifactB64 = Buffer.from(JSON.stringify(signed.artifact)).toString('base64');
    const result = await client.chat.create(artifactB64, CHAT_BODY);

    console.log('Decision:', result.decision);
    console.log('Reason:  ', result.reason);
    console.log('AI text: ', result.aiText);
  } catch (e) {
    console.log('error:', e.message, e.details ? JSON.stringify(e.details) : '');
  }
}

main();
