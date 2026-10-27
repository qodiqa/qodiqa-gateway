'use strict';

/**
 * Disposable local AI provider stub for /ai/chat acceptance tests.
 *
 * QODIQA's `local` provider (services/providers/local.js) is a first-class,
 * production-supported deployment mode: any self-hosted runtime exposing an
 * OpenAI-compatible `POST /chat/completions` (Ollama, llama.cpp, LM Studio,
 * ...), configured via LOCAL_BASE_URL. This starts a minimal, real HTTP
 * server implementing exactly that documented contract — it is a genuine
 * instance of an already-supported provider topology, not a mock of any
 * QODIQA code under test. Needed because reaching a genuine decision:EXECUTE
 * via /ai/chat (as opposed to /verify, whose nonce store is deliberately
 * read-only/dry-run — see src/validation/dryRunStores.js) requires the
 * pipeline to actually complete a provider call.
 */

const http = require('http');
const crypto = require('crypto');

/**
 * @param {{ replyText?: string, delayMs?: number, neverRespond?: boolean, failStatus?: number }} [opts]
 *   delayMs      — wait this long before writing the response (default 0).
 *   neverRespond — accept the connection and read the request, but never
 *                  write any response at all (simulates a truly hung
 *                  provider, distinct from a merely slow one).
 *   failStatus   — if set, always respond with this HTTP status (e.g. 429)
 *                  and an OpenAI-shaped error body, instead of a successful
 *                  completion — simulates a provider that is consistently
 *                  rate-limited/unavailable (used to test bounded retry and
 *                  failover, since a real backend can't be told to fail only
 *                  once deterministically from a test).
 * @returns {Promise<{ baseUrl: string, port: number, requestCount: () => number, stop: () => Promise<void> }>}
 */
function startLocalProvider(opts = {}) {
  const replyText = opts.replyText || 'Acceptance test canned reply.';
  const delayMs = opts.delayMs || 0;
  const neverRespond = opts.neverRespond === true;
  const failStatus = opts.failStatus || null;
  let requestCount = 0;

  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      if (req.method !== 'POST' || !req.url.endsWith('/chat/completions')) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'not found' }));
        return;
      }

      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        requestCount += 1;
        if (neverRespond) return; // deliberately hang — connection stays open, no response ever

        if (failStatus) {
          res.writeHead(failStatus, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { message: `Simulated ${failStatus} from acceptance test stub`, type: 'acceptance_test_error' } }));
          return;
        }

        let parsed = {};
        try { parsed = JSON.parse(body); } catch { /* tolerate empty/invalid body */ }

        const responsePayload = {
          id: `chatcmpl-${crypto.randomUUID()}`,
          object: 'chat.completion',
          model: parsed.model || 'acceptance-test-model',
          choices: [
            { index: 0, message: { role: 'assistant', content: replyText }, finish_reason: 'stop' },
          ],
          usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 },
        };

        const send = () => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(responsePayload));
        };
        if (delayMs > 0) setTimeout(send, delayMs);
        else send();
      });
    });

    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        baseUrl: `http://127.0.0.1:${port}/v1`,
        port,
        requestCount: () => requestCount,
        stop: () => new Promise((res) => server.close(() => res())),
      });
    });
  });
}

module.exports = { startLocalProvider };
