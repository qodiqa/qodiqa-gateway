'use strict';

/**
 * The sandbox AI provider: a deterministic, OpenAI-compatible server on loopback so that `qodiqa dev` works without any provider account. It is a stand-in for the MODEL only -
 * every request still goes through the real gateway (verification, policies, audit). It never calls the network, keeps nothing, and labels every answer as a sandbox answer.
 *
 *   GET  /v1/models
 *   POST /v1/chat/completions   { model, messages: [{role, content}], stream? }
 *
 * The answer is `[sandbox] <last user message>` (cut to 2,000 characters); usage is a plain character count / 4 so cost accounting and budgets can be tried out.
 */

const http = require('http');

const MODEL = 'sandbox-echo-1';
const MAX_BODY = 1_000_000;

function lastUserText(messages) {
  if (!Array.isArray(messages)) return '';
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i];
    if (m && m.role === 'user') {
      if (typeof m.content === 'string') return m.content;
      if (Array.isArray(m.content)) return m.content.map((p) => (p && typeof p.text === 'string' ? p.text : '')).join('');
    }
  }
  return '';
}

const tokens = (s) => Math.max(1, Math.ceil(String(s).length / 4));

function start({ port = 0, host = '127.0.0.1' } = {}) {
  const server = http.createServer((req, res) => {
    const send = (status, body, headers = {}) => { const p = JSON.stringify(body); res.writeHead(status, { 'content-type': 'application/json', 'x-qodiqa-sandbox': 'true', ...headers }); res.end(p); };
    if (req.method === 'GET' && req.url.startsWith('/v1/models')) return send(200, { object: 'list', data: [{ id: MODEL, object: 'model', owned_by: 'qodiqa-sandbox' }] });
    if (req.method !== 'POST' || !req.url.startsWith('/v1/chat/completions')) return send(404, { error: { message: 'not found' } });
    const chunks = []; let size = 0;
    req.on('data', (c) => { size += c.length; if (size > MAX_BODY) { req.destroy(); } else chunks.push(c); });
    req.on('end', () => {
      let body;
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return send(400, { error: { message: 'invalid JSON' } }); }
      const prompt = lastUserText(body.messages);
      const answer = `[sandbox] ${prompt}`.slice(0, 2000);
      const usage = { prompt_tokens: tokens(JSON.stringify(body.messages || [])), completion_tokens: tokens(answer) };
      usage.total_tokens = usage.prompt_tokens + usage.completion_tokens;
      const id = `chatcmpl-sandbox-${Date.now().toString(36)}`;
      const created = Math.floor(Date.now() / 1000);
      if (body.stream === true) {
        res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', 'x-qodiqa-sandbox': 'true' });
        const words = answer.split(/(\s+)/).filter(Boolean);
        for (const w of words) res.write(`data: ${JSON.stringify({ id, object: 'chat.completion.chunk', created, model: MODEL, choices: [{ index: 0, delta: { content: w }, finish_reason: null }] })}\n\n`);
        res.write(`data: ${JSON.stringify({ id, object: 'chat.completion.chunk', created, model: MODEL, choices: [{ index: 0, delta: {}, finish_reason: 'stop' }], usage })}\n\n`);
        res.end('data: [DONE]\n\n');
        return undefined;
      }
      return send(200, { id, object: 'chat.completion', created, model: MODEL, choices: [{ index: 0, message: { role: 'assistant', content: answer }, finish_reason: 'stop' }], usage });
    });
    return undefined;
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve({ server, url: `http://${host}:${server.address().port}/v1`, model: MODEL, close: () => new Promise((r) => server.close(() => r())) }));
  });
}

module.exports = { start, MODEL };
