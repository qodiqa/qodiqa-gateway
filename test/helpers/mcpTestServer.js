'use strict';

/**
 * A minimal MCP server over streamable HTTP for tests: loopback only, ephemeral port, JSON or SSE answers, programmable tools. Never started by production code.
 *
 *   const s = await startMcpTestServer({ mode: 'json'|'sse', tools: [...], handlers: { name: (args, ctx) => result } });
 *   s.url, s.calls (every tools/call received: { name, args, sessionId }), s.requests (every HTTP request), await s.close()
 */

const http = require('http');
const crypto = require('crypto');

const DEFAULT_TOOLS = [
  { name: 'echo', description: 'Echo the text back', inputSchema: { type: 'object', required: ['text'], properties: { text: { type: 'string' } }, additionalProperties: false } },
  { name: 'read_file', description: 'Read a file', inputSchema: { type: 'object', required: ['path'], properties: { path: { type: 'string' } }, additionalProperties: false } },
];

async function startMcpTestServer({ mode = 'json', tools = DEFAULT_TOOLS, handlers = {}, delayMs = 0, redirectTo = null, oversize = 0, serverInfo = { name: 'test-mcp', version: '0.0.1' } } = {}) {
  const calls = []; const requests = []; const sessions = new Set();
  const textResult = (text) => ({ content: [{ type: 'text', text }] });
  const defaults = { echo: (a) => textResult(String(a.text)), read_file: (a) => textResult(`contents of ${a.path}`) };

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (d) => chunks.push(d));
    req.on('end', async () => {
      requests.push({ method: req.method, url: req.url, headers: req.headers });
      if (redirectTo) { res.writeHead(302, { location: redirectTo }); return res.end(); }
      if (req.method === 'DELETE') { sessions.delete(req.headers['mcp-session-id']); res.writeHead(204); return res.end(); }
      let msg; try { msg = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { res.writeHead(400); return res.end(); }
      const reply = (result, error, headers = {}) => {
        const body = JSON.stringify({ jsonrpc: '2.0', id: msg.id, ...(error ? { error } : { result }) });
        if (mode === 'sse') {
          res.writeHead(200, { 'content-type': 'text/event-stream', ...headers });
          res.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/progress', params: { progress: 1 } })}\n\n`);
          res.write(`event: message\ndata: ${body}\n\n`);
          return setTimeout(() => res.end(), 20);
        }
        res.writeHead(200, { 'content-type': 'application/json', ...headers });
        return res.end(body);
      };
      if (delayMs) await new Promise((r) => setTimeout(r, delayMs));
      if (msg.method === 'notifications/initialized') { res.writeHead(202); return res.end(); }
      if (msg.method === 'initialize') { const sid = crypto.randomUUID(); sessions.add(sid); return reply({ protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo }, null, { 'mcp-session-id': sid }); }
      if (msg.method === 'tools/list') return reply({ tools });
      if (msg.method === 'tools/call') {
        const { name, arguments: args } = msg.params || {};
        calls.push({ name, args, sessionId: req.headers['mcp-session-id'] });
        const h = handlers[name] || defaults[name];
        if (!h) return reply(null, { code: -32602, message: `unknown tool ${name}` });
        try {
          const r = await h(args, { sessionId: req.headers['mcp-session-id'] });
          if (oversize) r.content.push({ type: 'text', text: 'x'.repeat(oversize) });
          return reply(r);
        } catch (e) { return reply(null, { code: -32000, message: e.message }); }
      }
      return reply(null, { code: -32601, message: 'method not found' });
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  return { url: `http://127.0.0.1:${port}/mcp`, port, calls, requests, sessions, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }) };
}

module.exports = { startMcpTestServer, DEFAULT_TOOLS };
