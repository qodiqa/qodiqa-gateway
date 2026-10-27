'use strict';

/**
 * A minimal MCP client over streamable HTTP for the tool gateway. HTTP(S) only - there is no stdio transport and nothing here starts a process.
 *
 *   withSession(server, fn, opts)   initialize -> notifications/initialized -> fn(session) -> close; `session.listTools()` / `session.callTool(name, args)`
 *   callTool(server, name, args, opts) / listTools(server, opts)    one-shot conveniences
 *
 * `server` = { url, local, pin, pinOnly } (see src/core/mcp/serverUrl.js: the destination is validated by the caller and again on every connection).
 * Hard limits, all configurable and all enforced here: a response of at most `maxResponseBytes` (default 1 MiB, then MCP_RESPONSE_TOO_LARGE), `timeoutMs`
 * (default 30 s for the whole exchange), and an AbortSignal that cancels the connection at once (kill of the session, revocation of the tool or of a delegation).
 * Redirects are never followed. A server request to the client (sampling, roots, elicitation) is refused, never answered.
 */

const http = require('http');
const https = require('https');
const { createMcpAgent } = require('./serverUrl');

const PROTOCOL_VERSION = '2025-06-18';
const CLIENT_INFO = Object.freeze({ name: 'qodiqa-tool-gateway', version: '1' });
const DEFAULTS = Object.freeze({ maxResponseBytes: 1_048_576, timeoutMs: 30_000 });

class McpCallError extends Error {
  constructor(code, message, extra = {}) { super(message || code); this.name = 'McpCallError'; this.code = code; Object.assign(this, extra); }
}

/** One JSON-RPC POST. @returns {Promise<{ status: number, headers: object, messages: object[] }>} messages = every JSON-RPC message of the response (JSON or SSE) up to the one answering `expectId` */
function post(server, body, { sessionId, signal, deadline, maxResponseBytes, expectId, agent }) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) return reject(new McpCallError('MCP_ABORTED', 'aborted'));
    const u = new URL(server.url);
    const lib = u.protocol === 'https:' ? https : http;
    const payload = Buffer.from(JSON.stringify(body), 'utf8');
    const headers = { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'content-length': payload.length, ...(sessionId ? { 'mcp-session-id': sessionId, 'mcp-protocol-version': PROTOCOL_VERSION } : {}) };
    let done = false; let bytes = 0; let req;
    const finish = (err, val) => {
      if (done) return; done = true; clearTimeout(timer); if (signal) signal.removeEventListener('abort', onAbort);
      if (err) { try { req && req.destroy(); } catch { /* already closed */ } reject(err); } else { try { req && req.destroy(); } catch { /* done reading */ } resolve(val); }
    };
    const timer = setTimeout(() => finish(new McpCallError('MCP_TIMEOUT', 'the MCP server did not answer in time')), Math.max(1, deadline - Date.now()));
    const onAbort = () => finish(new McpCallError('MCP_ABORTED', (signal.reason && signal.reason.message) || 'aborted', { cause: signal.reason }));
    if (signal) signal.addEventListener('abort', onAbort, { once: true });
    req = lib.request({ protocol: u.protocol, hostname: u.hostname.replace(/^\[|\]$/g, ''), port: u.port || undefined, path: `${u.pathname}${u.search}`, method: 'POST', headers, agent }, (res) => {
      const type = String(res.headers['content-type'] || '').toLowerCase();
      const meta = { status: res.statusCode, headers: res.headers, messages: [] };
      if (res.statusCode >= 300 && res.statusCode < 400) return finish(new McpCallError('MCP_REDIRECT_REFUSED', 'the MCP server answered with a redirect'));
      if (res.statusCode === 202 || res.statusCode === 204) { res.resume(); return res.on('end', () => finish(null, meta)); }
      if (res.statusCode < 200 || res.statusCode >= 300) { res.resume(); return finish(new McpCallError('MCP_HTTP_ERROR', `the MCP server answered HTTP ${res.statusCode}`, { httpStatus: res.statusCode })); }
      const chunks = []; let buf = '';
      res.on('data', (d) => {
        bytes += d.length;
        if (bytes > maxResponseBytes) return finish(new McpCallError('MCP_RESPONSE_TOO_LARGE', `the MCP response exceeds ${maxResponseBytes} bytes`));
        if (type.startsWith('text/event-stream')) {
          buf += d.toString('utf8');
          let i;
          while ((i = buf.search(/\r?\n\r?\n/)) >= 0) {
            const ev = buf.slice(0, i); buf = buf.slice(i).replace(/^\r?\n\r?\n/, '');
            const data = ev.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).replace(/^ /, '')).join('\n');
            if (!data) continue;
            let m; try { m = JSON.parse(data); } catch { return finish(new McpCallError('MCP_BAD_RESPONSE', 'an SSE event is not JSON')); }
            meta.messages.push(m);
            if (expectId !== undefined && m && m.id === expectId && (m.result !== undefined || m.error !== undefined)) return finish(null, meta);
          }
        } else chunks.push(d);
      });
      res.on('end', () => {
        if (type.startsWith('text/event-stream')) return finish(expectId === undefined ? null : new McpCallError('MCP_BAD_RESPONSE', 'the stream ended without an answer'), meta);
        let m; try { m = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return finish(new McpCallError('MCP_BAD_RESPONSE', 'the response is not JSON')); }
        meta.messages = Array.isArray(m) ? m : [m];
        return finish(null, meta);
      });
      res.on('error', (e) => finish(new McpCallError(e.code || 'MCP_NETWORK_ERROR', e.message)));
    });
    req.on('error', (e) => finish(new McpCallError(e.code === 'MCP_PIN_MISMATCH' ? 'MCP_PIN_MISMATCH' : (e.code === 'SSRF_BLOCKED_RESOLVED_ADDRESS' ? 'MCP_SSRF_BLOCKED' : 'MCP_NETWORK_ERROR'), e.code === 'MCP_PIN_MISMATCH' ? 'the server identity does not match the pinned key' : e.message)));
    req.end(payload);
  });
}

const answerOf = (meta, id) => {
  for (const m of meta.messages) {
    if (m && m.id === id && m.error) throw new McpCallError('MCP_RPC_ERROR', String(m.error.message || 'error').slice(0, 300), { rpcCode: m.error.code });
    if (m && m.id === id && m.result !== undefined) return m.result;
  }
  for (const m of meta.messages) if (m && m.method && m.id !== undefined) throw new McpCallError('MCP_SERVER_REQUEST_REFUSED', 'the server asked the client to do something');
  throw new McpCallError('MCP_BAD_RESPONSE', 'no answer to the request');
};

/** Run `fn(session)` inside an initialised MCP session. */
async function withSession(server, fn, opts = {}) {
  const limits = { ...DEFAULTS, ...opts };
  const deadline = Date.now() + limits.timeoutMs;
  const agent = opts.agent || createMcpAgent(server.url, { allowLocal: !!server.local, pin: server.pin || null, pinOnly: !!server.pinOnly });
  let nextId = 1; let sessionId;
  const common = () => ({ signal: opts.signal, deadline, maxResponseBytes: limits.maxResponseBytes, agent });
  const rpc = async (method, params) => {
    const id = nextId++;
    const meta = await post(server, { jsonrpc: '2.0', id, method, params }, { ...common(), sessionId, expectId: id });
    return { result: answerOf(meta, id), meta };
  };
  try {
    const init = await rpc('initialize', { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: CLIENT_INFO });
    const sid = init.meta.headers['mcp-session-id'];
    if (typeof sid === 'string' && sid) sessionId = sid;
    await post(server, { jsonrpc: '2.0', method: 'notifications/initialized' }, { ...common(), sessionId });
    const session = {
      serverInfo: init.result && init.result.serverInfo ? { name: String(init.result.serverInfo.name || '').slice(0, 200), version: String(init.result.serverInfo.version || '').slice(0, 100) } : null,
      protocolVersion: init.result && init.result.protocolVersion,
      async listTools() {
        const tools = []; let cursor;
        for (let page = 0; page < 20; page++) {
          const { result } = await rpc('tools/list', cursor ? { cursor } : {});
          if (!result || !Array.isArray(result.tools)) throw new McpCallError('MCP_BAD_RESPONSE', 'tools/list did not return a tools array');
          tools.push(...result.tools);
          if (!result.nextCursor) return tools;
          cursor = result.nextCursor;
        }
        throw new McpCallError('MCP_BAD_RESPONSE', 'tools/list has too many pages');
      },
      async callTool(name, args) {
        const { result } = await rpc('tools/call', { name, arguments: args });
        if (!result || typeof result !== 'object' || !Array.isArray(result.content)) throw new McpCallError('MCP_BAD_RESPONSE', 'tools/call did not return content');
        return result;
      },
    };
    return await fn(session);
  } finally {
    if (sessionId) {                                                                          // best effort: end the server-side session; never blocks, never throws
      const u = new URL(server.url); const lib = u.protocol === 'https:' ? https : http;
      try { const r = lib.request({ protocol: u.protocol, hostname: u.hostname.replace(/^\[|\]$/g, ''), port: u.port || undefined, path: `${u.pathname}${u.search}`, method: 'DELETE', headers: { 'mcp-session-id': sessionId }, agent, timeout: 2000 }, (res) => res.resume()); r.on('error', () => {}); r.on('timeout', () => r.destroy()); r.end(); } catch { /* ignore */ }
    }
  }
}

const listTools = (server, opts) => withSession(server, (s) => s.listTools(), opts);
const callTool = (server, name, args, opts) => withSession(server, (s) => s.callTool(name, args), opts);

module.exports = { PROTOCOL_VERSION, DEFAULTS, McpCallError, withSession, listTools, callTool };
