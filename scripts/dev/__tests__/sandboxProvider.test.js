'use strict';

/** the sandbox AI provider: deterministic, OpenAI-compatible, labelled, bounded, no network. */

const http = require('http');
const sandbox = require('../sandboxProvider');

let p;
beforeAll(async () => { p = await sandbox.start(); });
afterAll(async () => { await p.close(); });

const req = (method, path, body) => new Promise((resolve, reject) => {
  const u = new URL(p.url.replace(/\/v1$/, '') + path);
  const r = http.request({ host: u.hostname, port: u.port, path: u.pathname, method, headers: body ? { 'content-type': 'application/json' } : {} }, (res) => {
    const chunks = []; res.on('data', (c) => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }));
  });
  r.on('error', reject); if (body) r.write(typeof body === 'string' ? body : JSON.stringify(body)); r.end();
});

describe('sandbox provider', () => {
  test('SP-01 lists its one model and answers a chat with a labelled echo and usage', async () => {
    const m = JSON.parse((await req('GET', '/v1/models')).text);
    expect(m.data.map((x) => x.id)).toEqual([sandbox.MODEL]);
    const r = await req('POST', '/v1/chat/completions', { model: sandbox.MODEL, messages: [{ role: 'system', content: 's' }, { role: 'user', content: 'first' }, { role: 'user', content: 'hello there' }] });
    const j = JSON.parse(r.text);
    expect(r.headers['x-qodiqa-sandbox']).toBe('true');
    expect(j.choices[0].message).toEqual({ role: 'assistant', content: '[sandbox] hello there' });
    expect(j.usage.total_tokens).toBe(j.usage.prompt_tokens + j.usage.completion_tokens);
    expect(j.usage.completion_tokens).toBeGreaterThan(0);
  });

  test('SP-02 content given as parts is read; the answer is cut to 2000 characters', async () => {
    const parts = JSON.parse((await req('POST', '/v1/chat/completions', { messages: [{ role: 'user', content: [{ type: 'text', text: 'a' }, { type: 'text', text: 'b' }] }] })).text);
    expect(parts.choices[0].message.content).toBe('[sandbox] ab');
    const long = JSON.parse((await req('POST', '/v1/chat/completions', { messages: [{ role: 'user', content: 'x'.repeat(5000) }] })).text);
    expect(long.choices[0].message.content.length).toBe(2000);
  });

  test('SP-03 a stream ends with a usage frame and [DONE]', async () => {
    const r = await req('POST', '/v1/chat/completions', { stream: true, messages: [{ role: 'user', content: 'one two' }] });
    expect(r.headers['content-type']).toBe('text/event-stream');
    const frames = r.text.split('\n\n').filter(Boolean);
    expect(frames[frames.length - 1]).toBe('data: [DONE]');
    const chunks = frames.slice(0, -1).map((f) => JSON.parse(f.slice(6)));
    expect(chunks.map((c) => c.choices[0].delta.content || '').join('')).toBe('[sandbox] one two');
    expect(chunks[chunks.length - 1].choices[0].finish_reason).toBe('stop');
    expect(chunks[chunks.length - 1].usage.total_tokens).toBeGreaterThan(0);
  });

  test('SP-04 bad JSON is 400, an unknown route is 404, and the server listens on loopback only', async () => {
    expect((await req('POST', '/v1/chat/completions', '{not json')).status).toBe(400);
    expect((await req('GET', '/v1/other')).status).toBe(404);
    expect(p.server.address().address).toBe('127.0.0.1');
  });
});
