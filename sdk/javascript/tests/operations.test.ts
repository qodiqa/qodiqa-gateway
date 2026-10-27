import * as fs from 'fs';
import * as http from 'http';
import * as path from 'path';
import { QodiqaClient } from '../src/client';
import { OPERATIONS } from '../src/generated/operations';
import { AuthenticationError, ValidationError } from '../src/errors';

/**
 * the generated, operation-complete layer: every operation of docs/api/openapi.json is callable, with the right verb, URL, credential and checked parameters.
 * The contract file is read from the repository (this test is part of the repo gate, not of the published package).
 */

const SPEC = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', '..', 'docs', 'api', 'openapi.json'), 'utf8'));
const METHODS = ['get', 'post', 'put', 'patch', 'delete'];

interface Seen { method: string; url: string; headers: http.IncomingHttpHeaders; body: string }
let server: http.Server;
let base: string;
const seen: Seen[] = [];
let reply: (op: string | undefined, res: http.ServerResponse) => void = (_o, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"ok":true}'); };

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => { seen.push({ method: req.method ?? '', url: req.url ?? '', headers: req.headers, body: Buffer.concat(chunks).toString('utf8') }); reply(undefined, res); });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
afterAll(async () => { await new Promise<void>((r) => server.close(() => r())); });
beforeEach(() => { seen.length = 0; });

const contractOps = (): Array<{ id: string; method: string; path: string }> => {
  const out: Array<{ id: string; method: string; path: string }> = [];
  for (const [p, item] of Object.entries<any>(SPEC.paths)) for (const m of METHODS) if (item[m]) out.push({ id: item[m].operationId, method: m.toUpperCase(), path: p });
  return out;
};

const client = () => new QodiqaClient({ baseUrl: base, apiKey: 'ok_' + 'a'.repeat(64), signToken: 'sk_' + 'b'.repeat(64), maxRetries: 0, timeout: 5000 });

function argsFor(d: (typeof OPERATIONS)[string]): Record<string, unknown> {
  const a: Record<string, unknown> = {};
  if (d.pathParams.length) a.path = Object.fromEntries(d.pathParams.map((n) => [n, `v/${n} 1`]));
  if (d.requiredQuery.length) a.query = Object.fromEntries(d.requiredQuery.map((n) => [n, 'x']));
  if (d.body === 'json') a.body = { probe: true };
  return a;
}

describe('generated operations', () => {
  it('OP-01 covers EXACTLY the operations of the contract (same ids, verbs and paths)', () => {
    const contract = contractOps().map((o) => `${o.id} ${o.method} ${o.path}`).sort();
    const sdk = Object.values(OPERATIONS).map((o) => `${o.id} ${o.method} ${o.path}`).sort();
    expect(contract.length).toBeGreaterThan(300);
    expect(sdk).toEqual(contract);
  });

  it('OP-02 every operation is a method of client.operations and listed by list()', () => {
    const c = client();
    expect(c.operations.list().length).toBe(Object.keys(OPERATIONS).length);
    for (const id of Object.keys(OPERATIONS)) expect(typeof (c.operations as any)[id]).toBe('function');
  });

  it('OP-03 every non-streaming operation reaches the server with the right verb, an encoded path and its credential', async () => {
    const c = client();
    for (const d of Object.values(OPERATIONS)) {
      if (d.response === 'sse' || d.body === 'form' || d.body === 'raw') continue;
      seen.length = 0;
      await (c.operations as any)[d.id](argsFor(d));
      expect(seen.length).toBe(1);
      const s = seen[0];
      expect(s.method).toBe(d.method);
      const expectedPath = d.path.replace(/\{([^}]+)\}/g, (_m, n: string) => encodeURIComponent(`v/${n} 1`));
      expect(s.url.split('?')[0]).toBe(expectedPath);
      const auth = s.headers.authorization;
      if (d.auth === 'none') expect(auth).toBeUndefined();
      else if (d.auth === 'sign') expect(auth).toBe('Bearer sk_' + 'b'.repeat(64));
      else expect(auth).toBe('Bearer ok_' + 'a'.repeat(64));
    }
  });

  it('OP-04 a body goes out as JSON, a query is encoded, a documented header is forwarded', async () => {
    const c = client();
    const withBody = Object.values(OPERATIONS).find((d) => d.body === 'json' && d.query.length > 0 && d.headers.length > 0 && d.response === 'json')!;
    expect(withBody).toBeDefined();
    const a: any = argsFor(withBody);
    a.query = { ...(a.query ?? {}), [withBody.query[0]]: 'a b&c' };
    a.headers = { [withBody.headers[0]]: '123456' };
    await (c.operations as any)[withBody.id](a);
    const s = seen[0];
    expect(JSON.parse(s.body)).toEqual({ probe: true });
    expect(new URL(s.url, base).searchParams.get(withBody.query[0])).toBe('a b&c');
    expect(s.headers[withBody.headers[0].toLowerCase()]).toBe('123456');
  });

  it('OP-05 argument mistakes fail locally, before any request', async () => {
    const c: any = client();
    const withPath = Object.values(OPERATIONS).find((d) => d.pathParams.length === 1 && d.method === 'GET')!;
    expect(() => c.operations[withPath.id]({})).toThrow(ValidationError);
    expect(() => c.operations[withPath.id]({ path: { [withPath.pathParams[0]]: '' } })).toThrow(ValidationError);
    expect(() => c.operations[withPath.id]({ path: { [withPath.pathParams[0]]: 'x', extra: 'y' } })).toThrow(/unknown path parameter/);
    expect(() => c.operations[withPath.id]({ path: { [withPath.pathParams[0]]: 'x' }, query: { nope: 1 } })).toThrow(/unknown query parameter/);
    const noBody = Object.values(OPERATIONS).find((d) => d.body === 'none' && d.pathParams.length === 0 && d.method === 'GET')!;
    expect(() => c.operations[noBody.id]({ body: {} })).toThrow(/no request body/);
    expect(() => c.operations[noBody.id]({ headers: { 'X-Nope': '1' } })).toThrow(/unknown header/);
    const needsBody = Object.values(OPERATIONS).find((d) => d.bodyRequired && d.pathParams.length === 0)!;
    expect(() => c.operations[needsBody.id]({})).toThrow(/body is required/);
    expect(() => c.operations.call('noSuchOperation')).toThrow(/Unknown operation/);
    expect(seen.length).toBe(0);
  });

  it('OP-06 a credential that is not configured is a local AuthenticationError (operator vs signing key)', () => {
    const c: any = new QodiqaClient({ baseUrl: base, maxRetries: 0 });
    const ops = Object.values(OPERATIONS).find((d) => d.auth === 'ops' && d.pathParams.length === 0 && d.body === 'none')!;
    const sign = Object.values(OPERATIONS).find((d) => d.auth === 'sign' && d.pathParams.length === 0)!;
    expect(() => c.operations[ops.id]()).toThrow(AuthenticationError);
    expect(() => c.operations[sign.id](argsFor(sign))).toThrow(AuthenticationError);
    const none = Object.values(OPERATIONS).find((d) => d.auth === 'none' && d.pathParams.length === 0 && d.body === 'none' && d.response === 'json')!;
    expect(() => c.operations[none.id]()).not.toThrow();
    const optional = Object.values(OPERATIONS).find((d) => d.auth === 'optional' && d.pathParams.length === 0 && d.body === 'none')!;
    expect(() => c.operations[optional.id](argsFor(optional))).not.toThrow();
  });

  it('OP-07 binary operations return bytes, text operations text, SSE operations an async generator', async () => {
    const c: any = client();
    const bin = Object.values(OPERATIONS).find((d) => d.response === 'binary')!;
    reply = (_o, res) => { res.writeHead(200, { 'content-type': 'application/pdf' }); res.end(Buffer.from([0x25, 0x50, 0x44, 0x46, 0xff, 0xfe])); };
    const bytes = await c.operations[bin.id](argsFor(bin));
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(Array.from(bytes as Uint8Array)).toEqual([0x25, 0x50, 0x44, 0x46, 0xff, 0xfe]);
    const text = Object.values(OPERATIONS).find((d) => d.response === 'text' && d.pathParams.length === 0)!;
    reply = (_o, res) => { res.writeHead(200, { 'content-type': 'text/csv' }); res.end('a,b\n1,2\n'); };
    expect(await c.operations[text.id](argsFor(text))).toBe('a,b\n1,2\n');
    const sse = Object.values(OPERATIONS).find((d) => d.response === 'sse')!;
    reply = (_o, res) => { res.writeHead(200, { 'content-type': 'text/event-stream' }); res.write('data: {"n":1}\n\n'); res.end('data: [DONE]\n\n'); };
    const got: unknown[] = [];
    for await (const ev of c.operations[sse.id](argsFor(sse))) got.push(ev);
    expect(got).toEqual([{ n: 1 }]);
    reply = (_o, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"ok":true}'); };
  });
});
