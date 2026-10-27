import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as path from 'path';
import { artifactGuard, requestHash, StaticKeyProvider } from '../src/index';
import { envelopeHash } from '../src/verification/domainHash';

/**
 * the artifact guard for existing Node applications. Artifacts are signed with a real Ed25519 key and the SDK's own envelope hash; the trust bundle is the matching public key.
 * The guard runs behind a real http server, with a body parser written the way Express's json() works (req.body), and the request hash is pinned to the shared protocol vectors.
 */

const NOW = 1_790_000_000_000;
const KEY_ID = 'tenant-a:key_v1';
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const keys = new StaticKeyProvider([{ keyId: KEY_ID, algorithm: 'ed25519', publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'), status: 'active' }]);

function artifact(method: string, p: string, body: unknown, over: { requestHash?: string; ts?: number; exp?: number } = {}): string {
  const art: Record<string, unknown> = {
    expiry: over.exp ?? NOW + 60_000,
    payload: { requestId: 'r1', requestHash: over.requestHash ?? requestHash(method, p, body === undefined ? {} : body), tenantId: 'tenant-a' },
    publicKeyId: KEY_ID,
    timestamp: over.ts ?? NOW - 1000,
  };
  art.signature = crypto.sign(null, envelopeHash(art as never), privateKey).toString('base64');
  return Buffer.from(JSON.stringify(art)).toString('base64');
}

let server: http.Server;
let base: string;
let replayed = new Set<string>();
const seen: string[] = [];

beforeAll(async () => {
  const guard = artifactGuard({ keys, now: () => NOW, replayGuard: (info) => { const id = String(info.payload.requestId); if (replayed.has(id)) return false; replayed.add(id); return true; } });
  const open = artifactGuard({ keys, now: () => NOW });
  server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      const r = req as unknown as { body?: unknown; path?: string };
      r.body = text ? JSON.parse(text) : undefined;
      r.path = new URL(req.url ?? '/', 'http://x').pathname;
      const handler = (q: unknown, s: unknown) => { void q; seen.push(String(req.url)); (s as http.ServerResponse).end(JSON.stringify({ ok: true, tenant: ((req as unknown as { qodiqa?: { payload: { tenantId: string } } }).qodiqa?.payload.tenantId) })); };
      if (r.path === '/replay') return void guard(req as never, res as never, () => handler(req, res));
      if (r.path?.startsWith('/protected')) return void open(req as never, res as never, (e) => (e ? (res.statusCode = 500, res.end()) : handler(req, res)));
      return void handler(req, res);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
afterAll(async () => { await new Promise<void>((r) => server.close(() => r())); });
beforeEach(() => { seen.length = 0; replayed = new Set(); });

const call = async (method: string, p: string, body?: unknown, art?: string) => {
  const r = await fetch(base + p, { method, headers: { ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...(art ? { 'x-qodiqa-artifact': art } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  return { status: r.status, json: await r.json().catch(() => null), cache: r.headers.get('cache-control') };
};

describe('requestHash', () => {
  it('RH-01 equals the protocol vectors', () => {
    const v = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', '..', 'docs', 'protocol', 'vectors', 'qodiqa-protocol-vectors.json'), 'utf8'));
    expect(v.requestBinding.hashes.length).toBeGreaterThan(3);
    for (const h of v.requestBinding.hashes) expect(requestHash(h.request.method, h.request.path, h.request.body)).toBe(h.requestHashHex);
  });
});

describe('artifactGuard', () => {
  it('AG-01 a bound request passes with its body intact and the payload on req.qodiqa', async () => {
    const body = { prompt: 'hi' };
    const r = await call('POST', '/protected/echo?x=1', body, artifact('POST', '/protected/echo', body));
    expect(r.status).toBe(200);
    expect(r.json).toEqual({ ok: true, tenant: 'tenant-a' });
    expect(seen).toEqual(['/protected/echo?x=1']);     // the query does not take part in the V1 binding
  });

  it('AG-02 no header, a malformed or invalid artifact: 401 with a stable code, the handler is never reached', async () => {
    const none = await call('GET', '/protected/a');
    expect(none.status).toBe(401); expect(none.json.error.code).toBe('QODIQA_ARTIFACT_REQUIRED'); expect(none.cache).toBe('no-store');
    expect((await call('GET', '/protected/a', undefined, '%%%')).json.error.code).toBe('QODIQA_ARTIFACT_INVALID');
    expect((await call('GET', '/protected/a', undefined, Buffer.from('[]').toString('base64'))).status).toBe(401);
    const tampered = JSON.parse(Buffer.from(artifact('GET', '/protected/a', undefined), 'base64').toString());
    tampered.payload.tenantId = 'tenant-b';
    expect((await call('GET', '/protected/a', undefined, Buffer.from(JSON.stringify(tampered)).toString('base64'))).status).toBe(401);
    expect((await call('GET', '/protected/a', undefined, artifact('GET', '/protected/a', undefined, { ts: NOW - 120_000, exp: NOW - 60_000 }))).status).toBe(401);
    expect((await call('GET', '/protected/a', undefined, artifact('GET', '/protected/a', undefined, { ts: NOW + 60_000, exp: NOW + 120_000 }))).status).toBe(401);
    // an oversized header value is refused by the guard itself (Node refuses much larger headers before any middleware runs)
    const small = artifactGuard({ keys, maxHeaderBytes: 64, now: () => NOW });
    const fakeRes = { statusCode: 0, body: '', setHeader() {}, end(c?: string) { this.body = c ?? ''; } };
    await small({ method: 'GET', path: '/x', headers: { 'x-qodiqa-artifact': 'A'.repeat(65) } }, fakeRes, () => { throw new Error('must not pass'); });
    expect(fakeRes.statusCode).toBe(401); expect(JSON.parse(fakeRes.body).error.code).toBe('QODIQA_ARTIFACT_INVALID');
    expect(seen).toEqual([]);
  });

  it('AG-03 an artifact bound to another method, path or body is 403 QODIQA_REQUEST_MISMATCH', async () => {
    const art = artifact('POST', '/protected/echo', { prompt: 'hi' });
    for (const [m, p, b] of [['POST', '/protected/echo', { prompt: 'other' }], ['POST', '/protected/other', { prompt: 'hi' }], ['PUT', '/protected/echo', { prompt: 'hi' }]] as const) {
      const r = await call(m, p, b, art);
      expect(r.status).toBe(403); expect(r.json.error.code).toBe('QODIQA_REQUEST_MISMATCH');
    }
    expect(seen).toEqual([]);
  });

  it('AG-04 the replay guard decides after verification', async () => {
    const art = artifact('GET', '/replay', undefined);
    expect((await call('GET', '/replay', undefined, art)).status).toBe(200);
    const again = await call('GET', '/replay', undefined, art);
    expect(again.status).toBe(403); expect(again.json.error.code).toBe('QODIQA_REPLAY_OR_POLICY');
  });

  it('AG-06 behind an Express-style mount point the FULL path is what is bound (req.path is relative there)', async () => {
    const g = artifactGuard({ keys, now: () => NOW });
    const res = { statusCode: 0, body: '', setHeader() {}, end(c?: string) { this.body = c ?? ''; } };
    let passed = false;
    // Express: app.use('/protected', guard) - req.url/req.path are '/echo', originalUrl keeps '/protected/echo?x=1'
    await g({ method: 'POST', url: '/echo', path: '/echo', originalUrl: '/protected/echo?x=1', headers: { 'x-qodiqa-artifact': artifact('POST', '/protected/echo', { a: 1 }) }, body: { a: 1 } }, res, () => { passed = true; });
    expect(passed).toBe(true);
    // a plain http server has only req.url
    passed = false;
    await g({ method: 'GET', url: '/protected/a?z=1', headers: { 'x-qodiqa-artifact': artifact('GET', '/protected/a', undefined) } }, res, () => { passed = true; });
    expect(passed).toBe(true);
  });

  it('AG-05 construction needs a key provider', () => {
    expect(() => artifactGuard({} as never)).toThrow(/keys/);
  });
});
