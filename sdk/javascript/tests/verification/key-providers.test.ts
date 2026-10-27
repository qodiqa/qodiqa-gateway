import { StaticKeyProvider, RemoteKeyProvider, createKeyProvider } from '../../src/verification/keyProviders.js';
import { MockServer } from '../mock-server.js';

const PUB_B64 = 'MCowBQYDK2VwAyEArI9wKSGHg7Ig9ZtbOg+7d/QSddFvQ9xHSQxJ7ErydFs=';

describe('StaticKeyProvider', () => {
  test('resolves a configured key', async () => {
    const provider = new StaticKeyProvider([{ keyId: 'k1', publicKey: PUB_B64, status: 'active' }]);
    const resolved = await provider.getPublicKey('k1');
    expect(resolved).not.toBeNull();
    expect(resolved?.status).toBe('active');
    expect(resolved?.pubDer.toString('base64')).toBe(PUB_B64);
  });

  test('returns null for an unknown key id', async () => {
    const provider = new StaticKeyProvider([{ keyId: 'k1', publicKey: PUB_B64, status: 'active' }]);
    expect(await provider.getPublicKey('unknown')).toBeNull();
  });

  test('preserves a revoked status rather than hiding it', async () => {
    const provider = new StaticKeyProvider([{ keyId: 'k1', publicKey: PUB_B64, status: 'revoked' }]);
    const resolved = await provider.getPublicKey('k1');
    expect(resolved?.status).toBe('revoked');
  });
});

describe('createKeyProvider', () => {
  test('adapts a plain async function', async () => {
    const provider = createKeyProvider(async (keyId) =>
      keyId === 'k1' ? { pubDer: Buffer.from(PUB_B64, 'base64'), status: 'active' } : null,
    );
    expect((await provider.getPublicKey('k1'))?.status).toBe('active');
    expect(await provider.getPublicKey('other')).toBeNull();
  });
});

describe('RemoteKeyProvider', () => {
  let server: MockServer;
  let baseUrl: string;

  beforeEach(async () => {
    server = new MockServer();
    baseUrl = await server.start();
  });

  afterEach(async () => {
    await server.stop();
  });

  test('fetches and resolves a key from a well-known-shaped discovery endpoint', async () => {
    server.mock('GET', '/.well-known/qodiqa/keys', {
      status: 200,
      body: { keys: [{ keyId: 'dev-local:key_v1', algorithm: 'ed25519', publicKey: PUB_B64, status: 'active' }] },
    });
    const provider = new RemoteKeyProvider({ discoveryUrl: `${baseUrl}/.well-known/qodiqa/keys` });
    const resolved = await provider.getPublicKey('dev-local:key_v1');
    expect(resolved?.status).toBe('active');
    expect(resolved?.pubDer.toString('base64')).toBe(PUB_B64);
  });

  test('returns null for a key absent from the response', async () => {
    server.mock('GET', '/.well-known/qodiqa/keys', { status: 200, body: { keys: [] } });
    const provider = new RemoteKeyProvider({ discoveryUrl: `${baseUrl}/.well-known/qodiqa/keys` });
    expect(await provider.getPublicKey('unknown:key_v1')).toBeNull();
  });

  test('caches the key list and does not refetch within the TTL', async () => {
    server.mock('GET', '/.well-known/qodiqa/keys', {
      status: 200,
      body: { keys: [{ keyId: 'k1', algorithm: 'ed25519', publicKey: PUB_B64, status: 'active' }] },
    });
    const provider = new RemoteKeyProvider({ discoveryUrl: `${baseUrl}/.well-known/qodiqa/keys`, cacheTtlMs: 60_000 });
    await provider.getPublicKey('k1');
    await provider.getPublicKey('k1');
    await provider.getPublicKey('k1');
    const calls = server.getCallLog().filter((c) => c.path.startsWith('/.well-known/qodiqa/keys'));
    expect(calls.length).toBe(1);
  });

  test('refetches after the TTL expires', async () => {
    server.mock('GET', '/.well-known/qodiqa/keys', {
      status: 200,
      body: { keys: [{ keyId: 'k1', algorithm: 'ed25519', publicKey: PUB_B64, status: 'active' }] },
    });
    const provider = new RemoteKeyProvider({ discoveryUrl: `${baseUrl}/.well-known/qodiqa/keys`, cacheTtlMs: 1 });
    await provider.getPublicKey('k1');
    await new Promise((resolve) => setTimeout(resolve, 10));
    await provider.getPublicKey('k1');
    const calls = server.getCallLog().filter((c) => c.path.startsWith('/.well-known/qodiqa/keys'));
    expect(calls.length).toBe(2);
  });

  test('refresh() bypasses the cache', async () => {
    server.mock('GET', '/.well-known/qodiqa/keys', {
      status: 200,
      body: { keys: [{ keyId: 'k1', algorithm: 'ed25519', publicKey: PUB_B64, status: 'active' }] },
    });
    const provider = new RemoteKeyProvider({ discoveryUrl: `${baseUrl}/.well-known/qodiqa/keys`, cacheTtlMs: 60_000 });
    await provider.getPublicKey('k1');
    await provider.refresh();
    const calls = server.getCallLog().filter((c) => c.path.startsWith('/.well-known/qodiqa/keys'));
    expect(calls.length).toBe(2);
  });

  test('a network/HTTP failure is caught, not thrown — resolves to null', async () => {
    // No mock registered for this path -> MockServer returns 404.
    const provider = new RemoteKeyProvider({ discoveryUrl: `${baseUrl}/.well-known/qodiqa/keys` });
    await expect(provider.getPublicKey('k1')).resolves.toBeNull();
  });
});

describe('RemoteKeyProvider — archived-key fallback', () => {
  let server: MockServer;
  let baseUrl: string;
  let discoveryUrl: string;

  beforeEach(async () => {
    server = new MockServer();
    baseUrl = await server.start();
    discoveryUrl = `${baseUrl}/.well-known/qodiqa/keys`;
  });

  afterEach(async () => {
    await server.stop();
  });

  test('falls back to the archived endpoint when a key is absent from the live list', async () => {
    server.mock('GET', '/.well-known/qodiqa/keys', { status: 200, body: { keys: [] } });
    server.mock('GET', '/.well-known/qodiqa/keys/archived', {
      status: 200,
      body: { keys: [{ keyId: 'purged:key_v1', algorithm: 'ed25519', publicKey: PUB_B64, status: 'archived', source: 'archived' }] },
    });

    const provider = new RemoteKeyProvider({ discoveryUrl });
    const resolved = await provider.getPublicKey('purged:key_v1');
    expect(resolved).not.toBeNull();
    expect(resolved?.status).toBe('deprecated'); // normalized from the wire-only 'archived' marker
    expect(resolved?.source).toBe('archived');
    expect(resolved?.pubDer.toString('base64')).toBe(PUB_B64);
  });

  test('a key present in the live list is never looked up in the archive', async () => {
    server.mock('GET', '/.well-known/qodiqa/keys', {
      status: 200,
      body: { keys: [{ keyId: 'k1', algorithm: 'ed25519', publicKey: PUB_B64, status: 'active' }] },
    });
    // Deliberately no mock for /archived — if it were queried, MockServer's
    // 404 would still resolve to null here, but the call-log assertion below
    // proves it was never attempted at all.
    const provider = new RemoteKeyProvider({ discoveryUrl });
    const resolved = await provider.getPublicKey('k1');
    expect(resolved?.source).toBe('live');
    expect(server.getCallLog().some((c) => c.path.startsWith('/.well-known/qodiqa/keys/archived'))).toBe(false);
  });

  test('unknown everywhere (absent from both live and archived) resolves to null', async () => {
    server.mock('GET', '/.well-known/qodiqa/keys', { status: 200, body: { keys: [] } });
    server.mock('GET', '/.well-known/qodiqa/keys/archived', { status: 200, body: { keys: [] } });
    const provider = new RemoteKeyProvider({ discoveryUrl });
    expect(await provider.getPublicKey('nowhere:key_v1')).toBeNull();
  });

  test('the archived tier is cached independently and not refetched within the TTL', async () => {
    server.mock('GET', '/.well-known/qodiqa/keys', { status: 200, body: { keys: [] } });
    server.mock('GET', '/.well-known/qodiqa/keys/archived', {
      status: 200,
      body: { keys: [{ keyId: 'purged:key_v1', algorithm: 'ed25519', publicKey: PUB_B64, status: 'archived' }] },
    });
    const provider = new RemoteKeyProvider({ discoveryUrl, cacheTtlMs: 60_000 });
    await provider.getPublicKey('purged:key_v1');
    await provider.getPublicKey('purged:key_v1');
    await provider.getPublicKey('purged:key_v1');
    const archivedCalls = server.getCallLog().filter((c) => c.path.startsWith('/.well-known/qodiqa/keys/archived'));
    expect(archivedCalls.length).toBe(1);
  });

  test('archivedDiscoveryUrl is auto-derived from a /qodiqa/keys discoveryUrl', async () => {
    server.mock('GET', '/.well-known/qodiqa/keys', { status: 200, body: { keys: [] } });
    server.mock('GET', '/.well-known/qodiqa/keys/archived', {
      status: 200,
      body: { keys: [{ keyId: 'purged:key_v1', algorithm: 'ed25519', publicKey: PUB_B64, status: 'archived' }] },
    });
    const provider = new RemoteKeyProvider({ discoveryUrl }); // no archivedDiscoveryUrl passed
    expect((await provider.getPublicKey('purged:key_v1'))?.source).toBe('archived');
  });

  test('no archived tier is derived for the transparency-keys discovery URL', async () => {
    const transparencyUrl = `${baseUrl}/.well-known/qodiqa/transparency-keys`;
    server.mock('GET', '/.well-known/qodiqa/transparency-keys', { status: 200, body: { keys: [] } });
    const provider = new RemoteKeyProvider({ discoveryUrl: transparencyUrl });
    expect(await provider.getPublicKey('unknown:key_v1')).toBeNull();
    expect(server.getCallLog().some((c) => c.path.includes('archived'))).toBe(false);
  });

  test('archivedDiscoveryUrl: null explicitly disables the fallback even for a /qodiqa/keys URL', async () => {
    server.mock('GET', '/.well-known/qodiqa/keys', { status: 200, body: { keys: [] } });
    const provider = new RemoteKeyProvider({ discoveryUrl, archivedDiscoveryUrl: null });
    expect(await provider.getPublicKey('purged:key_v1')).toBeNull();
    expect(server.getCallLog().some((c) => c.path.includes('archived'))).toBe(false);
  });

  test('refresh() bypasses both the live and archived caches', async () => {
    server.mock('GET', '/.well-known/qodiqa/keys', { status: 200, body: { keys: [] } });
    server.mock('GET', '/.well-known/qodiqa/keys/archived', {
      status: 200,
      body: { keys: [{ keyId: 'purged:key_v1', algorithm: 'ed25519', publicKey: PUB_B64, status: 'archived' }] },
    });
    const provider = new RemoteKeyProvider({ discoveryUrl, cacheTtlMs: 60_000 });
    await provider.getPublicKey('purged:key_v1');
    await provider.refresh();
    await provider.getPublicKey('purged:key_v1');
    const liveCalls = server.getCallLog().filter((c) => c.path === '/.well-known/qodiqa/keys');
    const archivedCalls = server.getCallLog().filter((c) => c.path === '/.well-known/qodiqa/keys/archived');
    expect(liveCalls.length).toBe(2);
    // Proves the archived cache was also cleared by refresh() — otherwise
    // this second lookup would have been served from the still-cached
    // archived map instead of issuing a fresh request.
    expect(archivedCalls.length).toBe(2);
  });
});
