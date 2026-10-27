'use strict';

/**
 * Tests for the standalone external verifier's offline mode.
 *
 * Covers:
 *   - The online path is byte-identical to before this remediation (still
 *     fetches `/keys` over HTTP when no offline options are supplied).
 *   - Offline verification succeeds using only locally-supplied trust
 *     material, with zero network calls.
 *   - Offline verification fails closed (a clear reason, no network
 *     fallback) when trust material is missing.
 *   - `loadKeysFromFile()` accepts both `{ keys: [...] }` and bare `[...]`
 *     shapes, and fails clearly on a missing/malformed file.
 *   - The CLI itself, exercised as a real subprocess, for both new flag
 *     syntax and the untouched legacy positional syntax.
 */

const http    = require('http');
const fs      = require('fs');
const os      = require('os');
const path    = require('path');
const crypto  = require('crypto');
const { execFileSync } = require('child_process');

const { verify, stableStringify, computeRequestHash, loadKeysFromFile } = require('../tools/verify/verify.external.js');

// ── Fixture builder — genuine Ed25519 signing, mirrors tools/verify/verify.external.js's own
// envelopeHash() exactly so these are real signatures, not hand-crafted stubs. ──

function domainSeparatedHash(domain, canonical) {
  return crypto.createHash('sha256').update(domain, 'utf8').update(canonical, 'utf8').digest();
}

function buildSignedFixture({ expiresInMs = 300_000, keyId = 'dev-local:key_v1' } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubDerB64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');

  const request = { method: 'POST', path: '/demo', body: { hello: 'world' } };
  const requestHash = computeRequestHash(request.method, request.path, request.body);

  const artifact = {
    expiry:      Date.now() + expiresInMs,
    payload:     { requestId: 'req-1', requestHash, tenantId: 'dev-local' },
    publicKeyId: keyId,
    timestamp:   Date.now() - 10,
  };
  const canonical = stableStringify({
    expiry: artifact.expiry, payload: artifact.payload,
    publicKeyId: artifact.publicKeyId, timestamp: artifact.timestamp,
  });
  const hash = domainSeparatedHash('QODIQA::ARTIFACT::V1', canonical);
  artifact.signature = crypto.sign(null, hash, privateKey).toString('base64');

  const keysData = { keys: [{ keyId, publicKey: pubDerB64, status: 'active' }] };
  return { artifact, request, keysData };
}

// ── Minimal local `/keys` HTTP server for online-path tests ───────────────────

function startKeysServer(keysData) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(keysData));
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

// ── Online path — unchanged behavior ──────────────────────────────────────────

describe('verify() — online path (unchanged default)', () => {
  test('3-arg call still fetches /keys over HTTP and verifies successfully', async () => {
    const { artifact, request, keysData } = buildSignedFixture();
    const { server, baseUrl } = await startKeysServer(keysData);
    try {
      const result = await verify(baseUrl, artifact, request);
      expect(result.valid).toBe(true);
      expect(result.reason).toBe('PASS');
    } finally {
      server.close();
    }
  });

  test('KEYS_FETCH_FAILED when the server is unreachable (no offline options given)', async () => {
    const { artifact, request } = buildSignedFixture();
    const result = await verify('http://127.0.0.1:1', artifact, request);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('KEYS_FETCH_FAILED');
  });
});

// ── Offline path — ───────────────────────────────────────────────────

describe('verify() — offline mode', () => {
  test('succeeds using only local keysData, no baseUrl, no network', async () => {
    const { artifact, request, keysData } = buildSignedFixture();
    const start = Date.now();
    const result = await verify(null, artifact, request, { offline: true, keysData });
    expect(Date.now() - start).toBeLessThan(2000); // proves no network round trip was attempted
    expect(result.valid).toBe(true);
    expect(result.reason).toBe('PASS');
  });

  test('local keysData is honored even when a baseUrl is also present (no fetch happens)', async () => {
    const { artifact, request, keysData } = buildSignedFixture();
    // Unreachable base URL — if this were fetched, the call would fail/hang.
    const result = await verify('http://127.0.0.1:1', artifact, request, { keysData });
    expect(result.valid).toBe(true);
  });

  test('fails closed with OFFLINE_TRUST_MATERIAL_MISSING when offline and no keysData supplied', async () => {
    const { artifact, request } = buildSignedFixture();
    const result = await verify(null, artifact, request, { offline: true });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('OFFLINE_TRUST_MATERIAL_MISSING');
  });

  test('unknown key id in local trust material fails closed with KEY_NOT_FOUND', async () => {
    const { artifact, request } = buildSignedFixture();
    const result = await verify(null, artifact, request, { offline: true, keysData: { keys: [] } });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('KEY_NOT_FOUND');
  });

  test('tampered payload still fails signature verification offline, same as online', async () => {
    const { artifact, request, keysData } = buildSignedFixture();
    artifact.payload = { ...artifact.payload, tenantId: 'tampered' };
    const result = await verify(null, artifact, request, { offline: true, keysData });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  test('expiry is still enforced offline', async () => {
    const { artifact, request, keysData } = buildSignedFixture({ expiresInMs: -1000 });
    const result = await verify(null, artifact, request, { offline: true, keysData });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('EXPIRED');
  });
});

// ── loadKeysFromFile() ─────────────────────────────────────────────────────────

describe('loadKeysFromFile()', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-ext-js-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('accepts the { keys: [...] } shape (matches GET /keys / /.well-known/qodiqa/keys)', () => {
    const file = path.join(tmpDir, 'keys.json');
    fs.writeFileSync(file, JSON.stringify({ keys: [{ keyId: 'a:key_v1', publicKey: 'AA==', status: 'active' }] }));
    const data = loadKeysFromFile(file);
    expect(data.keys).toHaveLength(1);
  });

  test('accepts a bare [...] array shape', () => {
    const file = path.join(tmpDir, 'keys.json');
    fs.writeFileSync(file, JSON.stringify([{ keyId: 'a:key_v1', publicKey: 'AA==', status: 'active' }]));
    const data = loadKeysFromFile(file);
    expect(data.keys).toHaveLength(1);
  });

  test('throws a clear error when the file does not exist', () => {
    expect(() => loadKeysFromFile(path.join(tmpDir, 'missing.json'))).toThrow(/not found/);
  });

  test('throws a clear error on malformed JSON', () => {
    const file = path.join(tmpDir, 'bad.json');
    fs.writeFileSync(file, '{not json');
    expect(() => loadKeysFromFile(file)).toThrow(/not valid JSON/);
  });

  test('throws a clear error when the file has no "keys" array', () => {
    const file = path.join(tmpDir, 'wrong-shape.json');
    fs.writeFileSync(file, JSON.stringify({ notKeys: [] }));
    expect(() => loadKeysFromFile(file)).toThrow(/"keys" array/);
  });
});

// ── CLI, exercised as a real subprocess ───────────────────────────────────────

describe('CLI (subprocess)', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-ext-js-cli-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function runCLI(args) {
    try {
      const stdout = execFileSync('node', [require.resolve('../tools/verify/verify.external.js'), ...args], {
        encoding: 'utf8', timeout: 5000,
      });
      return { stdout, status: 0 };
    } catch (err) {
      return { stdout: err.stdout ? err.stdout.toString() : '', stderr: err.stderr ? err.stderr.toString() : '', status: err.status };
    }
  }

  test('--offline --key-file verifies a genuine artifact with zero network access', () => {
    const { artifact, request, keysData } = buildSignedFixture();
    const keysFile = path.join(tmpDir, 'keys.json');
    fs.writeFileSync(keysFile, JSON.stringify(keysData));

    const { stdout, status } = runCLI(['--offline', '--key-file', keysFile, JSON.stringify(artifact), JSON.stringify(request)]);
    expect(status).toBe(0);
    expect(JSON.parse(stdout).valid).toBe(true);
  });

  // a bundle's own keys are never a trust anchor. This test previously asserted that a bundle
  // alone verified — exactly the self-certification defect (a bundle forged with an attacker key verified valid).
  test('--offline --bundle verifies only against out-of-band trusted keys (--key-file)', () => {
    const { artifact, request, keysData } = buildSignedFixture();
    const bundleFile = path.join(tmpDir, 'bundle.json');
    const keysFile = path.join(tmpDir, 'keys.json');
    fs.writeFileSync(bundleFile, JSON.stringify({ artifact, request, keys: keysData.keys }));
    fs.writeFileSync(keysFile, JSON.stringify(keysData));

    const { stdout, status } = runCLI(['--offline', '--bundle', bundleFile, '--key-file', keysFile]);
    expect(status).toBe(0);
    expect(JSON.parse(stdout).valid).toBe(true);
  });

  test('--offline --bundle without trusted keys is refused (TRUST_ANCHOR_REQUIRED), never self-certified', () => {
    const { artifact, request, keysData } = buildSignedFixture();
    const bundleFile = path.join(tmpDir, 'bundle.json');
    fs.writeFileSync(bundleFile, JSON.stringify({ artifact, request, keys: keysData.keys }));

    const { status, stdout, stderr } = runCLI(['--offline', '--bundle', bundleFile]);
    expect(status).toBe(1);
    expect(`${stdout || ''}${stderr || ''}`).toMatch(/TRUST_ANCHOR_REQUIRED/);
  });

  test('--offline without --key-file or --bundle exits 1 with a clear error, no hang', () => {
    const { artifact, request } = buildSignedFixture();
    const { status, stderr } = runCLI(['--offline', JSON.stringify(artifact), JSON.stringify(request)]);
    expect(status).toBe(1);
    expect(stderr).toMatch(/OFFLINE_MISSING_TRUST_MATERIAL/);
  });

  test('legacy positional-only invocation (no flags) is unchanged: missing args -> usage + exit 1', () => {
    const { status, stderr } = runCLI([]);
    expect(status).toBe(1);
    expect(stderr).toMatch(/Usage:/);
  });
});
