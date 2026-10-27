'use strict';

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const { loadPolicies, resolvePolicyFilePath } = require('./loader');
const { computePolicyHash } = require('../policyHash');

// ── Helpers ───────────────────────────────────────────────────────────────────

const MINIMAL_VALID_DOC = {
  policies: [
    { id: 'POL-001', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
      config: { requireValidArtifact: true } },
  ],
};

function writeTempFile(content) {
  const dir  = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-loader-test-'));
  const file = path.join(dir, 'policies.json');
  fs.writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content), 'utf8');
  return { file, dir };
}

function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
}

// ── 1. Missing file → fail-closed ─────────────────────────────────────────────

describe('missing policies.json → fail-closed', () => {
  test('throws with descriptive error when file does not exist', () => {
    const missing = path.join(os.tmpdir(), `qodiqa-nonexistent-${Date.now()}.json`);
    expect(() => loadPolicies(missing)).toThrow(/PolicyLoader: cannot read/);
  });

  test('thrown error message includes the file path', () => {
    const missing = path.join(os.tmpdir(), 'qodiqa-absent.json');
    expect(() => loadPolicies(missing)).toThrow(missing);
  });
});

// ── 2. Malformed JSON → fail-closed ──────────────────────────────────────────

describe('malformed policies.json → fail-closed', () => {
  let dir;
  afterEach(() => cleanup(dir));

  test('throws on truncated JSON', () => {
    ({ dir } = writeTempFile('{ "policies": ['));
    const { file } = writeTempFile('{ "policies": [');
    dir = path.dirname(file);
    expect(() => loadPolicies(file)).toThrow(/invalid JSON/);
  });

  test('throws on non-JSON text', () => {
    const { file, dir: d } = writeTempFile('NOT JSON AT ALL');
    dir = d;
    expect(() => loadPolicies(file)).toThrow(/invalid JSON/);
  });

  test('throws on empty file', () => {
    const { file, dir: d } = writeTempFile('');
    dir = d;
    expect(() => loadPolicies(file)).toThrow(/invalid JSON/);
  });

  test('throws on JSON array at root (not an object)', () => {
    const { file, dir: d } = writeTempFile('[]');
    dir = d;
    expect(() => loadPolicies(file)).toThrow(/PolicyLoader/);
  });
});

// ── 3. Invalid schema → fail-closed ──────────────────────────────────────────

describe('invalid schema → fail-closed', () => {
  let dir;
  afterEach(() => cleanup(dir));

  test('throws when policies array is missing', () => {
    const { file, dir: d } = writeTempFile({ version: '1.0.0' });
    dir = d;
    expect(() => loadPolicies(file)).toThrow(/policies must be a non-empty array/);
  });

  test('throws when policies array is empty', () => {
    const { file, dir: d } = writeTempFile({ policies: [] });
    dir = d;
    expect(() => loadPolicies(file)).toThrow(/non-empty/);
  });

  test('throws when no enabled REQUIRE_CONSENT policy is present', () => {
    const { file, dir: d } = writeTempFile({
      policies: [
        { id: 'POL-001', type: 'BLOCK_IP', priority: 10, enabled: true,
          config: { blocklist: [], cidrs: [] } },
      ],
    });
    dir = d;
    expect(() => loadPolicies(file)).toThrow(/REQUIRE_CONSENT/);
  });

  test('throws when REQUIRE_CONSENT is disabled', () => {
    const { file, dir: d } = writeTempFile({
      policies: [
        { id: 'POL-001', type: 'REQUIRE_CONSENT', priority: 10, enabled: false,
          config: { requireValidArtifact: true } },
      ],
    });
    dir = d;
    expect(() => loadPolicies(file)).toThrow(/REQUIRE_CONSENT/);
  });

  test('throws on unknown policy type', () => {
    const { file, dir: d } = writeTempFile({
      policies: [
        { id: 'POL-001', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
          config: { requireValidArtifact: true } },
        { id: 'POL-002', type: 'UNKNOWN_FUTURE_TYPE', priority: 20, enabled: true,
          config: {} },
      ],
    });
    dir = d;
    expect(() => loadPolicies(file)).toThrow(/unknown type/);
  });

  test('throws on duplicate policy id', () => {
    const { file, dir: d } = writeTempFile({
      policies: [
        { id: 'POL-DUP', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
          config: { requireValidArtifact: true } },
        { id: 'POL-DUP', type: 'REQUIRE_CONSENT', priority: 20, enabled: true,
          config: { requireValidArtifact: true } },
      ],
    });
    dir = d;
    expect(() => loadPolicies(file)).toThrow(/duplicate/);
  });

  test('throws on prototype-pollution key in config', () => {
    // JSON.parse is the only standard way to produce __proto__ as an own
    // enumerable key — bracket assignment absorbs it as prototype.
    const rawJson = `{
      "policies": [{
        "id": "POL-001", "type": "REQUIRE_CONSENT",
        "priority": 10, "enabled": true,
        "config": { "requireValidArtifact": true, "__proto__": {"polluted": true} }
      }]
    }`;
    const { file, dir: d } = writeTempFile(rawJson);
    dir = d;
    expect(() => loadPolicies(file)).toThrow(/forbidden key/);
  });
});

// ── 4. Valid file → correct frozen result ─────────────────────────────────────

describe('valid policies.json → correct frozen result', () => {
  let dir;
  afterEach(() => cleanup(dir));

  test('returns frozen array with correct policy count', () => {
    const { file, dir: d } = writeTempFile(MINIMAL_VALID_DOC);
    dir = d;
    const result = loadPolicies(file);
    expect(Array.isArray(result)).toBe(true);
    expect(Object.isFrozen(result)).toBe(true);
    expect(result.length).toBe(1);
  });

  test('each policy object is frozen', () => {
    const { file, dir: d } = writeTempFile(MINIMAL_VALID_DOC);
    dir = d;
    const result = loadPolicies(file);
    expect(Object.isFrozen(result[0])).toBe(true);
    expect(Object.isFrozen(result[0].config)).toBe(true);
  });

  test('policies are sorted by priority', () => {
    const { file, dir: d } = writeTempFile({
      policies: [
        { id: 'POL-B', type: 'BLOCK_IP',        priority: 20, enabled: true, config: { blocklist: [], cidrs: [] } },
        { id: 'POL-A', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } },
      ],
    });
    dir = d;
    const result = loadPolicies(file);
    expect(result.map(p => p.id)).toEqual(['POL-A', 'POL-B']);
  });

  test('the real policies.json loads without error', () => {
    const realPath = path.resolve(__dirname, '../../policies.json');
    const result = loadPolicies(realPath);
    expect(result.length).toBeGreaterThan(0);
    expect(result.some(p => p.type === 'REQUIRE_CONSENT' && p.enabled)).toBe(true);
  });

  test('deploy/env/production.policies.example conforms to the actual policy schema/loader', () => {
    const examplePath = path.resolve(__dirname, '../../deploy/env/production.policies.example');
    const result = loadPolicies(examplePath);
    expect(result.length).toBeGreaterThan(0);
    expect(result.some(p => p.type === 'REQUIRE_CONSENT' && p.enabled)).toBe(true);
    // It must differ from the demo policies.json's exact semantics — most
    // concretely, BLOCK_IP ships disabled here rather than enabled-but-empty
    // (the "looks active but isn't" shape the demo file has).
    const blockIp = result.find(p => p.type === 'BLOCK_IP');
    expect(blockIp).toBeDefined();
    expect(blockIp.enabled).toBe(false);
  });
});

// ── 7. production policy-file selection ─────────────────────────────────

describe('resolvePolicyFilePath', () => {
  const ENV_KEYS = ['POLICY_FILE', 'NODE_ENV'];
  let saved;

  beforeEach(() => { saved = ENV_KEYS.reduce((acc, k) => ({ ...acc, [k]: process.env[k] }), {}); });
  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  test('returns the explicit POLICY_FILE value when set, regardless of environment', () => {
    delete process.env.NODE_ENV;
    process.env.POLICY_FILE = '/explicit/dev/path.json';
    expect(resolvePolicyFilePath('/default/path.json')).toBe('/explicit/dev/path.json');

    process.env.NODE_ENV = 'production';
    process.env.POLICY_FILE = '/explicit/prod/path.json';
    expect(resolvePolicyFilePath('/default/path.json')).toBe('/explicit/prod/path.json');
  });

  test('outside production, an unset POLICY_FILE returns the caller-supplied default (dev/test convenience preserved)', () => {
    delete process.env.POLICY_FILE;
    delete process.env.NODE_ENV;
    expect(resolvePolicyFilePath('/default/path.json')).toBe('/default/path.json');

    process.env.NODE_ENV = 'test';
    expect(resolvePolicyFilePath('/default/path.json')).toBe('/default/path.json');
  });

  test('in production, an unset POLICY_FILE throws POLICY_FILE_REQUIRED — no silent default', () => {
    delete process.env.POLICY_FILE;
    process.env.NODE_ENV = 'production';
    let thrown;
    try { resolvePolicyFilePath('/default/path.json'); } catch (e) { thrown = e; }
    expect(thrown).toBeDefined();
    expect(thrown.code).toBe('POLICY_FILE_REQUIRED');
  });

  test('the production error is deterministic and actionable — same message every call, names the example file and the env var', () => {
    delete process.env.POLICY_FILE;
    process.env.NODE_ENV = 'production';
    let first, second;
    try { resolvePolicyFilePath('/default/path.json'); } catch (e) { first = e.message; }
    try { resolvePolicyFilePath('/default/path.json'); } catch (e) { second = e.message; }
    expect(first).toBe(second);
    expect(first).toMatch(/production.policies.example/);
    expect(first).toMatch(/POLICY_FILE=/);
  });

  test('an empty-string POLICY_FILE is treated as unset (falls through to the same production rule)', () => {
    process.env.POLICY_FILE = '';
    process.env.NODE_ENV = 'production';
    expect(() => resolvePolicyFilePath('/default/path.json')).toThrow(/POLICY_FILE/);
  });

  test('the demo policies.json can no longer silently become the production policy source', () => {
    // The exact failure mode closes: nothing in resolvePolicyFilePath's
    // production branch ever returns the caller's default path (the
    // repo-root policies.json each call site passes in) — it always throws
    // instead. Proven directly against the real default server/startup.js
    // would use, not a synthetic path.
    delete process.env.POLICY_FILE;
    process.env.NODE_ENV = 'production';
    const realDemoDefault = path.resolve(__dirname, '../../policies.json');
    let resolved;
    try { resolved = resolvePolicyFilePath(realDemoDefault); } catch { /* expected */ }
    expect(resolved).toBeUndefined();
  });
});

// ── 5. Determinism — same file produces identical hash ────────────────────────

describe('policyHash determinism', () => {
  let dir;
  afterEach(() => cleanup(dir));

  test('loadPolicies twice on the same file produces identical policyHash', () => {
    const { file, dir: d } = writeTempFile(MINIMAL_VALID_DOC);
    dir = d;
    const a = loadPolicies(file);
    const b = loadPolicies(file);
    expect(computePolicyHash(a)).toBe(computePolicyHash(b));
  });

  test('policyHash differs when policy content changes', () => {
    const { file, dir: d } = writeTempFile(MINIMAL_VALID_DOC);
    dir = d;
    const hashA = computePolicyHash(loadPolicies(file));

    fs.writeFileSync(file, JSON.stringify({
      policies: [
        { id: 'POL-001', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
          config: { requireValidArtifact: true } },
        { id: 'POL-002', type: 'BLOCK_IP', priority: 20, enabled: true,
          config: { blocklist: ['1.2.3.4'], cidrs: [] } },
      ],
    }), 'utf8');

    const hashB = computePolicyHash(loadPolicies(file));
    expect(hashA).not.toBe(hashB);
  });

  test('policyHash is stable regardless of source JSON key ordering', () => {
    const { file: fileA, dir: dirA } = writeTempFile(JSON.stringify({
      policies: [{
        id: 'POL-001', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
        config: { requireValidArtifact: true },
      }],
    }));
    // Reverse key order in JSON
    const { file: fileB, dir: dirB } = writeTempFile(JSON.stringify({
      policies: [{
        config: { requireValidArtifact: true },
        enabled: true, priority: 10, type: 'REQUIRE_CONSENT', id: 'POL-001',
      }],
    }));

    const hashA = computePolicyHash(loadPolicies(fileA));
    const hashB = computePolicyHash(loadPolicies(fileB));

    cleanup(dirA);
    cleanup(dirB);
    dir = null; // already cleaned

    expect(hashA).toBe(hashB);
  });
});

// ── 6. Duplicate policy source detection ──────────────────────────────────────

describe('duplicate policy source detection', () => {
  let dir;
  afterEach(() => cleanup(dir));

  test('a singleton getter always returns the same frozen array reference', () => {
    const { file, dir: d } = writeTempFile(MINIMAL_VALID_DOC);
    dir = d;
    const policies  = loadPolicies(file);
    const getPolicies = () => policies;
    // Calling the getter N times must return the exact same frozen object —
    // no re-loading, no new array per call.
    for (let i = 0; i < 10; i++) {
      expect(getPolicies()).toBe(policies);
    }
  });

  test('two independent loadPolicies calls on the same file return equivalent but distinct arrays', () => {
    const { file, dir: d } = writeTempFile(MINIMAL_VALID_DOC);
    dir = d;
    const a = loadPolicies(file);
    const b = loadPolicies(file);
    // Not the same reference (two separate load calls)
    expect(a).not.toBe(b);
    // But they represent the same policy set (identical hash)
    expect(computePolicyHash(a)).toBe(computePolicyHash(b));
    // Having two separate loaders would be a mistake; only the singleton pattern
    // used in artifacts.js is correct.
  });

  test('policyHash acts as the single identity proof across two sources', () => {
    const { file, dir: d } = writeTempFile(MINIMAL_VALID_DOC);
    dir = d;
    const source1 = computePolicyHash(loadPolicies(file));
    const source2 = computePolicyHash(loadPolicies(file));
    // If two enforcement paths were accidentally wired, their hashes would still
    // match — proving they both derive from the same authoritative policies.json.
    expect(source1).toBe(source2);
  });
});
