'use strict';

/**
 * src/core/policy/store.js — POLICY_FILE resolution.
 *
 * This module has its OWN independent POLICY_FILE resolution — separate
 * from server/startup.js's — because it can be required standalone (DR
 * tooling, tests) outside a full server boot. It applies the same
 * production rule via services/policy/loader.js's shared
 * resolvePolicyFilePath(), but degrades gracefully rather than crashing the
 * process: in a real, fully-booted production server this path is
 * unreachable in the first place (server.js requires server/startup.js —
 * and its own fail-closed POLICY_FILE check — before it ever requires
 * src/app.js, the only path that pulls this module in). These tests prove
 * the degraded behavior is safe (no crash, empty store, clear WARN) for the
 * cases where this module IS reached independently of that gate.
 *
 * Every test uses jest.resetModules() + a fresh QODIQA_POLICY_STORE temp
 * path so store.js's module-load-time bootstrap IIFE genuinely re-runs
 * against a store that does not yet exist — the only branch that ever
 * reads POLICY_FILE at all (see store.js's own _bootstrap()).
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

jest.mock('../../../services/logger', () => ({ emit: jest.fn() }));

const ENV_KEYS = ['POLICY_FILE', 'NODE_ENV', 'QODIQA_POLICY_STORE'];

function freshStorePath() {
  return path.join(os.tmpdir(), `qodiqa-f19-store-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
}

function loadStoreFresh(env) {
  jest.resetModules();
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  Object.assign(process.env, env);
  const storeModule = require('./store');
  const { emit } = require('../../../services/logger');
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  // the store now seeds lazily into a process-wide control-plane
  // snapshot (dev/test memory mode). POLICY_FILE is still resolved under the
  // env above, at module load; drop any snapshot a previous case seeded so
  // this case's import runs against its own resolution.
  storeModule._reset();
  return { storeModule, emit };
}

let _tempStorePaths = [];
afterEach(() => {
  for (const p of _tempStorePaths) {
    try { fs.unlinkSync(p); } catch { /* best-effort */ }
  }
  _tempStorePaths = [];
});

describe('src/core/policy/store.js — POLICY_FILE resolution', () => {
  test('production + no POLICY_FILE + fresh store → boots with an EMPTY store, no crash', () => {
    const storePath = freshStorePath();
    _tempStorePaths.push(storePath);
    const { storeModule } = loadStoreFresh({
      NODE_ENV: 'production',
      QODIQA_POLICY_STORE: storePath,
    });
    expect(storeModule.listEnabledPolicies()).toEqual([]);
    expect(storeModule.getDashboard().total).toBe(0);
  });

  test('production + no POLICY_FILE → emits a deterministic, actionable WARN naming the cause', () => {
    const storePath = freshStorePath();
    _tempStorePaths.push(storePath);
    const { emit } = loadStoreFresh({
      NODE_ENV: 'production',
      QODIQA_POLICY_STORE: storePath,
    });
    const warnCall = emit.mock.calls.find(([level, event]) => level === 'WARN' && event === 'POLICY_STORE_BOOTSTRAP_SKIPPED');
    expect(warnCall).toBeDefined();
    expect(warnCall[2].reason).toMatch(/POLICY_FILE is not set/);
    expect(warnCall[2].reason).toMatch(/production.policies.example/);
  });

  test('the demo repository-root policies.json is never silently imported into a fresh production store', () => {
    const storePath = freshStorePath();
    _tempStorePaths.push(storePath);
    const { storeModule } = loadStoreFresh({
      NODE_ENV: 'production',
      QODIQA_POLICY_STORE: storePath,
    });
    // The demo file's own well-known policy ids must not appear — proof the
    // import genuinely never ran, not just that the count happens to be low.
    const ids = storeModule.listEnabledPolicies().map((p) => p.id);
    expect(ids).not.toContain('POL-001');
    expect(ids).not.toContain('POL-002');
  });

  test('production + an explicit, valid POLICY_FILE → imports correctly (the documented, required path still works)', () => {
    const storePath = freshStorePath();
    _tempStorePaths.push(storePath);
    const examplePath = path.resolve(__dirname, '../../../deploy/env/production.policies.example');
    const { storeModule } = loadStoreFresh({
      NODE_ENV: 'production',
      QODIQA_POLICY_STORE: storePath,
      POLICY_FILE: examplePath,
    });
    const ids = storeModule.listEnabledPolicies().map((p) => p.id);
    expect(ids).toContain('REQUIRE_CONSENT_BASELINE');
    expect(storeModule.getDashboard().total).toBeGreaterThan(0);
  });

  test('outside production, no POLICY_FILE + fresh store → imports from the real root policies.json (existing dev/test behavior preserved)', () => {
    const storePath = freshStorePath();
    _tempStorePaths.push(storePath);
    const { storeModule } = loadStoreFresh({
      NODE_ENV: 'test',
      QODIQA_POLICY_STORE: storePath,
    });
    const ids = storeModule.listEnabledPolicies().map((p) => p.id);
    expect(ids).toContain('POL-001'); // the real repo-root policies.json's own REQUIRE_CONSENT policy
  });
});
