'use strict';

/**
 * Structural regression test.
 *
 * The entire deployment-mode resolver design (src/infra/config/deploymentMode.js)
 * depends on ONE invariant that no unit test can otherwise verify: that
 * server/startup.js calls applyDeploymentMode() before it requires any
 * module that reads QODIQA_PG_ENABLED / QODIQA_AUDIT_ORDERING_MODE at
 * require() time or relies on the resolver's memoized result — most
 * critically src/core/audit/multiInstanceGuard.js, which computes its
 * ORDERING_MODE constant once, at require() time, and src/infra/postgres/pool.js.
 * A future refactor (splitting server/startup.js, alphabetizing/reordering
 * its requires, extracting a "requires" module) could silently break this
 * ordering with no other test failing — multiInstanceGuard.js would simply
 * fall back to resolving from process.env directly again, and
 * QODIQA_DEPLOYMENT_MODE would appear to have no effect, discovered only in
 * a production deployment.
 *
 * This is a real, static-source-position check — not a behavioral test
 * (require-order bugs of this kind can't be reliably reproduced by
 * requiring the module in Jest, since Jest's own module resolution and
 * server/startup.js's real top-level side effects, e.g. process.exit() on
 * missing config, make it impractical to actually execute this file in a
 * unit test). It parses server/startup.js's own source text and asserts the
 * relative ORDER of specific literal patterns — the same technique this
 * repo already uses for src/runtime/__tests__/logEnvelope.structural.test.js
 * and this file's own sibling, test/rateLimitSurfaceConsistency.test.js.
 */

const fs   = require('fs');
const path = require('path');

const STARTUP_PATH = path.resolve(__dirname, '..', '..', 'server', 'startup.js');

function loadSource() {
  return fs.readFileSync(STARTUP_PATH, 'utf8');
}

/** Returns the character index of the first match, or throws with a clear message. */
function indexOfOrThrow(source, pattern, label) {
  const idx = source.search(pattern);
  if (idx === -1) {
    throw new Error(`Expected to find ${label} in server/startup.js (pattern: ${pattern}) — has it been renamed or removed?`);
  }
  return idx;
}

describe('server/startup.js — require-order invariant (structural regression)', () => {
  test('sanity: server/startup.js exists and is non-trivial', () => {
    expect(fs.existsSync(STARTUP_PATH)).toBe(true);
    expect(loadSource().length).toBeGreaterThan(1000);
  });

  test('dotenv.config() runs before applyDeploymentMode() is called', () => {
    const source = loadSource();
    const dotenvIdx = indexOfOrThrow(source, /require\(['"]dotenv['"]\)\.config\(\)/, "require('dotenv').config()");
    const applyCallIdx = indexOfOrThrow(source, /\bapplyDeploymentMode\(\s*\)\s*;/, 'the applyDeploymentMode() call');
    expect(dotenvIdx).toBeLessThan(applyCallIdx);
  });

  test('applyDeploymentMode() is called before multiInstanceGuard.js is required', () => {
    const source = loadSource();
    const applyCallIdx = indexOfOrThrow(source, /\bapplyDeploymentMode(\s*)\(\s*\)\s*;/, 'the applyDeploymentMode() call');
    const guardRequireIdx = indexOfOrThrow(
      source,
      /require\(['"]\.\.\/src\/core\/audit\/multiInstanceGuard['"]\)/,
      "require('../../src/core/audit/multiInstanceGuard')",
    );
    expect(applyCallIdx).toBeLessThan(guardRequireIdx);
  });

  test('applyDeploymentMode() is called before src/infra/postgres/pool.js is required', () => {
    const source = loadSource();
    const applyCallIdx = indexOfOrThrow(source, /\bapplyDeploymentMode(\s*)\(\s*\)\s*;/, 'the applyDeploymentMode() call');
    const poolRequireIdx = indexOfOrThrow(
      source,
      /require\(['"]\.\.\/src\/infra\/postgres\/pool['"]\)/,
      "require('../../src/infra/postgres/pool')",
    );
    expect(applyCallIdx).toBeLessThan(poolRequireIdx);
  });

  test('applyDeploymentMode() is actually invoked, not merely imported', () => {
    const source = loadSource();
    // Distinguishes "const { applyDeploymentMode } = require(...)" (import
    // only) from an actual bare call — a regression that imported the
    // function but forgot to call it would otherwise pass every other
    // ordering assertion above vacuously (there's nothing to be "before" or
    // "after" if it's never called at all).
    expect(source).toMatch(/require\(['"]\.\.\/src\/infra\/config\/deploymentMode['"]\)/);
    expect(source).toMatch(/\bapplyDeploymentMode\(\s*\)\s*;/);
  });

  test('exactly one call to applyDeploymentMode() exists (single, unambiguous invocation point)', () => {
    const source = loadSource();
    const matches = source.match(/\bapplyDeploymentMode\(\s*\)/g) || [];
    // Expect exactly 2 occurrences of the bare identifier call syntax: the
    // require() destructure line does NOT match this call-shaped pattern
    // (it has no trailing parens directly after the identifier), so every
    // match here is a real invocation. Historically this file has called it
    // exactly once; more than one call site would be a sign of duplicated
    // startup logic (e.g. a leftover call from a bad merge).
    expect(matches.length).toBe(1);
  });
});

describe('server/startup.js — DEPLOYMENT_MODE_RESOLVED log enum accuracy (structural regression)', () => {
  test('the deploymentMode log field is never coerced to a non-enum sentinel value', () => {
    const source = loadSource();
    // A prior revision wrote `deploymentMode: _deploymentConfig.deploymentMode ?? 'legacy'`
    // — emitting the literal string "legacy" in a field documented (and
    // relied upon by dashboards) to be exactly 'single-node' | 'distributed'
    // | null. Assert that specific regression pattern can never reappear.
    expect(source).not.toMatch(/deploymentMode:\s*_deploymentConfig\.deploymentMode\s*\?\?/);
    // And assert the field is still present and assigned directly from the
    // resolver's own value, so this isn't just a vacuous "the bad pattern is
    // gone because the whole feature is gone" pass.
    expect(source).toMatch(/deploymentMode:\s*_deploymentConfig\.deploymentMode\s*,/);
  });
});
