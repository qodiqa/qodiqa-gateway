'use strict';

/**
 * Permanent regression test — CHAIN-2 Startup Watermark-Continuity Gate.
 *
 * Same rationale as test/auditMirrorStartupGate.test.js, applied to the new
 * gate: verifyChainVerifierContinuity() (src/core/audit/verifierStartupGate.js)
 * only protects the deployment if server.js actually calls it, awaits it,
 * and stops startup on a false return — BEFORE the HTTP server starts
 * accepting requests and BEFORE any background job (including the live
 * verifier's own runner) has a chance to run. A future refactor could
 * silently defeat this by reordering the call after app.listen(), dropping
 * the `if (!<result>) return;` guard, or forgetting to await it, while every
 * unit test for verifierStartupGate.js itself kept passing (those exercise
 * the module in isolation and have no way to know whether the startup
 * lifecycle calls it, or when). This test closes that gap via static
 * analysis of the real startup-lifecycle source (server/startup.js — see
 *'s composition-root decomposition; this logic previously lived
 * directly in server.js) — no server boot required (that path is already
 * covered, end-to-end, by test/serverStartupSmoke.test.js).
 */

const fs   = require('fs');
const path = require('path');

const SERVER_JS_PATH = path.join(__dirname, '..', 'server', 'startup.js');

describe('CHAIN-2 — startup watermark-continuity gate (static regression)', () => {
  let source;

  beforeAll(() => {
    source = fs.readFileSync(SERVER_JS_PATH, 'utf8');
  });

  test('server/startup.js imports verifyChainVerifierContinuity from the real production module', () => {
    expect(source).toMatch(
      /require\(\s*['"]\.\.\/src\/core\/audit\/verifierStartupGate['"]\s*\)/,
    );
    expect(source).toMatch(/verifyChainVerifierContinuity\s*:\s*(_verifyAuditChainVerifierContinuity|\w+)/);
  });

  test('the continuity check call is awaited and textually precedes app.listen(...)', () => {
    const callMatch = source.match(/await\s+_verifyAuditChainVerifierContinuity\s*\(\s*\)/);
    const listenMatch = source.match(/app\.listen\(/);

    expect(callMatch).not.toBeNull();
    expect(listenMatch).not.toBeNull();
    expect(callMatch.index).toBeLessThan(listenMatch.index);
  });

  test('a failure-path guard immediately follows the call, gating startup on its result', () => {
    const assignMatch = source.match(
      /const\s+(\w+)\s*=\s*await\s+_verifyAuditChainVerifierContinuity\s*\(\s*\)\s*;/,
    );
    expect(assignMatch).not.toBeNull();

    const resultVar = assignMatch[1];
    const afterAssign = source.slice(assignMatch.index, assignMatch.index + 400);

    const guardPattern = new RegExp(`if\\s*\\(\\s*!${resultVar}\\s*\\)\\s*return\\s*;`);
    expect(afterAssign).toMatch(guardPattern);
  });

  test('the guard return is reachable before any route registration or app.listen(...) runs', () => {
    const assignMatch = source.match(
      /const\s+(\w+)\s*=\s*await\s+_verifyAuditChainVerifierContinuity\s*\(\s*\)\s*;/,
    );
    const listenMatch = source.match(/app\.listen\(/);
    expect(assignMatch).not.toBeNull();
    expect(listenMatch).not.toBeNull();

    const resultVar = assignMatch[1];
    const guardPattern = new RegExp(`if\\s*\\(\\s*!${resultVar}\\s*\\)\\s*return\\s*;`);
    const guardMatch = source.match(guardPattern);
    expect(guardMatch).not.toBeNull();
    expect(guardMatch.index).toBeLessThan(listenMatch.index);
  });

  test('the continuity gate textually follows the mirror-consistency gate (correct ordering)', () => {
    const mirrorCallMatch = source.match(/await\s+_verifyAuditMirrorConsistency\s*\(\s*\)/);
    const continuityCallMatch = source.match(/await\s+_verifyAuditChainVerifierContinuity\s*\(\s*\)/);

    expect(mirrorCallMatch).not.toBeNull();
    expect(continuityCallMatch).not.toBeNull();
    expect(mirrorCallMatch.index).toBeLessThan(continuityCallMatch.index);
  });

  test('the background runner is started only after app.listen(...), not before', () => {
    const runnerStartMatch = source.match(/_auditChainVerifierRunner\.start\(\)/);
    const listenMatch = source.match(/app\.listen\(/);

    expect(runnerStartMatch).not.toBeNull();
    expect(listenMatch).not.toBeNull();
    expect(runnerStartMatch.index).toBeGreaterThan(listenMatch.index);
  });

  test('the runner is registered for graceful shutdown', () => {
    expect(source).toMatch(/AUDIT_CHAIN_VERIFIER['"]\s*,\s*store:\s*\{\s*disconnect:\s*\(\)\s*=>\s*_auditChainVerifierRunner\.stop\(\)/);
  });
});
