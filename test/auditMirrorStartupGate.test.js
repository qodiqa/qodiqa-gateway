'use strict';

/**
 * Permanent regression test — CHAIN-4 Startup Cross-Validation Gate.
 *
 * Background: the whole point of the file-chain/PostgreSQL-mirror startup
 * cross-check is
 * that it runs, and is obeyed, BEFORE the HTTP server starts accepting
 * requests. A future refactor of server.js's startup sequence could
 * accidentally reorder the call after app.listen(), drop the `if
 * (!_mirrorConsistent) return;` guard, or stop awaiting the promise —  any of
 * which would silently defeat the entire remediation while every unit test
 * for mirrorConsistencyCheck.js itself kept passing (those tests exercise the
 * module in isolation and have no way to know whether server.js actually
 * calls it, or when).
 *
 * This test closes that gap with deterministic static analysis over the real
 * startup-lifecycle source (server/startup.js —'s composition-root
 * decomposition; this logic previously lived directly in server.js) (no
 * server boot required — that's already covered, end-to-end, by
 * test/serverStartupSmoke.test.js, which needs Redis and is comparatively
 * slow). It asserts, from the source text itself:
 *   1. server/startup.js imports verifyMirrorConsistency from the real module.
 *   2. The call site awaits it and textually precedes app.listen(...).
 *   3. A failure-path guard (`if (!<result>) return;`) immediately follows
 *      the call, so a false return value actually stops startup rather than
 *      being ignored.
 */

const fs   = require('fs');
const path = require('path');

const SERVER_JS_PATH = path.join(__dirname, '..', 'server', 'startup.js');

describe('CHAIN-4 — startup cross-validation gate (static regression)', () => {
  let source;

  beforeAll(() => {
    source = fs.readFileSync(SERVER_JS_PATH, 'utf8');
  });

  test('server/startup.js imports verifyMirrorConsistency from the real production module', () => {
    expect(source).toMatch(
      /require\(\s*['"]\.\.\/src\/core\/audit\/mirrorConsistencyCheck['"]\s*\)/,
    );
    expect(source).toMatch(/verifyMirrorConsistency\s*:\s*(_verifyAuditMirrorConsistency|\w+)/);
  });

  test('the cross-validation call is awaited and textually precedes app.listen(...)', () => {
    const callMatch = source.match(/await\s+_verifyAuditMirrorConsistency\s*\(\s*\)/);
    const listenMatch = source.match(/app\.listen\(/);

    expect(callMatch).not.toBeNull();
    expect(listenMatch).not.toBeNull();
    expect(callMatch.index).toBeLessThan(listenMatch.index);
  });

  test('a failure-path guard immediately follows the call, gating startup on its result', () => {
    // Captures: const <var> = await _verifyAuditMirrorConsistency();
    //           ... if (!<var>) return; ...
    // within a short window so a guard placed elsewhere in the file (not
    // actually gating this call) cannot satisfy the assertion by accident.
    const assignMatch = source.match(
      /const\s+(\w+)\s*=\s*await\s+_verifyAuditMirrorConsistency\s*\(\s*\)\s*;/,
    );
    expect(assignMatch).not.toBeNull();

    const resultVar = assignMatch[1];
    const afterAssign = source.slice(assignMatch.index, assignMatch.index + 400);

    const guardPattern = new RegExp(`if\\s*\\(\\s*!${resultVar}\\s*\\)\\s*return\\s*;`);
    expect(afterAssign).toMatch(guardPattern);
  });

  test('the guard return is reachable before any route registration or app.listen(...) runs', () => {
    const assignMatch = source.match(
      /const\s+(\w+)\s*=\s*await\s+_verifyAuditMirrorConsistency\s*\(\s*\)\s*;/,
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
});
