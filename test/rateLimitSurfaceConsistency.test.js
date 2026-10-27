'use strict';

/**
 * Permanent regression test — Rate-Limit Surface Consistency.
 *
 * Background: src/api/routes/certificationBatch.js called
 * createRateLimitMiddleware('certification_batch'), but that surface name
 * had not been registered in KNOWN_SURFACES (src/core/rateLimit/config.js).
 * createRateLimitMiddleware() validates its surface argument synchronously,
 * at router-construction time (src/core/rateLimit/middleware.js) — so the
 * defect only needed the real, unmocked router to be *built*, not even
 * requested, to throw. It went undetected by the full 7206-test suite
 * because every test that constructed that router first replaced the
 * entire ../../core/rateLimit module with `jest.mock(...)`, so the real
 * getPolicy()/KNOWN_SURFACES check was never executed. No test in the
 * suite required server.js as a whole, which is the only place the real,
 * unmocked call actually runs. See test/serverStartupSmoke.test.js for
 * the companion regression test that closes that second gap.
 *
 * This test prevents recurrence structurally: it discovers every
 * createRateLimitMiddleware('<surface>') call literal directly from
 * production source files (a real filesystem/regex scan — not a manually
 * maintained list) and asserts each one is a member of the real
 * KNOWN_SURFACES Set, imported directly from the production module. If a
 * route ever references an unregistered or misspelled surface again, this
 * test fails without needing the real server to be booted at all.
 */

const fs   = require('fs');
const path = require('path');

const { KNOWN_SURFACES } = require('../src/core/rateLimit');

const REPO_ROOT = path.join(__dirname, '..');

// Directories that are never production source for this server (separate
// legacy/superseded implementations, build output, dependencies, or
// non-code assets) — excluded from the scan for precision and speed, not
// because the check depends on this list to be correct: any stray call
// site left in a scanned production directory is exactly what this test
// exists to catch.
const EXCLUDED_DIR_NAMES = new Set([
  'node_modules', '.git', 'sdk',
  'coverage', 'dist', 'public', 'data',
]);

// Matches createRateLimitMiddleware('surface') / ("surface") with a plain
// string literal.
//
// Only literal-argument call sites are discoverable this way, and that is
// deliberate, not a scanner limitation to be worked around:
//   - Project convention requires createRateLimitMiddleware()'s surface
//     argument to always be a string literal. Dynamically constructed
//     surface names (string concatenation, template interpolation,
//     variables, function calls) are prohibited precisely so that every
//     surface a route can reference is statically enumerable by reading the
//     source text — no JavaScript evaluation required.
//   - That constraint is what makes this test possible at all: it performs
//     deterministic static validation (regex over file contents), not
//     interpretation of arbitrary JS. Extending the pattern to "understand"
//     dynamic expressions would turn this into a partial JS interpreter,
//     which is unnecessary complexity for what the check needs and would
//     itself become a new source of false negatives/positives.
//   - A call site that ever needs a computed surface name is a signal that
//     this convention (and this test) need revisiting deliberately — not
//     that the regex should be made cleverer.
const CALL_PATTERN = /createRateLimitMiddleware\(\s*(['"])([A-Za-z0-9_]+)\1/g;

function isTestFile(filePath) {
  return filePath.split(path.sep).includes('__tests__') || filePath.endsWith('.test.js');
}

function collectProductionJsFiles(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith('.')) continue;
    if (EXCLUDED_DIR_NAMES.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      collectProductionJsFiles(full, out);
    } else if (entry.isFile() && entry.name.endsWith('.js') && !isTestFile(full)) {
      out.push(full);
    }
  }
  return out;
}

describe('Rate-limit surface consistency (regression)', () => {
  test('every createRateLimitMiddleware(...) surface literal in production source is registered in KNOWN_SURFACES', () => {
    const files = collectProductionJsFiles(REPO_ROOT);
    // Sanity check on the scan itself — this asserts the traversal is
    // *working*, not that the repository has reached some expected size.
    // A near-empty result (0, or a handful) would mean the walk is broken
    // (e.g. wrong root, an exclusion swallowing everything, readdirSync
    // throwing and being caught somewhere upstream) which would make the
    // rest of this test vacuously pass without checking anything.
    //
    // The threshold is deliberately low and coarse rather than tracking the
    // repository's actual file count (currently in the hundreds): the goal
    // is only to distinguish "the scanner is broken" from "the scanner
    // ran," so this should stay true whether the codebase grows or shrinks
    // over time. Any project this size — multiple route/service/middleware
    // directories — has well over 20 production .js files; a working scan
    // finding fewer than that indicates a broken traversal, not a small
    // repository.
    expect(files.length).toBeGreaterThan(20);

    const discovered = new Map(); // surface -> [relative file paths]
    for (const file of files) {
      const content = fs.readFileSync(file, 'utf8');
      CALL_PATTERN.lastIndex = 0;
      let match;
      while ((match = CALL_PATTERN.exec(content))) {
        const surface = match[2];
        const rel = path.relative(REPO_ROOT, file);
        if (!discovered.has(surface)) discovered.set(surface, []);
        if (!discovered.get(surface).includes(rel)) discovered.get(surface).push(rel);
      }
    }

    // Sanity check on the discovery mechanism itself — if a future refactor
    // changes the call syntax (e.g. a wrapper function, a spread call) this
    // regex would silently stop matching anything and the test below would
    // pass for the wrong reason. Known call sites exist today (attestation,
    // certification, certification_batch, transparency, portal,
    // webhooks_admin, ...), so discovering zero is itself a failure.
    expect(discovered.size).toBeGreaterThan(0);

    const unregistered = [...discovered.entries()]
      .filter(([surface]) => !KNOWN_SURFACES.has(surface));

    if (unregistered.length > 0) {
      const detail = unregistered
        .map(([surface, locs]) => `  "${surface}" referenced in: ${locs.join(', ')}`)
        .join('\n');
      throw new Error(
        'Found createRateLimitMiddleware() call(s) referencing a surface name that is ' +
        'not present in KNOWN_SURFACES (src/core/rateLimit/config.js):\n' + detail + '\n\n' +
        'Register the missing surface in _buildSurfaceDefaults(), or fix the typo. ' +
        'Without this, the real (unmocked) router construction throws at server startup.',
      );
    }
  });
});
