'use strict';

/**
 * Permanent regression test — Canonical Log Event Envelope.
 *
 * Background: services/logger.js's emit() used to build its record as
 * { ts, level, event, category, ...extra } while every consumer of that
 * record (src/core/audit/centralStore.js's platform_audit_events table,
 * src/observability/logShipping/schema.js's SIEM normalizer) had already
 * standardized on timestamp/severity/eventType — forcing a translation step
 * at every boundary. Separately, five independent startup-integrity gates
 * each hand-rolled their own copy of a fail-safe raw-stderr diagnostic
 * writer using those same legacy field names, discovered only by grepping
 * the whole repository for the literal pattern during the
 * remediation — nothing would have caught a sixth one appearing.
 *
 * for the full envelope contract
 * and the one approved exception (src/runtime/rawStderrDiagnostic.js).
 *
 * This test prevents recurrence structurally, the same way
 * test/rateLimitSurfaceConsistency.test.js does for its own concern: a
 * real filesystem/regex scan over production source, not a manually
 * maintained list, so a new violation is caught without anyone needing to
 * remember this ADR exists.
 *
 * Two independent things are checked:
 *
 *   1. No file outside the two-file allowlist (services/logger.js,
 *      src/runtime/rawStderrDiagnostic.js) writes a JSON.stringify()'d
 *      object directly to process.stdout/process.stderr. This is the
 *      "bypasses the canonical schema outside explicitly approved
 *      exceptions" check — every log producer must go through emit() or
 *      the one approved fail-safe helper, not invent a third path.
 *
 *   2. No file, anywhere (including the allowlist — the helper itself was
 *      rewritten to stop doing this), reintroduces the legacy
 *      `ts: new Date().toISOString()` construction this whole remediation
 *      exists to eliminate. This is the "introduces legacy fields" check.
 */

const fs   = require('fs');
const path = require('path');

const REPO_ROOT = path.join(__dirname, '..', '..', '..');

// The ONLY two files permitted to write a raw structured JSON record
// directly to stdout/stderr — kept in sync with
// and the header comment of
// src/runtime/rawStderrDiagnostic.js. A new fail-safe exception must be
// added to rawStderrDiagnostic.js itself (single shared implementation),
// not granted a new entry here.
const RAW_WRITE_ALLOWLIST = new Set([
  path.join('services', 'logger.js'),
  path.join('src', 'runtime', 'rawStderrDiagnostic.js'),
]);

// Matches process.stdout.write(JSON.stringify(...)) / process.stderr.write(JSON.stringify(...)),
// allowing arbitrary whitespace, exactly the shape every one of the five
// earlier duplicated diagnostic emitters used.
const RAW_WRITE_PATTERN = /process\s*\.\s*(?:stdout|stderr)\s*\.\s*write\s*\(\s*JSON\.stringify\s*\(/g;

// Matches the exact legacy field-construction snippet every one of the five
// duplicated emitters (and the pre-remediation services/logger.js) used.
// Deliberately narrow and literal — see rateLimitSurfaceConsistency.test.js's
// header comment for why a precise, static pattern is the right tool here
// rather than a "smarter" heuristic that would itself become a source of
// false positives/negatives.
const LEGACY_TS_PATTERN = /\bts\s*:\s*new Date\(\)\.toISOString\(\)/g;

function isTestFile(filePath) {
  return filePath.split(path.sep).includes('__tests__') || filePath.endsWith('.test.js');
}

function collectProductionJsFiles(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith('.')) continue;
    if (entry.name === 'node_modules') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      collectProductionJsFiles(full, out);
    } else if (entry.isFile() && entry.name.endsWith('.js') && !isTestFile(full)) {
      out.push(full);
    }
  }
  return out;
}

describe('Canonical log event envelope (regression — ADR-040)', () => {
  const files = [
    ...collectProductionJsFiles(path.join(REPO_ROOT, 'src')),
    ...collectProductionJsFiles(path.join(REPO_ROOT, 'services')),
  ];

  // Sanity check on the scan itself — see rateLimitSurfaceConsistency.test.js
  // for why this guards against a silently-broken traversal producing a
  // vacuous pass. src/ + services/ has well over 100 production .js files.
  test('sanity: the scan discovers a realistic number of production files', () => {
    expect(files.length).toBeGreaterThan(100);
  });

  test('no file outside the approved allowlist writes a raw JSON record to stdout/stderr', () => {
    const violations = [];
    for (const file of files) {
      const rel = path.relative(REPO_ROOT, file);
      if (RAW_WRITE_ALLOWLIST.has(rel)) continue;
      const content = fs.readFileSync(file, 'utf8');
      RAW_WRITE_PATTERN.lastIndex = 0;
      if (RAW_WRITE_PATTERN.test(content)) violations.push(rel);
    }

    if (violations.length > 0) {
      throw new Error(
        'Found file(s) writing a raw JSON.stringify()\'d record directly to ' +
        'stdout/stderr outside the approved allowlist ' +
        `(${[...RAW_WRITE_ALLOWLIST].join(', ')}):\n` +
        violations.map(v => `  ${v}`).join('\n') + '\n\n' +
        'Every log producer must go through services/logger.js\'s emit(), or — ' +
        'for the narrow fail-safe case where emit() itself cannot be trusted ' +
        '— call ' +
        'src/runtime/rawStderrDiagnostic.js\'s writeDiagnostic() rather than ' +
        'hand-rolling a new copy.'
      );
    }
  });

  test('no file reintroduces the legacy ts: new Date().toISOString() field pattern', () => {
    const violations = [];
    for (const file of files) {
      const content = fs.readFileSync(file, 'utf8');
      LEGACY_TS_PATTERN.lastIndex = 0;
      if (LEGACY_TS_PATTERN.test(content)) violations.push(path.relative(REPO_ROOT, file));
    }

    if (violations.length > 0) {
      throw new Error(
        'Found file(s) using the legacy `ts: new Date().toISOString()` log ' +
        'field pattern (replaced by `timestamp:` everywhere):\n' +
        violations.map(v => `  ${v}`).join('\n')
      );
    }
  });

  // Proves the allowlist itself is still accurate — if either approved file
  // is ever renamed/removed without updating RAW_WRITE_ALLOWLIST, the
  // "no violations" result above would be vacuously true for the wrong
  // reason (an allowlist entry silently matching nothing).
  test('every allowlisted path actually exists and is a scanned production file', () => {
    const scannedRelPaths = new Set(files.map(f => path.relative(REPO_ROOT, f)));
    for (const rel of RAW_WRITE_ALLOWLIST) {
      expect(scannedRelPaths.has(rel)).toBe(true);
    }
  });

  // Proves the raw-write pattern itself still matches something real — if a
  // future refactor of rawStderrDiagnostic.js changes its write call shape
  // (e.g. a template literal, a wrapper), this regex would silently stop
  // matching anything and the "no violations" test above would pass for the
  // wrong reason, exactly the failure mode
  // rateLimitSurfaceConsistency.test.js's equivalent check guards against.
  test('the raw-write pattern matches the approved helper (proves the detector itself works)', () => {
    const helperPath = path.join(REPO_ROOT, 'src', 'runtime', 'rawStderrDiagnostic.js');
    const content = fs.readFileSync(helperPath, 'utf8');
    RAW_WRITE_PATTERN.lastIndex = 0;
    expect(RAW_WRITE_PATTERN.test(content)).toBe(true);
  });
});
