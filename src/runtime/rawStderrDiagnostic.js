'use strict';

/**
 * Canonical fail-safe raw stderr diagnostic writer —.
 *
 * for the full canonical
 * envelope contract and the rationale for this module's existence as the
 * ONE approved exception to "every log producer calls services/logger.js's
 * emit()".
 *
 * A small number of startup/integrity gates must be able to report a
 * FATAL/WARN diagnostic even if the shared logger itself is what's broken
 * (e.g. its PostgreSQL-backed central store sink is unreachable — see
 * mirrorConsistencyCheck.js, which exists specifically to catch PG
 * divergence and therefore cannot depend on PG working to report that it
 * doesn't). Those modules write directly to process.stderr instead of
 * calling emit(), deliberately bypassing sanitization, the event bus, and
 * the central store — all three of which could themselves be broken.
 *
 * Approved callers (all five known fail-safe startup gates in this
 * codebase, kept in sync with the allowlist in
 * src/runtime/__tests__/logEnvelope.structural.test.js):
 *   - src/core/audit/retentionPrivilegeCheck.js
 *   - src/core/audit/mirrorConsistencyCheck.js
 *   - src/core/audit/multiInstanceGuard.js
 *   - src/core/audit/verifierStartupGate.js
 *   - src/runtime/processHardening.js
 *
 *each of the five modules above maintained its OWN copy of
 * this exact logic, and had independently drifted from the canonical field
 * names services/logger.js also drifted from (ts/level/event instead of
 * timestamp/severity/eventType). This is now the single, shared
 * implementation — every call site delegates here instead of keeping its
 * own copy, so there is exactly one place this shape is defined, and it
 * cannot drift from itself. A new fail-safe exception must be added here
 * (or call this function directly) and to the structural test's allowlist —
 * it must not hand-roll a new copy.
 *
 * No `category` field: services/logger.js's emit() computes `category` via
 * logClassifier.js's classify(severity, eventType), which is meaningful for
 * the full space of operational/security events. These diagnostics are
 * always FATAL/WARN startup-integrity failures, not general operational
 * events, so that classification does not apply here.
 *
 * @param {string} severity  'FATAL' | 'WARN' | 'INFO' (matches emit()'s levels)
 * @param {string} eventType SCREAMING_SNAKE_CASE event name
 * @param {object} [extra]   event-specific payload, spread onto the record as-is
 */
function writeDiagnostic(severity, eventType, extra = {}) {
  const record = { timestamp: new Date().toISOString(), severity, eventType, ...extra };
  process.stderr.write(JSON.stringify(record) + '\n');
}

module.exports = { writeDiagnostic };
