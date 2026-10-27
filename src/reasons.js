'use strict';

/**
 * QODIQA Canonical Reason Vocabulary
 *
 * ERR-2 remediation: this module is now a thin wrapper deriving
 * `REASONS` from src/errors/catalog.js — the single machine-readable source
 * of truth for the enforcement/protocol reason vocabulary (also consumed by
 * docs/operations/troubleshooting.md and docs/architecture/enforcement-flow.md). Previously this file
 * maintained its own partial (~29-code) subset independently of
 * docs/architecture/enforcement-flow.md's and docs/operations/troubleshooting.md's own hand-written tables —
 * see git history and WP-030-REMEDIATION-REPORT.md for the full
 * before/after. `REASONS` is now exhaustive (every code in the catalog),
 * not a subset.
 *
 * `reasons.test.js` verifies this vocabulary against real pipeline
 * behavior by calling validateArtifact(), validateBoundRequest(), and the
 * policy engine directly and asserting the returned `.reason` matches the
 * constant below.
 *
 * This module is not imported by route handlers at runtime (routes
 * construct `reason` strings directly); it exists as the machine-checked
 * reference for the codes it contains.
 *
 * Rules (enforced by src/errors/__tests__/catalog.governance.test.js and
 * src/__tests__/reasons.test.js):
 *   - UPPERCASE_SNAKE_CASE only
 *   - No near-synonyms: each semantic has exactly one code
 *   - Stable across deployments — codes are part of the public API contract
 */

const { ERROR_CATALOG } = require('./errors/catalog');

const REASONS = Object.freeze(
  Object.fromEntries(Object.keys(ERROR_CATALOG).map((code) => [code, code])),
);

module.exports = { REASONS };
