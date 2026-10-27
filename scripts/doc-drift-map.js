'use strict';

/**
 * Explicit mapping between source paths and the documentation that must be
 * updated alongside them — documentation-drift prevention.
 *
 * Each entry:
 *   name        - short label used in CI output
 *   sourceGlobs - RegExp array tested against changed file paths (repo-
 *                 relative, forward-slash separated, as `git diff` reports
 *                 them); if any changed file matches, `docFile` must also
 *                 appear in the same changed-file set
 *   docFile     - repo-relative path to the documentation file
 *   selfDoc     - true when the file documents its own status in a header
 *                 comment (sourceGlobs matches docFile itself) rather than
 *                 describing a separate source tree. For these, the check
 *                 instead requires the file's own "Last verified:
 *                 YYYY-MM-DD" line to change whenever the rest of the file
 *                 does.
 *
 * To extend coverage to a new area, add one entry below — no other file
 * needs to change.
 */
module.exports = [
  {
    // Doubles as the architecture-status, tooling-status, and
    // configuration-status coverage: this file's own header comment
    // claims a compliance status ("fully compliant as of this
    // remediation") for the rules defined immediately below it.
    name: 'dependency-cruiser-status',
    sourceGlobs: [/^\.dependency-cruiser\.js$/],
    docFile: '.dependency-cruiser.js',
    selfDoc: true,
  },
  {
    // Content-level correctness (does the KMS table's per-provider var set
    // actually match kmsConfig.js) is checked separately and unconditionally
    // by scripts/kms-config-doc-check.js — this entry is the complementary
    // co-change layer: forces a docs review whenever kmsConfig.js changes,
    // the same as every other mapping here.
    name: 'kms-config-reference',
    sourceGlobs: [/^src\/infra\/keys\/kmsConfig\.js$/],
    docFile: 'docs/configuration/reference.md',
  },
];
