'use strict';

/**
 * C-11: where an acceptance RUN writes its volatile output.
 *
 * Before: every `npm run acceptance` rewrote tracked files in place — test/acceptance/evidence/*, logs/*, reports/*,
 * results.json, and the auto-generated blocks of TEST-RESULTS.md and CHECKLIST.md — so a normal test run left the
 * working tree dirty.
 *
 * Now a run writes all of that under RUN_ROOT, which defaults to the git-ignored test/acceptance/.runs/latest/ and can
 * be redirected with QODIQA_ACCEPTANCE_OUT_DIR (an absolute path, or one relative to the repository root). The tracked
 * files stay as the last deliberate SNAPSHOT: `npm run acceptance:snapshot` copies a run into them and records a hash
 * manifest (helpers/snapshot.js). Case definitions, scripts, payloads and the deterministic assertions are unchanged.
 */

const path = require('path');

const ACCEPTANCE_ROOT = path.join(__dirname, '..');
const REPO_ROOT = path.join(ACCEPTANCE_ROOT, '..', '..');
const DEFAULT_RUN_ROOT = path.join(ACCEPTANCE_ROOT, '.runs', 'latest');

function runRoot() {
  const v = process.env.QODIQA_ACCEPTANCE_OUT_DIR;
  if (!v) return DEFAULT_RUN_ROOT;
  return path.isAbsolute(v) ? v : path.join(REPO_ROOT, v);
}

const RUN_ROOT = runRoot();

module.exports = {
  ACCEPTANCE_ROOT,
  REPO_ROOT,
  DEFAULT_RUN_ROOT,
  RUN_ROOT,
  RUN_EVIDENCE_DIR: path.join(RUN_ROOT, 'evidence'),
  RUN_LOGS_DIR: path.join(RUN_ROOT, 'logs'),
  RUN_REPORTS_DIR: path.join(RUN_ROOT, 'reports'),
  RUN_RESULTS_JSON: path.join(RUN_ROOT, 'results.json'),
  RUN_TEST_RESULTS_MD: path.join(RUN_ROOT, 'TEST-RESULTS.md'),
  RUN_CHECKLIST_MD: path.join(RUN_ROOT, 'CHECKLIST.md'),
  // The tracked snapshot locations (written only by `npm run acceptance:snapshot`).
  TRACKED: {
    evidence: path.join(ACCEPTANCE_ROOT, 'evidence'),
    logs: path.join(ACCEPTANCE_ROOT, 'logs'),
    reports: path.join(ACCEPTANCE_ROOT, 'reports'),
    resultsJson: path.join(ACCEPTANCE_ROOT, 'results.json'),
    testResultsMd: path.join(ACCEPTANCE_ROOT, 'TEST-RESULTS.md'),
    checklistMd: path.join(ACCEPTANCE_ROOT, 'CHECKLIST.md'),
  },
};
