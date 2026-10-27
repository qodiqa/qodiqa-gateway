'use strict';

/**
 * Filesystem helpers shared by every acceptance test: temp directories,
 * safe JSON read/write, and evidence/log file writers that follow the
 * naming convention already established
 * (evidence/AT-<id>-<description>.<ext>, logs/AT-<id>-<description>.log).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const ACCEPTANCE_ROOT = path.join(__dirname, '..');
// C-11: a run's evidence / logs / reports go under the git-ignored run root (helpers/outputRoot.js); the
// tracked test/acceptance/{evidence,logs,reports} are the last deliberate snapshot (npm run acceptance:snapshot). Returned
// paths stay 'evidence/<file>' / 'logs/<file>' (relative to the run root), valid in a run directory and in a snapshot.
const { RUN_EVIDENCE_DIR: EVIDENCE_DIR, RUN_LOGS_DIR: LOGS_DIR, RUN_REPORTS_DIR: REPORTS_DIR, RUN_ROOT } = require('./outputRoot');

function mkTempDir(prefix = 'qodiqa-acceptance-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function removeDir(dir) {
  if (dir && fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function readJson(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(raw);
}

function writeJson(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(data, null, 2)}\n`);
}

/**
 * Writes an evidence file under test/acceptance/evidence/, returning the
 * path written (repo-relative, for embedding in reports).
 *
 * @param {string} filename e.g. "AT-007-health.txt"
 * @param {string|object} content string written as-is; object JSON.stringify'd
 */
function writeEvidence(filename, content) {
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
  const filePath = path.join(EVIDENCE_DIR, filename);
  const body = typeof content === 'string' ? content : `${JSON.stringify(content, null, 2)}\n`;
  fs.writeFileSync(filePath, body);
  return path.relative(RUN_ROOT, filePath).split(path.sep).join('/');
}

/**
 * Writes a log file under test/acceptance/logs/, returning the path
 * written (repo-relative, for embedding in reports).
 *
 * @param {string} filename e.g. "AT-002-startup.log"
 */
function writeLog(filename, content) {
  fs.mkdirSync(LOGS_DIR, { recursive: true });
  const filePath = path.join(LOGS_DIR, filename);
  fs.writeFileSync(filePath, content);
  return path.relative(RUN_ROOT, filePath).split(path.sep).join('/');
}

module.exports = {
  ACCEPTANCE_ROOT,
  EVIDENCE_DIR,
  LOGS_DIR,
  REPORTS_DIR,
  mkTempDir,
  removeDir,
  readJson,
  writeJson,
  writeEvidence,
  writeLog,
};
