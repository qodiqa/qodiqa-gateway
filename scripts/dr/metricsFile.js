'use strict';

/**
 * Prometheus textfile-collector metrics emission for scheduled backup jobs
 *.
 *
 * CronJob/systemd-timer pods and units are ephemeral and are not scraped
 * directly by Prometheus, so the standard infrastructure-agnostic pattern is
 * used here: write a `.prom` file that node_exporter's (or any equivalent
 * agent's) textfile collector picks up on its own scrape interval. This adds
 * no new dependency (no client library, no push gateway) and works
 * identically on Kubernetes and bare-metal/systemd deployments.
 *
 * Writing is entirely opt-in (no-op if `filePath` is falsy) and never
 * throws — metric emission must never be the reason a backup job reports
 * failure. The write is atomic (temp file + rename) so the textfile
 * collector never observes a partially written file.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

function _sanitizeMetricName(name) {
  return String(name).replace(/[^a-zA-Z0-9_:]/g, '_');
}

/**
 * Values of `names` currently in `filePath` (unlabelled `name value` lines, as this module writes them).
 * Never throws: a missing/unreadable file simply yields {}.
 */
function _readPreserved(filePath, names) {
  const out = {};
  if (!names || names.length === 0) return out;
  try {
    const wanted = new Set(names.map(_sanitizeMetricName));
    for (const line of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
      const m = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*) (\S+)$/);
      if (m && wanted.has(m[1]) && Number.isFinite(Number(m[2]))) out[m[1]] = Number(m[2]);
    }
  } catch { /* no previous file */ }
  return out;
}

/**
 * @param {string|undefined} filePath — destination `.prom` file; no-op if falsy.
 * @param {Record<string, number>} metrics — flat map of metric name -> value.
 * @param {{ preserve?: string }} [options] — metric names whose CURRENT value in
 *   `filePath` is carried forward when `metrics` does not set them. The file is replaced as a whole on every write,
 *   so a failure run used to erase e.g. `qodiqa_dr_backup_last_success_timestamp_seconds` — the one series that
 *   says how long ago the last good backup was.
 */
function writeMetricsFile(filePath, metrics, options = {}) {
  if (!filePath) return;
  try {
    const carried = _readPreserved(filePath, options.preserve);
    const merged = { ...carried, ...metrics };
    const lines = Object.entries(merged).map(([name, value]) => `${_sanitizeMetricName(name)} ${Number(value)}`);
    const content = `${lines.join('\n')}\n`;

    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const tmpPath = path.join(path.dirname(filePath), `.${path.basename(filePath)}.${process.pid}.tmp`);
    fs.writeFileSync(tmpPath, content, 'utf8');
    fs.renameSync(tmpPath, filePath);
  } catch {
    // Metrics emission must never fail the job it's instrumenting.
  }
}

module.exports = { writeMetricsFile, _tmpdir: os.tmpdir() };
