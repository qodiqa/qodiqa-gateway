'use strict';

/**
 * JSON Exporter — machine-readable compliance report
 *
 * Produces a compact, API-friendly JSON payload that includes:
 *   - Full report metadata
 *   - All control assessments
 *   - Evidence summary
 *   - Findings and recommendations
 *   - Cryptographic signature envelope (if signed)
 *   - Integrity hash for independent verification
 *
 * The output is the canonical report format from which all other
 * export formats are derived.  It is self-describing and API-friendly.
 */

function exportJson(report, opts = {}) {
  const { pretty = false, includeRawEvidence = false } = opts;

  const payload = {
    $schema:  'https://qodiqa.com/schemas/compliance-report/v1.0',
    ...report,
  };

  if (!includeRawEvidence) {
    delete payload._rawEvidence;
  }

  return pretty
    ? JSON.stringify(payload, null, 2)
    : JSON.stringify(payload);
}

function exportJsonBuffer(report, opts = {}) {
  return Buffer.from(exportJson(report, opts), 'utf8');
}

module.exports = { exportJson, exportJsonBuffer };
