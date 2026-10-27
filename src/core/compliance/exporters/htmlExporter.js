'use strict';

/**
 * HTML Exporter — interactive, searchable compliance report
 *
 * Produces a standalone HTML document with:
 *   - Executive summary
 *   - Interactive control status table (color-coded)
 *   - Findings section with severity badges
 *   - Evidence summary statistics
 *   - Recommendations
 *   - Cryptographic signature details
 *   - Self-contained (no external dependencies)
 */

const VERDICT_COLOR = {
  COMPLIANT:            '#1a7f37',
  PARTIALLY_COMPLIANT:  '#9a6700',
  NON_COMPLIANT:        '#cf222e',
};

const STATUS_BADGE = {
  PASS:            '<span class="badge pass">PASS</span>',
  PARTIAL:         '<span class="badge partial">PARTIAL</span>',
  FAIL:            '<span class="badge fail">FAIL</span>',
  NOT_APPLICABLE:  '<span class="badge na">N/A</span>',
  ERROR:           '<span class="badge fail">ERROR</span>',
};

const SEVERITY_BADGE = {
  CRITICAL: '<span class="badge fail">CRITICAL</span>',
  HIGH:     '<span class="badge fail">HIGH</span>',
  MEDIUM:   '<span class="badge partial">MEDIUM</span>',
  LOW:      '<span class="badge na">LOW</span>',
};

function _esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function exportHtml(report) {
  const fw         = report.framework ?? {};
  const verdict    = report.overallVerdict ?? 'NON_COMPLIANT';
  const verdictCol = VERDICT_COLOR[verdict] ?? '#555';
  const score      = report.overallScore ?? 0;
  const cs         = report.controlsSummary ?? {};
  const assessments = report.controlAssessments ?? [];
  const findings   = report.findings ?? [];
  const recs       = report.recommendations ?? [];
  const evSum      = report.evidenceSummary ?? {};
  const sig        = report.signature;

  const controlRows = assessments.map(a => `
    <tr>
      <td><code>${_esc(a.controlId)}</code></td>
      <td>${_esc(a.controlRef)}</td>
      <td>${_esc(a.title)}</td>
      <td>${_esc(a.category)}</td>
      <td>${STATUS_BADGE[a.status] ?? _esc(a.status)}</td>
      <td class="score-cell">${a.score ?? 0}%</td>
      <td>${a.isCritical ? '<span class="badge fail">Critical</span>' : ''}</td>
      <td>${a.evidenceCount ?? 0}</td>
    </tr>`).join('');

  const findingRows = findings.map(f => `
    <tr>
      <td><code>${_esc(f.controlId)}</code></td>
      <td>${SEVERITY_BADGE[f.severity] ?? _esc(f.severity)}</td>
      <td>${_esc(f.description)}</td>
      <td>${_esc(f.detail)}</td>
      <td>${_esc(f.remediation)}</td>
    </tr>`).join('');

  const recItems = recs.map(r => `
    <li>
      <strong>[${_esc(r.severity)}]</strong> <code>${_esc(r.controlId)}</code>:
      ${_esc(r.action)}
    </li>`).join('');

  const sigHtml = sig ? `
    <div class="card">
      <h2>Cryptographic Signature</h2>
      <table class="meta-table">
        <tr><th>Key ID</th><td><code>${_esc(sig.keyId)}</code></td></tr>
        <tr><th>Algorithm</th><td>${_esc(sig.algorithm)}</td></tr>
        <tr><th>Signed At</th><td>${_esc(sig.signedAt)}</td></tr>
        <tr><th>Signer</th><td>${_esc(sig.signerId ?? '')}</td></tr>
        <tr><th>Report Hash</th><td style="word-break:break-all;font-size:0.8em"><code>${_esc(report._hash ?? '')}</code></td></tr>
      </table>
      <p>This report is cryptographically protected using Ed25519.
         Verify integrity using the QODIQA <code>POST /compliance/report/verify</code> API.</p>
    </div>` : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${_esc(fw.name)} Compliance Report — ${_esc(report.reportRef)}</title>
<style>
:root{--pass:#1a7f37;--fail:#cf222e;--partial:#9a6700;--na:#666;--bg:#f6f8fa;--card:#fff;--border:#d0d7de}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
     background:var(--bg);color:#24292f;font-size:14px;line-height:1.5}
.container{max-width:1200px;margin:0 auto;padding:24px}
h1{font-size:1.8em;margin-bottom:8px}
h2{font-size:1.2em;margin:20px 0 12px;color:#24292f;border-bottom:1px solid var(--border);padding-bottom:6px}
.card{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:20px;margin-bottom:20px}
.verdict{display:inline-block;padding:4px 12px;border-radius:4px;color:#fff;
          font-weight:600;font-size:1.1em;background:${verdictCol}}
.score-ring{display:inline-block;font-size:2.5em;font-weight:700;color:${verdictCol};padding:8px}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:0.75em;font-weight:600}
.badge.pass{background:#dafbe1;color:var(--pass)}
.badge.fail{background:#ffebe9;color:var(--fail)}
.badge.partial{background:#fff8c5;color:var(--partial)}
.badge.na{background:#f6f8fa;color:var(--na);border:1px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:0.875em}
th,td{text-align:left;padding:8px 10px;border:1px solid var(--border)}
th{background:#f6f8fa;font-weight:600}
tr:hover td{background:#f6f8fa}
.score-cell{font-weight:600}
.meta-table th{width:140px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}
.stat-box{background:var(--bg);border:1px solid var(--border);border-radius:6px;
           padding:12px;text-align:center}
.stat-val{font-size:1.6em;font-weight:700}
.stat-lbl{font-size:0.8em;color:#57606a}
ul{padding-left:20px}
li{margin:4px 0}
pre{background:var(--bg);border:1px solid var(--border);border-radius:4px;
    padding:10px;overflow-x:auto;font-size:0.8em;white-space:pre-wrap;word-break:break-all}
input[type=text]{width:100%;padding:6px 10px;border:1px solid var(--border);
                 border-radius:4px;margin-bottom:10px;font-size:0.875em}
</style>
</head>
<body>
<div class="container">

<div class="card">
  <h1>${_esc(fw.name)} Compliance Report</h1>
  <p><strong>Report Reference:</strong> ${_esc(report.reportRef)} &nbsp;|&nbsp;
     <strong>Generated:</strong> ${_esc(report.generatedAt)} &nbsp;|&nbsp;
     <strong>By:</strong> ${_esc(report.generatedBy)}</p>
  <p><strong>Assessment Period:</strong> ${_esc(report.period?.start)} to ${_esc(report.period?.end)}</p>
  ${report.tenantId ? `<p><strong>Tenant:</strong> ${_esc(report.tenantId)}</p>` : ''}
  <br>
  <span class="score-ring">${score}/100</span>
  <span class="verdict">${_esc(verdict.replace(/_/g,' '))}</span>
</div>

<div class="card">
  <h2>Executive Summary</h2>
  <pre>${_esc(report.executiveSummary ?? '')}</pre>
</div>

<div class="card">
  <h2>Controls Overview</h2>
  <div class="stats-grid">
    <div class="stat-box"><div class="stat-val">${cs.total ?? 0}</div><div class="stat-lbl">Total Controls</div></div>
    <div class="stat-box" style="color:var(--pass)"><div class="stat-val">${cs.pass ?? 0}</div><div class="stat-lbl">Passing</div></div>
    <div class="stat-box" style="color:var(--partial)"><div class="stat-val">${cs.partial ?? 0}</div><div class="stat-lbl">Partial</div></div>
    <div class="stat-box" style="color:var(--fail)"><div class="stat-val">${cs.fail ?? 0}</div><div class="stat-lbl">Failing</div></div>
    <div class="stat-box" style="color:var(--fail)"><div class="stat-val">${cs.criticalFails ?? 0}</div><div class="stat-lbl">Critical Fails</div></div>
    <div class="stat-box"><div class="stat-val">${report.evidenceCount ?? 0}</div><div class="stat-lbl">Evidence Items</div></div>
  </div>
</div>

<div class="card">
  <h2>Control Assessments</h2>
  <input type="text" id="ctrl-search" placeholder="Filter controls..." onkeyup="filterTable('ctrl-table','ctrl-search')">
  <div style="overflow-x:auto">
  <table id="ctrl-table">
    <thead><tr>
      <th>Control ID</th><th>Ref</th><th>Title</th><th>Category</th>
      <th>Status</th><th>Score</th><th>Critical</th><th>Evidence</th>
    </tr></thead>
    <tbody>${controlRows}</tbody>
  </table>
  </div>
</div>

${findings.length > 0 ? `
<div class="card">
  <h2>Findings (${findings.length})</h2>
  <div style="overflow-x:auto">
  <table>
    <thead><tr><th>Control</th><th>Severity</th><th>Issue</th><th>Detail</th><th>Remediation</th></tr></thead>
    <tbody>${findingRows}</tbody>
  </table>
  </div>
</div>` : `<div class="card"><h2>Findings</h2><p>No findings. All controls pass.</p></div>`}

<div class="card">
  <h2>Evidence Summary</h2>
  <div class="stats-grid">
    ${Object.entries(evSum).map(([k,v]) =>
      `<div class="stat-box"><div class="stat-val">${typeof v === 'boolean' ? (v ? '✓' : '✗') : v}</div><div class="stat-lbl">${k.replace(/([A-Z])/g,' $1').trim()}</div></div>`
    ).join('')}
  </div>
</div>

${recs.length > 0 ? `
<div class="card">
  <h2>Recommendations</h2>
  <ul>${recItems}</ul>
</div>` : ''}

${sigHtml}

<div class="card" style="font-size:0.8em;color:#57606a">
  <p>Generated by QODIQA Compliance Reporting Framework v${_esc(report.generatorVersion ?? '1.0.0')} &nbsp;|&nbsp;
     Schema ${_esc(report.schemaVersion ?? '1.0')} &nbsp;|&nbsp;
     Framework: ${_esc(fw.name)} ${_esc(fw.version)} — ${_esc(fw.issuer)}</p>
</div>

</div>

<script>
function filterTable(tableId, inputId) {
  const q = document.getElementById(inputId).value.toLowerCase();
  const rows = document.getElementById(tableId).querySelectorAll('tbody tr');
  rows.forEach(r => { r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none'; });
}
</script>
</body>
</html>`;
}

module.exports = { exportHtml };
