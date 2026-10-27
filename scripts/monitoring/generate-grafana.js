#!/usr/bin/env node
'use strict';

/**
 * generates the Grafana dashboards under deploy/monitoring/grafana/ from a compact description. Every expression uses only metrics that
 * src/observability/metrics.js registers (scripts/monitoring/__tests__/grafanaDashboards.test.js fails otherwise) and every PromQL expression is also
 * syntax-checked with promtool (scripts/monitoring/check-promql.sh).
 *
 *   node scripts/monitoring/generate-grafana.js          write
 *   node scripts/monitoring/generate-grafana.js --check  exit 1 when a committed dashboard differs from what this file generates
 */

const fs = require('fs');
const path = require('path');

const REPO = path.join(__dirname, '..', '..');
const OUT = path.join(REPO, 'deploy', 'monitoring', 'grafana');

const DS = { type: 'prometheus', uid: '${datasource}' };

let nextId = 1;
const panel = (type, title, exprs, { unit = 'short', w = 12, h = 8, desc = '', legend = [], thresholds = null, stack = false } = {}) => ({
  id: nextId++, type, title, description: desc, datasource: DS,
  gridPos: { h, w, x: 0, y: 0 },
  fieldConfig: {
    defaults: { unit, custom: type === 'timeseries' ? { drawStyle: 'line', fillOpacity: stack ? 30 : 10, lineWidth: 1, showPoints: 'never', stacking: { mode: stack ? 'normal' : 'none' } } : undefined,
      ...(thresholds ? { thresholds: { mode: 'absolute', steps: thresholds } } : {}) },
    overrides: [],
  },
  options: type === 'stat' ? { reduceOptions: { calcs: ['lastNotNull'] }, colorMode: 'value', graphMode: 'area' } : { legend: { displayMode: 'table', placement: 'bottom', calcs: ['lastNotNull', 'max'] }, tooltip: { mode: 'multi' } },
  targets: exprs.map((e, i) => ({ datasource: DS, expr: e, legendFormat: legend[i] ?? '', refId: String.fromCharCode(65 + i), range: true })),
});
const row = (title) => ({ id: nextId++, type: 'row', title, collapsed: false, gridPos: { h: 1, w: 24, x: 0, y: 0 }, panels: [] });

function layout(items) {
  let x = 0; let y = 0; let rowH = 0;
  for (const p of items) {
    if (p.type === 'row') { if (x > 0) { y += rowH; x = 0; rowH = 0; } p.gridPos.y = y; y += 1; continue; }
    if (x + p.gridPos.w > 24) { y += rowH; x = 0; rowH = 0; }
    p.gridPos.x = x; p.gridPos.y = y; x += p.gridPos.w; rowH = Math.max(rowH, p.gridPos.h);
  }
  return items;
}

const dashboard = (uid, title, description, panels) => {
  nextId = 1;
  return {
    uid, title, description, tags: ['qodiqa'], schemaVersion: 39, version: 1, editable: true, timezone: 'utc', refresh: '30s',
    time: { from: 'now-6h', to: 'now' },
    templating: { list: [{ name: 'datasource', type: 'datasource', query: 'prometheus', label: 'Prometheus', current: {}, hide: 0 }] },
    annotations: { list: [] },
    panels: layout(panels()),
  };
};

const OVERVIEW = () => [
  row('Traffic and decisions'),
  panel('stat', 'Requests / s (all route families)', ['sum(rate(qodiqa_http_responses_total[5m]))'], { unit: 'reqps', w: 6, h: 4 }),
  panel('stat', '5xx ratio (5 min)', ['sum(rate(qodiqa_http_responses_total{status_class="5xx"}[5m])) / clamp_min(sum(rate(qodiqa_http_responses_total[5m])), 1e-9)'], { unit: 'percentunit', w: 6, h: 4, thresholds: [{ color: 'green', value: null }, { color: 'orange', value: 0.01 }, { color: 'red', value: 0.05 }] }),
  panel('stat', 'In-flight enforcement requests', ['sum(qodiqa_active_requests)'], { w: 6, h: 4 }),
  panel('stat', 'Kill switch', ['max(qodiqa_kill_switch_active)'], { w: 6, h: 4, desc: '1 = the global kill switch is engaged: every enforcement request is refused.', thresholds: [{ color: 'green', value: null }, { color: 'red', value: 1 }] }),
  panel('timeseries', 'HTTP responses by status class', ['sum by (status_class) (rate(qodiqa_http_responses_total[5m]))'], { unit: 'reqps', legend: ['{{status_class}}'], stack: true }),
  panel('timeseries', 'HTTP responses by route family', ['sum by (route_family) (rate(qodiqa_http_responses_total[5m]))'], { unit: 'reqps', legend: ['{{route_family}}'], stack: true }),
  panel('timeseries', 'Enforcement decisions', ['sum by (decision) (rate(qodiqa_requests_total[5m]))'], { unit: 'reqps', legend: ['{{decision}}'], desc: 'EXECUTE = allowed, BLOCK = refused by a policy or a verification check.' }),
  panel('timeseries', 'Blocks by reason', ['topk(10, sum by (reason) (rate(qodiqa_blocks_total[5m])))'], { unit: 'reqps', legend: ['{{reason}}'] }),
  panel('timeseries', 'Request latency p50 / p95 / p99 (ms)', [
    'histogram_quantile(0.50, sum by (le) (rate(qodiqa_request_duration_ms_bucket[5m])))',
    'histogram_quantile(0.95, sum by (le) (rate(qodiqa_request_duration_ms_bucket[5m])))',
    'histogram_quantile(0.99, sum by (le) (rate(qodiqa_request_duration_ms_bucket[5m])))'], { unit: 'ms', legend: ['p50', 'p95', 'p99'] }),
  row('Load shedding'),
  panel('timeseries', 'Admission: in flight and queued', ['sum by (route) (qodiqa_admission_inflight)', 'sum by (route) (qodiqa_admission_queued)'], { legend: ['in flight {{route}}', 'queued {{route}}'] }),
  panel('timeseries', 'Admission: refused requests', ['sum by (route, cause) (rate(qodiqa_admission_rejected_total[5m]))'], { unit: 'reqps', legend: ['{{route}} {{cause}}'], desc: 'queue_full / queue_timeout / audit_backlog. Refusals are 503 SERVER_OVERLOADED with Retry-After; the artifact is not consumed.' }),
  row('Process'),
  panel('timeseries', 'Event loop delay p99 (ms)', ['qodiqa_event_loop_delay_p99_ms'], { unit: 'ms' }),
  panel('timeseries', 'Authentication failures and lockouts', ['sum(rate(qodiqa_ops_auth_failures_total[5m]))', 'sum(rate(qodiqa_auth_lockout_triggered_total[5m]))'], { unit: 'ops', legend: ['operator auth failures', 'lockouts triggered'] }),
];

const AUDIT = () => [
  row('Audit append path'),
  panel('timeseries', 'Audit append latency p95 (s)', ['histogram_quantile(0.95, sum by (le, mode) (rate(qodiqa_audit_append_duration_seconds_bucket{outcome="success"}[5m])))'], { unit: 's', legend: ['{{mode}}'] }),
  panel('timeseries', 'Audit append failures and fail-closed refusals', ['sum(rate(qodiqa_audit_append_failed_total[5m]))', 'sum(rate(qodiqa_audit_fail_closed_rejections_total[5m]))', 'sum(rate(qodiqa_audit_disk_full_total[5m]))'], { unit: 'ops', legend: ['append failed', 'fail-closed rejections', 'disk full'] }),
  panel('timeseries', 'fsync latency p95 (s)', ['histogram_quantile(0.95, sum by (le) (rate(qodiqa_audit_fsync_duration_seconds_bucket[5m])))', 'histogram_quantile(0.95, sum by (le) (rate(qodiqa_audit_wal_fsync_duration_seconds_bucket[5m])))'], { unit: 's', legend: ['audit fsync', 'WAL fsync'] }),
  panel('timeseries', 'PostgreSQL mirror lag (entries)', ['max(qodiqa_audit_pg_lag_entries)', 'max(qodiqa_audit_mirror_writer_depth)'], { legend: ['PG lag', 'mirror writer depth'] }),
  row('Integrity checks'),
  panel('stat', 'Chain verifier violations (1 h)', ['sum(increase(qodiqa_audit_chain_verifier_violations_total[1h]))'], { w: 6, h: 4, thresholds: [{ color: 'green', value: null }, { color: 'red', value: 1 }] }),
  panel('stat', 'Mirror count drift (1 h)', ['sum(increase(qodiqa_audit_mirror_count_drift_total[1h]))'], { w: 6, h: 4, thresholds: [{ color: 'green', value: null }, { color: 'red', value: 1 }] }),
  panel('stat', 'Unrecoverable gaps (24 h)', ['sum(increase(qodiqa_gap_scanner_gaps_unrecoverable_total[24h]))'], { w: 6, h: 4, thresholds: [{ color: 'green', value: null }, { color: 'red', value: 1 }] }),
  panel('stat', 'Checksum anchor mismatches (24 h)', ['sum(increase(qodiqa_audit_checksum_anchor_mismatch_total[24h]))'], { w: 6, h: 4, thresholds: [{ color: 'green', value: null }, { color: 'red', value: 1 }] }),
  panel('timeseries', 'Verifier and gap scanner runs', ['sum(rate(qodiqa_audit_chain_verifier_success_total[15m]))', 'sum(rate(qodiqa_audit_chain_verifier_failure_total[15m]))', 'sum(rate(qodiqa_gap_scanner_success_total[15m]))', 'sum(rate(qodiqa_gap_scanner_failures_total[15m]))'], { unit: 'ops', legend: ['verifier ok', 'verifier failed', 'gap scan ok', 'gap scan failed'] }),
  panel('timeseries', 'Verifier lag (entries behind the head)', ['max(qodiqa_audit_chain_verifier_lag_entries)'], {}),
  row('External anchoring'),
  panel('timeseries', 'Pending anchors and oldest pending age (s)', ['max(qodiqa_external_anchor_pending)', 'max(qodiqa_external_anchor_oldest_pending_seconds)'], { legend: ['pending', 'oldest pending (s)'] }),
  panel('timeseries', 'External anchor results', ['sum by (kind, outcome) (rate(qodiqa_external_anchor_total[15m]))'], { unit: 'ops', legend: ['{{kind}} {{outcome}}'] }),
];

const PROVIDERS = () => [
  row('Providers'),
  panel('timeseries', 'Provider failures by code', ['sum by (provider, code) (rate(qodiqa_provider_failures_total[5m]))'], { unit: 'ops', legend: ['{{provider}} {{code}}'] }),
  panel('timeseries', 'Provider calls cancelled', ['sum(rate(qodiqa_provider_execution_cancelled_total[5m]))'], { unit: 'ops' }),
  row('Cost and tokens (from the ROUTING / BUDGET tariffs)'),
  panel('timeseries', 'Cost per hour by provider (tariff currency)', ['sum by (provider, currency) (increase(qodiqa_provider_cost_micros_total[1h])) / 1e6'], { legend: ['{{provider}} {{currency}}'], desc: 'Accounted from the operator tariffs in the policy in force; the platform ships no prices.' }),
  panel('timeseries', 'Tokens per minute by provider and direction', ['sum by (provider, direction) (rate(qodiqa_provider_tokens_total[5m])) * 60'], { legend: ['{{provider}} {{direction}}'] }),
];

const FILES = {
  'qodiqa-overview.json': () => dashboard('qodiqa-overview', 'QODIQA - Overview', 'Traffic, decisions, latency and load shedding of the gateway.', OVERVIEW),
  'qodiqa-audit-integrity.json': () => dashboard('qodiqa-audit', 'QODIQA - Audit and integrity', 'The audit append path, the integrity checkers and external anchoring.', AUDIT),
  'qodiqa-providers.json': () => dashboard('qodiqa-providers', 'QODIQA - Providers and cost', 'Provider failures, accounted cost and tokens.', PROVIDERS),
};

function build() {
  const out = {};
  for (const [name, fn] of Object.entries(FILES)) out[name] = `${JSON.stringify(fn(), null, 2)}\n`;
  return out;
}

if (require.main === module) {
  const built = build();
  let drift = 0;
  for (const [name, content] of Object.entries(built)) {
    const file = path.join(OUT, name);
    if (process.argv.includes('--check')) {
      const cur = fs.existsSync(file) ? fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n') : null;
      if (cur !== content) { console.error(`DRIFT: deploy/monitoring/grafana/${name}`); drift += 1; }
    } else { fs.mkdirSync(OUT, { recursive: true }); fs.writeFileSync(file, content); console.log(`wrote deploy/monitoring/grafana/${name}`); }
  }
  if (drift) process.exit(1);
}

module.exports = { build, OUT };
