'use strict';

/**
 * 2026-10-06 —.
 *
 *   MR-01  every metric instance metrics.js exports is in the served registry (collect() / getRegistrySnapshot()) —
 *          seven were exported and written but never served, so the shipped QodiqaAdmissionRejecting alert was dead
 *   MR-02  the admission and anchor-outcome series the shipped alert rules match on are present at 0 before the first
 *          event (Prometheus increase() never sees a series' first sample)
 *   MR-03  every metric name referenced by the gateway PrometheusRule is served by collect()
 *   MR-04  the remaining closed label sets the shipped rules match on are seeded at 0; REPLAY_STATE_UNPROVABLE is mapped
 */

const fs = require('fs');
const path = require('path');
const metrics = require('../metrics');

const isMetric = (v) => v && typeof v === 'object' && typeof v.format === 'function' && typeof v.name === 'string';

describe('metrics registry completeness', () => {
  test('MR-01 every exported metric is served', () => {
    const served = new Set(metrics.getRegistrySnapshot());
    const missing = Object.entries(metrics).filter(([, v]) => isMetric(v) && !served.has(v)).map(([k, v]) => `${k} (${v.name})`);
    expect(missing).toEqual([]);
  });

  test('MR-02 alerted label sets are seeded at 0', () => {
    const text = metrics.collect(0);
    for (const route of ['sign', 'ai_chat']) {
      for (const cause of ['queue_full', 'queue_timeout', 'audit_backlog']) {
        expect(text).toMatch(new RegExp(`^qodiqa_admission_rejected_total\\{(?=[^}]*route="${route}")(?=[^}]*cause="${cause}")[^}]*\\} \\d+$`, 'm'));
      }
    }
    for (const outcome of ['anchored', 'witness_refused', 'witness_failed', 'export_failed', 'transparency_anchor_failed']) {
      expect(text).toMatch(new RegExp(`^qodiqa_audit_anchor_events_total\\{outcome="${outcome}"\\} \\d+$`, 'm'));
    }
  });

  test('MR-04 the remaining closed label sets the shipped rules match on are seeded at 0', () => {
    const text = metrics.collect(0);
    const seeded = {
      qodiqa_audit_fail_closed_rejections_total: ['stage', ['INTENT', 'ALLOW', 'STREAM_LIFECYCLE']],
      qodiqa_transparency_fail_closed_rejections_total: ['stage', ['ALLOW']],
      qodiqa_transparency_enforcement_failures_total: ['stage', ['BLOCK', 'ALLOW', 'STREAM']],
      qodiqa_audit_crosscheck_failure_total: ['reason', ['PG_UNREACHABLE', 'PG_CHAIN_INVALID', 'FILE_CHAIN_INVALID', 'DIVERGENCE']],
      qodiqa_queue_backlog_alerts_total: ['queue', ['prq_pending', 'prq_retrying', 'transparency_pending', 'prq_dlq', 'prq_journal', 'audit_mirror_writer', 'transparency_unrooted']],
      qodiqa_security_events_total: ['event', ['invalid_signature', 'expired_artifact', 'malformed_artifact', 'replay_detected', 'nonce_violation', 'anomaly_detected']],
      qodiqa_ops_auth_failures_total: ['reason', ['missing_credentials', 'invalid_token']],
      qodiqa_mfa_events_total: ['outcome', ['failed', 'locked', 'step_up_denied', 'step_up_error']],
      qodiqa_audit_mirror_count_drift_total: ['reason', ['MISMATCH', 'COUNTER_MISSING']],
    };
    const missing = [];
    for (const [name, [label, values]] of Object.entries(seeded)) {
      for (const v of values) if (!new RegExp(`^${name}\\{${label}="${v}"\\} \\d+$`, 'm').test(text)) missing.push(`${name}{${label}="${v}"}`);
    }
    expect(missing).toEqual([]);
    // every category REASON_SECURITY_EVENT can produce is seeded, and REPLAY_STATE_UNPROVABLE is mapped
    expect([...new Set(Object.values(metrics.REASON_SECURITY_EVENT))].sort()).toEqual(seeded.qodiqa_security_events_total[1].slice().sort());
    expect(metrics.REASON_SECURITY_EVENT.REPLAY_STATE_UNPROVABLE).toBe('nonce_violation');
  });

  test('MR-03 the gateway PrometheusRule only references served metrics', () => {
    const rule = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'deploy', 'kubernetes', 'overlays', 'examples', 'monitoring', 'prometheusrule.yaml'), 'utf8');
    const referenced = [...new Set([...rule.matchAll(/expr:.*?$/gm)].flatMap((m) => m[0].match(/qodiqa_[a-z0-9_]+/g) || []))];
    expect(referenced.length).toBeGreaterThan(0);
    const text = metrics.collect(0);
    // histograms are served as <name>_bucket/_sum/_count
    const servedNames = new Set([...text.matchAll(/^# TYPE (\S+) /gm)].map((m) => m[1]));
    const base = (n) => n.replace(/_(bucket|sum|count)$/, '');
    const unserved = referenced.filter((n) => !servedNames.has(n) && !servedNames.has(base(n)));
    expect(unserved).toEqual([]);
  });
});
