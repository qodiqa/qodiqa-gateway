'use strict';

/**
 * QODIQA observability — in-memory Prometheus-format metrics registry.
 *
 * Design invariants:
 *   • Pure in-memory.  Zero I/O on increment.  Zero external dependencies.
 *   • Never throws.  All public methods are infallible — errors are suppressed
 *     so metric instrumentation can never affect the enforcement path.
 *   • Prometheus text exposition format (version 0.0.4).
 *   • Single-threaded Node.js guarantees: no atomicity primitives needed.
 *   • No secrets, no payload content, no request bodies are stored.
 *
 * Metric naming follows Prometheus conventions:
 *   qodiqa_<subsystem>_<name>_<unit>
 */

const _STARTED_AT_MS = Date.now();

// ── Label helpers ─────────────────────────────────────────────────────────────

function _sanitizeLabel(v) {
  return String(v == null ? '' : v)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n');
}

function _labelsToKey(labels) {
  if (!labels || typeof labels !== 'object') return '';
  const keys = Object.keys(labels).sort();
  if (keys.length === 0) return '';
  return keys.map(k => `${k}="${_sanitizeLabel(labels[k])}"`).join(',');
}

function _labelSuffix(labelKey) {
  return labelKey ? `{${labelKey}}` : '';
}

// ── OTLP JSON translation helpers ────────────────────────────────────────
//
// Used only by the optional metrics OTLP export bridge (src/observability/
// metricsExport/), never by collect()/format()/the /metrics route. Pure,
// read-only, infallible-by-construction (no I/O, no throwing paths reachable
// from valid inputs).

const OTLP_TEMPORALITY_CUMULATIVE = 2; // OTLP AggregationTemporality enum (CUMULATIVE)

function _msToNano(ms) {
  return String(Math.round(ms * 1e6));
}

function _labelsToOtlpAttributes(labels) {
  if (!labels || typeof labels !== 'object') return [];
  return Object.keys(labels).sort().map(k => ({
    key: k,
    value: { stringValue: _sanitizeLabel(labels[k]) },
  }));
}

function _otlpNumberDataPoint(labels, value, startTimeUnixNano, timeUnixNano) {
  return {
    attributes: _labelsToOtlpAttributes(labels),
    startTimeUnixNano,
    timeUnixNano,
    asDouble: value,
  };
}

// ── Counter ───────────────────────────────────────────────────────────────────

class Counter {
  constructor(name, help) {
    this.name = name;
    this.help = help;
    this._values = new Map(); // labelKey -> number
    // original labels object per labelKey, kept ONLY so the optional
    // OTLP bridge (metricsExport/) can emit real attribute key/value pairs
    // without lossily re-parsing the joined labelKey string. Populated
    // alongside _values, never read by format()/collect() — zero effect on
    // existing /metrics output.
    this._labelsByKey = new Map();
  }

  inc(labels, amount = 1) {
    try {
      const k = _labelsToKey(labels);
      this._values.set(k, (this._values.get(k) || 0) + amount);
      if (!this._labelsByKey.has(k)) this._labelsByKey.set(k, labels || {});
    } catch { /* infallible */ }
  }

  format() {
    const out = [
      `# HELP ${this.name} ${this.help}`,
      `# TYPE ${this.name} counter`,
    ];
    for (const [k, v] of this._values) {
      out.push(`${this.name}${_labelSuffix(k)} ${v}`);
    }
    // Ensure at least a zero-value entry so the metric is always present
    if (this._values.size === 0) {
      out.push(`${this.name} 0`);
    }
    return out.join('\n');
  }

  // OTLP JSON translation, read-only over the same state format() uses.
  // Counters are monotonic sums with CUMULATIVE temporality (this registry
  // never resets counters mid-process, matching Prometheus's own semantics —
  // no delta computation, no risk of meaning drift).
  toOtlpMetric(startTimeUnixNano, timeUnixNano) {
    const dataPoints = [];
    for (const [k, v] of this._values) {
      dataPoints.push(_otlpNumberDataPoint(this._labelsByKey.get(k), v, startTimeUnixNano, timeUnixNano));
    }
    if (dataPoints.length === 0) {
      dataPoints.push(_otlpNumberDataPoint({}, 0, startTimeUnixNano, timeUnixNano));
    }
    return {
      name: this.name,
      description: this.help,
      unit: '',
      sum: { dataPoints, aggregationTemporality: OTLP_TEMPORALITY_CUMULATIVE, isMonotonic: true },
    };
  }
}

// ── Gauge ─────────────────────────────────────────────────────────────────────

class Gauge {
  constructor(name, help) {
    this.name = name;
    this.help = help;
    this._values = new Map();
    this._labelsByKey = new Map(); // see Counter's constructor comment
  }

  set(labels, value) {
    try {
      const k = _labelsToKey(labels);
      this._values.set(k, value);
      this._labelsByKey.set(k, labels || {});
    } catch { /* infallible */ }
  }

  inc(labels, amount = 1) {
    try {
      const k = _labelsToKey(labels);
      this._values.set(k, (this._values.get(k) || 0) + amount);
      if (!this._labelsByKey.has(k)) this._labelsByKey.set(k, labels || {});
    } catch { /* infallible */ }
  }

  dec(labels, amount = 1) {
    try {
      const k = _labelsToKey(labels);
      this._values.set(k, (this._values.get(k) || 0) - amount);
      if (!this._labelsByKey.has(k)) this._labelsByKey.set(k, labels || {});
    } catch { /* infallible */ }
  }

  format() {
    const out = [
      `# HELP ${this.name} ${this.help}`,
      `# TYPE ${this.name} gauge`,
    ];
    for (const [k, v] of this._values) {
      out.push(`${this.name}${_labelSuffix(k)} ${v}`);
    }
    if (this._values.size === 0) {
      out.push(`${this.name} 0`);
    }
    return out.join('\n');
  }

  // OTLP JSON translation. Gauges have no temporality/monotonicity
  // (current value only), matching OTLP's own Gauge data-point semantics.
  toOtlpMetric(startTimeUnixNano, timeUnixNano) {
    const dataPoints = [];
    for (const [k, v] of this._values) {
      dataPoints.push(_otlpNumberDataPoint(this._labelsByKey.get(k), v, startTimeUnixNano, timeUnixNano));
    }
    if (dataPoints.length === 0) {
      dataPoints.push(_otlpNumberDataPoint({}, 0, startTimeUnixNano, timeUnixNano));
    }
    return { name: this.name, description: this.help, unit: '', gauge: { dataPoints } };
  }
}

// ── Histogram ─────────────────────────────────────────────────────────────────
//
// Stores cumulative bucket counts per Prometheus convention.
// Each bucket[i] counts observations where value <= bucket[i].
// The +Inf bucket equals the total observation count.

const DEFAULT_LATENCY_BUCKETS = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000];
const FAST_LATENCY_BUCKETS    = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];

class Histogram {
  constructor(name, help, buckets) {
    this.name    = name;
    this.help    = help;
    this.buckets = [...(buckets || DEFAULT_LATENCY_BUCKETS)].sort((a, b) => a - b);
    this._data   = new Map(); // labelKey -> { counts[], sum, count }
    this._labelsByKey = new Map(); // see Counter's constructor comment
  }

  observe(labels, value) {
    try {
      const k = _labelsToKey(labels);
      if (!this._data.has(k)) {
        this._data.set(k, {
          counts: new Array(this.buckets.length).fill(0),
          sum:    0,
          count:  0,
        });
        this._labelsByKey.set(k, labels || {});
      }
      const d = this._data.get(k);
      d.sum   += value;
      d.count++;
      // Increment all buckets that contain this observation (cumulative).
      for (let i = 0; i < this.buckets.length; i++) {
        if (value <= this.buckets[i]) d.counts[i]++;
      }
    } catch { /* infallible */ }
  }

  // Exact mean (sum/count) for a label combination — 0 if unknown/empty. Never throws.
  getMean(labels) {
    try {
      const d = this._data.get(_labelsToKey(labels));
      return (d && d.count > 0) ? d.sum / d.count : 0;
    } catch {
      return 0;
    }
  }

  // #9: approximate percentile via linear interpolation across the
  // cumulative bucket boundaries — the same technique Prometheus's own
  // histogram_quantile() uses. Cheap and sufficient for alerting thresholds;
  // not a substitute for exact client-side percentile computation where that
  // precision actually matters. Returns 0 for an unknown label combination
  // or an empty histogram. Never throws.
  estimatePercentile(labels, p) {
    try {
      const k = _labelsToKey(labels);
      const d = this._data.get(k);
      if (!d || d.count === 0) return 0;

      const targetRank = (p / 100) * d.count;
      let prevBoundary = 0;
      let prevCount    = 0;
      for (let i = 0; i < this.buckets.length; i++) {
        const boundary = this.buckets[i];
        const count    = d.counts[i];
        if (count >= targetRank) {
          const bucketRange = count - prevCount;
          if (bucketRange <= 0) return boundary;
          const fraction = (targetRank - prevCount) / bucketRange;
          return prevBoundary + fraction * (boundary - prevBoundary);
        }
        prevBoundary = boundary;
        prevCount    = count;
      }
      // Target rank exceeds every finite bucket — fall back to the largest boundary.
      return this.buckets[this.buckets.length - 1];
    } catch {
      return 0;
    }
  }

  format() {
    const out = [
      `# HELP ${this.name} ${this.help}`,
      `# TYPE ${this.name} histogram`,
    ];
    for (const [k, d] of this._data) {
      const lePfx = k ? `{${k},le="` : '{le="';
      const leSfx = k ? `{${k},le="+Inf"}` : '{le="+Inf"}';
      const sfx   = _labelSuffix(k);

      for (let i = 0; i < this.buckets.length; i++) {
        out.push(`${this.name}_bucket${lePfx}${this.buckets[i]}"} ${d.counts[i]}`);
      }
      out.push(`${this.name}_bucket${leSfx} ${d.count}`);
      out.push(`${this.name}_sum${sfx} ${d.sum}`);
      out.push(`${this.name}_count${sfx} ${d.count}`);
    }
    if (this._data.size === 0) {
      for (const b of this.buckets) {
        out.push(`${this.name}_bucket{le="${b}"} 0`);
      }
      out.push(`${this.name}_bucket{le="+Inf"} 0`);
      out.push(`${this.name}_sum 0`);
      out.push(`${this.name}_count 0`);
    }
    return out.join('\n');
  }

  // OTLP JSON translation. OTLP histogram bucketCounts are INDIVIDUAL
  // (non-cumulative) per-bucket counts, unlike this class's own internal
  // storage and format()'s Prometheus le="" buckets, which are BOTH
  // cumulative (count of observations <= boundary) — converted here by
  // differencing consecutive cumulative counts. explicitBounds are the same
  // finite upper bounds this.buckets already holds (n bounds -> n+1
  // OTLP buckets, the last being the implicit +Inf bucket, exactly mirroring
  // Prometheus's own le="+Inf" convention). CUMULATIVE temporality, matching
  // Counter's — this registry never resets between scrapes/exports.
  toOtlpMetric(startTimeUnixNano, timeUnixNano) {
    const dataPoints = [];
    for (const [k, d] of this._data) {
      const bucketCounts = [];
      let prev = 0;
      for (let i = 0; i < this.buckets.length; i++) {
        bucketCounts.push(d.counts[i] - prev);
        prev = d.counts[i];
      }
      bucketCounts.push(d.count - prev); // +Inf bucket
      const point = _otlpNumberDataPoint(this._labelsByKey.get(k), null, startTimeUnixNano, timeUnixNano);
      delete point.asDouble;
      point.count = d.count;
      point.sum = d.sum;
      point.bucketCounts = bucketCounts;
      point.explicitBounds = this.buckets.slice();
      dataPoints.push(point);
    }
    if (dataPoints.length === 0) {
      const point = _otlpNumberDataPoint({}, null, startTimeUnixNano, timeUnixNano);
      delete point.asDouble;
      point.count = 0;
      point.sum = 0;
      point.bucketCounts = new Array(this.buckets.length + 1).fill(0);
      point.explicitBounds = this.buckets.slice();
      dataPoints.push(point);
    }
    return {
      name: this.name,
      description: this.help,
      unit: '',
      histogram: { dataPoints, aggregationTemporality: OTLP_TEMPORALITY_CUMULATIVE },
    };
  }
}

// ── Metric definitions ────────────────────────────────────────────────────────

// Enforcement — /ai/chat
const requestsTotal = new Counter(
  'qodiqa_requests_total',
  'Total AI execution requests by decision (EXECUTE or BLOCK)',
);
const blocksTotal = new Counter(
  'qodiqa_blocks_total',
  'Total blocked AI execution requests by reason code',
);
const requestDurationMs = new Histogram(
  'qodiqa_request_duration_ms',
  'AI execution request end-to-end latency in milliseconds',
  DEFAULT_LATENCY_BUCKETS,
);

// Verification — /verify
const verificationRequestsTotal = new Counter(
  'qodiqa_verification_requests_total',
  'Total verification check requests by decision (EXECUTE or BLOCK)',
);
const verificationBlocksTotal = new Counter(
  'qodiqa_verification_blocks_total',
  'Total blocked verification checks by reason code',
);
const verificationDurationMs = new Histogram(
  'qodiqa_verification_duration_ms',
  'Verification check end-to-end latency in milliseconds',
  FAST_LATENCY_BUCKETS,
);

// Security events
const securityEventsTotal = new Counter(
  'qodiqa_security_events_total',
  'Security events by type: invalid_signature, expired_artifact, malformed_artifact, replay_detected, anomaly_detected, nonce_violation',
);

// Runtime state gauges
const activeRequests = new Gauge(
  'qodiqa_active_requests',
  'Currently in-flight enforcement requests tracked by requestDrain',
);
// admission control (src/api/admission.js)
const admissionRejectedTotal = new Counter(
  'qodiqa_admission_rejected_total',
  'Requests refused 503 SERVER_OVERLOADED by admission control, by route family and cause (queue_full | queue_timeout | audit_backlog)',
);
const admissionInFlight = new Gauge(
  'qodiqa_admission_inflight',
  'Requests currently admitted (holding an admission slot), by route family',
);
const admissionQueued = new Gauge(
  'qodiqa_admission_queued',
  'Requests currently waiting in the admission queue, by route family',
);
const redisStoreUp = new Gauge(
  'qodiqa_redis_store_up',
  'Redis store availability per named store (1=up, 0=down)',
);
const providerCostMicrosTotal = new Counter(
  'qodiqa_provider_cost_micros_total',
  'Accounted cost of provider calls in millionths of the tariff currency, by executing provider and currency',
);
const providerTokensTotal = new Counter(
  'qodiqa_provider_tokens_total',
  'Tokens reported by providers, by executing provider and direction (input, output)',
);
const killSwitchActive = new Gauge(
  'qodiqa_kill_switch_active',
  'Global kill switch state on this replica (1 = active: /sign and /ai/chat refuse every request, 0 = off)',
);
const killSwitchBlocksTotal = new Counter(
  'qodiqa_kill_switch_blocks_total',
  'Requests refused by the global kill-switch gate, by route and cause (active, tampered, state_unavailable)',
);
const killSwitchTransitionsTotal = new Counter(
  'qodiqa_kill_switch_transitions_total',
  'Kill-switch activations and releases performed through this replica, by target state (on, off)',
);
const auditCommitsTotal = new Counter(
  'qodiqa_audit_commits_total',
  'COMMIT audit entries by outcome: recorded, skipped (audit schema v8 off), duplicate, failed, queued',
);
const proofRequestsTotal = new Counter(
  'qodiqa_proof_requests_total',
  'Downloadable-proof requests by outcome: served, not_found (unknown or another tenant), invalid, error',
);
const artifactRevocationsTotal = new Counter(
  'qodiqa_artifact_revocations_total',
  'Per-artifact revocations performed through this replica, by outcome (created, repeated)',
);
const artifactRevokedBlocksTotal = new Counter(
  'qodiqa_artifact_revoked_blocks_total',
  'Requests refused because their artifact had been revoked (ARTIFACT_REVOKED)',
);
const executionIntegrityFull = new Gauge(
  'qodiqa_execution_integrity_full',
  'Execution integrity is FULL (1) or DEGRADED (0)',
);

// Build info (static labels, value always 1)
const buildInfo = new Gauge(
  'qodiqa_build_info',
  'QODIQA build and runtime information',
);

// Policy Provenance — Component #20
const provenanceVersionsTotal = new Counter(
  'qodiqa_provenance_versions_total',
  'Total policy provenance versions recorded by event_type label',
);
const provenanceModificationsTotal = new Counter(
  'qodiqa_provenance_modifications_total',
  'Total policy modifications recorded in the provenance ledger by event_type label',
);
const provenanceRollbacksTotal = new Counter(
  'qodiqa_provenance_rollbacks_total',
  'Total policy rollback operations recorded in the provenance ledger',
);
const provenanceIntegrityFailuresTotal = new Counter(
  'qodiqa_provenance_integrity_failures_total',
  'Total hash-chain integrity failures detected across all policy provenance validation runs',
);
const provenanceAttributionFailuresTotal = new Counter(
  'qodiqa_provenance_attribution_failures_total',
  'Total policy mutations rejected at the API layer due to missing or incomplete attribution',
);
const provenanceDiffFailuresTotal = new Counter(
  'qodiqa_provenance_diff_failures_total',
  'Total failures generating structured diffs during provenance version recording',
);

// Transparency Log — Component #22
const transparencyEntriesTotal = new Counter(
  'qodiqa_transparency_entries_total',
  'Total transparency log entries registered by entry_type label',
);
const transparencyRootsTotal = new Counter(
  'qodiqa_transparency_roots_total',
  'Total transparency root digests generated',
);
const transparencyPersistFailuresTotal = new Counter(
  'qodiqa_transparency_persist_failures_total',
  'Total failures persisting transparency log entries or roots to PostgreSQL',
);
const transparencyVerificationsTotal = new Counter(
  'qodiqa_transparency_verifications_total',
  'Total transparency entry verification runs by result label (VALID, INVALID, PARTIAL, ERROR)',
);
const transparencyVerificationFailuresTotal = new Counter(
  'qodiqa_transparency_verification_failures_total',
  'Total transparency verification runs that returned INVALID or detected integrity failures',
);

// HSM-backed Transparency Key — Component #30
const transparencySignerSignaturesTotal = new Counter(
  'qodiqa_transparency_signer_signatures_total',
  'Total signatures issued by the transparency signer (entries + roots)',
);
const transparencySignerFailuresTotal = new Counter(
  'qodiqa_transparency_signer_failures_total',
  'Total transparency signing failures',
);
const transparencySignerKeyRotationsTotal = new Counter(
  'qodiqa_transparency_signer_key_rotations_total',
  'Total transparency signing key rotations',
);

// Public Verification Portal — Component #23
const portalVerificationsTotal = new Counter(
  'qodiqa_portal_verifications_total',
  'Total portal verification submissions by result label (VERIFIED, VERIFIED_WITH_WARNINGS, FAILED)',
);
const portalVerificationFailuresTotal = new Counter(
  'qodiqa_portal_verification_failures_total',
  'Total portal verification submissions that resulted in FAILED, by failed_check label',
);
const portalPersistFailuresTotal = new Counter(
  'qodiqa_portal_persist_failures_total',
  'Total failures persisting portal verification records to PostgreSQL',
);

// Evidence Chain — Component #21
const evidenceChainRecordsTotal = new Counter(
  'qodiqa_evidence_chain_records_total',
  'Total evidence chain records persisted by decision label (ALLOW or BLOCK)',
);
const evidenceChainPersistFailuresTotal = new Counter(
  'qodiqa_evidence_chain_persist_failures_total',
  'Total failures persisting evidence chain records to PostgreSQL',
);
const evidenceChainVerificationFailuresTotal = new Counter(
  'qodiqa_evidence_chain_verification_failures_total',
  'Total evidence chain verification runs that returned INVALID or detected chain continuity failures',
);

// Attestation API — Component #24
const attestationsTotal = new Counter(
  'qodiqa_attestations_total',
  'Total attestations generated by decision label (ATTESTED, ATTESTED_WITH_WARNINGS, NOT_ATTESTED)',
);
const attestationFailuresTotal = new Counter(
  'qodiqa_attestation_failures_total',
  'Total attestation runs that resulted in NOT_ATTESTED, by failed_check label',
);
const attestationPersistFailuresTotal = new Counter(
  'qodiqa_attestation_persist_failures_total',
  'Total failures persisting attestation records to PostgreSQL',
);
const attestationEvidenceVerificationsTotal = new Counter(
  'qodiqa_attestation_evidence_verifications_total',
  'Total evidence package verification runs by result label (VALID or INVALID)',
);
const attestationChainVerificationsTotal = new Counter(
  'qodiqa_attestation_chain_verifications_total',
  'Total evidence chain verification runs by result label (VALID or INVALID)',
);

// Certification Runtime — Component #25
const certificationsTotal = new Counter(
  'qodiqa_certifications_total',
  'Total certifications generated by level label (NOT_CERTIFIED, CERTIFIED, CERTIFIED_PLUS, CERTIFIED_PREMIUM)',
);
const certificationFailuresTotal = new Counter(
  'qodiqa_certification_failures_total',
  'Total certification evaluations that resulted in NOT_CERTIFIED, by reason label',
);
const certificationPersistFailuresTotal = new Counter(
  'qodiqa_certification_persist_failures_total',
  'Total failures persisting certification records to PostgreSQL',
);

// Transparency Gap Handling — Component #14
const transparencyGapTotal = new Counter(
  'qodiqa_transparency_gap_total',
  'Total transparency gaps detected, by gap_type, severity, and service labels',
);
const transparencyGapActive = new Gauge(
  'qodiqa_transparency_gap_active',
  'Number of currently active (unresolved) transparency gaps',
);
const transparencyGapResolvedTotal = new Counter(
  'qodiqa_transparency_gap_resolved_total',
  'Total transparency gaps resolved, by gap_type and service labels',
);
const transparencyGapCriticalTotal = new Counter(
  'qodiqa_transparency_gap_critical_total',
  'Total CRITICAL severity transparency gaps detected, by service label',
);
const transparencyGapDetectionLatencyMs = new Histogram(
  'qodiqa_transparency_gap_detection_latency_ms',
  'Transparency gap detection and classification latency in milliseconds',
  FAST_LATENCY_BUCKETS,
);

// Transparency Gap Scanner — Component #34
const gapScannerRunsTotal = new Counter(
  'qodiqa_gap_scanner_runs_total',
  'Total transparency gap scanner executions, by mode label (FULL or INCREMENTAL)',
);
const gapScannerSuccessTotal = new Counter(
  'qodiqa_gap_scanner_success_total',
  'Total transparency gap scanner runs that completed successfully, by mode label',
);
const gapScannerFailuresTotal = new Counter(
  'qodiqa_gap_scanner_failures_total',
  'Total transparency gap scanner runs that failed after all retries, by mode label',
);
const gapScannerSkippedTotal = new Counter(
  'qodiqa_gap_scanner_skipped_total',
  'Total scanner runs skipped (lock not acquired or scanner already active), by reason label',
);
const gapScannerActive = new Gauge(
  'qodiqa_gap_scanner_active',
  'Whether a transparency gap scan is currently executing (1=active, 0=idle)',
);
const gapScannerRunnerActive = new Gauge(
  'qodiqa_gap_scanner_runner_active',
  'Whether the gap scanner background runner is started (1=started, 0=stopped)',
);
const gapScannerLastSuccessTs = new Gauge(
  'qodiqa_gap_scanner_last_success_timestamp_seconds',
  'Unix timestamp of the last successful transparency gap scan (0 if never)',
);
const gapScannerDurationMs = new Histogram(
  'qodiqa_gap_scanner_duration_ms',
  'Total transparency gap scan duration in milliseconds',
  DEFAULT_LATENCY_BUCKETS,
);
const gapScannerGapsDetectedTotal = new Counter(
  'qodiqa_gap_scanner_gaps_detected_total',
  'Total transparency gaps detected by the scanner, by gap_type label',
);
const gapScannerGapsRecoveredTotal = new Counter(
  'qodiqa_gap_scanner_gaps_recovered_total',
  'Total transparency gaps auto-resolved after detection by the scanner',
);
const gapScannerGapsUnrecoverableTotal = new Counter(
  'qodiqa_gap_scanner_gaps_unrecoverable_total',
  'Total transparency gaps that could not be auto-resolved and were left active',
);
const gapScannerEntriesCheckedTotal = new Counter(
  'qodiqa_gap_scanner_entries_checked_total',
  'Total transparency log entries verified by the scanner across all runs',
);
const gapScannerRetriesTotal = new Counter(
  'qodiqa_gap_scanner_retries_total',
  'Total individual retry attempts made by the transparency gap scanner',
);

// Transparency Root Scheduler — Component #33
const trSchedulerRunsTotal = new Counter(
  'qodiqa_transparency_root_scheduler_runs_total',
  'Total transparency root scheduler generation attempts by trigger label (time or entry)',
);
const trSchedulerGeneratedTotal = new Counter(
  'qodiqa_transparency_root_scheduler_generated_total',
  'Total transparency roots successfully generated by the scheduler, by trigger label',
);
const trSchedulerSkippedTotal = new Counter(
  'qodiqa_transparency_root_scheduler_skipped_total',
  'Total scheduler runs skipped (no new entries or generation already in progress), by reason label',
);
const trSchedulerErrorsTotal = new Counter(
  'qodiqa_transparency_root_scheduler_errors_total',
  'Total transparency root scheduler generation failures after all retry attempts, by trigger label',
);
const trSchedulerRetriesTotal = new Counter(
  'qodiqa_transparency_root_scheduler_retries_total',
  'Total individual retry attempts made by the transparency root scheduler',
);
const trSchedulerDurationMs = new Histogram(
  'qodiqa_transparency_root_scheduler_duration_ms',
  'Transparency root generation duration from scheduler trigger to completion in milliseconds',
  DEFAULT_LATENCY_BUCKETS,
);
const trSchedulerLastRunTs = new Gauge(
  'qodiqa_transparency_root_scheduler_last_run_timestamp_seconds',
  'Unix timestamp of the last transparency root scheduler run attempt (0 if never run)',
);
const trSchedulerActive = new Gauge(
  'qodiqa_transparency_root_scheduler_active',
  'Whether the transparency root scheduler is currently running (1=active, 0=stopped)',
);

// Key Rotation Scheduler — automatic signing-key rotation
const keyRotationSchedulerRunsTotal = new Counter(
  'qodiqa_key_rotation_scheduler_runs_total',
  'Total key rotation scheduler evaluation attempts by trigger label (scheduled or manual)',
);
const keyRotationSchedulerSuccessTotal = new Counter(
  'qodiqa_key_rotation_scheduler_success_total',
  'Total signing key rotations completed successfully, by trigger and provider label',
);
const keyRotationSchedulerFailuresTotal = new Counter(
  'qodiqa_key_rotation_scheduler_failures_total',
  'Total signing key rotation failures after all retry attempts, by trigger and provider label',
);
const keyRotationSchedulerSkippedTotal = new Counter(
  'qodiqa_key_rotation_scheduler_skipped_total',
  'Total rotation checks skipped (not due, lock contention, or generation in progress), by reason label',
);
const keyRotationSchedulerRetriesTotal = new Counter(
  'qodiqa_key_rotation_scheduler_retries_total',
  'Total individual retry attempts made by the key rotation scheduler',
);
const keyRotationSchedulerDurationMs = new Histogram(
  'qodiqa_key_rotation_scheduler_duration_ms',
  'Signing key rotation duration from scheduler trigger to completion in milliseconds',
  DEFAULT_LATENCY_BUCKETS,
);
const keyRotationSchedulerLastRunTs = new Gauge(
  'qodiqa_key_rotation_scheduler_last_run_timestamp_seconds',
  'Unix timestamp of the last key rotation scheduler run attempt (0 if never run)',
);
const keyRotationSchedulerNextRunTs = new Gauge(
  'qodiqa_key_rotation_scheduler_next_run_timestamp_seconds',
  'Unix timestamp of the next scheduled key rotation check (0 if scheduler is stopped or disabled)',
);
const keyRotationSchedulerActive = new Gauge(
  'qodiqa_key_rotation_scheduler_active',
  'Whether the key rotation scheduler is currently running (1=active, 0=stopped)',
);
const keyRotationLockContentionTotal = new Counter(
  'qodiqa_key_rotation_lock_contention_total',
  'Total times this instance failed to acquire the distributed rotation lock because another instance held it',
);
const keyActiveAgeSeconds = new Gauge(
  'qodiqa_key_active_age_seconds',
  'Age in seconds of the current active signing key, by clientId label',
);

// Audit & Evidence Pipeline Reliability — fail-closed audit write guarantees
const auditAppendRetriesTotal = new Counter(
  'qodiqa_audit_append_retries_total',
  'Total retry attempts made by appendMandatory() against the file-based audit chain, by stage label (ALLOW, BLOCK, STREAM)',
);
const auditAppendFailedTotal = new Counter(
  'qodiqa_audit_append_failed_total',
  'Total times appendMandatory() exhausted all retries and could not durably record an audit entry, by stage label',
);
// 2026-10-06: every HTTP response, by bounded route family (first path segment of a mounted
// router, else "other") and status class — the basis for a 5xx-rate / availability alert, which request metrics
// limited to /ai/chat and /verify could not support.
const httpResponsesTotal = new Counter(
  'qodiqa_http_responses_total',
  'HTTP responses by route family (bounded: mounted first path segment, else other) and status class (1xx-5xx)',
);
// 2026-10-06: appendMandatory() exhausted its retries on ENOSPC — the audit volume is full.
// Until now this was only an AUDIT_DISK_FULL log event plus the generic append_failed counter.
const auditDiskFullTotal = new Counter(
  'qodiqa_audit_disk_full_total',
  'Times appendMandatory() exhausted its retries because the audit volume was full (ENOSPC), by stage label',
);
const auditFailClosedRejectionsTotal = new Counter(
  'qodiqa_audit_fail_closed_rejections_total',
  'Total requests rejected with a non-success response because mandatory audit evidence could not be recorded',
);
const auditPgRecoveryQueuedTotal = new Counter(
  'qodiqa_audit_pg_recovery_queued_total',
  'Total PostgreSQL audit/evidence dual-write failures durably queued for retry, by operation type label (AUDIT_CHAIN_PG_SAVE, EVIDENCE_CHAIN_SAVE)',
);
// FINDING-AUDIT-CHAIN-TENANT-GENESIS-COLLISION: single-node mode's startup
// hydration (audit-log.js) tries to seed _tailHash from audit_chain's true
// last row when PG is enabled and the file yielded no history, instead of
// unconditionally assuming GENESIS. A failure here (PG unreachable, query
// error) is absorbed exactly like the original bug's silent fallback was —
// but must never again be silent: this counter plus an ERROR log line are
// how a fallback-to-GENESIS gets noticed instead of hiding for months.
const auditPgHydrationFailedTotal = new Counter(
  'qodiqa_audit_pg_hydration_failed_total',
  'Total times single-node startup hydration of the audit-chain tail hash from PostgreSQL failed and fell back to GENESIS/file state',
);
// CHAIN-3 remediation: the Persistence Recovery Queue's durable store is now
// PostgreSQL itself (migration 032), not Redis — this counter observes the
// one remaining disclosed residual risk: PostgreSQL being unavailable at the
// exact moment recoveryManager.enqueue() tries to durably record a retry
// (i.e. both the original write AND the queue write fail simultaneously).
// Should be zero in normal operation; a nonzero rate means recovery work is
// being lost and PostgreSQL itself needs attention, not Redis.
const prqPersistFailedTotal = new Counter(
  'qodiqa_prq_persist_failed_total',
  'Total recovery-queue enqueue attempts that failed because PostgreSQL itself was unavailable at that moment, by operation type label — the sole remaining disclosed risk after CHAIN-3 (Redis is no longer a dependency of this path)',
);

// Live Enforcement → Transparency Log bridge — every /ai/chat
// decision (ALLOW or BLOCK) is registered into the RFC6962 transparency log
// via registrar.register(), mirroring the audit chain's ALLOW/BLOCK stage
// labeling above.
const transparencyEnforcementEntriesTotal = new Counter(
  'qodiqa_transparency_enforcement_entries_total',
  'Total /ai/chat enforcement decisions registered into the RFC6962 transparency log, by decision label (ALLOW, BLOCK)',
);
const transparencyEnforcementFailuresTotal = new Counter(
  'qodiqa_transparency_enforcement_failures_total',
  'Total failures registering an /ai/chat enforcement decision into the transparency log, by stage label (ALLOW, BLOCK)',
);
const transparencyFailClosedRejectionsTotal = new Counter(
  'qodiqa_transparency_fail_closed_rejections_total',
  'Total requests rejected with a non-success response because mandatory transparency log evidence could not be recorded',
);

// Persistence Recovery DLQ — Component #32
//
// Gauges are updated on every GET /v1/prq/stats call so Prometheus sees
// near-real-time values without a separate scrape-on-demand hook.
const prqDlqDepth = new Gauge(
  'qodiqa_prq_dlq_depth',
  'Current number of items in the Persistence Recovery Dead Letter Queue',
);
const prqArchivedDepth = new Gauge(
  'qodiqa_prq_archived_depth',
  'Total number of soft-archived DLQ items (persistence_recovery_queue rows with status = ARCHIVED)',
);
const prqDlqReplayTotal = new Counter(
  'qodiqa_prq_dlq_replay_total',
  'Total DLQ item replay attempts by result label (success or failure)',
);
const prqDlqArchiveTotal = new Counter(
  'qodiqa_prq_dlq_archive_total',
  'Total DLQ items soft-archived via admin action',
);
const prqDlqReplayDurationMs = new Histogram(
  'qodiqa_prq_dlq_replay_duration_ms',
  'DLQ item re-enqueue operation duration in milliseconds (queue insertion only, not worker processing)',
  FAST_LATENCY_BUCKETS,
);
const prqDlqOldestItemAgeSeconds = new Gauge(
  'qodiqa_prq_dlq_oldest_item_age_seconds',
  'Age in seconds of the oldest item currently in the DLQ (0 if empty)',
);
const prqDlqAverageRetryCount = new Gauge(
  'qodiqa_prq_dlq_average_retry_count',
  'Average retry count of items currently in the Dead Letter Queue (0 if empty)',
);

// Persistence Recovery Journal — FAILOVER-1 remediation.
//
// The filesystem-backed fallback recoveryManager.enqueue() uses when the
// PostgreSQL-backed recovery queue's own INSERT fails (i.e. PostgreSQL is
// unavailable at the exact moment a retry would have been durably queued).
// See src/core/persistenceRecovery/journal.js and journalWorker.js.
const prqJournalDepth = new Gauge(
  'qodiqa_prq_journal_depth',
  'Current number of entries in the filesystem persistence recovery journal awaiting replay into PostgreSQL',
);
const prqJournalOldestEntryAgeSeconds = new Gauge(
  'qodiqa_prq_journal_oldest_entry_age_seconds',
  'Age in seconds of the oldest entry currently in the filesystem recovery journal (0 if empty)',
);
const prqJournalBytes = new Gauge(
  'qodiqa_prq_journal_bytes',
  'Total size in bytes of all entries currently in the filesystem recovery journal',
);
const prqJournalWriteTotal = new Counter(
  'qodiqa_prq_journal_write_total',
  'Total attempts to durably write an operation into the filesystem recovery journal, by result label (success or failure)',
);
const prqJournalWriteFailedTotal = new Counter(
  'qodiqa_prq_journal_write_failed_total',
  'Total operations lost because BOTH the PostgreSQL-backed recovery queue AND the filesystem journal write failed at the same moment — the sole remaining unrecoverable case after FAILOVER-1 (should be ~0)',
);
const prqJournalReplayedTotal = new Counter(
  'qodiqa_prq_journal_replayed_total',
  'Total filesystem journal entries successfully replayed back into the PostgreSQL-backed recovery queue',
);
const prqJournalReplayFailedTotal = new Counter(
  'qodiqa_prq_journal_replay_failed_total',
  'Total filesystem journal replay attempts that failed (PostgreSQL still unavailable), by operation type label',
);
const prqJournalReplayDurationMs = new Histogram(
  'qodiqa_prq_journal_replay_duration_ms',
  'Duration in milliseconds of a single filesystem journal entry replay (re-enqueue into PostgreSQL + local file deletion)',
  FAST_LATENCY_BUCKETS,
);

// ── Streaming Enforcement — Component #38 ────────────────────────────────────

const streamingActiveStreams = new Gauge(
  'qodiqa_streaming_active_streams',
  'Number of currently active SSE/chunked streaming sessions',
);
const streamingCompletedTotal = new Counter(
  'qodiqa_streaming_completed_total',
  'Total streaming sessions completed normally by termination_reason label',
);
const streamingCancelledTotal = new Counter(
  'qodiqa_streaming_cancelled_total',
  'Total streaming sessions cancelled (client disconnect, timeout, policy) by reason label',
);
const streamingRejectedTotal = new Counter(
  'qodiqa_streaming_rejected_total',
  'Total streaming requests rejected at enforcement (before stream started) by reason label',
);
const streamingEnforcementFailuresTotal = new Counter(
  'qodiqa_streaming_enforcement_failures_total',
  'Total mid-stream enforcement failures requiring immediate stream termination',
);
const streamingBytesTotal = new Counter(
  'qodiqa_streaming_bytes_total',
  'Total bytes of AI output forwarded across all streaming sessions',
);
const streamingChunksTotal = new Counter(
  'qodiqa_streaming_chunks_total',
  'Total SSE chunks forwarded to clients across all streaming sessions',
);
const streamingDurationMs = new Histogram(
  'qodiqa_streaming_duration_ms',
  'Streaming session end-to-end duration in milliseconds',
  DEFAULT_LATENCY_BUCKETS,
);

// ── Non-streaming provider cancellation — Component #38 (Finding 32) ─────────
//
// Counts route-level timeouts that cancelled in-flight, non-streaming
// provider work via AbortSignal (see src/api/routes/aiChat.js and
// services/providers/router.js), labeled by the code recorded in the audit
// entry — REQUEST_TIMEOUT (signal was already aborted before dispatch began)
// or PROVIDER_CANCELLED (an outbound call in flight was aborted mid-request).
const providerExecutionCancelledTotal = new Counter(
  'qodiqa_provider_execution_cancelled_total',
  'Total non-streaming provider executions cancelled by a route-level timeout, by reason label',
);
const streamingProviderLatencyMs = new Histogram(
  'qodiqa_streaming_provider_latency_ms',
  'Time from stream start to first chunk received from provider in milliseconds',
  FAST_LATENCY_BUCKETS,
);

// ── Multi-Tenant Organization Metrics — Component #39 ────────────────────────
//
// Cardinality strategy:
//   Labels are limited to organizationId and tenantId.  These are bounded by the
//   set of registered organizations/tenants (provisioned at startup or via the
//   admin API), not by unbounded per-request parameters.  For deployments with
//   >1 000 tenants, set TENANT_METRICS_ENABLED=false to suppress tenant labels
//   and reduce series cardinality.  Counters remain accurate at the aggregate
//   level regardless of this setting.

const orgRequestsTotal = new Counter(
  'qodiqa_org_requests_total',
  'Total enforcement requests by organization and tenant (label: organization_id, tenant_id)',
);
const orgBlocksTotal = new Counter(
  'qodiqa_org_blocks_total',
  'Total blocked requests by organization and tenant (label: organization_id, tenant_id, reason)',
);
const orgActiveSessions = new Gauge(
  'qodiqa_org_active_sessions',
  'Currently active enforcement sessions per organization (label: organization_id)',
);

// ── Policy Simulation Metrics — Component #40 ────────────────────────────────

const simulationsTotal = new Counter(
  'qodiqa_simulations_total',
  'Total policy simulation requests by decision (EXECUTE or BLOCK)',
);
const simulationDurationMs = new Histogram(
  'qodiqa_simulation_duration_ms',
  'Policy simulation evaluation latency in milliseconds',
  FAST_LATENCY_BUCKETS,
);
const simulationFailuresTotal = new Counter(
  'qodiqa_simulation_failures_total',
  'Total policy simulation blocks and errors by reason code',
);
const policyComparisonsTotal = new Counter(
  'qodiqa_policy_comparisons_total',
  'Total policy comparison evaluation requests',
);
const batchSimulationsTotal = new Counter(
  'qodiqa_batch_simulations_total',
  'Total batch simulation requests',
);

// ── Rate Limiting — ────────────────────────────────────────────────
//
// Mirrors src/core/rateLimit/metrics.js's internal rl_* counters under the
// qodiqa_ naming convention so rate-limit health is visible on the same
// /metrics surface as everything else (see docs/operations/metrics-and-alerting.md).
// The internal rl_* counters are untouched — both are incremented at the same
// call sites in src/core/rateLimit/middleware.js.
//
// Cardinality: `surface` is a fixed, bounded enum of route surfaces
// (resolvePolicies' surface registry); `dimension` and `reason` are likewise
// bounded, fixed sets — never unbounded per-request values.

const rateLimitRequestsTotal = new Counter(
  'qodiqa_rate_limit_requests_total',
  'Total requests evaluated by rate limiting, by surface',
);
const rateLimitAllowedTotal = new Counter(
  'qodiqa_rate_limit_allowed_total',
  'Total requests that passed rate limiting, by surface',
);
const rateLimitLimitedTotal = new Counter(
  'qodiqa_rate_limit_limited_total',
  'Total requests rejected (HTTP 429) by rate limiting, by surface and reason (SUSTAINED, BURST, DISABLED, BACKEND)',
);
const rateLimitRedisFailuresTotal = new Counter(
  'qodiqa_rate_limit_redis_failures_total',
  'Total rate-limit backend (Redis) failures causing fail-closed 429s, by surface',
);
// (D3 → C): 1 while a traffic bucket runs on the per-process fallback limiter.
const rateLimitDegraded = new Gauge(
  'qodiqa_rate_limit_degraded',
  'Rate-limit bucket enforced by the per-process in-memory fallback because Redis is unavailable (1) or on Redis (0), by bucket',
);
// unauthenticated /ai/chat rejects no longer reach the audit
// chain or the transparency log; they are counted here (and sampled in logs).
const preAuthRejectsTotal = new Counter(
  'qodiqa_preauth_rejects_total',
  'Requests rejected before caller authentication (no/undecodable artifact, invalid body, bad signature, unknown or expired key) — not written to the audit chain or transparency log — by reason and route',
);
// consent-cache entries that failed MAC verification (unsigned, tampered,
// unknown key, expired, version mismatch) and were treated as a miss (PG re-verified).
const consentCacheIntegrityFailuresTotal = new Counter(
  'qodiqa_consent_cache_integrity_failures_total',
  'Consent-cache entries rejected by MAC/integrity verification and treated as a miss (PostgreSQL re-verifies), by reason',
);
// pub/sub messages (consent revocation, org status) and org-status
// records rejected for a missing or invalid signature, by channel and reason.
const pubsubSignatureRejectsTotal = new Counter(
  'qodiqa_pubsub_signature_rejects_total',
  'Consent-revocation / org-status messages and org-status records rejected for a missing or invalid MAC, by channel and reason',
);
const rateLimitBurstConsumedTotal = new Counter(
  'qodiqa_rate_limit_burst_consumed_total',
  'Total burst-capacity-consumed events, by surface and dimension',
);
const rateLimitQuotaUtilization = new Gauge(
  'qodiqa_rate_limit_quota_utilization',
  'Current quota utilization per surface and dimension, scaled 0-1000 (count / maxRequests * 1000)',
);
const rateLimitLatencyMs = new Histogram(
  'qodiqa_rate_limit_latency_ms',
  'Rate-limit middleware processing latency in milliseconds, by surface',
  FAST_LATENCY_BUCKETS,
);

// ── Auth-Failure Lockout — AUTH-2 ────────────────────────────────────────────
//
// Dedicated, credential-outcome-aware counterpart to the rate-limit metrics
// above — see src/core/authLockout. Deliberately unlabeled (no per-IP/
// per-identity label): cardinality must stay bounded regardless of how many
// distinct sources attempt authentication (requirement: "avoid excessive
// cardinality"). Per-source detail belongs in the structured logs
// (AUTH_LOCKOUT_* events), not in a metric label.

const authLockoutFailuresTotal = new Counter(
  'qodiqa_auth_lockout_failures_total',
  'Total ops-auth authentication failures tracked by the lockout control',
);
const authLockoutTriggeredTotal = new Counter(
  'qodiqa_auth_lockout_triggered_total',
  'Total times a source crossed the failure threshold and was locked out',
);
const authLockoutActiveGauge = new Gauge(
  'qodiqa_auth_lockout_active',
  'Best-effort count of currently locked-out sources (decremented when an expired lock is next observed)',
);
const authLockoutRecoveriesTotal = new Counter(
  'qodiqa_auth_lockout_recoveries_total',
  'Total successful authentications that followed one or more prior failures',
);
const authLockoutBackoffAppliedTotal = new Counter(
  'qodiqa_auth_lockout_backoff_applied_total',
  'Total requests delayed by exponential backoff prior to lockout',
);
const authLockoutStorageFailuresTotal = new Counter(
  'qodiqa_auth_lockout_storage_failures_total',
  'Total lockout-storage (Redis) failures — the control fails closed on each one',
);

// ── Webhook Delivery — Component #28 ─────────────────────────────────────────
//
// Mirrors src/core/webhooks/webhookMetrics.js's internal webhook_* counters
// under the qodiqa_ naming convention. The internal counters are untouched —
// both are incremented at the same call sites in
// src/core/webhooks/webhookDelivery.js. `event_type` is a fixed, internally
// defined enum of QODIQA event names, not user-supplied — bounded cardinality.

const webhookDeliveriesTotal = new Counter(
  'qodiqa_webhook_deliveries_total',
  'Total successful webhook deliveries, by event_type',
);
const webhookDeliveryFailuresTotal = new Counter(
  'qodiqa_webhook_delivery_failures_total',
  'Total failed webhook deliveries, by event_type',
);
const webhookRetriesTotal = new Counter(
  'qodiqa_webhook_retries_total',
  'Total webhook delivery retry attempts, by event_type',
);
const webhookDeliveryDurationMs = new Histogram(
  'qodiqa_webhook_delivery_duration_ms',
  'Webhook delivery attempt duration in milliseconds, by event_type',
  FAST_LATENCY_BUCKETS,
);

// ── Alerting Notification Delivery — MON-3 ───────────────────────────────────
//
// Incremented by src/alerting/notification/channels/BaseChannel.js#deliver(),
// alongside its existing ALERT_NOTIFICATION_SENT/_FAILED/ALERT_CHANNEL_RATE_LIMITED
// log emits. `channel` is one of the fixed CHANNEL enum values in
// src/alerting/constants.js (WEBHOOK/SLACK/TEAMS/SIEM/EMAIL/PAGERDUTY/SMS) —
// bounded cardinality. Distinct from qodiqa_webhook_* above, which tracks
// src/core/webhooks/ (outbound customer webhooks), not alert notifications.

const alertNotificationSentTotal = new Counter(
  'qodiqa_alert_notification_sent_total',
  'Total alert notifications successfully delivered, by channel and severity',
);
const alertNotificationFailedTotal = new Counter(
  'qodiqa_alert_notification_failed_total',
  'Total alert notification deliveries that exhausted all retries, by channel and severity',
);
const alertNotificationRetriesTotal = new Counter(
  'qodiqa_alert_notification_retries_total',
  'Total alert notification delivery retry attempts, by channel',
);
const alertNotificationRateLimitedTotal = new Counter(
  'qodiqa_alert_notification_rate_limited_total',
  'Total alert notifications dropped by per-channel rate limiting, by channel',
);

// ── Log Shipping / SIEM Export — ──────────────────────────────────────
//
// Incremented directly by src/observability/logShipping/queue.js at the same
// dispatch call sites for every destination (elk, datadog, splunk, siem),
// mirroring queue.js's own internal getMetrics() under the qodiqa_ naming
// convention. `destination` is a fixed, internally defined set of adapter
// names — bounded cardinality.

const logShipExportedTotal = new Counter(
  'qodiqa_logship_exported_total',
  'Total log/audit events successfully exported, by destination',
);
const logShipFailuresTotal = new Counter(
  'qodiqa_logship_failures_total',
  'Total log/audit event export failures (non-retryable or retries exhausted), by destination',
);
const logShipRetriesTotal = new Counter(
  'qodiqa_logship_retries_total',
  'Total log/audit event export retry attempts, by destination',
);
const logShipDroppedTotal = new Counter(
  'qodiqa_logship_dropped_total',
  'Total log/audit events dropped because a destination\'s in-flight queue depth cap was reached, by destination',
);
const logShipReconnectsTotal = new Counter(
  'qodiqa_logship_reconnects_total',
  'Total reconnect attempts for persistent-connection destinations, by destination (reserved: current transports are per-request/per-datagram, not persistent connections)',
);
const logShipQueueDepth = new Gauge(
  'qodiqa_logship_queue_depth',
  'Current in-flight (queued, not yet settled) event count, by destination',
);
const logShipDestinationHealthy = new Gauge(
  'qodiqa_logship_destination_healthy',
  'Destination health: 1=healthy, 0=degraded, -1=unknown, by destination',
);
const logShipDispatchDurationMs = new Histogram(
  'qodiqa_logship_dispatch_duration_ms',
  'Log/audit event dispatch duration in milliseconds, by destination',
  FAST_LATENCY_BUCKETS,
);
// #6: a schema-mapping function (ecsMapper/cimMapper) failure never
// breaks delivery — the destination falls back to the raw event and counts
// it here, so operators notice mapping drift without losing the event.
const logShipSchemaMappingErrorsTotal = new Counter(
  'qodiqa_logship_schema_mapping_errors_total',
  'Total SIEM schema-mapping failures (ECS/CIM), by destination and schema — event delivery falls back to raw on failure',
);

// ── Audit/PostgreSQL Startup Cross-Validation — CHAIN-4 ──────────────────────
//
// Emitted once per process lifetime, by verifyMirrorConsistency() in
// src/core/audit/mirrorConsistencyCheck.js, immediately after the startup
// cross-check between the file audit chain and the PostgreSQL mirror
// completes (success, failure, or recovery-mode-degraded). Duration is
// recorded in seconds (not the ms convention used elsewhere in this file)
// to match the operator-facing metric name audit_crosscheck_duration_seconds
// required by the CHAIN-4 remediation spec.
const SECONDS_BUCKETS = [0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60];

const auditCrosscheckSuccessTotal = new Counter(
  'qodiqa_audit_crosscheck_success_total',
  'Total successful startup cross-validations between the file audit chain and the PostgreSQL mirror',
);
const auditCrosscheckFailureTotal = new Counter(
  'qodiqa_audit_crosscheck_failure_total',
  'Total failed startup cross-validations between the file audit chain and the PostgreSQL mirror, by reason label',
);
const auditCrosscheckDurationSeconds = new Histogram(
  'qodiqa_audit_crosscheck_duration_seconds',
  'Duration of the startup file-chain/PostgreSQL-mirror cross-validation in seconds',
  SECONDS_BUCKETS,
);
const auditCrosscheckRecordsChecked = new Gauge(
  'qodiqa_audit_crosscheck_records_checked',
  'Number of audit records compared during the most recent startup cross-validation run',
);
const auditCrosscheckLastVerifiedTimestamp = new Gauge(
  'qodiqa_audit_crosscheck_last_verified_timestamp_seconds',
  'Unix timestamp of the most recent successful (fully consistent) startup cross-validation (0 if never)',
);

// ── Live Audit Chain Integrity Verifier — CHAIN-2 ────────────────────────────
//
// Emitted by src/core/audit/verifier/ChainVerifier.js (each verify() /
// verifyPgDivergence() call) and its background runner
// (src/core/audit/verifier/index.js). Distinct from the CHAIN-4 metrics
// above: those cover the one-shot STARTUP file/PG cross-check
// (mirrorConsistencyCheck.js); these cover the CONTINUOUS, incremental and
// full, live verification of the execution audit chain itself — the actual
// enforcement record, as opposed to the separate transparency log the
// existing gapScanner* metrics below cover.
const auditChainVerifierRunsTotal = new Counter(
  'qodiqa_audit_chain_verifier_runs_total',
  'Total live audit chain verifier runs, by mode (FULL or INCREMENTAL) and trigger (STARTUP, SCHEDULED, or MANUAL)',
);
const auditChainVerifierSuccessTotal = new Counter(
  'qodiqa_audit_chain_verifier_success_total',
  'Total live audit chain verifier runs that completed with no violations found, by mode',
);
const auditChainVerifierFailureTotal = new Counter(
  'qodiqa_audit_chain_verifier_failure_total',
  'Total live audit chain verifier runs that either errored or found violations, by mode and reason label',
);
const auditChainVerifierViolationsTotal = new Counter(
  'qodiqa_audit_chain_verifier_violations_total',
  'Total individual chain integrity violations detected, by reason and severity label',
);
const auditChainVerifierActive = new Gauge(
  'qodiqa_audit_chain_verifier_active',
  '1 while a live audit chain verification scan is in flight, 0 otherwise',
);
const auditChainVerifierRunnerActive = new Gauge(
  'qodiqa_audit_chain_verifier_runner_active',
  '1 while the live audit chain verifier background runner is started, 0 otherwise',
);
const auditChainVerifierLastSuccessTimestamp = new Gauge(
  'qodiqa_audit_chain_verifier_last_success_timestamp_seconds',
  'Unix timestamp of the most recent clean (no violations) verification run (0 if never)',
);
const auditChainVerifierLastViolationTimestamp = new Gauge(
  'qodiqa_audit_chain_verifier_last_violation_timestamp_seconds',
  'Unix timestamp of the most recently detected chain integrity violation (0 if never)',
);
const auditChainVerifierDurationSeconds = new Histogram(
  'qodiqa_audit_chain_verifier_duration_seconds',
  'Duration of a live audit chain verification run in seconds, by mode',
  SECONDS_BUCKETS,
);
const auditChainVerifierEntriesCheckedTotal = new Counter(
  'qodiqa_audit_chain_verifier_entries_checked_total',
  'Cumulative count of audit chain entries verified across all runs',
);
const auditChainVerifierWatermarkPosition = new Gauge(
  'qodiqa_audit_chain_verifier_watermark_position',
  'Current verified-up-to cursor (chain index in file mode, seq in PG-authoritative mode) — lets an operator confirm the verifier is not stalled',
);
// (VERIFIER-DESIGN.md, owner amendments 5 and 7)
const auditChainVerifierLagEntries = new Gauge(
  'qodiqa_audit_chain_verifier_lag_entries',
  'Entries appended to the audit chain but not yet verified by the incremental verifier (appended count minus the verified watermark) - a growing value means verification is falling behind',
);
const auditChainVerifierConsecutiveIncomplete = new Gauge(
  'qodiqa_audit_chain_verifier_consecutive_incomplete',
  'Consecutive verifier runs of a mode that did not complete (timeout or failure); >= 3 raises AUDIT_CHAIN_VERIFIER_NOT_COMPLETING',
);
const auditChainVerifierSkippedTotal = new Counter(
  'qodiqa_audit_chain_verifier_skipped_total',
  'Total verification runs skipped without executing, by reason label (lock_not_acquired, already_scanning, PG_DISABLED, DISTRIBUTED_MODE, etc.)',
);
const auditChainVerifierRetriesTotal = new Counter(
  'qodiqa_audit_chain_verifier_retries_total',
  'Total engine-failure retry attempts by the live audit chain verifier background runner',
);
const auditChainVerifierRepairAttempts = new Gauge(
  'qodiqa_audit_chain_verifier_repair_attempts',
  'Fixed at 0 — repair is not supported by design; see docs/protocol/AUDIT-SCHEMA-V8.md',
);
auditChainVerifierRepairAttempts.set({}, 0);

// ── Audit Retention — ──────────────────────────────────────────────────
//
// Emitted by retention.js's runRetentionCycle() (execution outcome metrics)
// and retentionPrivilegeCheck.js's verifyRetentionPrivileges() (startup
// privilege-check metrics). `operation` on the failure counters is bounded
// to 'UPDATE' | 'DELETE' | 'UNKNOWN' — retention.js issues no other write
// against platform_audit_events. Full failure text (SQLSTATE, PG message,
// table) is not carried as a label — unbounded cardinality — and instead
// goes to the FATAL/ERROR log record and, for completed runs, the existing
// audit_retention_runs table (see GET /audit-store/retention/runs).

const auditRetentionRunsTotal = new Counter(
  'qodiqa_audit_retention_runs_total',
  'Total audit retention cycle executions, by status label (COMPLETE or FAILED)',
);
const auditRetentionPermissionFailuresTotal = new Counter(
  'qodiqa_audit_retention_permission_failures_total',
  'Total audit retention cycle failures caused by a database permission or RLS-policy problem, by operation label (UPDATE or DELETE)',
);
const auditRetentionEventsExpiredTotal = new Counter(
  'qodiqa_audit_retention_events_expired_total',
  'Total platform_audit_events rows deleted by the retention job across all runs',
);
const auditRetentionEventsHeldTotal = new Counter(
  'qodiqa_audit_retention_events_held_total',
  'Total observations of expired-but-legal-hold-blocked platform_audit_events rows across all runs',
);
const auditRetentionDurationMs = new Histogram(
  'qodiqa_audit_retention_duration_ms',
  'Audit retention cycle end-to-end duration in milliseconds',
  DEFAULT_LATENCY_BUCKETS,
);
const auditRetentionLastSuccessTimestamp = new Gauge(
  'qodiqa_audit_retention_last_success_timestamp_seconds',
  'Unix timestamp of the most recent successfully completed retention cycle (0 if never)',
);
const auditRetentionLastFailureTimestamp = new Gauge(
  'qodiqa_audit_retention_last_failure_timestamp_seconds',
  'Unix timestamp of the most recent failed retention cycle (0 if never)',
);
const auditRetentionPrivilegeCheckSuccessTotal = new Counter(
  'qodiqa_audit_retention_privilege_check_success_total',
  'Total successful startup privilege validations for the audit retention job',
);
const auditRetentionPrivilegeCheckFailureTotal = new Counter(
  'qodiqa_audit_retention_privilege_check_failure_total',
  'Total failed startup privilege validations for the audit retention job, by operation label (UPDATE, DELETE, or UNKNOWN)',
);
const auditRetentionPrivilegeCheckDurationSeconds = new Histogram(
  'qodiqa_audit_retention_privilege_check_duration_seconds',
  'Duration of the startup audit retention privilege validation in seconds',
  SECONDS_BUCKETS,
);

// ── Audit Append/Fsync/Persistence Latency — #3 ───────────────────────
//
// Additive alongside the existing auditAppendRetriesTotal/auditAppendFailedTotal
// counters above — those measure retry/failure counts, these measure latency
// distribution for every attempt (success and failure alike), isolating the
// three distinct I/O phases of _appendOne() in src/core/audit/audit-log.js.

const auditAppendDurationSeconds = new Histogram(
  'qodiqa_audit_append_duration_seconds',
  'Audit entry append latency in seconds (WAL write through chain commit for single-node; PG head-row-lock transaction for distributed), labeled by mode and outcome',
  SECONDS_BUCKETS,
);
const auditFsyncDurationSeconds = new Histogram(
  'qodiqa_audit_fsync_duration_seconds',
  'Audit log file fsync latency in seconds',
  SECONDS_BUCKETS,
);
// Finding C: the WAL file itself must be durable (fsynced) BEFORE the
// main-log append it protects is attempted — see audit-log.js's _appendOne()
// header comment. Tracked as its own histogram (not reusing
// auditFsyncDurationSeconds) so operators can distinguish the two distinct
// fsync calls now on the hot append path.
const auditWalFsyncDurationSeconds = new Histogram(
  'qodiqa_audit_wal_fsync_duration_seconds',
  'Audit WAL file fsync latency in seconds (durability barrier before the main log append)',
  SECONDS_BUCKETS,
);
const auditChecksumPersistDurationSeconds = new Histogram(
  'qodiqa_audit_checksum_persist_duration_seconds',
  'Audit checksum anchor persist latency in seconds',
  SECONDS_BUCKETS,
);

// ── Ordering-Authority Throughput — REL-06 ──────────────────────────────────
//
// Makes the item-23/item-24 measured ceiling (distributedOrdering.js's
// audit_chain_head row-lock serialization point) observable before it's
// binding, not discovered after. The ordering logic itself is untouched —
// these are pure measurement, wrapped around both the single-node and
// distributed append paths in audit-log.js's shared _appendOne() dispatch.
//
// qodiqa_ordering_ceiling_appends_per_sec / qodiqa_ordering_baseline_rps are
// static reference gauges (set once below, from the named constants at the
// bottom of this file) so an operator scraping /metrics sees the measured
// ceiling and baseline right next to the live counter — no PromQL literacy
// required to eyeball headroom, though the documented queries
// (rate(qodiqa_ordering_append_total{mode="distributed"}[1m]) / 330, and the
// same divided by 70 for the baseline-multiple) give the precise form.
//.
const orderingAppendTotal = new Counter(
  'qodiqa_ordering_append_total',
  'Total audit-chain append attempts through the ordering authority, labeled by mode (single-node|distributed) and outcome (success|failure)',
);
const orderingInflightAppends = new Gauge(
  'qodiqa_ordering_inflight_appends',
  'Concurrent in-flight audit-chain append calls, labeled by mode — a backlog/contention proxy for the ordering authority',
);
// entries accepted into audit.log whose single-node PG mirror write
// is still waiting on the serialized writer (audit-log.js _enqueueMirrorWrite).
const auditMirrorWriterDepth = new Gauge(
  'qodiqa_audit_mirror_writer_depth',
  'Single-node PG mirror writes waiting on the serialized (chain-ordered) mirror writer',
);
// (D3 / queue monitor): transparency leaves queued instead of persisted
// synchronously, and per-queue depth gauges sampled by
// src/core/persistenceRecovery/queueMonitor.js.
const transparencyPendingTotal = new Counter(
  'qodiqa_transparency_pending_total',
  'Enforcement-decision transparency leaves whose synchronous registration failed on PostgreSQL persistence and were durably queued (TRANSPARENCY_SAVE), by durable label (queue|journal)',
);
const transparencyJournalUnavailable = new Gauge(
  'qodiqa_transparency_journal_unavailable',
  '1 while neither the recovery queue nor the file journal can take a transparency leaf; new EXECUTE decisions are refused once this lasts past QODIQA_TRANSPARENCY_JOURNAL_MAX_UNAVAILABLE_MS',
);
const transparencyJournalBuffered = new Gauge(
  'qodiqa_transparency_journal_buffered',
  'Transparency leaves held in memory because no durable store would take them; retried in order',
);
const transparencyJournalRefusedTotal = new Counter(
  'qodiqa_transparency_journal_refused_total',
  'EXECUTE decisions refused (503 TRANSPARENCY_JOURNAL_UNAVAILABLE) because the transparency evidence store was unavailable past its bound',
);
const transparencyUnrecordedTotal = new Counter(
  'qodiqa_transparency_unrecorded_total',
  'Transparency leaves that could not be recorded anywhere, by reason (buffer_full)',
);
const externalAnchorTotal = new Counter(
  'qodiqa_external_anchor_total',
  'External checkpoint anchors by kind (git, ots, rfc3161) and outcome (confirmed, retry, failed)',
);
const externalAnchorPending = new Gauge(
  'qodiqa_external_anchor_pending',
  'External checkpoint anchors not yet confirmed',
);
const externalAnchorOldestPendingSeconds = new Gauge(
  'qodiqa_external_anchor_oldest_pending_seconds',
  'Age in seconds of the oldest unconfirmed external anchor',
);
const prqQueueDepth = new Gauge(
  'qodiqa_prq_queue_depth',
  'Persistence recovery queue rows by operation_type and status (PENDING|DLQ), sampled by the queue-depth monitor',
);
const prqRetryingDepth = new Gauge(
  'qodiqa_prq_retrying_depth',
  'PENDING persistence recovery queue rows that have failed at least once (retry_count > 0), by operation_type',
);
const prqOldestPendingAgeSeconds = new Gauge(
  'qodiqa_prq_oldest_pending_age_seconds',
  'Age in seconds of the oldest PENDING persistence recovery queue row, by operation_type (0 if none)',
);
const transparencyUnrootedIdSpan = new Gauge(
  'qodiqa_transparency_unrooted_id_span',
  'Latest transparency_log_entries id minus the latest root seq_to: an upper bound on leaves not yet covered by a signed root',
);
const queueBacklogAlertsTotal = new Counter(
  'qodiqa_queue_backlog_alerts_total',
  'Queue-depth monitor alerts raised when a queue crossed its alert threshold, by queue label',
);
const orderingCeilingAppendsPerSec = new Gauge(
  'qodiqa_ordering_ceiling_appends_per_sec',
  'Static reference: measured distributed-mode ordering-authority throughput ceiling in appends/sec (ITEM-23 report, conservative lower bound of the observed ~330-545 band)',
);
const orderingBaselineRps = new Gauge(
  'qodiqa_ordering_baseline_rps',
  'Static reference: measured platform baseline throughput in RPS under real combined load (ITEM-24 report, conservative lower bound of the observed ~70-82 band) — compare rate(qodiqa_ordering_append_total[1m]) against this to watch for the ~5x-growth design-review trigger',
);

// ── Audit Checksum Anchor Isolation — #2 ──────────────────────────────
//
// src/core/audit/checksumAnchor.js dual-writes the checksum anchor into a
// PostgreSQL table (audit_checksum_anchor, migration 036) independent of the
// audit.log filesystem, in addition to the existing co-located file anchor.

const auditChecksumAnchorBackend = new Gauge(
  'qodiqa_audit_checksum_anchor_backend',
  'Whether the isolated PG-backed checksum anchor is active (1=pg, 0=file-only)',
);
const auditChecksumAnchorLastWriteTimestamp = new Gauge(
  'qodiqa_audit_checksum_anchor_last_write_timestamp_seconds',
  'Unix timestamp (seconds) of the most recent isolated (PG) checksum anchor write attempt',
);
const auditChecksumAnchorMismatchTotal = new Counter(
  'qodiqa_audit_checksum_anchor_mismatch_total',
  'Total times the isolated PG checksum anchor was found to disagree with the in-memory chain tail',
);
// ER 2026-10-06: outcome of each external anchor publication (checkpointWriter): anchored | witness_refused |
// (+ transparency_anchor_failed — the checkpoint's transparency-log registration failed) |
// witness_failed | export_failed. witness_refused means a witness saw a rollback/equivocation attempt (alert: critical).
const auditAnchorEventsTotal = new Counter(
  'qodiqa_audit_anchor_events_total',
  'External audit-anchor publication outcomes, by outcome',
);

// ── Redis High Availability — ────────────────────────────────────────────
//
// Emitted by src/infra/redis/managedClient.js for every managed Redis
// connection (one per `purpose` — nonce, anomaly, rateLimit, rateLimitPolicy,
// consentCache, revocationPublisher, revocationSubscriber, keyRotationLock,
// persistenceQueue). Cardinality is bounded: `purpose` and `mode` are both
// small, fixed, internally-defined enums, never unbounded per-request values.

const redisReconnectTotal = new Counter(
  'qodiqa_redis_reconnect_total',
  'Total Redis client reconnect attempts, by purpose and mode',
);
const redisFailoverTotal = new Counter(
  'qodiqa_redis_failover_total',
  'Total detected Redis master failovers (Sentinel MASTER_CHANGE topology events), by purpose',
);
const redisConnectionUptimeSeconds = new Gauge(
  'qodiqa_redis_connection_uptime_seconds',
  'Seconds since the current Redis connection last became ready, by purpose',
);
const redisCurrentMasterInfo = new Gauge(
  'qodiqa_redis_current_master_info',
  'Info metric (always 1) identifying the current Redis master host/port per purpose, by purpose/host/port label',
);
const redisLatencyMs = new Histogram(
  'qodiqa_redis_latency_ms',
  'Redis command round-trip latency in milliseconds (PING probe), by purpose',
  FAST_LATENCY_BUCKETS,
);
const redisCommandFailuresTotal = new Counter(
  'qodiqa_redis_command_failures_total',
  'Total Redis command failures, by purpose',
);
const redisRetryTotal = new Counter(
  'qodiqa_redis_retry_total',
  'Total bounded reconnect-strategy retry attempts, by purpose',
);
const redisRecoveryDurationMs = new Histogram(
  'qodiqa_redis_recovery_duration_ms',
  'Duration from connection loss to ready-again (full recovery), in milliseconds, by purpose',
  DEFAULT_LATENCY_BUCKETS,
);
const redisSubscriptionRecoveryTotal = new Counter(
  'qodiqa_redis_subscription_recovery_total',
  'Total pub/sub subscription restorations after a reconnect or failover, by purpose',
);
const redisQueueRecoveryTotal = new Counter(
  'qodiqa_redis_queue_recovery_total',
  'Total persistence-recovery-queue resumptions after a reconnect or failover, by purpose',
);

// Single-mode self-healing recovery — Finding 49. A terminal `end` no longer
// leaves a store permanently degraded; these track the resulting supervised
// destroy-and-recreate loop (see src/infra/redis/managedClient.js).
const redisRecoveryCompletedTotal = new Counter(
  'qodiqa_redis_recovery_completed_total',
  'Total times a managed Redis connection fully recovered (reconnected, authenticated, and PING-verified) after a terminal disconnect, by purpose',
);
const redisRecoveryConsecutiveFailures = new Gauge(
  'qodiqa_redis_recovery_consecutive_failures',
  'Current count of consecutive failed recovery attempts since the last terminal disconnect, by purpose (reset to 0 on recovery)',
);
const redisConnectionStateCode = new Gauge(
  'qodiqa_redis_connection_state_code',
  'Current lifecycle state of a managed Redis connection, by purpose (0=DISCONNECTED, 1=DEGRADED, 2=RECOVERING, 3=HEALTHY)',
);

// ── Periodic Redis Durability Validator — #1 ──────────────────────────
//
// src/infra/redis/persistenceMonitor.js re-runs the same durability check
// server/startup.js performs once at boot, on a recurring background
// interval, against the live nonce-store connection — detects configuration
// drift (safe -> unsafe) that the one-shot startup check cannot see.

const redisPersistenceSafe = new Gauge(
  'qodiqa_redis_persistence_safe',
  'Current classification of the periodic Redis durability check (1=safe, 0=unsafe, -1=unknown/unverified)',
);
const redisPersistenceAofEnabled = new Gauge(
  'qodiqa_redis_persistence_aof_enabled_bool',
  'Whether Redis AOF persistence was enabled on the most recent periodic check (1=yes, 0=no, -1=unknown)',
);
const redisPersistenceLastCheckTimestamp = new Gauge(
  'qodiqa_redis_persistence_last_check_timestamp_seconds',
  'Unix timestamp (seconds) of the most recent periodic Redis persistence check',
);
const redisPersistenceDriftTotal = new Counter(
  'qodiqa_redis_persistence_drift_total',
  'Total safe-to-unsafe Redis persistence configuration drift transitions detected after startup',
);
const redisPersistenceCheckDurationMs = new Histogram(
  'qodiqa_redis_persistence_check_duration_ms',
  'Duration of each periodic Redis persistence CONFIG GET/INFO check, in milliseconds',
  FAST_LATENCY_BUCKETS,
);

// ── Periodic Key Expiry Re-Validation — #9 ────────────────────────────

const keyExpiryMonitorRunsTotal = new Counter(
  'qodiqa_key_expiry_monitor_runs_total',
  'Total periodic key expiry re-validation checks run',
);
const keyExpiryApproachingCount = new Gauge(
  'qodiqa_key_expiry_approaching_count',
  'Number of active signing keys currently within the expiry warning window, per the most recent check',
);
const keyRotationOverdueCount = new Gauge(
  'qodiqa_key_rotation_overdue_count',
  'Number of active signing keys currently past their rotation-due deadline, per the most recent check',
);

// ── Dashboard SSE Backpressure — #7 ───────────────────────────────────
//
// src/dashboard/sseManager.js skips a periodic 'snapshot' broadcast to a
// client whose res.write() last returned false (socket buffer full) rather
// than buffering unboundedly — 'log' events stay full-priority regardless.

const dashboardSseBackpressureEventsTotal = new Counter(
  'qodiqa_dashboard_sse_backpressure_events_total',
  'Total dashboard SSE broadcasts skipped for a backpressured client, by eventName',
);

// ── Semantic Policy Engine Fail-Closed — remediation ────────────────────
//
// Emitted by src/core/semantic/index.js whenever the Semantic Policy Engine
// cannot establish that semantic inspection completed successfully (registry
// load failure, empty registry, every classifier failing/timing out/
// returning invalid output, or aggregation/confidence/evidence computation
// itself throwing) — see reasons.js's ENGINE_STATUS/ENGINE_FAILURE_REASONS.
// `reason`/`classifierId` labels are bounded, fixed-vocabulary enums
// (ENGINE_FAILURE_REASONS values, or classifier ids from the registry),
// never unbounded per-request values.

const semanticEngineFailuresTotal = new Counter(
  'qodiqa_semantic_engine_failures_total',
  'Total Semantic Policy Engine infrastructure failures (registry load failure, empty registry, all classifiers failed, aggregation/confidence/evidence failure, internal error), by reason label',
);
const semanticRegistryLoadFailuresTotal = new Counter(
  'qodiqa_semantic_registry_load_failures_total',
  'Total Semantic Policy Engine classifier registry discovery/initialization failures',
);
const semanticClassifierFailuresTotal = new Counter(
  'qodiqa_semantic_classifier_failures_total',
  'Total individual classifier execution failures (exceptions), by classifierId label',
);
const semanticClassifierTimeoutsTotal = new Counter(
  'qodiqa_semantic_classifier_timeouts_total',
  'Total individual classifier executions that exceeded the configured timeout budget, by classifierId label',
);
const semanticEmptyRegistryTotal = new Counter(
  'qodiqa_semantic_empty_registry_total',
  'Total Semantic Policy Engine evaluations that found zero usable classifiers in the registry',
);
const semanticInvalidOutputTotal = new Counter(
  'qodiqa_semantic_invalid_output_total',
  'Total individual classifier executions that returned malformed/invalid output, by classifierId label',
);
const semanticFailClosedTotal = new Counter(
  'qodiqa_semantic_fail_closed_total',
  'Total requests denied because the Semantic Policy Engine could not complete inspection, by reason label',
);
const semanticPartialFailureTotal = new Counter(
  'qodiqa_semantic_partial_failure_total',
  'Total Semantic Policy Engine evaluations that completed with some (but not all) classifiers failing/timing out/returning invalid output',
);

// ── Semantic layer — FT-2, the fifth gate ─
//
// FT-2 is the only gate on the decision path that costs a SECOND model forward
// pass, so it is grey-band gated: it runs only when the four cheap gates return
// non-DENY and the max anchor similarity has reached B_lo (0.2977). These three
// counters exist to make that band observable in production rather than trusted
// from an offline measurement.
//
// THE INVOCATION RATE IS THE ALERT-BEARING SIGNAL:
//
//     rate = ft2_consulted_total / ft2_eligible_total
//
// Measured before enabling, on the three legitimate populations: holdout-2176
// 23.94%, external-88 15.91%, DCL-008-391 59.85% — a real-traffic mix sits near
// 24%. External ADVERSARIAL traffic runs at 44.28%, so a sustained rise is
// either an attack-shaped traffic shift or a band/threshold drift; both are
// things an operator wants to see. A sustained COLLAPSE toward zero means the
// gate has stopped being consulted at all, which is how a silently-broken band
// would look. Alert on either direction — see embeddingGate.js for the bounds.
const semanticFt2EligibleTotal = new Counter(
  'qodiqa_semantic_ft2_eligible_total',
  'Total embedding-gate evaluations that completed and were therefore eligible for the FT-2 fifth gate (the invocation-rate denominator)',
);
const semanticFt2ConsultedTotal = new Counter(
  'qodiqa_semantic_ft2_consulted_total',
  'Total evaluations where the FT-2 fifth gate was actually invoked (four gates non-DENY AND max anchor score >= the grey band), by fired label',
);
const semanticFt2FailuresTotal = new Counter(
  'qodiqa_semantic_ft2_failures_total',
  'Total FT-2 fifth-gate scoring failures. FAIL-CLOSED: each one is a DENY, so a nonzero and rising value is a denial storm, not a degradation',
);

// ── FT-3, the fine-tuned gate in the SWAP configuration ────────
//
// DUAL-TRACKED, not re-pointed. FT-2 stays wired behind its flag (default OFF)
// so the swap is reversible without a deploy; its counters therefore stay live
// and keep meaning what they meant. These three are the exact FT-3 analogues.
//
// The eligibility denominator and the grey band are IDENTICAL to FT-2's — both
// gates read the same `result.score` against the same 0.2977 band, and in the
// swap configuration FT-3 occupies the same position in the chain FT-2 held
// (first fine-tuned gate, consulted when the four cheap gates did not DENY).
// Measured identity, not assumption: over the recorded sets the consultation
// populations match exactly.
// That is why embeddingGate.js reuses FT-2's calibrated 0.24 +/- 0.10 band for
// FT-3 rather than inventing a second, uncalibrated one.
const semanticFt3EligibleTotal = new Counter(
  'qodiqa_semantic_ft3_eligible_total',
  'Total embedding-gate evaluations that completed and were therefore eligible for the FT-3 fine-tuned gate (the invocation-rate denominator)',
);
const semanticFt3ConsultedTotal = new Counter(
  'qodiqa_semantic_ft3_consulted_total',
  'Total evaluations where the FT-3 fine-tuned gate was actually invoked (four gates non-DENY AND max anchor score >= the grey band), by fired label',
);
const semanticFt3FailuresTotal = new Counter(
  'qodiqa_semantic_ft3_failures_total',
  'Total FT-3 fine-tuned-gate scoring failures. FAIL-CLOSED: each one is a DENY, so a nonzero and rising value is a denial storm, not a degradation',
);
// denials produced by a tenant's tighten-only embedding score bar —
// requests the pinned-default gate ALLOWed but the tenant's stricter
// configuration denied (embeddingGate.js). Never fires for tenants without
// a stored semantic config.
const semanticTenantTightenedDenialsTotal = new Counter(
  'qodiqa_semantic_tenant_tightened_denials_total',
  'Total embedding-gate denials produced by a tenant\'s tighten-only score threshold — the pinned-default gate allowed, the tenant\'s stricter bar denied',
);

// every ALLOW the intent gate produced by OVERRIDING an ensemble DENY (embeddingGate.js).
// A rising rate is the signal a protective-frame wrapper is being probed; each one is also recorded in the audit entry's semantic
// evidence (`intentGate`) and logged as SEM_INTENT_GATE_OVERRIDE.
const semanticIntentGateOverridesTotal = new Counter(
  'qodiqa_semantic_intent_gate_overrides_total',
  'Total embedding-ensemble DENY decisions overridden to ALLOW by the intent gate (labelled by the matching frame)',
);

// ── Semantic Policy Engine — output-side enforcement ───────────────
//
// Distinct from the fail-closed metrics above (which fire when inspection
// itself could not complete, on either surface): these fire when inspection
// completed and found a genuine blocking match in the PROVIDER'S RESPONSE
// text, as opposed to the request prompt. `reason` is a SEMANTIC_REASONS
// value (bounded enum), same label vocabulary the request-side match uses.
const semanticOutputBlockedTotal = new Counter(
  'qodiqa_semantic_output_blocked_total',
  'Total non-streaming responses blocked by output-side semantic classification before reaching the caller, by reason label',
);
const streamingSemanticBlockedTotal = new Counter(
  'qodiqa_streaming_semantic_blocked_total',
  'Total streaming sessions aborted by output-side semantic classification, by reason label',
);
// SEM-C session 3: distinct from streamingSemanticBlockedTotal above — that
// counter fires when a mid-stream chunk check blocks BEFORE the offending
// chunk is forwarded (content withheld). This one fires only when the
// mandatory end-of-stream embedding recheck (outputSemanticWindow.js's
// evaluateFinal()) retroactively marks the whole response BLOCK after every
// chunk had already been forwarded to the client — audit-truth, not
// content-suppression. Operators need to be able to tell these apart: the
// first is prevention, the second is detection-after-the-fact.
const streamingSemanticBlockedFinalTotal = new Counter(
  'qodiqa_streaming_semantic_blocked_final_total',
  'Total streaming sessions retroactively marked BLOCK by the mandatory end-of-stream embedding recheck, after all chunks had already reached the client, by reason label',
);

// ── Readiness Gate — READY-50 ─────────────────────────────────────────────────
//
// Emitted by src/runtime/readinessTracker.js, called from GET /ready
// (src/api/routes/ready.js) on every probe. `component` is a small, fixed,
// internally-defined enum (nonceStore, anomalyStore, rateLimitStore,
// persistenceStore, consentSubscriber) — bounded cardinality, never an
// unbounded per-request value. State is derived by diffing against the
// previously observed value, so transition/failure/recovery counters only
// increment on an actual state change, not on every probe hit — this keeps
// the signal usable under high probe frequency without becoming a per-tick
// counter.

const readinessState = new Gauge(
  'qodiqa_readiness_state',
  'Overall GET /ready outcome (1=ready, 0=not ready)',
);
const readinessComponentUp = new Gauge(
  'qodiqa_readiness_component_up',
  'Current readiness of each individual /ready dependency (1=healthy, 0=unhealthy), by component label',
);
const readinessDependencyFailuresTotal = new Counter(
  'qodiqa_readiness_dependency_failures_total',
  'Total transitions of a /ready dependency from healthy to unhealthy, by component label',
);
const readinessDependencyRecoveryTotal = new Counter(
  'qodiqa_readiness_dependency_recovery_total',
  'Total transitions of a /ready dependency from unhealthy back to healthy, by component label',
);
const readinessTransitionsTotal = new Counter(
  'qodiqa_readiness_transitions_total',
  'Total overall readiness state transitions, by to label (ready or not_ready)',
);
const readinessDependencyDowntimeMs = new Histogram(
  'qodiqa_readiness_dependency_downtime_ms',
  'Duration a /ready dependency spent unhealthy before recovering, in milliseconds, by component label',
  DEFAULT_LATENCY_BUCKETS,
);

// ── PostgreSQL Connection Pool — ─────────────────────────────────────────
//
// Refreshed synchronously from pg.Pool's own in-process counters
// (totalCount/idleCount/waitingCount) on every readiness monitor tick — see
// src/infra/postgres/pool.js's poolStats()/_refreshPoolMetrics(). No
// additional database query is issued to populate these; they reflect the
// pool object's own bookkeeping, not a pg_stat_activity read.

const pgPoolSize = new Gauge(
  'qodiqa_pg_pool_size',
  'Total PostgreSQL connections currently held by the pool (idle + active)',
);
const pgPoolActive = new Gauge(
  'qodiqa_pg_pool_active',
  'PostgreSQL connections currently checked out and in use',
);
const pgPoolIdle = new Gauge(
  'qodiqa_pg_pool_idle',
  'PostgreSQL connections currently idle in the pool',
);
const pgPoolWaiting = new Gauge(
  'qodiqa_pg_pool_waiting',
  'Callers currently queued waiting for a PostgreSQL connection to become available (pgPool.waitingCount)',
);
const pgPoolMax = new Gauge(
  'qodiqa_pg_pool_max',
  'Configured maximum PostgreSQL pool size (QODIQA_PG_POOL_MAX)',
);
const pgPoolAcquireFailuresTotal = new Counter(
  'qodiqa_pg_pool_acquire_failures_total',
  'Total failed PostgreSQL connection acquisitions (pool.connect() rejecting — e.g. pool exhausted past connectionTimeoutMillis)',
);

// ── PostgreSQL Query Circuit Breaker (FAILOVER-2) ─────────────────────────────
// src/infra/postgres/pgCircuitBreaker.js — same CLOSED/OPEN/HALF_OPEN pattern
// as the signing (signingCircuit*Total above) and provider circuit breakers,
// a single process-wide instance (one PG backend per process, unlike the
// per-provider registries those use).
const pgCircuitOpensTotal = new Counter(
  'qodiqa_pg_circuit_opens_total',
  'Total times the PostgreSQL query circuit breaker transitioned to OPEN',
);
const pgCircuitClosesTotal = new Counter(
  'qodiqa_pg_circuit_closes_total',
  'Total times the PostgreSQL query circuit breaker transitioned to CLOSED',
);
const pgCircuitHalfOpenTotal = new Counter(
  'qodiqa_pg_circuit_half_open_total',
  'Total times the PostgreSQL query circuit breaker transitioned to HALF_OPEN',
);
const pgCircuitRejectedTotal = new Counter(
  'qodiqa_pg_circuit_rejected_total',
  'Total PostgreSQL queries/acquisitions fast-failed immediately because the circuit was OPEN',
);

// ── Background Task Isolation — Finding 3.6 ───────────────────────────────────
//
// Emitted by src/runtime/backgroundTasks/BackgroundTaskRunner.js for every
// task executed through runTask(). `task` label is the registry task name
// (src/runtime/backgroundTasks/taskRegistry.js) — a small, bounded set, safe
// as a label. `reason` on the failure counter is the error's classification
// (e.g. 'thrown', 'rejected', 'timeout', 'escaped_isolation' — the last one
// only ever incremented by processHardening.js's global handler, and its
// presence above zero indicates a bug that escaped BackgroundTaskRunner's own
// containment, which should not happen in normal operation).
const backgroundTasksStartedTotal = new Counter(
  'qodiqa_background_tasks_started_total',
  'Total background task executions started, by task name',
);
const backgroundTasksCompletedTotal = new Counter(
  'qodiqa_background_tasks_completed_total',
  'Total background task executions that completed without error, by task name',
);
const backgroundTasksFailedTotal = new Counter(
  'qodiqa_background_tasks_failed_total',
  'Total background task executions that failed, by task name and reason label',
);
const backgroundTaskDurationSeconds = new Histogram(
  'qodiqa_background_task_duration_seconds',
  'Background task execution duration in seconds, by task name',
  SECONDS_BUCKETS,
);
const backgroundTaskTimeoutsTotal = new Counter(
  'qodiqa_background_task_timeouts_total',
  'Total background task executions that exceeded their configured timeout, by task name',
);
const backgroundTaskRetriesTotal = new Counter(
  'qodiqa_background_task_retries_total',
  'Total runner-level retry attempts for background tasks without internal retry logic, by task name',
);

// ── Event Loop Delay Monitor — ─────────────────────────────────────────
//
// Emitted by src/runtime/eventLoopMonitor.js on a background interval tick
// (default every 5s), reading directly off a perf_hooks.monitorEventLoopDelay()
// histogram — no request-path instrumentation, no per-request allocation.
// meanMs is the primary signal used for state classification; the rest give
// operators the full distribution needed to distinguish transient GC blips
// from sustained synchronous-I/O blocking.

const eventLoopDelayMeanMs = new Gauge(
  'qodiqa_event_loop_delay_mean_ms',
  'Mean Node.js event loop delay in milliseconds, from perf_hooks.monitorEventLoopDelay()',
);
const eventLoopDelayMaxMs = new Gauge(
  'qodiqa_event_loop_delay_max_ms',
  'Maximum recorded Node.js event loop delay in milliseconds since the histogram was enabled',
);
const eventLoopDelayMinMs = new Gauge(
  'qodiqa_event_loop_delay_min_ms',
  'Minimum recorded Node.js event loop delay in milliseconds since the histogram was enabled',
);
const eventLoopDelayStddevMs = new Gauge(
  'qodiqa_event_loop_delay_stddev_ms',
  'Standard deviation of Node.js event loop delay in milliseconds',
);
const eventLoopDelayP50Ms = new Gauge(
  'qodiqa_event_loop_delay_p50_ms',
  'Median (p50) Node.js event loop delay in milliseconds',
);
const eventLoopDelayP95Ms = new Gauge(
  'qodiqa_event_loop_delay_p95_ms',
  'p95 Node.js event loop delay in milliseconds',
);
const eventLoopDelayP99Ms = new Gauge(
  'qodiqa_event_loop_delay_p99_ms',
  'p99 Node.js event loop delay in milliseconds',
);
// RT-08: the gauges above are LIFETIME values (one histogram since boot), so "max"
// is the boot-time model load forever. These two are over the LAST sampling interval only — usable as a load signal.
const eventLoopDelayWindowMaxMs = new Gauge(
  'qodiqa_event_loop_delay_window_max_ms',
  'Maximum Node.js event loop delay in milliseconds over the last sampling interval (QODIQA_EVENT_LOOP_CHECK_INTERVAL_MS)',
);
const eventLoopDelayWindowP99Ms = new Gauge(
  'qodiqa_event_loop_delay_window_p99_ms',
  'p99 Node.js event loop delay in milliseconds over the last sampling interval',
);
const eventLoopDelayStateCode = new Gauge(
  'qodiqa_event_loop_delay_state_code',
  'Event loop delay readiness classification against configurable thresholds (0=healthy, 1=degraded, 2=unhealthy)',
);

// ── Signing Resilience (KMS/Vault/HSM) — ────────────────────────────────
//
// Emitted by src/infra/keys/resilience/*.js — the centralized timeout/retry/
// circuit-breaker/health layer wrapped around every KekProvider and
// NativeSigningProvider (local, Vault, AWS KMS, Azure Key Vault, GCP KMS, HSM).

const signingLatencyMs = new Histogram(
  'qodiqa_signing_latency_ms',
  'KMS/Vault/HSM signing-provider operation latency in milliseconds, by provider and operation label',
  DEFAULT_LATENCY_BUCKETS,
);
const signingTimeoutsTotal = new Counter(
  'qodiqa_signing_timeouts_total',
  'Total signing-provider operations that exceeded the configured deadline (SIGNING_TIMEOUT_MS), by provider and operation label',
);
const signingRetriesTotal = new Counter(
  'qodiqa_signing_retries_total',
  'Total bounded retry attempts issued for a transient signing-provider failure, by provider and operation label',
);
const signingRetrySuccessTotal = new Counter(
  'qodiqa_signing_retry_success_total',
  'Total signing-provider operations that succeeded after at least one retry, by provider and operation label',
);
const signingRetryExhaustedTotal = new Counter(
  'qodiqa_signing_retry_exhausted_total',
  'Total signing-provider operations that failed after exhausting all retry attempts, by provider and operation label',
);
const signingCircuitOpensTotal = new Counter(
  'qodiqa_signing_circuit_opens_total',
  'Total times a signing-provider circuit breaker transitioned to OPEN, by provider label',
);
const signingCircuitClosesTotal = new Counter(
  'qodiqa_signing_circuit_closes_total',
  'Total times a signing-provider circuit breaker transitioned to CLOSED, by provider label',
);
const signingCircuitHalfOpenTotal = new Counter(
  'qodiqa_signing_circuit_half_open_total',
  'Total times a signing-provider circuit breaker transitioned to HALF_OPEN, by provider label',
);
const signingCircuitRejectedTotal = new Counter(
  'qodiqa_signing_circuit_rejected_total',
  'Total signing-provider operations rejected immediately because the circuit was OPEN, by provider and operation label',
);
const signingHealthState = new Gauge(
  'qodiqa_signing_health_state',
  'Signing provider health classification (2=healthy, 1=degraded, 0=unavailable), by provider label',
);
const signingConsecutiveFailures = new Gauge(
  'qodiqa_signing_consecutive_failures',
  'Current consecutive-failure count observed by the signing provider health monitor, by provider label',
);
const signingFailuresTotal = new Counter(
  'qodiqa_signing_failures_total',
  'Total signing-provider operation failures, by provider, operation, and failure category label',
);

// ── 2026-10-06 observability fixes ──────────────────
// Each is written by a single best-effort, try/catch-wrapped call at the site named in its help text; none sits on a
// decision path. Labels are bounded at the write site (fixed enums, or a code/permission constant).
const providerFailuresTotal = new Counter( //
  'qodiqa_provider_failures_total',
  'Total provider executions that failed, streaming and non-streaming (cancellations, client disconnects and stream timeouts excluded — see qodiqa_provider_execution_cancelled_total / qodiqa_streaming_cancelled_total), by provider and bounded error code label (src/api/routes/aiChat.js provider catch; src/streaming/streamEnforcer.js STREAM_PROVIDER_ERROR)',
);
const rbacDenialsTotal = new Counter( //
  'qodiqa_rbac_denials_total',
  'Total RBAC 403 denials on the operator surface, by action (permission constant) and reason label (src/middleware/rbac.js RBAC_DENY)',
);
const opsAuthFailuresTotal = new Counter( //
  'qodiqa_ops_auth_failures_total',
  'Total operator-surface authentication failures, by reason label (missing_credentials | invalid_token; src/middleware/opsAuth.js)',
);
const mfaEventsTotal = new Counter( //
  'qodiqa_mfa_events_total',
  'Total operator MFA failures, by outcome label (failed | locked | step_up_denied | step_up_error; src/core/rbac/mfa.js, src/middleware/mfaStepUp.js)',
);
const auditMirrorCountDriftTotal = new Counter( //
  'qodiqa_audit_mirror_count_drift_total',
  'Total audit_chain row-counter reconciliation runs that found drift, by reason label (MISMATCH | COUNTER_MISSING; src/core/audit/mirrorCountReconciler.js AUDIT_MIRROR_COUNT_DRIFT)',
);
const auditPgLagEntries = new Gauge( //
  'qodiqa_audit_pg_lag_entries',
  'Entries the PostgreSQL audit mirror is behind the authoritative file chain, as of the last successful lag check (src/core/audit/pgLagMonitor.js; 0 when in sync or never measured)',
);

// ── Registry ──────────────────────────────────────────────────────────────────

const _registry = [
  requestsTotal,
  blocksTotal,
  requestDurationMs,
  verificationRequestsTotal,
  verificationBlocksTotal,
  verificationDurationMs,
  securityEventsTotal,
  activeRequests,
  redisStoreUp,
  providerCostMicrosTotal, providerTokensTotal,   //
  killSwitchActive, killSwitchBlocksTotal, killSwitchTransitionsTotal,   //
  artifactRevocationsTotal, artifactRevokedBlocksTotal,   //
  auditCommitsTotal,   //
  proofRequestsTotal,  //
  executionIntegrityFull,
  buildInfo,
  provenanceVersionsTotal,
  provenanceModificationsTotal,
  provenanceRollbacksTotal,
  provenanceIntegrityFailuresTotal,
  provenanceAttributionFailuresTotal,
  provenanceDiffFailuresTotal,
  // Evidence Chain — Component #21
  evidenceChainRecordsTotal,
  evidenceChainPersistFailuresTotal,
  evidenceChainVerificationFailuresTotal,
  // Transparency Log — Component #22
  transparencyEntriesTotal,
  transparencyRootsTotal,
  transparencyPersistFailuresTotal,
  transparencyVerificationsTotal,
  transparencyVerificationFailuresTotal,
  // Public Verification Portal — Component #23
  portalVerificationsTotal,
  portalVerificationFailuresTotal,
  portalPersistFailuresTotal,
  // Attestation API — Component #24
  attestationsTotal,
  attestationFailuresTotal,
  attestationPersistFailuresTotal,
  attestationEvidenceVerificationsTotal,
  attestationChainVerificationsTotal,
  // Certification Runtime — Component #25
  certificationsTotal,
  certificationFailuresTotal,
  certificationPersistFailuresTotal,
  // Transparency Gap Handling — Component #14
  transparencyGapTotal,
  transparencyGapActive,
  transparencyGapResolvedTotal,
  transparencyGapCriticalTotal,
  transparencyGapDetectionLatencyMs,
  // Persistence Recovery DLQ metrics — Component #32
  prqDlqDepth,
  prqArchivedDepth,
  prqDlqReplayTotal,
  prqDlqArchiveTotal,
  prqDlqReplayDurationMs,
  prqDlqOldestItemAgeSeconds,
  prqDlqAverageRetryCount,
  // Persistence Recovery Journal metrics — FAILOVER-1
  prqJournalDepth,
  prqJournalOldestEntryAgeSeconds,
  prqJournalBytes,
  prqJournalWriteTotal,
  prqJournalWriteFailedTotal,
  prqJournalReplayedTotal,
  prqJournalReplayFailedTotal,
  prqJournalReplayDurationMs,
  // Transparency Root Scheduler metrics — Component #33
  trSchedulerRunsTotal,
  trSchedulerGeneratedTotal,
  trSchedulerSkippedTotal,
  trSchedulerErrorsTotal,
  trSchedulerRetriesTotal,
  trSchedulerDurationMs,
  trSchedulerLastRunTs,
  trSchedulerActive,
  // Transparency Gap Scanner metrics — Component #34
  gapScannerRunsTotal,
  gapScannerSuccessTotal,
  gapScannerFailuresTotal,
  gapScannerSkippedTotal,
  gapScannerActive,
  gapScannerRunnerActive,
  gapScannerLastSuccessTs,
  gapScannerDurationMs,
  gapScannerGapsDetectedTotal,
  gapScannerGapsRecoveredTotal,
  gapScannerGapsUnrecoverableTotal,
  gapScannerEntriesCheckedTotal,
  gapScannerRetriesTotal,
  // Streaming Enforcement — Component #38
  streamingActiveStreams,
  streamingCompletedTotal,
  streamingCancelledTotal,
  streamingRejectedTotal,
  streamingEnforcementFailuresTotal,
  streamingBytesTotal,
  streamingChunksTotal,
  streamingDurationMs,
  streamingProviderLatencyMs,
  // Multi-Tenant Organization Metrics — Component #39
  orgRequestsTotal,
  orgBlocksTotal,
  orgActiveSessions,
  // Policy Simulation Metrics — Component #40
  simulationsTotal,
  simulationDurationMs,
  simulationFailuresTotal,
  policyComparisonsTotal,
  batchSimulationsTotal,
  // Rate Limiting —
  rateLimitRequestsTotal,
  rateLimitAllowedTotal,
  rateLimitLimitedTotal,
  rateLimitRedisFailuresTotal,
  rateLimitDegraded,
  preAuthRejectsTotal,
  consentCacheIntegrityFailuresTotal,
  pubsubSignatureRejectsTotal,
  rateLimitBurstConsumedTotal,
  rateLimitQuotaUtilization,
  rateLimitLatencyMs,
  // Auth-Failure Lockout — AUTH-2
  authLockoutFailuresTotal,
  authLockoutTriggeredTotal,
  authLockoutActiveGauge,
  authLockoutRecoveriesTotal,
  authLockoutBackoffAppliedTotal,
  authLockoutStorageFailuresTotal,
  // Webhook Delivery — Component #28
  webhookDeliveriesTotal,
  webhookDeliveryFailuresTotal,
  webhookRetriesTotal,
  webhookDeliveryDurationMs,
  // Alerting Notification Delivery — MON-3
  alertNotificationSentTotal,
  alertNotificationFailedTotal,
  alertNotificationRetriesTotal,
  alertNotificationRateLimitedTotal,
  // Log Shipping / SIEM Export —
  logShipExportedTotal,
  logShipFailuresTotal,
  logShipRetriesTotal,
  logShipDroppedTotal,
  logShipReconnectsTotal,
  logShipQueueDepth,
  logShipDestinationHealthy,
  logShipDispatchDurationMs,
  logShipSchemaMappingErrorsTotal,
  // Key Rotation Scheduler
  keyRotationSchedulerRunsTotal,
  keyRotationSchedulerSuccessTotal,
  keyRotationSchedulerFailuresTotal,
  keyRotationSchedulerSkippedTotal,
  keyRotationSchedulerRetriesTotal,
  keyRotationSchedulerDurationMs,
  keyRotationSchedulerLastRunTs,
  keyRotationSchedulerNextRunTs,
  keyRotationSchedulerActive,
  keyRotationLockContentionTotal,
  keyActiveAgeSeconds,
  // Audit & Evidence Pipeline Reliability
  auditAppendRetriesTotal,
  auditAppendFailedTotal,
  auditFailClosedRejectionsTotal,
  auditPgRecoveryQueuedTotal,
  auditPgHydrationFailedTotal,
  prqPersistFailedTotal,
  // Live Enforcement → Transparency Log bridge —
  transparencyEnforcementEntriesTotal,
  transparencyEnforcementFailuresTotal,
  transparencyFailClosedRejectionsTotal,
  // Audit/PostgreSQL Startup Cross-Validation — CHAIN-4
  auditCrosscheckSuccessTotal,
  auditCrosscheckFailureTotal,
  auditCrosscheckDurationSeconds,
  auditCrosscheckRecordsChecked,
  auditCrosscheckLastVerifiedTimestamp,
  // Redis High Availability —
  redisReconnectTotal,
  redisFailoverTotal,
  redisConnectionUptimeSeconds,
  redisCurrentMasterInfo,
  redisLatencyMs,
  redisCommandFailuresTotal,
  redisRetryTotal,
  redisRecoveryDurationMs,
  redisSubscriptionRecoveryTotal,
  redisQueueRecoveryTotal,
  redisRecoveryCompletedTotal,
  redisRecoveryConsecutiveFailures,
  redisConnectionStateCode,
  // Periodic Redis Durability Validator — #1
  redisPersistenceSafe,
  redisPersistenceAofEnabled,
  redisPersistenceLastCheckTimestamp,
  redisPersistenceDriftTotal,
  redisPersistenceCheckDurationMs,
  // Periodic Key Expiry Re-Validation — #9
  keyExpiryMonitorRunsTotal,
  keyExpiryApproachingCount,
  keyRotationOverdueCount,
  // Dashboard SSE Backpressure — #7
  dashboardSseBackpressureEventsTotal,
  // Audit Retention —
  auditRetentionRunsTotal,
  auditRetentionPermissionFailuresTotal,
  auditRetentionEventsExpiredTotal,
  auditRetentionEventsHeldTotal,
  auditRetentionDurationMs,
  auditRetentionLastSuccessTimestamp,
  auditRetentionLastFailureTimestamp,
  auditRetentionPrivilegeCheckSuccessTotal,
  auditRetentionPrivilegeCheckFailureTotal,
  auditRetentionPrivilegeCheckDurationSeconds,
  // Audit Append/Fsync/Persistence Latency — #3
  auditAppendDurationSeconds,
  auditFsyncDurationSeconds,
  auditWalFsyncDurationSeconds,
  auditChecksumPersistDurationSeconds,
  // Ordering-Authority Throughput — REL-06
  orderingAppendTotal,
  orderingInflightAppends,
  auditMirrorWriterDepth,
  transparencyPendingTotal,
  transparencyJournalUnavailable, transparencyJournalBuffered, transparencyJournalRefusedTotal, transparencyUnrecordedTotal,   //
  externalAnchorTotal, externalAnchorPending, externalAnchorOldestPendingSeconds,   //
  prqQueueDepth,
  prqRetryingDepth,
  prqOldestPendingAgeSeconds,
  transparencyUnrootedIdSpan,
  queueBacklogAlertsTotal,
  orderingCeilingAppendsPerSec,
  orderingBaselineRps,
  // Audit Checksum Anchor Isolation — #2
  auditChecksumAnchorBackend,
  auditChecksumAnchorLastWriteTimestamp,
  auditChecksumAnchorMismatchTotal,
  auditAnchorEventsTotal,
  // Semantic Policy Engine Fail-Closed — remediation
  semanticEngineFailuresTotal,
  semanticRegistryLoadFailuresTotal,
  semanticClassifierFailuresTotal,
  semanticClassifierTimeoutsTotal,
  semanticEmptyRegistryTotal,
  semanticInvalidOutputTotal,
  semanticFailClosedTotal,
  semanticFt2EligibleTotal,
  semanticFt2ConsultedTotal,
  semanticFt2FailuresTotal,
  semanticFt3EligibleTotal,
  semanticFt3ConsultedTotal,
  semanticFt3FailuresTotal,
  semanticTenantTightenedDenialsTotal,
  semanticIntentGateOverridesTotal,
  semanticPartialFailureTotal,
  semanticOutputBlockedTotal,
  streamingSemanticBlockedTotal,
  streamingSemanticBlockedFinalTotal,
  // Live Audit Chain Integrity Verifier — CHAIN-2
  auditChainVerifierRunsTotal,
  auditChainVerifierSuccessTotal,
  auditChainVerifierFailureTotal,
  auditChainVerifierViolationsTotal,
  auditChainVerifierActive,
  auditChainVerifierRunnerActive,
  auditChainVerifierLastSuccessTimestamp,
  auditChainVerifierLastViolationTimestamp,
  auditChainVerifierDurationSeconds,
  auditChainVerifierEntriesCheckedTotal,
  auditChainVerifierWatermarkPosition,
  auditChainVerifierLagEntries,
  auditChainVerifierConsecutiveIncomplete,
  auditChainVerifierSkippedTotal,
  auditChainVerifierRetriesTotal,
  auditChainVerifierRepairAttempts,
  // Readiness Gate — READY-50
  readinessState,
  readinessComponentUp,
  readinessDependencyFailuresTotal,
  readinessDependencyRecoveryTotal,
  readinessTransitionsTotal,
  readinessDependencyDowntimeMs,
  // PostgreSQL Connection Pool —
  pgPoolSize,
  pgPoolActive,
  pgPoolIdle,
  pgPoolWaiting,
  pgPoolMax,
  pgPoolAcquireFailuresTotal,
  // PostgreSQL Query Circuit Breaker — FAILOVER-2
  pgCircuitOpensTotal,
  pgCircuitClosesTotal,
  pgCircuitHalfOpenTotal,
  pgCircuitRejectedTotal,
  // Background Task Isolation — Finding 3.6
  backgroundTasksStartedTotal,
  backgroundTasksCompletedTotal,
  backgroundTasksFailedTotal,
  backgroundTaskDurationSeconds,
  backgroundTaskTimeoutsTotal,
  backgroundTaskRetriesTotal,
  // Event Loop Delay Monitor —
  eventLoopDelayMeanMs,
  eventLoopDelayMaxMs,
  eventLoopDelayMinMs,
  eventLoopDelayStddevMs,
  eventLoopDelayP50Ms,
  eventLoopDelayP95Ms,
  eventLoopDelayP99Ms,
  eventLoopDelayWindowMaxMs,
  eventLoopDelayWindowP99Ms,
  eventLoopDelayStateCode,
  // Signing Resilience (KMS/Vault/HSM) —
  signingLatencyMs,
  signingTimeoutsTotal,
  signingRetriesTotal,
  signingRetrySuccessTotal,
  signingRetryExhaustedTotal,
  signingCircuitOpensTotal,
  signingCircuitClosesTotal,
  signingCircuitHalfOpenTotal,
  signingCircuitRejectedTotal,
  signingHealthState,
  signingConsecutiveFailures,
  signingFailuresTotal,
  // 2026-10-06: exported and written, but never served — the shipped QodiqaAdmissionRejecting
  // alert could not fire. metricsRegistryCompleteness.test.js now fails if an exported metric is missing here.
  admissionRejectedTotal,
  admissionInFlight,
  admissionQueued,
  auditDiskFullTotal, //
  httpResponsesTotal, //
  transparencySignerSignaturesTotal,
  transparencySignerFailuresTotal,
  transparencySignerKeyRotationsTotal,
  providerExecutionCancelledTotal,
  // 2026-10-06: new failure signals, each with a shipped alert rule.
  providerFailuresTotal,
  rbacDenialsTotal,
  opsAuthFailuresTotal,
  mfaEventsTotal,
  auditMirrorCountDriftTotal,
  auditPgLagEntries,
];

// Uptime gauge is computed dynamically at collect time.
const processUptimeSeconds = new Gauge(
  'qodiqa_process_uptime_seconds',
  'Process uptime in seconds',
);

// ── Initialise static gauges ──────────────────────────────────────────────────

try {
  const pkg = require('../../package.json');
  buildInfo.set({ version: pkg.version || 'unknown', node_version: process.version }, 1);
} catch {
  buildInfo.set({ version: 'unknown', node_version: process.version }, 1);
}

// Seed Redis store gauges at 0 so Prometheus sees them before first transition.
redisStoreUp.set({ store: 'nonce' },       0);
redisStoreUp.set({ store: 'anomaly' },     0);
redisStoreUp.set({ store: 'rate_limit' },  0);
artifactRevokedBlocksTotal.inc(0);   //
for (const outcome of ['created', 'repeated']) artifactRevocationsTotal.inc({ outcome }, 0);
for (const outcome of ['recorded', 'skipped', 'duplicate', 'failed', 'queued']) auditCommitsTotal.inc({ outcome }, 0);   //
for (const outcome of ['served', 'not_found', 'invalid', 'error']) proofRequestsTotal.inc({ outcome }, 0);   //
killSwitchActive.set(0);   // exported from the first scrape
externalAnchorPending.set(0); externalAnchorOldestPendingSeconds.set(0); for (const k of ['git', 'ots', 'rfc3161']) for (const o of ['confirmed', 'retry', 'failed']) externalAnchorTotal.inc({ kind: k, outcome: o }, 0);   //
transparencyJournalUnavailable.set(0); transparencyJournalBuffered.set(0); transparencyUnrecordedTotal.inc({ reason: 'buffer_full' }, 0);   //
for (const to of ['on', 'off']) killSwitchTransitionsTotal.inc({ to }, 0);
for (const cause of ['active', 'tampered', 'state_unavailable']) killSwitchBlocksTotal.inc({ route: '/ai/chat', cause }, 0);
executionIntegrityFull.set({}, 0);

// 2026-10-06: labelled counters only appear on their first increment, already at 1, so a
// Prometheus increase() over that first sample reads 0 and the first event per series is never alerted. Seed the
// closed label sets the shipped alert rules match on, at 0.
for (const route of ['sign', 'ai_chat', 'verify', 'actions', 'tools']) {
  for (const cause of ['queue_full', 'queue_timeout', 'audit_backlog']) admissionRejectedTotal.inc({ route, cause }, 0);
}
for (const outcome of ['anchored', 'witness_refused', 'witness_failed', 'export_failed', 'transparency_anchor_failed']) auditAnchorEventsTotal.inc({ outcome }, 0);
// The remaining CLOSED label sets an alert rule matches on (each list = every literal its write sites pass). Open-ended
// label sets (audit_append_failed{stage}, verifier {mode,reason}, retention {operation}, prq_persist {operationType},
// key-rotation {trigger,provider}, root-scheduler {trigger}, background_tasks {task,reason}, readiness {component},
// rbac_denials {action,reason}, provider_failures {provider,code}) are NOT seeded: their rules use the
// `increase(X[w]) > 0 or (X > 0 unless X offset w)` form instead.
for (const stage of ['INTENT', 'ALLOW', 'STREAM_LIFECYCLE']) auditFailClosedRejectionsTotal.inc({ stage }, 0);
transparencyFailClosedRejectionsTotal.inc({ stage: 'ALLOW' }, 0);
for (const stage of ['BLOCK', 'ALLOW', 'STREAM']) transparencyEnforcementFailuresTotal.inc({ stage }, 0); //
for (const reason of ['PG_UNREACHABLE', 'PG_CHAIN_INVALID', 'FILE_CHAIN_INVALID', 'DIVERGENCE']) auditCrosscheckFailureTotal.inc({ reason }, 0);
for (const queue of ['prq_pending', 'prq_retrying', 'transparency_pending', 'prq_dlq', 'prq_journal', 'audit_mirror_writer', 'transparency_unrooted']) queueBacklogAlertsTotal.inc({ queue }, 0);
for (const event of ['invalid_signature', 'expired_artifact', 'malformed_artifact', 'replay_detected', 'nonce_violation', 'anomaly_detected']) securityEventsTotal.inc({ event }, 0);
for (const reason of ['missing_credentials', 'invalid_token']) opsAuthFailuresTotal.inc({ reason }, 0);
for (const outcome of ['failed', 'locked', 'step_up_denied', 'step_up_error']) mfaEventsTotal.inc({ outcome }, 0);
for (const reason of ['MISMATCH', 'COUNTER_MISSING']) auditMirrorCountDriftTotal.inc({ reason }, 0);

// REL-06 — measured reference constants, named so they're greppable/auditable
// independent of the /metrics output. Source: audit/remediation/
// ITEM-23-REMEDIATION-REPORT.md (ceiling, conservative lower bound of the
// observed ~330-545 appends/sec band) and ITEM-24-REMEDIATION-REPORT.md
// (baseline, conservative lower bound of the observed ~70-82 RPS band under
// real combined load). Re-set here, not computed, if either report is ever
// superseded by a re-benchmark.
const ORDERING_CEILING_APPENDS_PER_SEC = 330;
const ORDERING_BASELINE_RPS = 70;
orderingCeilingAppendsPerSec.set({}, ORDERING_CEILING_APPENDS_PER_SEC);
orderingBaselineRps.set({}, ORDERING_BASELINE_RPS);

// ── collect() — assemble full Prometheus text payload ─────────────────────────

/**
 * Assemble the Prometheus exposition text.
 *
 * @param {number} [currentActiveRequests]  Injected from requestDrain.activeCount().
 * @returns {string}  Full Prometheus text payload, UTF-8 safe, terminated with \n.
 */
function collect(currentActiveRequests) {
  try {
    activeRequests.set({}, typeof currentActiveRequests === 'number' ? currentActiveRequests : 0);
    processUptimeSeconds.set({}, Math.floor((Date.now() - _STARTED_AT_MS) / 1000));

    const sections = [..._registry, processUptimeSeconds].map(m => {
      try { return m.format(); } catch { return ''; }
    }).filter(Boolean);

    return sections.join('\n\n') + '\n';
  } catch {
    return '# collection error\n';
  }
}

// read-only accessor for the optional metrics OTLP export bridge
// (src/observability/metricsExport/). Returns the SAME live metric
// instances collect() itself iterates (including processUptimeSeconds,
// which _registry alone omits — collect() appends it separately, mirrored
// here so OTLP export sees exactly what the Prometheus scrape sees) — a
// snapshot ARRAY (new each call, cheap: just spreading references, not
// cloning metric state), never a mutable reference to _registry itself.
// Never throws; returns [] on any internal error so the bridge always has
// a safe, iterable fallback.
function getRegistrySnapshot() {
  try {
    return [..._registry, processUptimeSeconds];
  } catch {
    return [];
  }
}

// ── Security event reason → canonical category map ────────────────────────────

const REASON_SECURITY_EVENT = Object.freeze({
  // Invalid signature
  'INVALID_SIGNATURE':           'invalid_signature',
  'SIGNATURE_INVALID':           'invalid_signature',
  'INVALID_SIGNATURE_FORMAT':    'invalid_signature',
  // Expired / stale artifact
  'ARTIFACT_EXPIRED':            'expired_artifact',
  'ARTIFACT_ALREADY_EXPIRED':    'expired_artifact',
  'ARTIFACT_STALE':              'expired_artifact',
  'CLOCK_SKEW_EXCEEDED':         'expired_artifact',
  // Future timestamp
  'FUTURE_TIMESTAMP':            'malformed_artifact',
  'TIMESTAMP_IN_FUTURE':         'malformed_artifact',
  // Replay
  'REPLAY_DETECTED':             'replay_detected',
  'NONCE_ALREADY_USED':          'replay_detected',
  // Nonce store failures (not replay but nonce-layer blocks)
  'NONCE_STORE_ERROR':           'nonce_violation',
  // 2026-10-06: a replay refusal because the nonce state could not be proven (503) — was unmapped.
  'REPLAY_STATE_UNPROVABLE':     'nonce_violation',
  // Anomaly / burst
  'ANOMALY_DETECTED':            'anomaly_detected',
  // Malformed artifact
  'MALFORMED_JSON':              'malformed_artifact',
  'ARTIFACT_DECODE_FAILED':      'malformed_artifact',
  'ARTIFACT_INVALID_TYPE':       'malformed_artifact',
  'INVALID_ARTIFACT':            'malformed_artifact',
  'MALFORMED_ARTIFACT':          'malformed_artifact',
  'SCHEMA_VIOLATION':            'malformed_artifact',
  'EXTRA_FIELDS':                'malformed_artifact',
  'MISSING_FIELDS':              'malformed_artifact',
  'MISSING_ARTIFACT':            'malformed_artifact',
  'ARTIFACT_TOO_LARGE':          'malformed_artifact',
  'ARTIFACT_FIELD_UNDEFINED':    'malformed_artifact',
  'INVALID_PAYLOAD':             'malformed_artifact',
  'KEY_NOT_FOUND':               'invalid_signature',
  'PUBLIC_KEY_NOT_FOUND':        'invalid_signature',
});

module.exports = {
  // Metric instances (for direct increment from server.js hooks)
  admissionRejectedTotal, admissionInFlight, admissionQueued, //
  requestsTotal,
  blocksTotal,
  requestDurationMs,
  verificationRequestsTotal,
  verificationBlocksTotal,
  verificationDurationMs,
  securityEventsTotal,
  activeRequests,
  redisStoreUp,
  providerCostMicrosTotal, providerTokensTotal,   //
  killSwitchActive, killSwitchBlocksTotal, killSwitchTransitionsTotal,   //
  artifactRevocationsTotal, artifactRevokedBlocksTotal,   //
  auditCommitsTotal,   //
  proofRequestsTotal,  // (audit remediation 2026-10-27: was registered but never exported, so every .inc threw a swallowed TypeError)
  executionIntegrityFull,
  buildInfo,
  // Provenance metrics — Component #20
  provenanceVersionsTotal,
  provenanceModificationsTotal,
  provenanceRollbacksTotal,
  provenanceIntegrityFailuresTotal,
  provenanceAttributionFailuresTotal,
  provenanceDiffFailuresTotal,
  // Evidence Chain metrics — Component #21
  evidenceChainRecordsTotal,
  evidenceChainPersistFailuresTotal,
  evidenceChainVerificationFailuresTotal,
  // Transparency Log metrics — Component #22
  transparencyEntriesTotal,
  transparencyRootsTotal,
  transparencyPersistFailuresTotal,
  transparencyVerificationsTotal,
  transparencyVerificationFailuresTotal,
  // HSM-backed Transparency Key metrics — Component #30
  transparencySignerSignaturesTotal,
  transparencySignerFailuresTotal,
  transparencySignerKeyRotationsTotal,
  // Public Verification Portal metrics — Component #23
  portalVerificationsTotal,
  portalVerificationFailuresTotal,
  portalPersistFailuresTotal,
  // Attestation API metrics — Component #24
  attestationsTotal,
  attestationFailuresTotal,
  attestationPersistFailuresTotal,
  attestationEvidenceVerificationsTotal,
  attestationChainVerificationsTotal,
  // Certification Runtime metrics — Component #25
  certificationsTotal,
  certificationFailuresTotal,
  certificationPersistFailuresTotal,
  // Transparency Gap Handling metrics — Component #14
  transparencyGapTotal,
  transparencyGapActive,
  transparencyGapResolvedTotal,
  transparencyGapCriticalTotal,
  transparencyGapDetectionLatencyMs,
  // Persistence Recovery DLQ metrics — Component #32
  prqDlqDepth,
  prqArchivedDepth,
  prqDlqReplayTotal,
  prqDlqArchiveTotal,
  prqDlqReplayDurationMs,
  prqDlqOldestItemAgeSeconds,
  prqDlqAverageRetryCount,
  // Persistence Recovery Journal metrics — FAILOVER-1
  prqJournalDepth,
  prqJournalOldestEntryAgeSeconds,
  prqJournalBytes,
  prqJournalWriteTotal,
  prqJournalWriteFailedTotal,
  prqJournalReplayedTotal,
  prqJournalReplayFailedTotal,
  prqJournalReplayDurationMs,
  // Transparency Root Scheduler metrics — Component #33
  trSchedulerRunsTotal,
  trSchedulerGeneratedTotal,
  trSchedulerSkippedTotal,
  trSchedulerErrorsTotal,
  trSchedulerRetriesTotal,
  trSchedulerDurationMs,
  trSchedulerLastRunTs,
  trSchedulerActive,
  // Transparency Gap Scanner metrics — Component #34
  gapScannerRunsTotal,
  gapScannerSuccessTotal,
  gapScannerFailuresTotal,
  gapScannerSkippedTotal,
  gapScannerActive,
  gapScannerRunnerActive,
  gapScannerLastSuccessTs,
  gapScannerDurationMs,
  gapScannerGapsDetectedTotal,
  gapScannerGapsRecoveredTotal,
  gapScannerGapsUnrecoverableTotal,
  gapScannerEntriesCheckedTotal,
  gapScannerRetriesTotal,
  // Streaming Enforcement metrics — Component #38
  streamingActiveStreams,
  streamingCompletedTotal,
  streamingCancelledTotal,
  streamingRejectedTotal,
  streamingEnforcementFailuresTotal,
  streamingBytesTotal,
  streamingChunksTotal,
  streamingDurationMs,
  streamingProviderLatencyMs,
  providerExecutionCancelledTotal,
  // Multi-Tenant Organization Metrics — Component #39
  orgRequestsTotal,
  orgBlocksTotal,
  orgActiveSessions,
  // Policy Simulation Metrics — Component #40
  simulationsTotal,
  simulationDurationMs,
  simulationFailuresTotal,
  policyComparisonsTotal,
  batchSimulationsTotal,
  // Rate Limiting —
  rateLimitRequestsTotal,
  rateLimitAllowedTotal,
  rateLimitLimitedTotal,
  rateLimitRedisFailuresTotal,
  rateLimitDegraded,
  preAuthRejectsTotal,
  consentCacheIntegrityFailuresTotal,
  pubsubSignatureRejectsTotal,
  rateLimitBurstConsumedTotal,
  rateLimitQuotaUtilization,
  rateLimitLatencyMs,
  // Webhook Delivery — Component #28
  webhookDeliveriesTotal,
  webhookDeliveryFailuresTotal,
  webhookRetriesTotal,
  webhookDeliveryDurationMs,
  // Alerting Notification Delivery — MON-3
  alertNotificationSentTotal,
  alertNotificationFailedTotal,
  alertNotificationRetriesTotal,
  alertNotificationRateLimitedTotal,
  // Log Shipping / SIEM Export —
  logShipExportedTotal,
  logShipFailuresTotal,
  logShipRetriesTotal,
  logShipDroppedTotal,
  logShipReconnectsTotal,
  logShipQueueDepth,
  logShipDestinationHealthy,
  logShipDispatchDurationMs,
  logShipSchemaMappingErrorsTotal,
  // Key Rotation Scheduler
  keyRotationSchedulerRunsTotal,
  keyRotationSchedulerSuccessTotal,
  keyRotationSchedulerFailuresTotal,
  keyRotationSchedulerSkippedTotal,
  keyRotationSchedulerRetriesTotal,
  keyRotationSchedulerDurationMs,
  keyRotationSchedulerLastRunTs,
  keyRotationSchedulerNextRunTs,
  keyRotationSchedulerActive,
  keyRotationLockContentionTotal,
  keyActiveAgeSeconds,
  // Audit & Evidence Pipeline Reliability
  auditAppendRetriesTotal,
  auditAppendFailedTotal,
  auditDiskFullTotal,
  httpResponsesTotal,
  auditFailClosedRejectionsTotal,
  auditPgRecoveryQueuedTotal,
  auditPgHydrationFailedTotal,
  prqPersistFailedTotal,
  // Live Enforcement → Transparency Log bridge metrics —
  transparencyEnforcementEntriesTotal,
  transparencyEnforcementFailuresTotal,
  transparencyFailClosedRejectionsTotal,
  // Audit/PostgreSQL Startup Cross-Validation metrics — CHAIN-4
  auditCrosscheckSuccessTotal,
  auditCrosscheckFailureTotal,
  auditCrosscheckDurationSeconds,
  auditCrosscheckRecordsChecked,
  auditCrosscheckLastVerifiedTimestamp,
  // Redis High Availability metrics —
  redisReconnectTotal,
  redisFailoverTotal,
  redisConnectionUptimeSeconds,
  redisCurrentMasterInfo,
  redisLatencyMs,
  redisCommandFailuresTotal,
  redisRetryTotal,
  redisRecoveryDurationMs,
  redisSubscriptionRecoveryTotal,
  redisQueueRecoveryTotal,
  redisRecoveryCompletedTotal,
  redisRecoveryConsecutiveFailures,
  redisConnectionStateCode,
  // Periodic Redis Durability Validator — #1
  redisPersistenceSafe,
  redisPersistenceAofEnabled,
  redisPersistenceLastCheckTimestamp,
  redisPersistenceDriftTotal,
  redisPersistenceCheckDurationMs,
  // Periodic Key Expiry Re-Validation — #9
  keyExpiryMonitorRunsTotal,
  keyExpiryApproachingCount,
  keyRotationOverdueCount,
  // Dashboard SSE Backpressure — #7
  dashboardSseBackpressureEventsTotal,
  // Audit Retention metrics —
  auditRetentionRunsTotal,
  auditRetentionPermissionFailuresTotal,
  auditRetentionEventsExpiredTotal,
  auditRetentionEventsHeldTotal,
  auditRetentionDurationMs,
  auditRetentionLastSuccessTimestamp,
  auditRetentionLastFailureTimestamp,
  auditRetentionPrivilegeCheckSuccessTotal,
  auditRetentionPrivilegeCheckFailureTotal,
  auditRetentionPrivilegeCheckDurationSeconds,
  // Audit Append/Fsync/Persistence Latency — #3
  auditAppendDurationSeconds,
  auditFsyncDurationSeconds,
  auditWalFsyncDurationSeconds,
  auditChecksumPersistDurationSeconds,
  // Ordering-Authority Throughput — REL-06
  orderingAppendTotal,
  orderingInflightAppends,
  auditMirrorWriterDepth,
  transparencyPendingTotal,
  transparencyJournalUnavailable, transparencyJournalBuffered, transparencyJournalRefusedTotal, transparencyUnrecordedTotal,   //
  externalAnchorTotal, externalAnchorPending, externalAnchorOldestPendingSeconds,   //
  prqQueueDepth,
  prqRetryingDepth,
  prqOldestPendingAgeSeconds,
  transparencyUnrootedIdSpan,
  queueBacklogAlertsTotal,
  orderingCeilingAppendsPerSec,
  orderingBaselineRps,
  // Audit Checksum Anchor Isolation — #2
  auditChecksumAnchorBackend,
  auditChecksumAnchorLastWriteTimestamp,
  auditChecksumAnchorMismatchTotal,
  auditAnchorEventsTotal,
  // Semantic Policy Engine Fail-Closed metrics — remediation
  semanticEngineFailuresTotal,
  semanticRegistryLoadFailuresTotal,
  semanticClassifierFailuresTotal,
  semanticClassifierTimeoutsTotal,
  semanticEmptyRegistryTotal,
  semanticInvalidOutputTotal,
  semanticFailClosedTotal,
  semanticFt2EligibleTotal,
  semanticFt2ConsultedTotal,
  semanticFt2FailuresTotal,
  semanticFt3EligibleTotal,
  semanticFt3ConsultedTotal,
  semanticFt3FailuresTotal,
  semanticTenantTightenedDenialsTotal,
  semanticIntentGateOverridesTotal,
  semanticPartialFailureTotal,
  semanticOutputBlockedTotal,
  streamingSemanticBlockedTotal,
  streamingSemanticBlockedFinalTotal,
  // Live Audit Chain Integrity Verifier metrics — CHAIN-2
  auditChainVerifierRunsTotal,
  auditChainVerifierSuccessTotal,
  auditChainVerifierFailureTotal,
  auditChainVerifierViolationsTotal,
  auditChainVerifierActive,
  auditChainVerifierRunnerActive,
  auditChainVerifierLastSuccessTimestamp,
  auditChainVerifierLastViolationTimestamp,
  auditChainVerifierDurationSeconds,
  auditChainVerifierEntriesCheckedTotal,
  auditChainVerifierWatermarkPosition,
  auditChainVerifierLagEntries,
  auditChainVerifierConsecutiveIncomplete,
  auditChainVerifierSkippedTotal,
  auditChainVerifierRetriesTotal,
  auditChainVerifierRepairAttempts,
  // Readiness Gate metrics — READY-50
  readinessState,
  readinessComponentUp,
  readinessDependencyFailuresTotal,
  readinessDependencyRecoveryTotal,
  readinessTransitionsTotal,
  readinessDependencyDowntimeMs,
  // PostgreSQL Connection Pool metrics —
  pgPoolSize,
  pgPoolActive,
  pgPoolIdle,
  pgPoolWaiting,
  pgPoolMax,
  pgPoolAcquireFailuresTotal,
  // PostgreSQL Query Circuit Breaker metrics — FAILOVER-2
  pgCircuitOpensTotal,
  pgCircuitClosesTotal,
  pgCircuitHalfOpenTotal,
  pgCircuitRejectedTotal,
  // Background Task Isolation metrics — Finding 3.6
  backgroundTasksStartedTotal,
  backgroundTasksCompletedTotal,
  backgroundTasksFailedTotal,
  backgroundTaskDurationSeconds,
  backgroundTaskTimeoutsTotal,
  backgroundTaskRetriesTotal,
  // Event Loop Delay Monitor metrics —
  eventLoopDelayMeanMs,
  eventLoopDelayMaxMs,
  eventLoopDelayMinMs,
  eventLoopDelayStddevMs,
  eventLoopDelayP50Ms,
  eventLoopDelayP95Ms,
  eventLoopDelayP99Ms,
  eventLoopDelayWindowMaxMs,
  eventLoopDelayWindowP99Ms,
  eventLoopDelayStateCode,
  // Signing Resilience (KMS/Vault/HSM) —
  signingLatencyMs,
  signingTimeoutsTotal,
  signingRetriesTotal,
  signingRetrySuccessTotal,
  signingRetryExhaustedTotal,
  signingCircuitOpensTotal,
  signingCircuitClosesTotal,
  signingCircuitHalfOpenTotal,
  signingCircuitRejectedTotal,
  signingHealthState,
  signingConsecutiveFailures,
  signingFailuresTotal,
  // Auth-Failure Lockout — AUTH-2
  authLockoutFailuresTotal,
  authLockoutTriggeredTotal,
  authLockoutActiveGauge,
  authLockoutRecoveriesTotal,
  authLockoutBackoffAppliedTotal,
  authLockoutStorageFailuresTotal,
  // 2026-10-06
  providerFailuresTotal,
  rbacDenialsTotal,
  opsAuthFailuresTotal,
  mfaEventsTotal,
  auditMirrorCountDriftTotal,
  auditPgLagEntries,
  // Registry
  collect,
  getRegistrySnapshot,
  // classes exported so tests can construct genuinely fresh, isolated
  // instances (e.g. for empty-metric edge cases) without depending on
  // whether some OTHER test in the same file already observed a value into
  // one of the shared singleton instances above. Never used by collect()/
  // format()/the /metrics route, which only ever touch the singletons.
  Counter,
  Gauge,
  Histogram,
  REASON_SECURITY_EVENT,
};
