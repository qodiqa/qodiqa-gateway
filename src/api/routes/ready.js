'use strict';

const express          = require('express');
const readinessState   = require('../../runtime/readinessState');
const readinessTracker = require('../../runtime/readinessTracker');
const nonceStore       = require('../../validation/nonceStore');
const anomalyStore     = require('../../validation/anomalyStore');
const rateLimitStore   = require('../../../services/policy/store');
const pgPool           = require('../../infra/postgres/pool');
const consentSubscriber = require('../../core/consent/revocation/RevocationSubscriber');
const consentCache      = require('../../core/consent/ConsentCache');
const router            = express.Router();

// dependency classification — every runtime dependency touched by the
// enforcement/consent hot path, and why it does or doesn't gate readiness:
//   • nonceStore, anomalyStore, rateLimitStore — REQUIRED. Hot-path replay
//     protection, burst detection, and policy rate limiting; unavailability
//     means requests cannot be safely evaluated.
//   • persistenceStore (PostgreSQL)  — REQUIRED, conditionally (only when
//     this deployment enables QODIQA_PG_ENABLED). See pgPool.isHealthy().
//   • consentSubscriber (RevocationSubscriber) — REQUIRED, unconditionally.
//     A node that cannot receive revocation events cannot guarantee consent
//     withdrawal is enforced (see RevocationSubscriber.js header).
//   • consentCache (ConsentCache/Redis) — OPTIONAL / best-effort, and
//     DELIBERATELY EXCLUDED from gating. By design (see ConsentCache.js
//     header + ConsentVerifier.js step 1-2), a cache miss or a fully
//     unavailable cache transparently falls through to the PostgreSQL
//     lookup — there is no fail-open path, correctness is unaffected. Gating
//     readiness on it would pull healthy pods out of rotation on a transient
//     Redis cache blip while every request would still be served correctly
//     (just at cache-miss latency), which is worse for availability than the
//     blip itself. Still surfaced below for operational visibility — a
//     prolonged outage manifests as elevated PostgreSQL load, which
//     operators should be able to see coming.
const REQUIRED_COMPONENTS = [
  'nonceStore', 'anomalyStore', 'rateLimitStore', 'persistenceStore', 'consentSubscriber',
  // not saturated — false while an admission queue is full, so a load balancer stops routing new
  // traffic to this instance (its clients get fast 503 SERVER_OVERLOADED either way).
  'admission',
  // 2026-10-06: false while the audit mirror backlog is above its bound (audit-log.js
  // mirrorBackpressureEngaged) — admission refuses new work with cause audit_backlog until it drains to half.
  'auditBacklog',
  // false while mandatory audit appends are failing (AUDIT_PERSISTENCE_FAILED,
  // e.g. a full audit volume) — every /ai/chat request would fail closed with 503 anyway, so the instance must leave
  // rotation. Latched on QODIQA_READY_AUDIT_FAILURE_THRESHOLD (default 3) CONSECUTIVE failures, cleared by the next
  // successful append or by a passing audit-directory writability probe; a single transient failure never flips it.
  // Full rule: src/api/auditPersistenceHealth.js.
  'auditPersistence',
  // (D-F5-1): false once the transparency evidence store (recovery queue AND file journal) has been unavailable longer than
  // QODIQA_TRANSPARENCY_JOURNAL_MAX_UNAVAILABLE_MS (default 60 s): new EXECUTE decisions are refused, so the instance leaves rotation.
  'transparencyJournal',
];

function _auditBacklogClear() {
  try { return require('../../core/audit/audit-log').mirrorBackpressureEngaged() !== true; } catch { return true; }
}

function _transparencyJournalAvailable() {
  try { return require('../../core/transparency/journalHealth').isRefusing() !== true; } catch { return true; }
}

function _auditPersistenceHealthy() {
  try { return require('../auditPersistenceHealth').isHealthy() === true; } catch { return false; }
}

router.get('/', (_req, res) => {
  const components = {
    nonceStore:     nonceStore.isReady(),
    anomalyStore:   anomalyStore.isReady(),
    rateLimitStore: rateLimitStore.isReady(),
    // PostgreSQL connectivity (READY-50). A generic name is used deliberately
    // — /ready and /health never disclose backing infrastructure identity
    // (see src/middleware/__tests__/healthContentSafety.test.js). Only a
    // mandatory dependency when this deployment actually uses PostgreSQL
    // (QODIQA_PG_ENABLED=true); reads a value refreshed by a bounded
    // background probe (src/infra/postgres/pool.js) rather than querying
    // inline, so GET /ready never issues a query itself.
    persistenceStore: !pgPool.isEnabled() || pgPool.isHealthy(),
    // Consent revocation subscriber (READY-50). Always a mandatory,
    // unconditional dependency — see RevocationSubscriber.js's header: a
    // node that cannot receive revocation events cannot guarantee consent
    // withdrawal is enforced. isReady() is maintained reactively by the
    // subscriber's own Redis client event handlers — also zero I/O here.
    consentSubscriber: consentSubscriber.isReady(),
    // Consent cache — informational only, NOT in REQUIRED_COMPONENTS.
    // See the classification comment above the router for why this is safe.
    consentCache: consentCache.isReady(),
    admission: !require('../admission').anySaturated(),
    auditBacklog: _auditBacklogClear(),
    auditPersistence: _auditPersistenceHealthy(),
    transparencyJournal: _transparencyJournalAvailable(),
  };

  // Readiness must reflect CURRENT ability to serve, not just a one-time
  // startup flag (see docs/deployment/kubernetes-probes.md — "sending traffic to a pod
  // with no Redis connection would block all requests anyway, so early
  // removal is safe"). readinessState.isReady() alone only tracks the
  // startup/shutdown lifecycle; a dependency that disconnects mid-run must
  // also pull this endpoint back to 503, or a load balancer never learns the
  // pod stopped being able to safely serve enforcement traffic.
  //
  // Gating is computed only over REQUIRED_COMPONENTS — an optional/
  // best-effort dependency (consentCache) reporting unhealthy must never by
  // itself flip `ready` to false.
  const componentsReady = REQUIRED_COMPONENTS.every((name) => components[name] === true);
  const ready = readinessState.isReady() && componentsReady;

  // Transition-only metrics/logging (READY-50) — no-op on repeated,
  // unchanged probe results; see src/runtime/readinessTracker.js.
  for (const [component, healthy] of Object.entries(components)) {
    readinessTracker.recordComponent(component, healthy);
  }
  readinessTracker.recordOverall(ready);

  if (!ready) {
    return res.status(503).json({ ready: false, components });
  }
  res.status(200).json({ ready: true, components });
});

module.exports = router;
