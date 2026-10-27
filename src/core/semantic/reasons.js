'use strict';

/**
 * Standardized semantic-intent reason taxonomy.
 *
 * Classifiers reference these constants rather than inventing ad-hoc
 * strings, so every consumer (evidence, audit, policy, dashboards) can rely
 * on a stable, documented vocabulary. Adding a new reason is a one-line
 * addition here plus a classifier that uses it — no other module needs to
 * change (see registry/classifierRegistry.js).
 *
 * remediation: every code below is now either emitted by
 * exactly one registered classifier/gate, or documented as a deliberate
 * non-emitting taxonomy entry with its own justification comment. Five
 * codes that were declared here with zero backing classifier anywhere in
 * the codebase (ROLE_ESCALATION_ATTEMPT, SECRET_EXTRACTION,
 * CHAIN_OF_THOUGHT_REQUEST, MODEL_MANIPULATION, PROVIDER_ESCAPE_ATTEMPT)
 * were removed as obsolete taxonomy debt — confirmed via a full-repo
 * search that no test, fixture, schema, or persisted-data reference
 * depended on the removed constants (git history confirms no classifier
 * for any of them ever existed and was later deleted — these were never
 * live), and via docs/architecture/content-screening.md's own §14 "Detection
 * Gaps"/§4 gap list, which already documented all five as deliberate,
 * tracked gaps rather than reserved/intentional taxonomy. See
 *'s entry for the full
 * per-code disposition and evidence trail.
 */
const SEMANTIC_REASONS = Object.freeze({
  SECURITY_OVERRIDE_ATTEMPT: 'SECURITY_OVERRIDE_ATTEMPT',
  PROMPT_INJECTION_ATTEMPT:  'PROMPT_INJECTION_ATTEMPT',
  SYSTEM_PROMPT_EXTRACTION:  'SYSTEM_PROMPT_EXTRACTION',
  POLICY_BYPASS_ATTEMPT:     'POLICY_BYPASS_ATTEMPT',
  JAILBREAK_ATTEMPT:         'JAILBREAK_ATTEMPT',
  TOOL_ABUSE_ATTEMPT:        'TOOL_ABUSE_ATTEMPT',
  // previously permanently mislabeled — toolAbuse.js had a
  // purpose-built signal (`unauthorized_tool_phrase`) for exactly this
  // scenario, but defineClassifier()'s one-reason-per-classifier-file
  // contract meant the whole file could only ever report
  // TOOL_ABUSE_ATTEMPT. Fixed by splitting the three "lacks authorization/
  // outside scope" signals into their own classifier file
  // (unauthorizedToolRequest.js), which is now this code's real,
  // dedicated producer — see that file's header for the exact signal set.
  UNAUTHORIZED_TOOL_REQUEST: 'UNAUTHORIZED_TOOL_REQUEST',
  DATA_EXFILTRATION:         'DATA_EXFILTRATION',
  CREDENTIAL_EXTRACTION:     'CREDENTIAL_EXTRACTION',
  PII_EXTRACTION:            'PII_EXTRACTION',
  MEMORY_EXTRACTION:         'MEMORY_EXTRACTION',
  FILE_SYSTEM_ENUMERATION:   'FILE_SYSTEM_ENUMERATION',
  IMPERSONATION_ATTEMPT:     'IMPERSONATION_ATTEMPT',
  // SEM-C session 3: the embedding-similarity gate's own DENY reason — see
  // embeddingGate.js. Deliberately distinct from the keyword classifiers'
  // reasons above so audit consumers can tell which layer caught a request.
  EMBEDDING_SIMILARITY_MATCH: 'EMBEDDING_SIMILARITY_MATCH',
});

const SEVERITY = Object.freeze({
  LOW:      'LOW',
  MEDIUM:   'MEDIUM',
  HIGH:     'HIGH',
  CRITICAL: 'CRITICAL',
});

const DECISION = Object.freeze({
  ALLOW:  'ALLOW',
  WARN:   'WARN',
  REVIEW: 'REVIEW',
  DENY:   'DENY',
});

/**
 * Semantic Policy Engine operational health.
 *
 * Distinct from DECISION above: DECISION classifies a *prompt* once
 * inspection has completed; ENGINE_STATUS classifies whether inspection
 * completed at all.
 *
 *   READY       — every classifier that ran, ran successfully.
 *   DEGRADED    — at least one classifier failed/timed out/returned invalid
 *                 output, but enough classifiers still succeeded to produce
 *                 a trustworthy decision (see index.js's minimum-inspection
 *                 invariant: at least one success).
 *   FAILED      — inspection was attempted but could not produce a
 *                 trustworthy decision (every classifier failed, or
 *                 aggregation/confidence/evidence computation itself threw).
 *   UNAVAILABLE — inspection could not even be attempted (the classifier
 *                 registry could not be loaded, or is empty).
 *
 * FAILED and UNAVAILABLE both fail closed identically; the distinction is
 * for audit/observability, not for behavior.
 */
const ENGINE_STATUS = Object.freeze({
  READY:       'READY',
  DEGRADED:    'DEGRADED',
  FAILED:      'FAILED',
  UNAVAILABLE: 'UNAVAILABLE',
});

/**
 * Root-cause categories for a semantic-engine fail-closed denial.
 *
 * Distinct from SEMANTIC_REASONS, which classifies *detected attack intent*
 * once inspection succeeds — these classify *why inspection itself could
 * not be completed*. Recorded in evidence.failureReason for audit and
 * observability; never exposed to the client in place of the deterministic
 * SEMANTIC_ENGINE_UNAVAILABLE_REASON below.
 */
const ENGINE_FAILURE_REASONS = Object.freeze({
  POLICY_LOAD_FAILED:         'POLICY_LOAD_FAILED',
  REGISTRY_LOAD_FAILED:       'REGISTRY_LOAD_FAILED',
  EMPTY_CLASSIFIER_REGISTRY:  'EMPTY_CLASSIFIER_REGISTRY',
  NORMALIZATION_FAILED:       'NORMALIZATION_FAILED',
  ALL_CLASSIFIERS_FAILED:     'ALL_CLASSIFIERS_FAILED',
  AGGREGATION_FAILED:         'AGGREGATION_FAILED',
  POLICY_RESOLUTION_FAILED:   'POLICY_RESOLUTION_FAILED',
  EVIDENCE_GENERATION_FAILED: 'EVIDENCE_GENERATION_FAILED',
  INTERNAL_ENGINE_ERROR:      'INTERNAL_ENGINE_ERROR',
});

// Deterministic, client/audit-facing denial reason for every fail-closed
// path above. Callers must always be able to tell "inspection did not
// complete" apart from "inspection completed, no attack found" (ALLOW) —
// they do not need a different top-level reason string per infra failure
// mode to do that; the granular category above is preserved in evidence.
const SEMANTIC_ENGINE_UNAVAILABLE_REASON = 'SEMANTIC_INSPECTION_UNAVAILABLE';

module.exports = {
  SEMANTIC_REASONS,
  SEVERITY,
  DECISION,
  ENGINE_STATUS,
  ENGINE_FAILURE_REASONS,
  SEMANTIC_ENGINE_UNAVAILABLE_REASON,
};
