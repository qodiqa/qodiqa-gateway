'use strict';

/**
 * PolicyGovernanceService — orchestrates the maker-checker policy change
 * lifecycle:
 *
 *   DRAFT -> SUBMITTED -> [IN_REVIEW -> REVIEWED] -> APPROVED -> [SCHEDULED] -> PUBLISHED
 *                                                                            -> REJECTED / WITHDRAWN (terminal)
 *
 * Every stage function: (1) loads the request, (2) validates the
 * transition via ChangeRequestStateModel, (3) runs the relevant
 * makerCheckerRules assertion(s) — fail-closed, server-side, comparing
 * individual actor identity never role — then (4) writes the status hop +
 * its evidence row(s) inside ONE transaction (ChangeRequestStore.
 * updateStatusInTx + governanceEvents, both given the same `tx`), so a
 * workflow transition and its evidence are never partially committed.
 *
 * Only publish() touches the existing, untouched file-based enforcement
 * store (src/core/policy/store.js) — every other stage is pure workflow
 * state in Postgres with zero effect on the live policy set. If the
 * store.js write or the subsequent _reloadPolicies() (called by the
 * router, not here) fails, the change request has already moved to
 * PUBLISHED — this mirrors the exact same caveat the legacy
 * policyManagement.js endpoints have always had (a file write cannot be
 * transactionally rolled back together with a Postgres commit); it is not
 * a new limitation introduced by this remediation, and is documented in
 * docs/guides/policy-governance.md.
 */

const pool               = require('../../../infra/postgres/pool');
const ChangeRequestStore = require('./ChangeRequestStore');
const governanceEvents   = require('./governanceEvents');
const stateModel         = require('./ChangeRequestStateModel');
const rules              = require('./makerCheckerRules');
const policyStore        = require('../store');
const { recordPolicyProvenance } = require('./provenanceBridge');
const { ROLES }          = require('../../rbac/roles');
const rbacStore          = require('../../rbac/store');
//a change request
// carrying a tenantId targets that tenant's PG-persisted configuration
// instead of the global file store — same lifecycle, same maker-checker
// rules, same hash-chained events (which have always recorded tenant_id).
const tenantConfigStore      = require('../../tenancy/tenantConfigStore');
const tenantPolicyRegistry   = require('../../tenancy/tenantPolicyRegistry');
const tenantSemanticRegistry = require('../../tenancy/tenantSemanticRegistry');
// (residual): the policy-layer counterpart of the
// tighten-only invariant — a tenant set may never disable, retype, or
// loosen a floor policy (REQUIRE_CONSENT + every enabled global policy).
const tenantPolicyFloor      = require('../../tenancy/tenantPolicyFloor');

// Reserved policyId addressing the tenant's SEMANTIC config (a singleton per
// tenant — requestType UPDATE with upsert semantics). Collides with no real
// policy: draft() rejects it without a tenantId.
const TENANT_SEMANTIC_CONFIG_ID = 'TENANT-SEMANTIC-CONFIG';

const STRICT_MODE = process.env.POLICY_GOVERNANCE_STRICT_MODE !== 'false';

// a reviewer/approver/publisher the author provisioned (created, or keyed) is not an independent second person.
//
const _assertIndependentOfAuthor = require('./independence').assertIndependentOfAuthor;

function isStrictMode() {
  return STRICT_MODE;
}

class InvalidTransitionError extends Error {
  constructor(from, to) {
    super(`Invalid policy change-request transition: ${from} -> ${to}`);
    this.name = 'InvalidTransitionError';
    this.code = 'INVALID_TRANSITION';
  }
}

function _assertTransition(from, to) {
  if (!stateModel.isValidTransition(from, to, isStrictMode())) {
    throw new InvalidTransitionError(from, to);
  }
}

function _notFound(id) {
  const err = new Error(`Change request not found: ${id}`);
  err.code  = 'NOT_FOUND';
  return err;
}

/**
 * workflow rows for a TENANT-scoped change request (and their
 * hash-chained approval_events / reviews / approvals / publications) carry
 * the tenant_id and sit behind migration 029's RLS — every stage
 * transaction must therefore run under the request's own tenant context.
 * Platform-scoped requests (tenant_id NULL) keep the plain transaction,
 * byte-for-byte the earlier path.
 */
function _txForRequest(request) {
  return request && request.tenant_id
    ? (fn) => pool.withTenantTransaction(request.tenant_id, fn)
    : (fn) => pool.withTransaction(fn);
}

/**
 * Validate a CREATE/UPDATE payload against the same rules
 * store.js.createPolicy()/updatePolicy() would apply at publish time, so
 * malformed drafts are rejected immediately (matching the pre-COMP-12
 * behavior of the legacy endpoints) rather than sailing through review and
 * approval only to fail at the very last step.
 */
function _validateDraftPayload(policyId, requestType, payload) {
  if (requestType !== 'CREATE' && requestType !== 'UPDATE') return;

  let candidate;
  let currentId = null;
  if (requestType === 'CREATE') {
    // validatePolicyCandidate() itself does not check for an existing id
    // (store.js's own createPolicy() does that separately) — checked here
    // too so a duplicate id is rejected at draft time, not only after
    // review/approval have already been spent on it.
    if (policyStore.getPolicy(policyId)) {
      const err = new Error(`POLICY_ALREADY_EXISTS: policy "${policyId}" already exists`);
      err.code  = 'POLICY_ALREADY_EXISTS';
      throw err;
    }
    candidate = { id: policyId, type: payload.type, priority: payload.priority, enabled: true, config: payload.config };
  } else {
    const current = policyStore.getPolicy(policyId);
    if (!current) {
      const err = new Error(`Policy not found: ${policyId}`);
      err.code  = 'NOT_FOUND';
      throw err;
    }
    currentId = policyId;
    candidate = {
      id: policyId, type: current.type, enabled: current.enabled,
      priority: 'priority' in payload ? payload.priority : current.priority,
      config:   'config'   in payload ? payload.config   : current.config,
    };
  }

  const result = policyStore.validatePolicyCandidate(candidate, currentId);
  if (!result.valid) {
    const err = new Error(`VALIDATION_FAILED: ${result.errors.join('; ')}`);
    err.code  = 'VALIDATION_FAILED';
    throw err;
  }
}

/**
 * ENABLE/DISABLE/ARCHIVE requests target an existing policy — checked here
 * so a request for a nonexistent policy id is rejected at draft time, not
 * only after it has already been reviewed and approved. (CREATE is exactly
 * for new ids, handled by _validateDraftPayload above; ROLLBACK goes
 * through RollbackGovernanceService, which checks existence itself.)
 */
function _assertPolicyExists(policyId, requestType) {
  if (!['ENABLE', 'DISABLE', 'ARCHIVE'].includes(requestType)) return;
  if (!policyStore.getPolicy(policyId)) {
    const err = new Error(`NOT_FOUND: policy "${policyId}" not found`);
    err.code  = 'NOT_FOUND';
    throw err;
  }
}

/**
 * throws VALIDATION_FAILED, naming the floor policy, when `entry`
 * (the resulting tenant-policy object a draft/publish step would produce)
 * would disable, retype, or loosen a floor policy. A no-op for any id that
 * isn't a floor id, and for a floor id simply absent from `entry`'s array —
 * omission is closed by tenantPolicyRegistry.getEffectivePoliciesForTenant()
 * at evaluation time, not rejected here.
 */
function _assertFloorCompliant(entry) {
  const check = tenantPolicyFloor.checkEntryAgainstFloor(entry);
  if (!check.ok) {
    const err = new Error(`VALIDATION_FAILED: ${check.reason}`);
    err.code  = 'VALIDATION_FAILED';
    throw err;
  }
}

/**
 * Draft-time validation for TENANT-targeted requests — the
 * write-time half of the tighten-only enforcement, plus the same
 * reject-at-draft discipline _validateDraftPayload applies globally.
 */
async function _validateTenantDraft(tenantId, policyId, requestType, payload) {
  if (policyId === TENANT_SEMANTIC_CONFIG_ID) {
    if (requestType !== 'UPDATE') {
      const err = new Error(`VALIDATION_FAILED: ${TENANT_SEMANTIC_CONFIG_ID} requests must be requestType UPDATE (singleton upsert)`);
      err.code  = 'VALIDATION_FAILED';
      throw err;
    }
    // NON-NEGOTIABLE INVARIANT — write-time rejection: a config that
    // would loosen any pinned default (or express a non-representable knob:
    // REVIEW_BLOCKS, classifier disabling, FT flags, gate selection) never
    // enters the workflow at all.
    const check = tenantSemanticRegistry.validateTightenOnly(payload);
    if (!check.ok) {
      const err = new Error(`TENANT_SEMANTIC_TIGHTEN_ONLY_VIOLATION: ${check.errors.join('; ')}`);
      err.code  = 'VALIDATION_FAILED';
      throw err;
    }
    return;
  }

  // Tenant policy set: same candidate shape rules as the global store,
  // existence checked against the TENANT's current set (PG authority).
  const currentSet = await tenantConfigStore.getPolicySet(tenantId);
  const policies = currentSet ? currentSet.policies : [];
  const existing = policies.find((p) => p && p.id === policyId) || null;

  if (requestType === 'CREATE') {
    if (existing) {
      const err = new Error(`POLICY_ALREADY_EXISTS: policy "${policyId}" already exists in tenant "${tenantId}"'s set`);
      err.code  = 'POLICY_ALREADY_EXISTS';
      throw err;
    }
    const candidate = { id: policyId, type: payload.type, priority: payload.priority, enabled: true, config: payload.config };
    const result = policyStore.validatePolicyCandidate(candidate, null);
    if (!result.valid) {
      const err = new Error(`VALIDATION_FAILED: ${result.errors.join('; ')}`);
      err.code  = 'VALIDATION_FAILED';
      throw err;
    }
    // a CREATE sharing a floor policy's id must be at least as strict
    // as the floor (tightening is fine — the tenant is taking over that
    // slot with a stricter definition).
    _assertFloorCompliant(candidate);
    return;
  }

  if (!existing) {
    const err = new Error(`NOT_FOUND: policy "${policyId}" not found in tenant "${tenantId}"'s set`);
    err.code  = 'NOT_FOUND';
    throw err;
  }
  if (requestType === 'UPDATE') {
    const candidate = {
      id: policyId, type: existing.type, enabled: existing.enabled,
      priority: 'priority' in payload ? payload.priority : existing.priority,
      config:   'config'   in payload ? payload.config   : existing.config,
    };
    // Same currentId convention as the global UPDATE path above — the shape
    // rules are shared; existence was checked against the TENANT set.
    const result = policyStore.validatePolicyCandidate(candidate, policyId);
    if (!result.valid) {
      const err = new Error(`VALIDATION_FAILED: ${result.errors.join('; ')}`);
      err.code  = 'VALIDATION_FAILED';
      throw err;
    }
    // an UPDATE must not loosen a floor policy's config.
    _assertFloorCompliant(candidate);
    return;
  }
  // ENABLE only tightens (disabled -> enabled) and is always floor-
  // compliant if the entry already is; DISABLE/ARCHIVE would take a floor
  // policy to disabled — reject naming it.
  _assertFloorCompliant({ ...existing, enabled: requestType === 'ENABLE' });
}

/**
 * Create a new DRAFT change request. Never auto-submits — callers (or the
 * legacy /policy-ui compatibility wrapper) call submit() explicitly.
 */
async function draft({ policyId, tenantId = null, requestType, payload, changeReason, actor }) {
  if (!policyId || !requestType || !changeReason) {
    throw new Error('policyId, requestType, and changeReason are required');
  }
  if (tenantId) {
    // Tenant-targeted request: validated against the TENANT's
    // stores — the global checks below would be wrong for it (e.g. CREATE of
    // a tenant policy that shadows a global id is legal).
    await _validateTenantDraft(tenantId, policyId, requestType, payload || {});
  } else {
    if (policyId === TENANT_SEMANTIC_CONFIG_ID) {
      const err = new Error(`VALIDATION_FAILED: "${TENANT_SEMANTIC_CONFIG_ID}" is reserved for tenant-targeted requests (tenantId required)`);
      err.code  = 'VALIDATION_FAILED';
      throw err;
    }
    _validateDraftPayload(policyId, requestType, payload || {});
    _assertPolicyExists(policyId, requestType);
  }
  // F13-GOV-01: hash and store the payload in its JSON form. The HTTP routes build payloads with optional members left undefined (name, description);
  // the database drops them, so a hash taken over the object with undefined members never matched the stored payload at publish time (audit 4.3 check)
  // and a policy created without a name could not be published.
  const storedPayload = payload === undefined ? payload : JSON.parse(JSON.stringify(payload));
  const payloadHash = governanceEvents.hashPayload(storedPayload);

  const request = await ChangeRequestStore.create({
    policy_id: policyId, tenant_id: tenantId, request_type: requestType,
    payload: storedPayload, payload_hash: payloadHash, change_reason: changeReason, author: actor,
  });

  await _txForRequest({ tenant_id: tenantId })((tx) => governanceEvents.recordEvent(tx, {
    changeRequestId: request.id, policyId, tenantId, eventType: 'DRAFT_CREATED',
    previousStatus: null, newStatus: stateModel.STATE.DRAFT, actor, reason: changeReason,
    detail: { requestType },
  }));

  return request;
}

/** DRAFT -> SUBMITTED. Only the author may submit their own draft. */
async function submit({ requestId, actor }) {
  const request = await ChangeRequestStore.findById(requestId);
  if (!request) throw _notFound(requestId);
  _assertTransition(request.status, stateModel.STATE.SUBMITTED);
  if (request.author_id !== actor.id) {
    throw new Error('Only the author may submit their own draft');
  }

  return _txForRequest(request)(async (tx) => {
    const updated = await ChangeRequestStore.updateStatusInTx(tx, {
      id: requestId, expectedVersion: request.version, status: stateModel.STATE.SUBMITTED,
      patch: { submitted_by: actor.id, submitted_at: new Date() },
    });
    await governanceEvents.recordEvent(tx, {
      changeRequestId: requestId, policyId: request.policy_id, tenantId: request.tenant_id,
      eventType: 'SUBMITTED', previousStatus: request.status, newStatus: stateModel.STATE.SUBMITTED, actor,
    });
    return updated;
  });
}

/**
 * SUBMITTED -> IN_REVIEW ("claim" for review — a distinct actor from the
 * author, checked here since nothing binding has been decided yet).
 */
async function startReview({ requestId, actor }) {
  const request = await ChangeRequestStore.findById(requestId);
  if (!request) throw _notFound(requestId);
  _assertTransition(request.status, stateModel.STATE.IN_REVIEW);
  rules.assertReviewerNotAuthor(request.author_id, actor.id);
  _assertIndependentOfAuthor(request, actor, 'REVIEWER');

  return _txForRequest(request)(async (tx) => {
    const updated = await ChangeRequestStore.updateStatusInTx(tx, {
      id: requestId, expectedVersion: request.version, status: stateModel.STATE.IN_REVIEW,
      patch: { reviewer_id: actor.id, reviewer_username: actor.username },
    });
    await governanceEvents.recordEvent(tx, {
      changeRequestId: requestId, policyId: request.policy_id, tenantId: request.tenant_id,
      eventType: 'REVIEW_STARTED', previousStatus: request.status, newStatus: stateModel.STATE.IN_REVIEW, actor,
    });
    return updated;
  });
}

/**
 * IN_REVIEW -> REVIEWED (decision=APPROVED) or -> DRAFT
 * (decision=CHANGES_REQUESTED, sends the proposal back for rework).
 * The decider must be the actor who claimed the review via startReview(),
 * and must not be the author.
 */
async function review({ requestId, actor, decision, notes = null }) {
  if (decision !== 'APPROVED' && decision !== 'CHANGES_REQUESTED') {
    throw new Error("decision must be 'APPROVED' or 'CHANGES_REQUESTED'");
  }
  const request = await ChangeRequestStore.findById(requestId);
  if (!request) throw _notFound(requestId);
  rules.assertReviewerNotAuthor(request.author_id, actor.id);
  if (request.reviewer_id && request.reviewer_id !== actor.id) {
    throw new Error('This request is claimed by a different reviewer');
  }

  const nextStatus = decision === 'APPROVED' ? stateModel.STATE.REVIEWED : stateModel.STATE.DRAFT;
  _assertTransition(request.status, nextStatus);

  return _txForRequest(request)(async (tx) => {
    const updated = await ChangeRequestStore.updateStatusInTx(tx, {
      id: requestId, expectedVersion: request.version, status: nextStatus,
      patch: {
        reviewer_id: actor.id, reviewer_username: actor.username,
        reviewed_at: new Date(), review_decision: decision,
      },
    });
    await governanceEvents.recordEvent(tx, {
      changeRequestId: requestId, policyId: request.policy_id, tenantId: request.tenant_id,
      eventType: decision === 'APPROVED' ? 'REVIEWED' : 'CHANGES_REQUESTED',
      previousStatus: request.status, newStatus: nextStatus, actor, reason: notes,
    });
    await governanceEvents.recordReview(tx, {
      changeRequestId: requestId, tenantId: request.tenant_id, reviewer: actor, decision, notes,
    });
    return updated;
  });
}

/**
 * REVIEWED -> APPROVED (strict mode); SUBMITTED -> APPROVED (relaxed mode,
 * merging reviewer into approver). Approver must not be the author, and
 * (strict mode only) must not be the reviewer.
 */
async function approve({ requestId, actor, notes = null }) {
  const request = await ChangeRequestStore.findById(requestId);
  if (!request) throw _notFound(requestId);
  _assertTransition(request.status, stateModel.STATE.APPROVED);
  rules.assertApproverNotAuthor(request.author_id, actor.id);
  rules.assertApproverNotReviewer(request.reviewer_id, actor.id, { strict: isStrictMode() });
  _assertIndependentOfAuthor(request, actor, 'APPROVER');

  return _txForRequest(request)(async (tx) => {
    const updated = await ChangeRequestStore.updateStatusInTx(tx, {
      id: requestId, expectedVersion: request.version, status: stateModel.STATE.APPROVED,
      patch: { approver_id: actor.id, approver_username: actor.username, approved_at: new Date() },
    });
    await governanceEvents.recordEvent(tx, {
      changeRequestId: requestId, policyId: request.policy_id, tenantId: request.tenant_id,
      eventType: 'APPROVED', previousStatus: request.status, newStatus: stateModel.STATE.APPROVED, actor, reason: notes,
    });
    await governanceEvents.recordApproval(tx, {
      changeRequestId: requestId, tenantId: request.tenant_id, approver: actor, decision: 'APPROVED', notes,
    });
    return updated;
  });
}

/** REVIEWED (or SUBMITTED in relaxed mode) -> REJECTED. Terminal. */
async function reject({ requestId, actor, reason }) {
  if (!reason) throw new Error('reason is required to reject a change request');
  const request = await ChangeRequestStore.findById(requestId);
  if (!request) throw _notFound(requestId);
  _assertTransition(request.status, stateModel.STATE.REJECTED);

  return _txForRequest(request)(async (tx) => {
    const updated = await ChangeRequestStore.updateStatusInTx(tx, {
      id: requestId, expectedVersion: request.version, status: stateModel.STATE.REJECTED,
      patch: { rejected_by: actor.id, rejected_at: new Date(), rejection_reason: reason },
    });
    await governanceEvents.recordEvent(tx, {
      changeRequestId: requestId, policyId: request.policy_id, tenantId: request.tenant_id,
      eventType: 'REJECTED', previousStatus: request.status, newStatus: stateModel.STATE.REJECTED, actor, reason,
    });
    await governanceEvents.recordApproval(tx, {
      changeRequestId: requestId, tenantId: request.tenant_id, approver: actor, decision: 'REJECTED', notes: reason,
    });
    return updated;
  });
}

/**
 * APPROVED -> SCHEDULED. publish() refuses to run before scheduledFor —
 * there is no background auto-fire (no scheduler/cron exists anywhere else
 * in this codebase either; retention.js's cycle is likewise only ever
 * admin-triggered). This is an explicit, documented scope limit.
 */
async function schedule({ requestId, actor, scheduledFor }) {
  const scheduledDate = new Date(scheduledFor);
  if (!scheduledFor || isNaN(scheduledDate.getTime()) || scheduledDate <= new Date()) {
    throw new Error('scheduledFor must be a valid future timestamp');
  }
  const request = await ChangeRequestStore.findById(requestId);
  if (!request) throw _notFound(requestId);
  _assertTransition(request.status, stateModel.STATE.SCHEDULED);

  return _txForRequest(request)(async (tx) => {
    const updated = await ChangeRequestStore.updateStatusInTx(tx, {
      id: requestId, expectedVersion: request.version, status: stateModel.STATE.SCHEDULED,
      patch: { scheduled_for: scheduledDate },
    });
    await governanceEvents.recordEvent(tx, {
      changeRequestId: requestId, policyId: request.policy_id, tenantId: request.tenant_id,
      eventType: 'SCHEDULED', previousStatus: request.status, newStatus: stateModel.STATE.SCHEDULED, actor,
      detail: { scheduledFor: scheduledDate.toISOString() },
    });
    return updated;
  });
}

/**
 * Applies a tenant-targeted publish to the PG stores and the
 * in-memory registries. Returns a summary object standing in for the global
 * path's `policy` return value.
 */
async function _applyTenantPublish(request, actor) {
  const tenantId = request.tenant_id;
  const payload  = request.payload || {};

  if (request.policy_id === TENANT_SEMANTIC_CONFIG_ID) {
    // defense in depth: the tighten-only invariant was enforced at
    // draft time; re-check at publish so a row edited between draft and
    // publish (or an older client) still cannot loosen anything.
    const check = tenantSemanticRegistry.validateTightenOnly(payload);
    if (!check.ok) {
      const err = new Error(`TENANT_SEMANTIC_TIGHTEN_ONLY_VIOLATION: ${check.errors.join('; ')}`);
      err.code  = 'VALIDATION_FAILED';
      throw err;
    }
    const saved = await tenantConfigStore.upsertSemanticConfig({
      tenantId, config: payload, changeRequestId: request.id, updatedBy: actor.username,
    });
    // Publishing instance's cache updates synchronously; other replicas
    // converge via tenantConfigHydrator's periodic refresh (ADR §5).
    tenantSemanticRegistry.setConfig(tenantId, payload, { version: saved.version });
    return { target: 'TENANT_SEMANTIC_CONFIG', tenantId, id: request.policy_id, version: saved.version, configHash: saved.hash };
  }

  const currentSet = await tenantConfigStore.getPolicySet(tenantId);
  const policies = currentSet ? currentSet.policies.map((p) => ({ ...p })) : [];
  const idx = policies.findIndex((p) => p && p.id === request.policy_id);

  switch (request.request_type) {
    case 'CREATE': {
      if (idx !== -1) {
        const err = new Error(`POLICY_ALREADY_EXISTS: policy "${request.policy_id}" already exists in tenant "${tenantId}"'s set`);
        err.code  = 'POLICY_ALREADY_EXISTS';
        throw err;
      }
      policies.push({
        id: request.policy_id,
        type: payload.type,
        ...(payload.name !== undefined ? { name: payload.name } : {}),
        ...(payload.description !== undefined ? { description: payload.description } : {}),
        ...(payload.priority !== undefined ? { priority: payload.priority } : {}),
        enabled: true,
        config: payload.config,
      });
      break;
    }
    case 'UPDATE': {
      if (idx === -1) throw Object.assign(new Error(`Policy not found in tenant set: ${request.policy_id}`), { code: 'NOT_FOUND' });
      policies[idx] = {
        ...policies[idx],
        ...(payload.name !== undefined ? { name: payload.name } : {}),
        ...(payload.description !== undefined ? { description: payload.description } : {}),
        ...(payload.priority !== undefined ? { priority: payload.priority } : {}),
        ...(payload.config   !== undefined ? { config: payload.config }     : {}),
      };
      break;
    }
    case 'ENABLE':
    case 'DISABLE':
    case 'ARCHIVE': {
      if (idx === -1) throw Object.assign(new Error(`Policy not found in tenant set: ${request.policy_id}`), { code: 'NOT_FOUND' });
      policies[idx] = { ...policies[idx], enabled: request.request_type === 'ENABLE' };
      break;
    }
    default:
      throw new Error(`publish() does not support request_type ${request.request_type} for tenant-targeted requests`);
  }

  // defense in depth: re-check the entry this publish actually produced
  // — mirrors the semantic-config re-check above, in case a floor-violating
  // payload somehow reached APPROVED (an older client, a row edited between
  // draft and publish). Nothing is stored on rejection.
  const changedEntry = policies.find((p) => p && p.id === request.policy_id);
  if (changedEntry) _assertFloorCompliant(changedEntry);

  const saved = await tenantConfigStore.upsertPolicySet({
    tenantId, policies, changeRequestId: request.id, updatedBy: actor.username,
  });
  // PostgreSQL keeps the RAW candidate config (JSON-safe, human-
  // diffable) — the in-memory registry gets each entry preprocessed the
  // same way the global loader preprocesses every GLOBAL policy at load
  // time, so tenantPolicyRegistry.getPoliciesForTenant() (the raw getter)
  // is evaluator-ready by construction and no longer depends on a future
  // reader going through getEffectivePoliciesForTenant()/mergeForEvaluation
  // to avoid the EVALUATOR_ERROR class found (see tenantPolicyFloor.js).
  tenantPolicyRegistry.setPolicies(tenantId, policies.map(tenantPolicyFloor.preprocessEntry));
  return { target: 'TENANT_POLICY_SET', tenantId, id: request.policy_id, version: saved.version, policiesHash: saved.hash, policyCount: policies.length };
}

/**
 * APPROVED or SCHEDULED -> PUBLISHED. The only function that mutates the
 * live enforcement store. Publisher must not be the author.
 *
 * @returns {Promise<{changeRequest: object, policy: object}>}
 */
async function publish({ requestId, actor }) {
  const request = await ChangeRequestStore.findById(requestId);
  if (!request) throw _notFound(requestId);
  _assertTransition(request.status, stateModel.STATE.PUBLISHED);
  rules.assertPublisherNotAuthor(request.author_id, actor.id);
  _assertIndependentOfAuthor(request, actor, 'PUBLISHER'); // audit 2026-10-20 (4.3): the same independence rule review/approve already applied

  // publish used to apply request.payload as stored, without proving it is still what was drafted/approved.
  // payload_hash is fixed at draft time (hashPayload); a payload edited in the database between approval and publish is refused.
  if (request.payload_hash && governanceEvents.hashPayload(request.payload) !== request.payload_hash) {
    const err = new Error(`Change request ${requestId}: stored payload no longer matches the approved payload_hash — refusing to publish`);
    err.code  = 'PAYLOAD_HASH_MISMATCH';
    throw err;
  }

  if (request.status === stateModel.STATE.SCHEDULED && request.scheduled_for
      && new Date() < new Date(request.scheduled_for)) {
    const err = new Error(`Cannot publish before the scheduled time (${request.scheduled_for})`);
    err.code  = 'NOT_YET_SCHEDULED';
    throw err;
  }

  const payload = request.payload || {};
  let policy;

  // ── tenant-targeted publish ─────────────────────────────────────
  // request.tenant_id steers the apply step to the tenant's PG-persisted
  // configuration (tenantConfigStore) and the in-memory registries — the
  // global file store is never touched. Workflow rows/events above and below
  // are identical to the global path (they always recorded tenant_id).
  // recordPolicyProvenance() is deliberately NOT called for tenant requests:
  // policy_provenance_versions tracks the GLOBAL store's version chain; the
  // tenant row's own version + the hash-chained approval_events are the
  // provenance record here.
  if (request.tenant_id) {
    policy = await _applyTenantPublish(request, actor);
    const resultingTenantVersion = policy.version;
    const updatedTenantRow = await _txForRequest(request)(async (tx) => {
      const row = await ChangeRequestStore.updateStatusInTx(tx, {
        id: requestId, expectedVersion: request.version, status: stateModel.STATE.PUBLISHED,
        patch: {
          publisher_id: actor.id, publisher_username: actor.username, published_at: new Date(),
          resulting_policy_version: resultingTenantVersion,
        },
      });
      await governanceEvents.recordEvent(tx, {
        changeRequestId: requestId, policyId: request.policy_id, tenantId: request.tenant_id,
        eventType: 'PUBLISHED', previousStatus: request.status, newStatus: stateModel.STATE.PUBLISHED, actor,
        detail: { resultingVersion: resultingTenantVersion, target: policy.target },
      });
      await governanceEvents.recordPublication(tx, {
        changeRequestId: requestId, tenantId: request.tenant_id, policyId: request.policy_id,
        publisher: actor, resultingVersion: resultingTenantVersion, policyHash: request.payload_hash,
      });
      return row;
    });
    return { changeRequest: updatedTenantRow, policy };
  }

  switch (request.request_type) {
    case 'CREATE':
      policy = await policyStore.createPolicy({ ...payload, actor: actor.username, comment: request.change_reason });
      break;
    case 'UPDATE':
      policy = await policyStore.updatePolicy(request.policy_id, payload, { actor: actor.username, comment: request.change_reason });
      break;
    case 'ENABLE':
      policy = await policyStore.setEnabled(request.policy_id, true, { actor: actor.username, comment: request.change_reason });
      break;
    case 'DISABLE':
    case 'ARCHIVE':
      policy = await policyStore.setEnabled(request.policy_id, false, { actor: actor.username, comment: request.change_reason });
      break;
    default:
      throw new Error(`publish() does not support request_type ${request.request_type} — use RollbackGovernanceService for ROLLBACK`);
  }

  const resultingVersion = policy.currentVersion;

  const updated = await _txForRequest(request)(async (tx) => {
    const row = await ChangeRequestStore.updateStatusInTx(tx, {
      id: requestId, expectedVersion: request.version, status: stateModel.STATE.PUBLISHED,
      patch: {
        publisher_id: actor.id, publisher_username: actor.username, published_at: new Date(),
        resulting_policy_version: resultingVersion,
      },
    });
    await governanceEvents.recordEvent(tx, {
      changeRequestId: requestId, policyId: request.policy_id, tenantId: request.tenant_id,
      eventType: 'PUBLISHED', previousStatus: request.status, newStatus: stateModel.STATE.PUBLISHED, actor,
      detail: { resultingVersion },
    });
    await governanceEvents.recordPublication(tx, {
      changeRequestId: requestId, tenantId: request.tenant_id, policyId: request.policy_id,
      publisher: actor, resultingVersion, policyHash: request.payload_hash,
    });
    return row;
  });

  // policy_provenance_versions' event_type CHECK constraint (migration 009)
  // has no ARCHIVE variant — ARCHIVE maps to the same setEnabled(false)
  // call as DISABLE above, so it's recorded under the same event type.
  const PROVENANCE_EVENT_TYPE = Object.freeze({
    CREATE: 'POLICY_CREATED', UPDATE: 'POLICY_UPDATED',
    ENABLE: 'POLICY_ENABLED', DISABLE: 'POLICY_DISABLED', ARCHIVE: 'POLICY_DISABLED',
  });
  recordPolicyProvenance(policy, {
    eventType: PROVENANCE_EVENT_TYPE[request.request_type],
    actor, sourceIp: actor.sourceIp, changeReason: request.change_reason,
    changeNotes: `Published via governed change request ${requestId}`,
  });

  return { changeRequest: updated, policy };
}

/**
 * Any non-terminal status -> WITHDRAWN. Callable by the author or an
 * admin. Not maker-checker-relevant (withdrawing one's own proposal, or an
 * admin cleaning up, carries no self-approval risk).
 */
async function withdraw({ requestId, actor }) {
  const request = await ChangeRequestStore.findById(requestId);
  if (!request) throw _notFound(requestId);
  if (stateModel.isTerminal(request.status)) {
    throw new Error(`Cannot withdraw a request already in terminal status ${request.status}`);
  }
  if (request.author_id !== actor.id && actor.role !== ROLES.ADMIN) {
    throw new Error('Only the author or an admin may withdraw a change request');
  }
  _assertTransition(request.status, stateModel.STATE.WITHDRAWN);

  return _txForRequest(request)(async (tx) => {
    const updated = await ChangeRequestStore.updateStatusInTx(tx, {
      id: requestId, expectedVersion: request.version, status: stateModel.STATE.WITHDRAWN,
      patch: { withdrawn_by: actor.id, withdrawn_at: new Date() },
    });
    await governanceEvents.recordEvent(tx, {
      changeRequestId: requestId, policyId: request.policy_id, tenantId: request.tenant_id,
      eventType: 'WITHDRAWN', previousStatus: request.status, newStatus: stateModel.STATE.WITHDRAWN, actor,
    });
    return updated;
  });
}

async function getRequest(id) { return ChangeRequestStore.findById(id); }
async function listRequests(filters) { return ChangeRequestStore.list(filters); }

module.exports = {
  isStrictMode,
  draft, submit, startReview, review, approve, reject, schedule, publish, withdraw,
  getRequest, listRequests,
  InvalidTransitionError,
  // exported (unchanged logic) so EmergencyPolicyService.activate()/
  // retroApprove() can apply the SAME tenant-targeted mutation this module's own
  // publish() already uses, instead of duplicating it or falling through to the
  // global file store for a tenant-targeted emergency activation.
  applyTenantPublish: _applyTenantPublish,
};
