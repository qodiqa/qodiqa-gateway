'use strict';

/**
 * EmergencyPolicyService — governed emergency/break-glass policy
 * activation.
 *
 * activate() is the ONE deliberate bypass of the normal maker-checker gate
 * in this whole workflow — every other mutation requires independent
 * review/approval/publish by distinct individuals before it touches the
 * live enforcement store; an emergency activation applies immediately,
 * single-actor. This is compensated for, not left ungoverned: a mandatory
 * incident reference, a mandatory written justification, a hard
 * expiration (`expires_at`), and a mandatory retrospective approval by a
 * DIFFERENT individual than the activator (retroApprove(), enforced via
 * makerCheckerRules.assertEmergencyRetroApproverNotActivator). If
 * retrospective approval never happens, the activation auto-expires and
 * the policy is automatically reverted.
 *
 * sweepExpired() mirrors exactly how src/core/audit/retention.js's
 * runRetentionCycle() is operated in this codebase today: there is no
 * internal cron/scheduler anywhere in this platform, so retention (and now
 * this) is only ever triggered via an admin API call. Correctness never
 * depends on that external trigger actually running, though — retroApprove()
 * performs the same expiry check lazily, under a row lock, before accepting
 * any decision, as defense in depth.
 */

const crypto              = require('crypto');
const pool                = require('../../../infra/postgres/pool');
const rolePools = require('../../../infra/postgres/rolePools'); // the ops-wide expiry sweep runs as qodiqa_system
const ChangeRequestStore  = require('./ChangeRequestStore');
const governanceEvents    = require('./governanceEvents');
const stateModel          = require('./ChangeRequestStateModel');
const rules                = require('./makerCheckerRules');
const policyStore          = require('../store');
const { recordPolicyProvenance } = require('./provenanceBridge');
const { emit }              = require('../../../../services/logger');
// reuses PolicyGovernanceService's own tenant-targeted publish
// logic (applyTenantPublish) instead of duplicating it — no circular
// dependency, PolicyGovernanceService.js does not require this file.
const { applyTenantPublish } = require('./PolicyGovernanceService');

const PROVENANCE_EVENT_TYPE = Object.freeze({
  CREATE: 'POLICY_CREATED', UPDATE: 'POLICY_UPDATED', ENABLE: 'POLICY_ENABLED', DISABLE: 'POLICY_DISABLED',
});

const DEFAULT_TTL_HOURS = 24;
const MAX_TTL_HOURS     = 168; // 7 days
const SYSTEM_ACTOR = Object.freeze({ id: 'system:sweep', username: 'system:sweep', role: 'system' });

/**
 * Immediately create AND apply an emergency change. Bypasses the normal
 * review/approve/publish chain — see module docblock for the compensating
 * controls.
 *
 * @returns {Promise<{changeRequest: object, emergency: object, policy: object}>}
 */
async function activate({
  policyId, tenantId = null, requestType, payload,
  incidentReference, justification, ttlHours = DEFAULT_TTL_HOURS, actor,
}) {
  if (!policyId || !requestType || !incidentReference || !justification) {
    throw new Error('policyId, requestType, incidentReference, and justification are required');
  }
  if (!Number.isFinite(ttlHours) || ttlHours <= 0 || ttlHours > MAX_TTL_HOURS) {
    throw new Error(`ttlHours must be a positive number, max ${MAX_TTL_HOURS} (7 days)`);
  }
  if (!['CREATE', 'UPDATE', 'ENABLE', 'DISABLE'].includes(requestType)) {
    throw new Error(`Emergency activation does not support request_type ${requestType}`);
  }

  const payloadHash  = governanceEvents.hashPayload(payload);
  const changeReason = `EMERGENCY: ${justification}`;

  const request = await ChangeRequestStore.create({
    policy_id: policyId, tenant_id: tenantId, request_type: requestType,
    payload, payload_hash: payloadHash, change_reason: changeReason, author: actor,
  });

  // a tenant-targeted emergency activation must apply to that
  // tenant's own PG-persisted policy set (tenantConfigStore), not the GLOBAL
  // file store — previously this switch ran unconditionally against the
  // global store regardless of tenantId, mutating the wrong blast radius.
  // applyTenantPublish (PolicyGovernanceService's own tenant-publish logic,
  // reused unmodified) expects a request-shaped object; `request` (just
  // created above via ChangeRequestStore.create) already has every field it
  // needs (tenant_id, payload, policy_id, request_type, id).
  let policy;
  let resultingVersion;
  if (tenantId) {
    policy = await applyTenantPublish(request, actor);
    resultingVersion = policy.version;
  } else {
    switch (requestType) {
      case 'CREATE':  policy = await policyStore.createPolicy({ ...payload, actor: actor.username, comment: changeReason }); break;
      case 'UPDATE':  policy = await policyStore.updatePolicy(policyId, payload, { actor: actor.username, comment: changeReason }); break;
      case 'ENABLE':  policy = await policyStore.setEnabled(policyId, true, { actor: actor.username, comment: changeReason }); break;
      case 'DISABLE': policy = await policyStore.setEnabled(policyId, false, { actor: actor.username, comment: changeReason }); break;
    }
    resultingVersion = policy.currentVersion;
  }
  const expiresAt = new Date(Date.now() + ttlHours * 3_600_000);

  // the follow-up transaction must run under the same tenant
  // context applyTenantPublish just used, or its own writes (the
  // policy_change_requests status UPDATE, policy_emergency_activations
  // INSERT) are RLS-blocked for a tenant-scoped request exactly like the
  // global-vs-tenant mismatch above.
  const runFollowUp = tenantId
    ? (fn) => pool.withTenantTransaction(tenantId, fn)
    : (fn) => pool.withTransaction(fn);

  const { changeRequest, emergency } = await runFollowUp(async (tx) => {
    const cr = await ChangeRequestStore.updateStatusInTx(tx, {
      id: request.id, expectedVersion: request.version, status: stateModel.STATE.PUBLISHED,
      patch: {
        publisher_id: actor.id, publisher_username: actor.username, published_at: new Date(),
        resulting_policy_version: resultingVersion,
      },
    });
    await governanceEvents.recordEvent(tx, {
      changeRequestId: request.id, policyId, tenantId, eventType: 'EMERGENCY_ACTIVATED',
      previousStatus: stateModel.STATE.DRAFT, newStatus: stateModel.STATE.PUBLISHED, actor,
      reason: justification, detail: { incidentReference, ttlHours, resultingVersion },
    });
    await governanceEvents.recordPublication(tx, {
      changeRequestId: request.id, tenantId, policyId, publisher: actor, resultingVersion,
      policyHash: payloadHash, emergency: true,
    });

    const checksum = crypto.createHash('sha256')
      .update([request.id, actor.id, incidentReference, expiresAt.toISOString()].join('|')).digest('hex');

    const inserted = await tx.query(
      `INSERT INTO policy_emergency_activations
         (change_request_id, tenant_id, policy_id, activated_by, activated_username,
          incident_reference, justification, expires_at, checksum)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       RETURNING *`,
      [request.id, tenantId, policyId, actor.id, actor.username, incidentReference, justification, expiresAt, checksum],
    );

    return { changeRequest: cr, emergency: inserted.rows[0] };
  });

  emit('WARN', 'POLICY_EMERGENCY_ACTIVATED', {
    changeRequestId: request.id, policyId, actorId: actor.id, incidentReference, expiresAt: expiresAt.toISOString(),
  });

  recordPolicyProvenance(policy, {
    eventType: PROVENANCE_EVENT_TYPE[requestType], actor, sourceIp: actor.sourceIp,
    changeReason: changeReason,
    changeNotes: `EMERGENCY activation — incident ${incidentReference}, change request ${request.id}`,
  });

  return { changeRequest, emergency, policy };
}

/**
 * Disable the emergency-activated policy and mark the activation reverted.
 * Called under a row lock from retroApprove()/sweepExpired() — the policy
 * mutation itself is a synchronous file-store call, not part of the
 * Postgres transaction (the same file-vs-Postgres caveat documented for
 * PolicyGovernanceService.publish() applies here identically).
 */
async function _revertInTx(tx, emergency, actor, { retrospectiveStatus, cause }) {
  // a tenant-scoped emergency activation must be reverted in
  // that tenant's own store, not the global one — mirrors activate()'s own
  // tenantId branch above, using a minimal request-shaped object
  // applyTenantPublish accepts (DISABLE only ever needs policy_id/payload).
  const policy = emergency.tenant_id
    ? await applyTenantPublish({
        tenant_id: emergency.tenant_id, policy_id: emergency.policy_id,
        request_type: 'DISABLE', payload: {}, id: emergency.change_request_id,
      }, actor)
    : await policyStore.setEnabled(emergency.policy_id, false, {
        actor: actor.username, comment: `Emergency activation auto-reverted (${cause})`,
      });
  const result = await tx.query(
    `UPDATE policy_emergency_activations
        SET retrospective_status = $1, reverted_at = NOW()
      WHERE id = $2
      RETURNING *`,
    [retrospectiveStatus, emergency.id],
  );
  return { emergencyRow: result.rows[0], policy };
}

/**
 * Retrospectively approve or reject an emergency activation. The approver
 * must be a different individual than the activator. If the activation has
 * already expired (lazily checked here, under a row lock, independent of
 * whether sweepExpired() ran), the decision is refused and the activation
 * is auto-reverted instead.
 *
 * accepts an optional tenantId — without it, this stays scoped
 * to platform-level emergency activations only, unchanged from prior
 * behavior (this table's SELECT/UPDATE RLS is the same nullable shape as
 * every other migration-029 table).
 *
 * @returns {Promise<{emergency: object}>}
 */
async function retroApprove({ emergencyId, tenantId = null, actor, decision, notes = null }) {
  if (decision !== 'APPROVED' && decision !== 'REJECTED') {
    throw new Error("decision must be 'APPROVED' or 'REJECTED'");
  }

  const runInTransaction = tenantId
    ? (fn) => pool.withTenantTransaction(tenantId, fn)
    : (fn) => pool.withTransaction(fn);

  return runInTransaction(async (tx) => {
    const existing = await tx.query(
      'SELECT * FROM policy_emergency_activations WHERE id = $1 FOR UPDATE',
      [emergencyId],
    );
    if (!existing.rows.length) {
      const err = new Error(`Emergency activation not found: ${emergencyId}`);
      err.code  = 'NOT_FOUND';
      throw err;
    }
    const emergency = existing.rows[0];

    if (emergency.retrospective_status !== 'PENDING') {
      throw new Error(`Emergency activation ${emergencyId} retrospective review is already ${emergency.retrospective_status}`);
    }

    if (new Date(emergency.expires_at) < new Date()) {
      await _revertInTx(tx, emergency, actor, {
        retrospectiveStatus: 'EXPIRED', cause: 'expired without retrospective approval',
      });
      await governanceEvents.recordEvent(tx, {
        changeRequestId: emergency.change_request_id, policyId: emergency.policy_id, tenantId: emergency.tenant_id,
        eventType: 'EMERGENCY_EXPIRED', previousStatus: 'PENDING', newStatus: 'EXPIRED', actor,
        reason: 'Retrospective approval window expired before a decision was recorded',
      });
      const err = new Error(
        `Emergency activation ${emergencyId} expired before retrospective approval — it has been auto-reverted`,
      );
      err.code = 'EMERGENCY_EXPIRED';
      throw err;
    }

    rules.assertEmergencyRetroApproverNotActivator(emergency.activated_by, actor.id);

    const result = await tx.query(
      `UPDATE policy_emergency_activations
          SET retrospective_status = $1, retrospective_approved_by = $2, retrospective_approved_username = $3,
              retrospective_notes = $4, retrospective_decided_at = NOW()
        WHERE id = $5
        RETURNING *`,
      [decision, actor.id, actor.username, notes, emergencyId],
    );
    let updated = result.rows[0];

    if (decision === 'REJECTED') {
      const reverted = await _revertInTx(tx, updated, actor, { retrospectiveStatus: 'REJECTED', cause: 'retrospectively rejected' });
      updated = reverted.emergencyRow;
    }

    await governanceEvents.recordEvent(tx, {
      changeRequestId: updated.change_request_id, policyId: updated.policy_id, tenantId: updated.tenant_id,
      eventType: decision === 'APPROVED' ? 'EMERGENCY_RETRO_APPROVED' : 'EMERGENCY_RETRO_REJECTED',
      previousStatus: 'PENDING', newStatus: decision, actor, reason: notes,
    });

    return { emergency: updated };
  });
}

/**
 * Admin-triggered sweep: auto-reverts every PENDING activation whose
 * expires_at has passed. Mirrors retention.js's runRetentionCycle() —
 * operators schedule this the same way (external cron hitting the admin
 * endpoint); there is no in-process scheduler.
 *
 * @returns {Promise<{swept: number, ids: string[]}>}
 */
async function sweepExpired() {
  // This ops-wide sweep (it used to be an open gap) must see
  // EVERY tenant's PENDING activations to auto-revert ones that expired
  // without retrospective approval. A plain pool.query() with no tenant
  // context was silently restricted to platform-level activations only by
  // pea_tenant_select's nullable RLS policy — a tenant-scoped emergency
  // activation that expired without retrospective approval was never
  // auto-reverted. Fixed via the genuinely cross-tenant SECURITY DEFINER
  // bypass function migration 056 added (qodiqa_policy_emergency_activations_full_read()),
  // the same pattern migration 053 established for
  // centralStore/chainStore/AlertStore/retention's own ops-wide listings.
  // Reached only via the RBAC-gated POST /policy-governance/emergency/sweep
  // admin route (opsAuth) — never by tenant-scoped business logic.
  const pending = await rolePools.system.query(
    `SELECT id, tenant_id FROM qodiqa_policy_emergency_activations_full_read() WHERE retrospective_status = 'PENDING' AND expires_at < NOW()`,
    [], 'pea_find_expired',
  );

  const reverted = [];
  for (const row of pending.rows) {
    try {
      // the discovery query above sees every tenant via the bypass
      // function, but the row-lock + revert below runs on an ordinary
      // (RLS-enforced) transaction — it must run under THIS row's own tenant
      // context (or global, for a platform-level activation), the same
      // runInTransaction idiom activate()/retroApprove() already use, or
      // pea_tenant_select would silently hide the row again at lock time.
      const runInTransaction = row.tenant_id
        ? (fn) => pool.withTenantTransaction(row.tenant_id, fn)
        : (fn) => pool.withTransaction(fn);
      const outcome = await runInTransaction(async (tx) => {
        const locked = await tx.query('SELECT * FROM policy_emergency_activations WHERE id = $1 FOR UPDATE', [row.id]);
        const emergency = locked.rows[0];
        if (!emergency || emergency.retrospective_status !== 'PENDING' || new Date(emergency.expires_at) >= new Date()) {
          return null; // already handled concurrently (retroApprove or another sweep run)
        }
        const { emergencyRow } = await _revertInTx(tx, emergency, SYSTEM_ACTOR, {
          retrospectiveStatus: 'EXPIRED', cause: 'expired without retrospective approval (automated sweep)',
        });
        await governanceEvents.recordEvent(tx, {
          changeRequestId: emergency.change_request_id, policyId: emergency.policy_id, tenantId: emergency.tenant_id,
          eventType: 'EMERGENCY_EXPIRED', previousStatus: 'PENDING', newStatus: 'EXPIRED', actor: SYSTEM_ACTOR,
          reason: 'Retrospective approval window expired before a decision was recorded (automated sweep)',
        });
        return emergencyRow;
      });
      if (outcome) reverted.push(outcome);
    } catch (err) {
      emit('ERROR', 'POLICY_EMERGENCY_SWEEP_FAILED', { emergencyId: row.id, error: err.message });
    }
  }

  if (reverted.length) {
    emit('WARN', 'POLICY_EMERGENCY_SWEEP_REVERTED', { count: reverted.length, ids: reverted.map((r) => r.id) });
  }

  return { swept: reverted.length, ids: reverted.map((r) => r.id) };
}

async function get(emergencyId) {
  const result = await pool.query('SELECT * FROM policy_emergency_activations WHERE id = $1', [emergencyId], 'pea_find_by_id');
  return result.rows[0] ?? null;
}

async function list({ policyId, tenantId, retrospectiveStatus, limit = 50, offset = 0 } = {}) {
  const conditions = [];
  const params     = [];
  if (policyId)             { params.push(policyId);             conditions.push(`policy_id = $${params.length}`); }
  if (tenantId)             { params.push(tenantId);             conditions.push(`tenant_id = $${params.length}`); }
  if (retrospectiveStatus)  { params.push(retrospectiveStatus);  conditions.push(`retrospective_status = $${params.length}`); }
  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  params.push(Math.min(limit, 200));
  const limitParam = params.length;
  params.push(Math.max(offset, 0));
  const offsetParam = params.length;
  const result = await pool.query(
    `SELECT * FROM policy_emergency_activations ${where} ORDER BY activated_at DESC LIMIT $${limitParam} OFFSET $${offsetParam}`,
    params, 'pea_list',
  );
  return result.rows;
}

module.exports = { activate, retroApprove, sweepExpired, get, list };
