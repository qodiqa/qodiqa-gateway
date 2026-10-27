'use strict';

/**
 * evidenceGenerator — assembles an evidence package for a
 * policy change request: full review chain, approval chain,
 * publication record, rollback record (if applicable), the complete
 * hash-chained workflow history, and a live cryptographic-integrity
 * verification of that hash chain (governanceEvents.verifyChain).
 */

const pool               = require('../../../infra/postgres/pool');
const governanceEvents   = require('./governanceEvents');
const ChangeRequestStore = require('./ChangeRequestStore');

async function generate(requestId) {
  const request = await ChangeRequestStore.findById(requestId);
  if (!request) {
    const err = new Error(`Change request not found: ${requestId}`);
    err.code  = 'NOT_FOUND';
    throw err;
  }

  // these 5 tables all have tenant-checked SELECT RLS
  // (nullable shape); previously queried with no tenant context, which
  // silently returned empty arrays for a tenant-scoped change request's real
  // evidence (fail-closed, not a leak, but a compliance-integrity defect —
  // the evidence package looked clean/empty when it wasn't). `request` is
  // already known safe to read here (findById's own SECURITY DEFINER
  // fallback + this route's RBAC gate, see CHANGE-REQUEST-INVENTORY.md) — its
  // own `tenant_id` is now threaded to actually see that tenant's rows.
  // A single transaction is bound to ONE connection — its 5 queries must run
  // sequentially, not via Promise.all (concurrent queries on one client are
  // unsafe/deprecated in node-postgres). The no-tenant-context branch still
  // draws each query from the POOL independently, so those 5 stay
  // parallelized exactly as before this fix.
  const runQueriesSequential = async (exec) => {
    const reviews      = await exec('SELECT * FROM policy_reviews WHERE change_request_id = $1 ORDER BY reviewed_at ASC', [requestId]);
    const approvals    = await exec('SELECT * FROM policy_approvals WHERE change_request_id = $1 ORDER BY approved_at ASC', [requestId]);
    const publications = await exec('SELECT * FROM policy_publications WHERE change_request_id = $1 ORDER BY published_at ASC', [requestId]);
    const rollbacks    = await exec('SELECT * FROM policy_rollbacks WHERE change_request_id = $1 ORDER BY requested_at ASC', [requestId]);
    const events       = await exec('SELECT * FROM approval_events WHERE change_request_id = $1 ORDER BY occurred_at ASC', [requestId]);
    return [reviews, approvals, publications, rollbacks, events];
  };
  const runQueriesParallel = (exec) => Promise.all([
    exec('SELECT * FROM policy_reviews WHERE change_request_id = $1 ORDER BY reviewed_at ASC', [requestId]),
    exec('SELECT * FROM policy_approvals WHERE change_request_id = $1 ORDER BY approved_at ASC', [requestId]),
    exec('SELECT * FROM policy_publications WHERE change_request_id = $1 ORDER BY published_at ASC', [requestId]),
    exec('SELECT * FROM policy_rollbacks WHERE change_request_id = $1 ORDER BY requested_at ASC', [requestId]),
    exec('SELECT * FROM approval_events WHERE change_request_id = $1 ORDER BY occurred_at ASC', [requestId]),
  ]);

  const [[reviews, approvals, publications, rollbacks, events], chainIntegrity] = await Promise.all([
    request.tenant_id
      ? pool.withTenantTransaction(request.tenant_id, (tx) => runQueriesSequential((sql, p) => tx.query(sql, p)))
      : runQueriesParallel((sql, p) => pool.query(sql, p, 'ev_query')),
    governanceEvents.verifyChain(requestId),
  ]);

  return {
    changeRequest:   request,
    reviewChain:     reviews.rows,
    approvalChain:   approvals.rows,
    publications:    publications.rows,
    rollback:        rollbacks.rows[0] ?? null,
    workflowHistory: events.rows,
    hashChainIntegrity: chainIntegrity,
    policyHash:      request.payload_hash,
    generatedAt:     new Date().toISOString(),
  };
}

module.exports = { generate };
