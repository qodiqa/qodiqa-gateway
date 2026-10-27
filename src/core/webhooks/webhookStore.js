'use strict';

/**
 * Webhook Store — Component #28
 *
 * PostgreSQL persistence for webhook endpoint subscriptions and delivery logs.
 *
 * WRITE PATH (endpoints):  createEndpoint(), updateEndpoint(), deleteEndpoint()
 * READ PATH  (endpoints):  getEndpointById(), listEndpoints(), listByEventType()
 * WRITE PATH (delivery):   logDelivery()
 * READ PATH  (delivery):   listDeliveries()
 *
 * Secrets are stored AES-256-GCM encrypted (via webhookSecrets).
 * Secret columns (secret_enc, secret_iv, secret_tag) are explicitly excluded
 * from all SELECT projections except getEndpointForDelivery() which is
 * internal-only and used exclusively for signing outbound payloads.
 */

const pgPool              = require('../../infra/postgres/pool');
const { emit }            = require('../../../services/logger');
const { encryptSecret, decryptSecret, generateSecret } = require('./webhookSecrets');

const MAX_PAGE_SIZE     = 500;
const DEFAULT_PAGE_SIZE = 50;

// ── Safe endpoint projection (never includes secret columns) ──────────────────

const ENDPOINT_COLUMNS = `
  id, tenant_id, url, enabled, event_types,
  description, created_by, created_at, updated_at
`.trim();

// Defense-in-depth: strip encrypted secret fields from any endpoint row
// before it leaves the store layer, regardless of SQL projection.
function _stripSecrets(row) {
  if (!row) return row;
  const { secret_enc: _e, secret_iv: _i, secret_tag: _t, _secret: _s, ...safe } = row;
  return safe;
}

// ── Endpoint CRUD ─────────────────────────────────────────────────────────────

/**
 * Create a new webhook endpoint.
 * Generates a signing secret, encrypts it, stores ciphertext only.
 * Returns the endpoint row PLUS the plaintext secret (returned once only).
 *
 * @param {object} opts
 * @param {string} opts.tenantId
 * @param {string} opts.url
 * @param {string[]} opts.eventTypes
 * @param {string}  [opts.description]
 * @param {string}  [opts.createdBy]
 * @returns {Promise<{ endpoint: object, secret: string }>}
 */
async function createEndpoint({ tenantId, url, eventTypes, description, createdBy }) {
  if (!pgPool.isEnabled()) return null;

  const plainSecret = generateSecret();
  const { enc, iv, tag } = encryptSecret(plainSecret);

  const result = await pgPool.withTenantTransaction(tenantId, (tx) => tx.query(`
    INSERT INTO webhook_endpoints (
      tenant_id, url, enabled, event_types,
      secret_enc, secret_iv, secret_tag,
      description, created_by
    ) VALUES ($1, $2, TRUE, $3, $4, $5, $6, $7, $8)
    RETURNING ${ENDPOINT_COLUMNS}
  `, [
    tenantId,
    url,
    eventTypes,
    enc,
    iv,
    tag,
    description ?? null,
    createdBy   ?? 'external',
  ]));

  emit('INFO', 'WEBHOOK_ENDPOINT_CREATED', {
    endpointId: result.rows[0]?.id,
    tenantId,
    url,
    eventTypes,
    createdBy: createdBy ?? 'external',
  });

  return { endpoint: result.rows[0], secret: plainSecret };
}

/**
 * Retrieve an endpoint by UUID (never returns secret columns).
 *
 * Tenant-scoped: `tenantId` is required and establishes RLS context for the
 * query, so an id belonging to a different tenant is invisible (returns
 * null), not merely filtered client-side.
 *
 * @param {string} id
 * @param {string} tenantId
 * @returns {Promise<object|null>}
 */
async function getEndpointById(id, tenantId) {
  if (!pgPool.isEnabled()) return null;
  const result = await pgPool.withTenantTransaction(tenantId, (tx) => tx.query(
    `SELECT ${ENDPOINT_COLUMNS} FROM webhook_endpoints WHERE id = $1`,
    [id],
  ));
  return _stripSecrets(result.rows[0] ?? null);
}

/**
 * Internal: retrieve endpoint including encrypted secret fields for delivery signing.
 * Must only be called from webhookDelivery — never exposed via API.
 *
 * Tenant-scoped: `tenantId` is required and establishes RLS context for the
 * query. Callers that cannot determine a tenant for the delivery (e.g. the
 * background retry path when the enqueued payload carries no tenantId) must
 * not call this function — see webhookDelivery.retryHandler's own fail-closed
 * handling of that case, which never reaches here.
 *
 * @param {string} id
 * @param {string} tenantId
 * @returns {Promise<object|null>}
 */
async function _getEndpointForDelivery(id, tenantId) {
  if (!pgPool.isEnabled()) return null;
  const result = await pgPool.withTenantTransaction(tenantId, (tx) => tx.query(
    `SELECT *, secret_enc, secret_iv, secret_tag
       FROM webhook_endpoints
      WHERE id = $1 AND enabled = TRUE`,
    [id],
  ));
  if (!result.rows[0]) return null;
  const row = result.rows[0];
  const plainSecret = decryptSecret(row.secret_enc, row.secret_iv, row.secret_tag);
  return { ...row, _secret: plainSecret };
}

/**
 * List all endpoints for a tenant.
 *
 * @param {object} opts
 * @param {string}  opts.tenantId
 * @param {boolean} [opts.enabledOnly]
 * @param {number}  [opts.page]
 * @param {number}  [opts.pageSize]
 * @returns {Promise<{ endpoints: object[], total: number, page: number, pageSize: number }>}
 */
async function listEndpoints({ tenantId, enabledOnly, page = 1, pageSize = DEFAULT_PAGE_SIZE, sortOrder = 'desc' }) {
  if (!pgPool.isEnabled()) return { endpoints: [], total: 0, page, pageSize };

  const size   = Math.min(MAX_PAGE_SIZE, Math.max(1, pageSize));
  const offset = (Math.max(1, page) - 1) * size;
  const dir    = sortOrder === 'asc' ? 'ASC' : 'DESC';

  const conditions = ['tenant_id = $1'];
  const params     = [tenantId];

  if (enabledOnly) {
    conditions.push('enabled = TRUE');
  }

  const where = conditions.join(' AND ');

  const [rows, count] = await pgPool.withTenantTransaction(tenantId, (tx) => Promise.all([
    tx.query(
      `SELECT ${ENDPOINT_COLUMNS}
         FROM webhook_endpoints
        WHERE ${where}
        ORDER BY created_at ${dir}, id ${dir}
        LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, size, offset],
    ),
    tx.query(
      `SELECT COUNT(*)::int AS total FROM webhook_endpoints WHERE ${where}`,
      params,
    ),
  ]));

  return {
    endpoints: rows.rows.map(_stripSecrets),
    total:     count.rows[0]?.total ?? 0,
    page:      Math.max(1, page),
    pageSize:  size,
  };
}

/**
 * Find all enabled endpoints subscribed to a given event type.
 * Used by the dispatcher for fan-out delivery.
 *
 * When called inside a tenant transaction (pass { tx }), RLS automatically
 * restricts results to the active tenant's endpoints.  This is the correct
 * behavior for fan-out: each tenant's events notify only that tenant's endpoints.
 *
 * @param {string}  eventType          e.g. 'certification.completed'
 * @param {object}  [opts]
 * @param {{ query: Function }} [opts.tx]  Transactional client (enables tenant RLS)
 * @returns {Promise<object[]>}  includes encrypted secret fields
 */
async function listByEventType(eventType, { tx } = {}) {
  if (!pgPool.isEnabled()) return [];

  const exec = tx
    ? (sql, p) => tx.query(sql, p)
    : (sql, p) => pgPool.query(sql, p);

  const result = await exec(
    `SELECT id, tenant_id, url, event_types, secret_enc, secret_iv, secret_tag
       FROM webhook_endpoints
      WHERE enabled = TRUE
        AND $1 = ANY(event_types)`,
    [eventType],
  );

  return result.rows.map(row => {
    const plainSecret = decryptSecret(row.secret_enc, row.secret_iv, row.secret_tag);
    return { ...row, _secret: plainSecret };
  });
}

/**
 * Update endpoint fields (url, enabled, eventTypes, description).
 *
 * Tenant-scoped: `tenantId` is required. The UPDATE's RLS policy also
 * requires the existing row's tenant_id to match, so an id belonging to a
 * different tenant is affected by zero rows (RETURNING is empty → null),
 * not merely rejected client-side.
 *
 * @param {string}   id
 * @param {object}   updates
 * @param {string}   tenantId
 * @returns {Promise<object|null>}
 */
async function updateEndpoint(id, updates, tenantId) {
  if (!pgPool.isEnabled()) return null;

  const sets   = [];
  const params = [];

  if (updates.url        != null) { params.push(updates.url);        sets.push(`url         = $${params.length}`); }
  if (updates.enabled    != null) { params.push(updates.enabled);    sets.push(`enabled     = $${params.length}`); }
  if (updates.eventTypes != null) { params.push(updates.eventTypes); sets.push(`event_types = $${params.length}`); }
  if (updates.description != null) { params.push(updates.description); sets.push(`description = $${params.length}`); }

  if (sets.length === 0) return getEndpointById(id, tenantId);

  sets.push(`updated_at = NOW()`);
  params.push(id);

  const result = await pgPool.withTenantTransaction(tenantId, (tx) => tx.query(
    `UPDATE webhook_endpoints
        SET ${sets.join(', ')}
      WHERE id = $${params.length}
   RETURNING ${ENDPOINT_COLUMNS}`,
    params,
  ));

  return _stripSecrets(result.rows[0] ?? null);
}

/**
 * Soft-delete: disable an endpoint permanently.
 * Hard deletes are intentionally not supported via the application role.
 *
 * Tenant-scoped: `tenantId` is required (same RLS-enforced-zero-rows
 * behavior as updateEndpoint above for a cross-tenant id).
 *
 * @param {string} id
 * @param {string} tenantId
 * @returns {Promise<object|null>}
 */
async function deleteEndpoint(id, tenantId) {
  if (!pgPool.isEnabled()) return null;

  const result = await pgPool.withTenantTransaction(tenantId, (tx) => tx.query(
    `UPDATE webhook_endpoints
        SET enabled = FALSE, updated_at = NOW()
      WHERE id = $1
   RETURNING ${ENDPOINT_COLUMNS}`,
    [id],
  ));

  return _stripSecrets(result.rows[0] ?? null);
}

// ── Delivery log ──────────────────────────────────────────────────────────────

/**
 * Append a delivery attempt to the log.
 * Never throws — a failed log write must not disrupt the delivery path.
 *
 * @param {object} entry
 * @param {string}  entry.endpointId
 * @param {string}  entry.eventId
 * @param {string}  entry.eventType
 * @param {number}  entry.attempt
 * @param {number|null} entry.httpStatus
 * @param {number|null} entry.durationMs
 * @param {boolean} entry.success
 * @param {string|null} entry.errorMsg
 * @returns {Promise<void>}
 */
async function logDelivery({ endpointId, eventId, eventType, attempt, httpStatus, durationMs, success, errorMsg }) {
  if (!pgPool.isEnabled()) return;

  try {
    await pgPool.query(
      `INSERT INTO webhook_delivery_log
         (endpoint_id, event_id, event_type, attempt, http_status, duration_ms, success, error_msg)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [endpointId, eventId, eventType, attempt, httpStatus ?? null, durationMs ?? null, success, errorMsg ?? null],
    );
  } catch (err) {
    emit('ERROR', 'WEBHOOK_DELIVERY_LOG_FAILED', {
      endpointId,
      eventId,
      eventType,
      attempt,
      error: err.message,
    });
  }
}

/**
 * List delivery attempts for an endpoint.
 *
 * Tenant-scoped: `tenantId` is required. webhook_delivery_log has no
 * tenant_id column of its own — its SELECT RLS policy (wdl_tenant_select,
 * migration 018) gates visibility via a subquery on the parent endpoint's
 * tenant_id, so without tenant context this always returns zero rows
 * (fail-closed) regardless of endpointId.
 *
 * @param {object} opts
 * @param {string}  opts.endpointId
 * @param {string}  opts.tenantId
 * @param {number}  [opts.page]
 * @param {number}  [opts.pageSize]
 * @param {boolean} [opts.failedOnly]
 * @returns {Promise<{ deliveries: object[], total: number, page: number, pageSize: number }>}
 */
async function listDeliveries({ endpointId, tenantId, page = 1, pageSize = DEFAULT_PAGE_SIZE, failedOnly, sortOrder = 'desc' }) {
  if (!pgPool.isEnabled()) return { deliveries: [], total: 0, page, pageSize };

  const size   = Math.min(MAX_PAGE_SIZE, Math.max(1, pageSize));
  const offset = (Math.max(1, page) - 1) * size;
  const dir    = sortOrder === 'asc' ? 'ASC' : 'DESC';

  const conditions = ['endpoint_id = $1'];
  const params     = [endpointId];

  if (failedOnly) {
    conditions.push('success = FALSE');
  }

  const where = conditions.join(' AND ');

  const [rows, count] = await pgPool.withTenantTransaction(tenantId, (tx) => Promise.all([
    tx.query(
      `SELECT delivery_id, endpoint_id, event_id, event_type, attempt,
              delivered_at, http_status, duration_ms, success, error_msg
         FROM webhook_delivery_log
        WHERE ${where}
        ORDER BY delivered_at ${dir}, delivery_id ${dir}
        LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, size, offset],
    ),
    tx.query(
      `SELECT COUNT(*)::int AS total FROM webhook_delivery_log WHERE ${where}`,
      params,
    ),
  ]));

  return {
    deliveries: rows.rows,
    total:      count.rows[0]?.total ?? 0,
    page:       Math.max(1, page),
    pageSize:   size,
  };
}

module.exports = {
  createEndpoint,
  getEndpointById,
  listEndpoints,
  updateEndpoint,
  deleteEndpoint,
  listByEventType,
  logDelivery,
  listDeliveries,
  // Internal: exported for use by webhookDelivery only
  _getEndpointForDelivery,
};
