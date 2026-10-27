'use strict';

// TenantKeyManager — multi-tenant active key health, provisioning, and alerting.
//
// Wraps the keyStore API with structured per-tenant health checks, automatic
// provisioning of missing keys, deterministic active-key selection, and
// CRITICAL/WARN level operational alerts.
//
// Intended startup call order in server.js:
//   1. keyManager.validateStartup()  — security invariants, KEK, structural checks
//   2. tenantKeyManager.validateAllTenantsAtStartup([QODIQA_CLIENT_ID])
//        — ensures every known tenant has an active key; provisions if missing;
//          emits WARN for expiring/rotation-overdue; does NOT throw on warnings.
//          Only throws if an auto-provisioning attempt itself fails.

const {
  listKeys,
  getKeysByClient,
  rotateKeyGracefully,
  ROTATION_DAYS,
  EXPIRY_DAYS,
  EXPIRY_WARNING_DAYS,
} = require('./keyStore');
const { emit } = require('../logger');

const CLIENT_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

// ── Internal helpers ──────────────────────────────────────────────────────────

function _addDays(isoDate, n) {
  const d = new Date(isoDate);
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString();
}

function _daysFromNow(isoDate) {
  return (/** @type {any} */ (new Date(isoDate)) - Date.now()) / 86_400_000;
}

// Adds lifecycle fields to a key record from getKeysByClient().
// Those records carry createdAt but not expiresAt/rotationDeadline, so we
// recompute from the same constants used by keyStore._computeLifecycle().
function _enrichWithLifecycle(rec) {
  const expiresAt         = _addDays(rec.createdAt, EXPIRY_DAYS);
  const rotationDeadline  = _addDays(rec.createdAt, ROTATION_DAYS);
  const daysUntilExpiry   = _daysFromNow(expiresAt);
  const daysUntilRotation = _daysFromNow(rotationDeadline);
  return {
    ...rec,
    expiresAt,
    rotationDeadline,
    daysUntilExpiry:   Math.round(daysUntilExpiry   * 10) / 10,
    daysUntilRotation: Math.round(daysUntilRotation * 10) / 10,
    isExpired:         daysUntilExpiry   <= 0,
    isRotationDue:     daysUntilRotation <= 0,
    isExpiringSoon:    daysUntilExpiry > 0 && daysUntilExpiry <= EXPIRY_WARNING_DAYS,
  };
}

// Returns { status, issues, activeKey, keyCount, activeKeyCount }.
// Deterministic active key: if multiple active keys exist (structural violation),
// selects the most recently created one and reports MULTIPLE_ACTIVE_KEYS.
function _computeTenantStatus(clientId, enrichedKeys) {
  const activeKeys = enrichedKeys.filter(k => k.status === 'active');
  const issues     = [];
  let   status     = 'HEALTHY';
  let   activeKey  = null;

  if (activeKeys.length === 0) {
    issues.push('NO_ACTIVE_KEY');
    status = 'CRITICAL';
  } else {
    if (activeKeys.length > 1) {
      issues.push('MULTIPLE_ACTIVE_KEYS');
      if (status === 'HEALTHY') status = 'WARNING';
    }

    // Deterministic selection: most recent by createdAt.
    activeKey = [...activeKeys].sort(
      (a, b) => /** @type {any} */ (new Date(b.createdAt)) - /** @type {any} */ (new Date(a.createdAt)),
    )[0];

    if (activeKey.isExpired) {
      issues.push('KEY_EXPIRED');
      status = 'CRITICAL';
    } else {
      if (activeKey.isExpiringSoon) {
        issues.push('KEY_EXPIRING');
        if (status === 'HEALTHY') status = 'WARNING';
      }
      if (activeKey.isRotationDue) {
        issues.push('KEY_ROTATION_OVERDUE');
        if (status === 'HEALTHY') status = 'WARNING';
      }
    }
  }

  return {
    clientId,
    status,
    issues,
    activeKey: activeKey
      ? {
          keyId:            activeKey.keyId,
          version:          activeKey.version,
          createdAt:        activeKey.createdAt,
          expiresAt:        activeKey.expiresAt,
          rotationDeadline: activeKey.rotationDeadline,
          daysUntilExpiry:  activeKey.daysUntilExpiry,
          daysUntilRotation: activeKey.daysUntilRotation,
        }
      : null,
    keyCount:       enrichedKeys.length,
    activeKeyCount: activeKeys.length,
  };
}

// ── Public API ────────────────────────────────────────────────────────────────

// Returns per-tenant health status — does not modify any state.
function getTenantKeyStatus(clientId) {
  if (typeof clientId !== 'string' || !CLIENT_ID_RE.test(clientId)) {
    throw new TypeError(`getTenantKeyStatus: invalid clientId "${clientId}"`);
  }
  const keys     = getKeysByClient(clientId);
  const enriched = keys.map(_enrichWithLifecycle);
  return _computeTenantStatus(clientId, enriched);
}

// Returns aggregate health across all tenants currently in the key store.
function getKeyHealthSummary() {
  const allKeys   = listKeys();
  const clientIds = [...new Set(allKeys.map(k => k.clientId))];

  const tenants = clientIds.map(clientId => {
    const keys     = allKeys.filter(k => k.clientId === clientId);
    const enriched = keys.map(_enrichWithLifecycle);
    return _computeTenantStatus(clientId, enriched);
  });

  const critical = tenants.filter(t => t.status === 'CRITICAL').length;
  const warning  = tenants.filter(t => t.status === 'WARNING').length;
  const healthy  = tenants.filter(t => t.status === 'HEALTHY').length;

  return {
    timestamp:       new Date().toISOString(),
    totalTenants:    tenants.length,
    healthyTenants:  healthy,
    warningTenants:  warning,
    criticalTenants: critical,
    overallStatus:   critical > 0 ? 'CRITICAL' : warning > 0 ? 'WARNING' : 'HEALTHY',
    tenants,
  };
}

// Ensures the given tenant has a non-expired active key.
//   • No active key  → provision via rotateKeyGracefully(); emit WARN KEY_PROVISIONED.
//   • Expired key    → emit CRITICAL; auto-rotate (graceful); emit INFO KEY_ROTATION_AUTO.
//   • Multiple keys  → emit WARN; select most recent; do not change store.
//   • Healthy        → no-op.
//
// this module only ever performs *planned* rotation — a key simply
// aging past its expiry timestamp is not evidence of compromise, it's routine
// maintenance the system performs automatically at startup. It therefore
// always uses rotateKeyGracefully() (outgoing key deprecated, still
// verifiable), never the emergency/revoke default that
// POST /key-admin/:clientId/rotate uses for operator-initiated,
// incident-response rotation. An operator who suspects compromise must use
// that endpoint (or /revoke) explicitly — this module never makes that call
// on its own.
//
// Throws only if a provisioning or rotation attempt itself fails (CRITICAL event
// is emitted before throwing so the operator has structured context).
//
// Returns { provisioned, rotated, keyId }.
function ensureActiveKey(clientId) {
  if (typeof clientId !== 'string' || !CLIENT_ID_RE.test(clientId)) {
    throw new TypeError(`ensureActiveKey: invalid clientId "${clientId}"`);
  }

  const tenantStatus = getTenantKeyStatus(clientId);

  if (tenantStatus.issues.includes('MULTIPLE_ACTIVE_KEYS')) {
    emit('WARN', 'MULTIPLE_ACTIVE_KEYS_DETECTED', {
      clientId,
      activeKeyCount: tenantStatus.activeKeyCount,
      selectedKeyId:  tenantStatus.activeKey?.keyId,
    });
  }

  if (tenantStatus.issues.includes('NO_ACTIVE_KEY')) {
    emit('WARN', 'TENANT_KEY_MISSING', {
      clientId,
      message: `No active key for tenant "${clientId}" — provisioning automatically.`,
    });
    try {
      const { keyId } = rotateKeyGracefully(clientId);
      emit('INFO', 'KEY_PROVISIONED', { clientId, keyId });
      return { provisioned: true, rotated: false, keyId };
    } catch (err) {
      emit('CRITICAL', 'TENANT_KEY_PROVISIONING_FAILED', {
        clientId,
        error:   err.message,
        message: `CRITICAL: Failed to provision key for tenant "${clientId}".`,
      });
      throw err;
    }
  }

  if (tenantStatus.issues.includes('KEY_EXPIRED')) {
    emit('CRITICAL', 'TENANT_KEY_EXPIRED_ACTIVE', {
      clientId,
      keyId:   tenantStatus.activeKey?.keyId,
      message: `CRITICAL: Active key for tenant "${clientId}" is expired — rotating automatically.`,
    });
    try {
      const { keyId } = rotateKeyGracefully(clientId);
      emit('INFO', 'KEY_ROTATION_AUTO', {
        clientId,
        newKeyId: keyId,
        message:  `Auto-rotated expired key for tenant "${clientId}".`,
      });
      return { provisioned: false, rotated: true, keyId };
    } catch (err) {
      emit('CRITICAL', 'TENANT_KEY_ROTATION_FAILED', {
        clientId,
        error:   err.message,
        message: `CRITICAL: Failed to auto-rotate expired key for tenant "${clientId}".`,
      });
      throw err;
    }
  }

  return { provisioned: false, rotated: false, keyId: tenantStatus.activeKey?.keyId ?? null };
}

// Calls ensureActiveKey for each supplied client ID.
// Returns { results: [{ clientId, provisioned, rotated, keyId, error }] }.
// Does not throw — per-client failures are captured in the results array.
function ensureAllTenantsHaveActiveKeys(clientIds) {
  const results = [];
  for (const clientId of (clientIds || [])) {
    try {
      const r = ensureActiveKey(clientId);
      results.push({ clientId, ...r, error: null });
    } catch (err) {
      results.push({ clientId, provisioned: false, rotated: false, keyId: null, error: err.message });
    }
  }
  return { results };
}

// Startup validation for all tenants.
// Called in server.js AFTER keyManager.validateStartup() has succeeded.
//
// Steps:
//   1. Enumerate all clients currently in the key store.
//   2. Add any explicitly supplied clientIds (e.g. QODIQA_CLIENT_ID in case the
//      store is empty on first run).
//   3. For each client: call ensureActiveKey().
//      — Missing key    → provision; emit WARN.
//      — Expired key    → CRITICAL emit + auto-rotate.
//      — Provisioning failure → CRITICAL emit; push to failed list.
//   4. Emit WARN for expiring / rotation-overdue keys.
//   5. Emit INFO TENANT_KEY_STARTUP_COMPLETE summary.
//   6. Throw if any provisioning/rotation attempt failed.
//
// Returns the health summary (post-remediation).
function validateAllTenantsAtStartup(clientIds) {
  const extraIds = (clientIds || []).filter(
    id => typeof id === 'string' && CLIENT_ID_RE.test(id),
  );

  // Collect all clients in the store plus any explicitly supplied ones.
  const allKnownClients = new Set(listKeys().map(k => k.clientId));
  for (const id of extraIds) allKnownClients.add(id);

  const allIds      = [...allKnownClients];
  const failed      = [];
  const provisioned = [];
  const rotated     = [];

  for (const clientId of allIds) {
    try {
      const result = ensureActiveKey(clientId);
      if (result.provisioned) provisioned.push({ clientId, keyId: result.keyId });
      if (result.rotated)     rotated.push({ clientId, keyId: result.keyId });
    } catch (err) {
      failed.push({ clientId, error: err.message });
    }
  }

  // Post-remediation health summary (re-reads store after any provisioning).
  const summary = getKeyHealthSummary();

  // Emit warnings for expiring/rotation-overdue keys (informational; startup continues).
  for (const tenant of summary.tenants) {
    if (tenant.issues.includes('KEY_EXPIRING')) {
      emit('WARN', 'KEY_EXPIRING_SOON', {
        clientId:      tenant.clientId,
        keyId:         tenant.activeKey?.keyId,
        daysRemaining: tenant.activeKey?.daysUntilExpiry,
      });
    }
    if (tenant.issues.includes('KEY_ROTATION_OVERDUE')) {
      emit('WARN', 'KEY_ROTATION_OVERDUE', {
        clientId:    tenant.clientId,
        keyId:       tenant.activeKey?.keyId,
        daysOverdue: tenant.activeKey?.daysUntilRotation != null
          ? Math.ceil(-tenant.activeKey.daysUntilRotation)
          : null,
      });
    }
    if (tenant.issues.includes('MULTIPLE_ACTIVE_KEYS')) {
      emit('WARN', 'MULTIPLE_ACTIVE_KEYS_DETECTED', {
        clientId:      tenant.clientId,
        activeKeyCount: tenant.activeKeyCount,
        selectedKeyId:  tenant.activeKey?.keyId,
      });
    }
  }

  emit('INFO', 'TENANT_KEY_STARTUP_COMPLETE', {
    totalTenants:    allIds.length,
    provisioned:     provisioned.length,
    rotated:         rotated.length,
    failed:          failed.length,
    healthyTenants:  summary.healthyTenants,
    warningTenants:  summary.warningTenants,
    criticalTenants: summary.criticalTenants,
  });

  if (failed.length > 0) {
    throw new Error(
      `TenantKeyManager: ${failed.length} tenant(s) failed key provisioning — ` +
      `see TENANT_KEY_PROVISIONING_FAILED events above. ` +
      `Affected: ${failed.map(f => f.clientId).join(', ')}`,
    );
  }

  return summary;
}

module.exports = {
  getTenantKeyStatus,
  getKeyHealthSummary,
  ensureActiveKey,
  ensureAllTenantsHaveActiveKeys,
  validateAllTenantsAtStartup,
};
