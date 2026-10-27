'use strict';

/**
 * QODIQA Policy Provenance Engine — Component #20
 *
 * Pure-logic module: no I/O, no side effects.  All functions are synchronous
 * and deterministic.  Database persistence is handled by provenanceStore.js.
 *
 * Responsibilities:
 *   • Canonical JSON serialisation and SHA-256 hash computation
 *   • Structured and human-readable diff generation
 *   • Attribution context validation (fail-closed)
 *   • Change reason validation
 *   • Hash-chain integrity verification over an array of version records
 *   • Provenance record assembly
 */

const { createHash }  = require('crypto');
const stableStringify = require('../../utils/stableStringify');
const { sanitizeCsvCell } = require('../../utils/csvSanitize');

// ── Canonical JSON ────────────────────────────────────────────────────────────

/**
 * Produce a stable, whitespace-free JSON representation of obj with all
 * object keys sorted recursively.  Arrays preserve their element order.
 * This is the canonical form used for SHA-256 hashing.
 *
 * Delegates to the shared stableStringify (src/utils/stableStringify.js) —
 * the single canonical serialization authority — rather than a local
 * reimplementation, so provenance policy-content hashing gets the same
 * NaN/Infinity/forbidden-key/circular-reference/unsupported-type guards as
 * every other QODIQA hashing pipeline.
 */
function canonicalJson(obj) {
  return stableStringify(obj);
}

/**
 * Compute SHA-256 of the canonical JSON representation of policyContent.
 * Returns a 64-character lowercase hex string.
 *
 * @param {object} policyContent — policy snapshot object
 * @returns {string} 64-char hex SHA-256
 */
function computePolicyHash(policyContent) {
  const canonical = canonicalJson(policyContent);
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

// ── Deep diff ─────────────────────────────────────────────────────────────────

/**
 * Recursively compute field-level differences between two objects.
 * Returns an array of { path, op, from, to } change descriptors.
 * op values: 'ADDED' | 'MODIFIED' | 'REMOVED'
 *
 * @param {*}      a       — previous value
 * @param {*}      b       — new value
 * @param {string} [prefix] — dot-path prefix for nested keys
 * @returns {{ path: string, op: string, from: *, to: * }[]}
 */
function _deepDiff(a, b, prefix) {
  const path  = prefix || '';
  const diffs = [];

  const aIsObj = a !== null && typeof a === 'object' && !Array.isArray(a);
  const bIsObj = b !== null && typeof b === 'object' && !Array.isArray(b);

  if (aIsObj && bIsObj) {
    const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
    for (const key of keys) {
      const sub  = path ? `${path}.${key}` : key;
      const hasA = Object.prototype.hasOwnProperty.call(a, key);
      const hasB = Object.prototype.hasOwnProperty.call(b, key);
      if (!hasA) {
        diffs.push({ path: sub, op: 'ADDED',    from: undefined, to: b[key] });
      } else if (!hasB) {
        diffs.push({ path: sub, op: 'REMOVED',  from: a[key],    to: undefined });
      } else {
        diffs.push(..._deepDiff(a[key], b[key], sub));
      }
    }
    return diffs;
  }

  const aStr = JSON.stringify(a);
  const bStr = JSON.stringify(b);
  if (aStr !== bStr) {
    diffs.push({ path: path || '(root)', op: 'MODIFIED', from: a, to: b });
  }
  return diffs;
}

/**
 * Generate a structured diff (array of change descriptors) between two policy
 * content snapshots.  Automatically called at every version creation.
 *
 * @param {object} previous — snapshot from the prior version
 * @param {object} current  — snapshot for the new version
 * @returns {{ path: string, op: string, from: *, to: * }[]}
 */
function generateStructuredDiff(previous, current) {
  if (!previous || typeof previous !== 'object') return [];
  if (!current  || typeof current  !== 'object') return [];
  return _deepDiff(previous, current, '');
}

/**
 * Convert a structured diff array into a human-readable summary string.
 *
 * @param {{ path: string, op: string, from: *, to: * }[]} diff
 * @returns {string}
 */
function generateHumanReadableDiff(diff) {
  if (!Array.isArray(diff) || diff.length === 0) return 'No changes.';

  const lines = diff.map(c => {
    switch (c.op) {
      case 'ADDED':
        return `+ ${c.path}: (new) ${JSON.stringify(c.to)}`;
      case 'REMOVED':
        return `- ${c.path}: ${JSON.stringify(c.from)} → (removed)`;
      case 'MODIFIED':
        return `~ ${c.path}: ${JSON.stringify(c.from)} → ${JSON.stringify(c.to)}`;
      default:
        return `? ${c.path}: ${c.op}`;
    }
  });

  const added    = diff.filter(c => c.op === 'ADDED').length;
  const removed  = diff.filter(c => c.op === 'REMOVED').length;
  const modified = diff.filter(c => c.op === 'MODIFIED').length;

  const summary = [
    added    ? `${added} added`    : null,
    modified ? `${modified} modified` : null,
    removed  ? `${removed} removed` : null,
  ].filter(Boolean).join(', ');

  return `Summary: ${summary}\n${lines.join('\n')}`;
}

// ── Attribution validation ─────────────────────────────────────────────────────

/**
 * Validate that an attribution context object contains all required fields.
 * Fail-closed: throws with code ATTRIBUTION_MISSING if any field is absent or blank.
 *
 * Required fields: actorId, actorUsername, actorRole, sourceIp
 *
 * @param {{ actorId?: string, actorUsername?: string, actorRole?: string, sourceIp?: string }} ctx
 * @throws {Error} code ATTRIBUTION_MISSING
 */
function validateAttributionContext(ctx) {
  const required = ['actorId', 'actorUsername', 'actorRole', 'sourceIp'];
  const missing  = [];

  for (const field of required) {
    const v = ctx && ctx[field];
    if (typeof v !== 'string' || !v.trim()) {
      missing.push(field);
    }
  }

  if (missing.length > 0) {
    const err = new Error(
      `ATTRIBUTION_MISSING: policy modification requires complete attribution. ` +
      `Missing or blank fields: ${missing.join(', ')}`
    );
    err.code = 'ATTRIBUTION_MISSING';
    throw err;
  }
}

/**
 * Validate that a change reason is present and non-empty.
 * Fail-closed: throws with code REASON_REQUIRED if blank or missing.
 *
 * @param {string} reason
 * @throws {Error} code REASON_REQUIRED
 */
function validateChangeReason(reason) {
  if (typeof reason !== 'string' || !reason.trim()) {
    const err = new Error(
      'REASON_REQUIRED: a non-empty changeReason is mandatory for all policy modifications'
    );
    err.code = 'REASON_REQUIRED';
    throw err;
  }
}

// ── Provenance record assembly ─────────────────────────────────────────────────

/**
 * Assemble a complete provenance record ready for persistence.
 *
 * @param {object} opts
 * @param {string}  opts.policyId
 * @param {number}  opts.versionNumber
 * @param {number|null} opts.parentVersion      — null for v1
 * @param {number}  opts.rootVersion            — always 1 for now
 * @param {string}  opts.eventType
 * @param {Date}    opts.occurredAt
 * @param {string}  opts.actorId
 * @param {string}  opts.actorUsername
 * @param {string}  opts.actorRole
 * @param {string}  opts.sourceIp
 * @param {string}  opts.changeReason
 * @param {string}  [opts.changeNotes]
 * @param {object}  opts.policyContent          — full snapshot
 * @param {string|null} opts.previousPolicyHash — hash of prior version; null for v1
 * @param {object|null} opts.previousContent    — snapshot of prior version; null for v1
 * @param {number|null} [opts.rolledBackToVersion]
 * @returns {object} complete provenance record
 */
function buildProvenanceRecord({
  policyId,
  versionNumber,
  parentVersion,
  rootVersion,
  eventType,
  occurredAt,
  actorId,
  actorUsername,
  actorRole,
  sourceIp,
  changeReason,
  changeNotes,
  policyContent,
  previousPolicyHash,
  previousContent,
  rolledBackToVersion,
}) {
  const policyHash      = computePolicyHash(policyContent);
  const diffStructured  = previousContent
    ? generateStructuredDiff(previousContent, policyContent)
    : [];
  const diffHumanReadable = generateHumanReadableDiff(diffStructured);

  return {
    policyId,
    versionNumber,
    parentVersion:       parentVersion  ?? null,
    rootVersion:         rootVersion    ?? 1,
    eventType,
    occurredAt:          occurredAt     instanceof Date ? occurredAt : new Date(occurredAt),
    actorId:             actorId.trim(),
    actorUsername:       actorUsername.trim(),
    actorRole:           actorRole.trim(),
    sourceIp:            sourceIp.trim(),
    changeReason:        changeReason.trim(),
    changeNotes:         (changeNotes  || '').trim(),
    policyContent,
    policyHash,
    previousPolicyHash:  previousPolicyHash || null,
    diffStructured,
    diffHumanReadable,
    rolledBackToVersion: rolledBackToVersion || null,
  };
}

// ── Hash chain integrity verification ─────────────────────────────────────────

/**
 * Verify the hash chain over an ordered array of provenance version records.
 * Records must be sorted by version_number ASC.
 *
 * Each record is expected to have: version_number, policy_hash,
 * previous_policy_hash, policy_content.
 *
 * Returns { valid, checkedCount, failureVersion, failureDetail }.
 *
 * @param {object[]} versions — ordered ASC by version_number
 * @returns {{ valid: boolean, checkedCount: number, failureVersion: number|null, failureDetail: string|null }}
 */
function verifyChainIntegrity(versions) {
  if (!Array.isArray(versions) || versions.length === 0) {
    return { valid: true, checkedCount: 0, failureVersion: null, failureDetail: null };
  }

  let checkedCount = 0;
  let prevHash     = null;

  for (const v of versions) {
    const vNum           = v.version_number ?? v.versionNumber;
    const storedHash     = v.policy_hash     ?? v.policyHash;
    const storedPrevHash = v.previous_policy_hash ?? v.previousPolicyHash ?? null;
    const content        = v.policy_content  ?? v.policyContent;

    // Recompute hash from stored content
    let recomputedHash;
    try {
      recomputedHash = computePolicyHash(content);
    } catch (e) {
      return {
        valid:          false,
        checkedCount,
        failureVersion: vNum,
        failureDetail:  `Cannot recompute hash for version ${vNum}: ${e.message}`,
      };
    }

    // Check stored hash matches content
    if (recomputedHash !== storedHash) {
      return {
        valid:          false,
        checkedCount,
        failureVersion: vNum,
        failureDetail:  `Content hash mismatch at version ${vNum}: stored ${storedHash}, computed ${recomputedHash}`,
      };
    }

    // Check previous hash pointer matches prior iteration
    if (vNum === 1) {
      if (storedPrevHash !== null && storedPrevHash !== undefined) {
        return {
          valid:          false,
          checkedCount,
          failureVersion: vNum,
          failureDetail:  `Version 1 must have null previous_policy_hash, found: ${storedPrevHash}`,
        };
      }
    } else {
      if (prevHash !== null && storedPrevHash !== prevHash) {
        return {
          valid:          false,
          checkedCount,
          failureVersion: vNum,
          failureDetail:  `Chain break at version ${vNum}: expected prev_hash ${prevHash}, found ${storedPrevHash}`,
        };
      }
    }

    prevHash = storedHash;
    checkedCount++;
  }

  return { valid: true, checkedCount, failureVersion: null, failureDetail: null };
}

// ── Report data assembly ───────────────────────────────────────────────────────

/**
 * Assemble a provenance report summary for a policy from its version array.
 * Returns structured data suitable for JSON, CSV, or PDF rendering.
 *
 * @param {string}   policyId
 * @param {object[]} versions — from provenanceStore.getHistory()
 * @param {object}   [opts]
 * @param {string}   [opts.requestedBy]
 * @param {Date}     [opts.generatedAt]
 * @returns {object}
 */
function assembleReport(policyId, versions, opts) {
  const { requestedBy = 'system', generatedAt = new Date() } = opts || {};

  const rollbacks  = versions.filter(v => (v.event_type || v.eventType) === 'POLICY_ROLLED_BACK');
  const actorSet   = new Set(versions.map(v => v.actor_username || v.actorUsername));
  const firstEvent = versions.length ? versions[0] : null;
  const lastEvent  = versions.length ? versions[versions.length - 1] : null;

  const integrityResult = verifyChainIntegrity(
    [...versions].sort((a, b) => {
      const av = a.version_number ?? a.versionNumber;
      const bv = b.version_number ?? b.versionNumber;
      return av - bv;
    })
  );

  const eventTypeBreakdown = {};
  for (const v of versions) {
    const et = v.event_type || v.eventType || 'UNKNOWN';
    eventTypeBreakdown[et] = (eventTypeBreakdown[et] || 0) + 1;
  }

  return {
    reportType:      'POLICY_PROVENANCE',
    policyId,
    generatedAt:     generatedAt.toISOString(),
    requestedBy,
    summary: {
      totalVersions:   versions.length,
      totalActors:     actorSet.size,
      actors:          [...actorSet],
      rollbackCount:   rollbacks.length,
      firstVersion:    firstEvent ? {
        versionNumber:  firstEvent.version_number ?? firstEvent.versionNumber,
        occurredAt:     firstEvent.occurred_at ?? firstEvent.occurredAt,
        actorUsername:  firstEvent.actor_username ?? firstEvent.actorUsername,
        eventType:      firstEvent.event_type ?? firstEvent.eventType,
      } : null,
      latestVersion:   lastEvent ? {
        versionNumber:  lastEvent.version_number ?? lastEvent.versionNumber,
        occurredAt:     lastEvent.occurred_at ?? lastEvent.occurredAt,
        actorUsername:  lastEvent.actor_username ?? lastEvent.actorUsername,
        eventType:      lastEvent.event_type ?? lastEvent.eventType,
      } : null,
    },
    eventTypeBreakdown,
    integrityStatus: {
      valid:          integrityResult.valid,
      checkedCount:   integrityResult.checkedCount,
      failureVersion: integrityResult.failureVersion,
      failureDetail:  integrityResult.failureDetail,
    },
    rollbacks: rollbacks.map(v => ({
      versionNumber:      v.version_number ?? v.versionNumber,
      occurredAt:         v.occurred_at ?? v.occurredAt,
      actorUsername:      v.actor_username ?? v.actorUsername,
      rolledBackToVersion: v.rolled_back_to_version ?? v.rolledBackToVersion,
      changeReason:       v.change_reason ?? v.changeReason,
    })),
    versions: versions.map(v => ({
      versionNumber:  v.version_number    ?? v.versionNumber,
      eventType:      v.event_type        ?? v.eventType,
      occurredAt:     v.occurred_at       ?? v.occurredAt,
      actorId:        v.actor_id          ?? v.actorId,
      actorUsername:  v.actor_username    ?? v.actorUsername,
      actorRole:      v.actor_role        ?? v.actorRole,
      sourceIp:       v.source_ip         ?? v.sourceIp,
      changeReason:   v.change_reason     ?? v.changeReason,
      policyHash:     v.policy_hash       ?? v.policyHash,
      diffSummary:    _summariseDiff(v.diff_structured ?? v.diffStructured),
    })),
  };
}

function _summariseDiff(diff) {
  if (!Array.isArray(diff) || diff.length === 0) return 'no changes';
  const added    = diff.filter(c => c.op === 'ADDED').length;
  const removed  = diff.filter(c => c.op === 'REMOVED').length;
  const modified = diff.filter(c => c.op === 'MODIFIED').length;
  return [
    added    ? `${added} added`    : null,
    modified ? `${modified} modified` : null,
    removed  ? `${removed} removed` : null,
  ].filter(Boolean).join(', ') || 'no changes';
}

/**
 * Convert a versions array to CSV rows for export.
 * Returns a string with header row + data rows.
 *
 * @param {object[]} versions
 * @returns {string}
 */
function versionsToCSV(versions) {
  const headers = [
    'version_number', 'event_type', 'occurred_at',
    'actor_id', 'actor_username', 'actor_role', 'source_ip',
    'change_reason', 'policy_hash', 'previous_policy_hash',
    'diff_summary',
  ];

  // INJ-7: centralized sanitizer — neutralizes leading =/+/-/@ (spreadsheet
  // formula injection) in addition to standard quote-escaping.
  const escape = sanitizeCsvCell;

  const rows = versions.map(v => [
    v.version_number    ?? v.versionNumber    ?? '',
    v.event_type        ?? v.eventType        ?? '',
    v.occurred_at       ?? v.occurredAt       ?? '',
    v.actor_id          ?? v.actorId          ?? '',
    v.actor_username    ?? v.actorUsername    ?? '',
    v.actor_role        ?? v.actorRole        ?? '',
    v.source_ip         ?? v.sourceIp         ?? '',
    v.change_reason     ?? v.changeReason     ?? '',
    v.policy_hash       ?? v.policyHash       ?? '',
    v.previous_policy_hash ?? v.previousPolicyHash ?? '',
    _summariseDiff(v.diff_structured ?? v.diffStructured),
  ].map(escape).join(','));

  return [headers.join(','), ...rows].join('\n');
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  canonicalJson,
  computePolicyHash,
  generateStructuredDiff,
  generateHumanReadableDiff,
  validateAttributionContext,
  validateChangeReason,
  buildProvenanceRecord,
  verifyChainIntegrity,
  assembleReport,
  versionsToCSV,
};
