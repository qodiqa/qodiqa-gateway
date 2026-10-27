'use strict';

/**
 * Tenant Semantic Configuration Registry —
 
 *
 * In-memory map tenantId → tighten-only semantic overlay, hydrated from
 * PostgreSQL (tenant_semantic_configs) by tenantConfigHydrator.js and
 * updated in-place by the governed publish step. A tenant with no
 * entry gets the pinned defaults — every consumer's null branch is the
 * unchanged pre-M-03 code path, byte-for-byte.
 *
 * ── The tighten-only invariant (non-negotiable) ─────────────────────────────
 * A tenant overlay may only TIGHTEN relative to the deployment's pinned
 * defaults — never loosen, never disable a gate, never change FT flags.
 * The schema is strict (unknown keys rejected), so loosening is not even
 * expressible:
 *
 *   thresholds.WARN / .REVIEW / .DENY  — each ≤ the default tier threshold
 *                                        0.70 pinned defaults) and > 0.
 *   enforcement.WARN_BLOCKS            — only `true` accepted (default
 *                                        false; enabling is a tightening).
 *                                        REVIEW_BLOCKS is NOT a key — its
 *                                        default `true` could only be
 *                                        loosened, so expressing it at all
 *                                        is rejected.
 *   embedding.scoreThreshold           — in (0, SIMILARITY_THRESHOLD]
 *                                        (pinned global 0.48). Applied as an
 *                                        ADDITIONAL post-classify bar in
 *                                        embeddingGate.js — classify()
 *                                        itself is untouched.
 *
 * Enforced TWICE: validateTightenOnly() rejects at write time (
 * draft validation), and clampToDefaults() clamps at load time (hydration)
 * with a TENANT_SEMANTIC_CONFIG_CLAMPED WARN — so even a tampered or
 * hand-edited PG row cannot loosen a running system.
 *
 * The bounds are read from the LIVE deployment configuration
 * (loadSemanticPolicy() / embeddingSimilarity config) rather than
 * hard-coded copies, so a deployment that already tightened its global
 * defaults via env cannot be loosened back by a tenant either.
 *
 * tighten-only keeps those figures valid lower bounds on detection for
 * every tenant configuration reachable through the API.
 */

const crypto = require('crypto');
const stableStringify = require('../../utils/stableStringify');
const { loadSemanticPolicy } = require('../semantic/policies/semanticPolicy');

const _configs = new Map(); // tenantId → frozen { config, hash, version }

// disclosureNotice is the tenant's end-user AI-disclosure
// wording (EU AI Act Art. 50) — carried by the same governed publish path, but
// it is text shown to users, never a semantic control: it has no effect on any
// decision and is validated only as plain text (1..DISCLOSURE_NOTICE_MAX chars,
// no control characters).
const ALLOWED_TOP_KEYS        = new Set(['thresholds', 'enforcement', 'embedding', 'disclosureNotice']);
const DISCLOSURE_NOTICE_MAX   = 280;
// eslint-disable-next-line no-control-regex
const _validNotice = (v) => typeof v === 'string' && v.trim().length >= 1 && v.length <= DISCLOSURE_NOTICE_MAX && !/[\u0000-\u001f\u007f]/.test(v);
const ALLOWED_THRESHOLD_KEYS  = new Set(['WARN', 'REVIEW', 'DENY']);
const ALLOWED_ENFORCEMENT_KEYS = new Set(['WARN_BLOCKS']);
const ALLOWED_EMBEDDING_KEYS  = new Set(['scoreThreshold']);

/** The deployment's pinned bounds, resolved live (see header). */
function pinnedDefaults() {
  const policy = loadSemanticPolicy();
  // Required lazily: embeddingSimilarity/config.js pulls in the model
  // integrity surface; the tier-threshold half of this registry must work
  // even in unit suites that never touch the embedding layer.
  const { SIMILARITY_THRESHOLD } = require('../semantic/embeddingSimilarity/config');
  return {
    thresholds: { ...policy.thresholds },
    enforcement: { WARN_BLOCKS: policy.enforcement.WARN_BLOCKS },
    embedding: { scoreThreshold: SIMILARITY_THRESHOLD },
  };
}

function configHash(config) {
  return crypto.createHash('sha256').update(stableStringify(config)).digest('hex');
}

/**
 * Write-time validation: strict schema + tighten-only.
 * @returns {{ok: boolean, errors: string[]}}
 */
function validateTightenOnly(config) {
  const errors = [];
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    return { ok: false, errors: ['config must be a plain object'] };
  }
  const defaults = pinnedDefaults();

  for (const key of Object.keys(config)) {
    if (!ALLOWED_TOP_KEYS.has(key)) errors.push(`unknown key "${key}" — not representable in tenant semantic config`);
  }

  const t = config.thresholds;
  if (t !== undefined) {
    if (!t || typeof t !== 'object' || Array.isArray(t)) errors.push('thresholds must be a plain object');
    else {
      for (const key of Object.keys(t)) {
        if (!ALLOWED_THRESHOLD_KEYS.has(key)) { errors.push(`unknown thresholds key "${key}"`); continue; }
        const v = t[key];
        if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0) {
          errors.push(`thresholds.${key} must be a finite number > 0`);
        } else if (v > defaults.thresholds[key]) {
          errors.push(`thresholds.${key}=${v} would LOOSEN the pinned default ${defaults.thresholds[key]} — tenant config may only tighten`);
        }
      }
    }
  }

  const e = config.enforcement;
  if (e !== undefined) {
    if (!e || typeof e !== 'object' || Array.isArray(e)) errors.push('enforcement must be a plain object');
    else {
      for (const key of Object.keys(e)) {
        if (!ALLOWED_ENFORCEMENT_KEYS.has(key)) { errors.push(`unknown enforcement key "${key}" — only WARN_BLOCKS is tenant-configurable (tighten-only)`); continue; }
        if (e[key] !== true) errors.push(`enforcement.${key} may only be set to true — false is the loosening direction`);
      }
    }
  }

  const m = config.embedding;
  if (m !== undefined) {
    if (!m || typeof m !== 'object' || Array.isArray(m)) errors.push('embedding must be a plain object');
    else {
      for (const key of Object.keys(m)) {
        if (!ALLOWED_EMBEDDING_KEYS.has(key)) { errors.push(`unknown embedding key "${key}"`); continue; }
        const v = m[key];
        if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0) {
          errors.push('embedding.scoreThreshold must be a finite number > 0');
        } else if (v > defaults.embedding.scoreThreshold) {
          errors.push(`embedding.scoreThreshold=${v} would LOOSEN the pinned global threshold ${defaults.embedding.scoreThreshold} — tenant config may only tighten`);
        }
      }
    }
  }

  if (config.disclosureNotice !== undefined && !_validNotice(config.disclosureNotice)) {
    errors.push(`disclosureNotice must be plain text, 1-${DISCLOSURE_NOTICE_MAX} characters, no control characters`);
  }

  return { ok: errors.length === 0, errors };
}

/**
 * Load-time clamp (hydration): any stored value that would loosen is forced
 * back to the default and reported, any non-representable key is dropped.
 * Never throws — a tampered row degrades to the pinned defaults, field by
 * field, and the caller emits TENANT_SEMANTIC_CONFIG_CLAMPED with `changes`.
 * @returns {{config: object, changes: string[]}}
 */
function clampToDefaults(config) {
  const changes = [];
  const defaults = pinnedDefaults();
  const out = {};
  const src = (config && typeof config === 'object' && !Array.isArray(config)) ? config : {};
  if (src !== config) changes.push('config was not an object — replaced with pinned defaults');

  if (src.thresholds && typeof src.thresholds === 'object' && !Array.isArray(src.thresholds)) {
    const t = {};
    for (const key of ALLOWED_THRESHOLD_KEYS) {
      const v = src.thresholds[key];
      if (v === undefined) continue;
      if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0) {
        changes.push(`thresholds.${key} invalid — dropped (default applies)`);
      } else if (v > defaults.thresholds[key]) {
        t[key] = defaults.thresholds[key];
        changes.push(`thresholds.${key}=${v} loosens default ${defaults.thresholds[key]} — clamped`);
      } else {
        t[key] = v;
      }
    }
    for (const key of Object.keys(src.thresholds)) {
      if (!ALLOWED_THRESHOLD_KEYS.has(key)) changes.push(`thresholds.${key} not representable — dropped`);
    }
    if (Object.keys(t).length) out.thresholds = t;
  }

  if (src.enforcement && typeof src.enforcement === 'object' && !Array.isArray(src.enforcement)) {
    if (src.enforcement.WARN_BLOCKS === true) out.enforcement = { WARN_BLOCKS: true };
    else if (src.enforcement.WARN_BLOCKS !== undefined) changes.push('enforcement.WARN_BLOCKS!==true is the loosening direction — dropped');
    for (const key of Object.keys(src.enforcement)) {
      if (!ALLOWED_ENFORCEMENT_KEYS.has(key)) changes.push(`enforcement.${key} not representable — dropped`);
    }
  }

  if (src.embedding && typeof src.embedding === 'object' && !Array.isArray(src.embedding)) {
    const v = src.embedding.scoreThreshold;
    if (v !== undefined) {
      if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0) {
        changes.push('embedding.scoreThreshold invalid — dropped');
      } else if (v > defaults.embedding.scoreThreshold) {
        out.embedding = { scoreThreshold: defaults.embedding.scoreThreshold };
        changes.push(`embedding.scoreThreshold=${v} loosens global ${defaults.embedding.scoreThreshold} — clamped`);
      } else {
        out.embedding = { scoreThreshold: v };
      }
    }
    for (const key of Object.keys(src.embedding)) {
      if (!ALLOWED_EMBEDDING_KEYS.has(key)) changes.push(`embedding.${key} not representable — dropped`);
    }
  }

  if (src.disclosureNotice !== undefined) {
    if (_validNotice(src.disclosureNotice)) out.disclosureNotice = src.disclosureNotice;
    else changes.push('disclosureNotice invalid — dropped (platform default applies)');
  }

  for (const key of Object.keys(src)) {
    if (!ALLOWED_TOP_KEYS.has(key)) changes.push(`${key} not representable — dropped`);
  }

  return { config: out, changes };
}

/**
 * Registry write (hydrator / publish step only — never a request path).
 * The caller passes the ALREADY validated-or-clamped config; this function
 * re-clamps defensively (belt and braces: the registry itself can never
 * hold a loosening value, whoever called it).
 */
function setConfig(tenantId, config, { version = 1 } = {}) {
  if (typeof tenantId !== 'string' || !tenantId) throw new Error('TENANT_CONTEXT_MISSING');
  const { config: safe } = clampToDefaults(config);
  _configs.set(tenantId, Object.freeze({
    config: Object.freeze(JSON.parse(JSON.stringify(safe))),
    hash: configHash(safe),
    version,
  }));
}

/**
 * Request-path read. Returns null for a tenant with no config — every
 * caller's null branch is the unchanged default code path.
 * @returns {{config: object, hash: string, version: number}|null}
 */
function getConfig(tenantId) {
  if (!tenantId) return null;
  return _configs.get(tenantId) || null;
}

/**
 * The effective semantic-policy overlay for the keyword engine: pinned
 * defaults merged with the tenant's (already tighten-only) values. Returns
 * null when the tenant has no config — the engine then uses its unmodified
 * loadSemanticPolicy() object.
 */
function getEffectivePolicyOverlay(tenantId, basePolicy) {
  const entry = getConfig(tenantId);
  if (!entry) return null;
  const c = entry.config;
  const thresholds = { ...basePolicy.thresholds };
  if (c.thresholds) {
    for (const key of Object.keys(c.thresholds)) {
      // min() is redundant after clamp — kept so the overlay is monotone
      // tightening BY CONSTRUCTION regardless of registry contents.
      thresholds[key] = Math.min(thresholds[key], c.thresholds[key]);
    }
  }
  const enforcement = {
    WARN_BLOCKS: basePolicy.enforcement.WARN_BLOCKS || c.enforcement?.WARN_BLOCKS === true,
    REVIEW_BLOCKS: basePolicy.enforcement.REVIEW_BLOCKS, // never tenant-touchable
  };
  return Object.freeze({
    ...basePolicy,
    thresholds: Object.freeze(thresholds),
    enforcement: Object.freeze(enforcement),
    tenantConfig: Object.freeze({ hash: entry.hash, version: entry.version, source: 'TENANT' }),
  });
}

/** The tenant's embedding tightening bar, or null (no additional check). */
function getEmbeddingScoreThreshold(tenantId) {
  const entry = getConfig(tenantId);
  const v = entry?.config?.embedding?.scoreThreshold;
  return (typeof v === 'number' && Number.isFinite(v) && v > 0) ? v : null;
}

/** (D9-A): the tenant's AI-disclosure wording, or null (caller applies the platform default). */
function getDisclosureNotice(tenantId) {
  return getConfig(tenantId)?.config?.disclosureNotice ?? null;
}

function deleteConfig(tenantId) { _configs.delete(tenantId); }
function listTenantIds() { return [..._configs.keys()]; }
function _reset() { _configs.clear(); }

module.exports = {
  pinnedDefaults,
  configHash,
  validateTightenOnly,
  clampToDefaults,
  setConfig,
  getConfig,
  getEffectivePolicyOverlay,
  getEmbeddingScoreThreshold,
  getDisclosureNotice,
  DISCLOSURE_NOTICE_MAX,
  deleteConfig,
  listTenantIds,
  _reset,
};
