'use strict';

const fs       = require('fs');
const path     = require('path');
const REGISTRY = require('./evaluators/index');
const { logLoad }           = require('./log');
const { computePolicyHash } = require('../policyHash');

// Hard limits that apply to the policy file as a whole.
const MAX_POLICIES          = 100;
const MAX_CONFIG_KEYS       = 32;
const MAX_BLOCKLIST_ENTRIES = 1000;
const MAX_CIDR_ENTRIES      = 256;
const MAX_TIME_WINDOWS      = 50;

// Policy IDs must be printable ASCII, no whitespace, no special chars.
const POLICY_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

// Keys that must never appear in any config object.
const POISON_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// The only keys allowed at the policy-object root.  Any extra key is rejected
// — unknown fields indicate a typo or schema mismatch.
const ALLOWED_ROOT_KEYS = new Set(['id', 'type', 'priority', 'enabled', 'config']);

/**
 * Resolve the POLICY_FILE path.
 *
 * There are two independent call sites that each need their own choice of
 * "what to load if the operator didn't say" — server/startup.js (the boot-time
 * policy load) and src/core/policy/store.js (the admin-managed policy store's
 * one-time bootstrap import) — so the rule lives here once, not duplicated:
 *
 *   - POLICY_FILE set (any non-empty value)  → use it, in every environment.
 *   - POLICY_FILE unset AND NODE_ENV=production → THROW. There is no safe
 *     default in production. The repository-root policies.json is a demo/
 *     development fixture (an always-on BLOCK_IP rule, demo-tuned rate
 *     limits — see deploy/env/production.policies.example for a production-oriented
 *     template) and must never be silently assumed for a real deployment.
 *   - POLICY_FILE unset, not production      → return `defaultPath`. This is
 *     the existing, intentional developer convenience (`npm run dev` boots
 *     against the repo's own policies.json out of the box) and is
 *     unchanged by this remediation.
 *
 * @param {string} defaultPath - path to use outside production when
 *   POLICY_FILE is unset (each caller passes its own repo-root-relative
 *   policies.json path, computed from its own __dirname).
 * @returns {string} the resolved path — never validated for existence here;
 *   that is loadPolicies()'s job.
 * @throws {Error} with `.code = 'POLICY_FILE_REQUIRED'` in production when
 *   POLICY_FILE is not set.
 */
function resolvePolicyFilePath(defaultPath) {
  const configured = process.env.POLICY_FILE;
  if (configured) return configured;

  if (process.env.NODE_ENV === 'production') {
    const err = new Error(
      'POLICY_FILE is not set. Production deployments must explicitly choose a policy file — ' +
      'there is no safe default. The repository-root policies.json ships demo/development policy ' +
      'semantics (an always-on BLOCK_IP rule, demo-tuned rate limits) and must never be silently ' +
      'assumed for a production deployment. Copy deploy/env/production.policies.example to a path outside ' +
      'the repository (e.g. /opt/qodiqa/config/policies.json), review and adjust its policies for ' +
      'your deployment, then set POLICY_FILE=/path/to/your/policies.json. ' +
      'See docs/configuration/reference.md ("Policy Configuration") for the full contract.'
    );
    err.code = 'POLICY_FILE_REQUIRED';
    throw err;
  }

  return defaultPath;
}

/**
 * Load and validate a policy file from disk.
 * Throws on any error — callers must never serve requests if this throws.
 *
 * @param {string} filePath
 * @returns {ReadonlyArray}
 */
function loadPolicies(filePath) {
  const resolved = path.resolve(filePath);

  let raw;
  try {
    raw = fs.readFileSync(resolved, 'utf8');
  } catch (err) {
    throw new Error(`PolicyLoader: cannot read ${resolved} — ${err.message}`);
  }

  if (raw.length > 1_048_576) { // 1 MB hard cap
    throw new Error('PolicyLoader: policy file exceeds 1 MB size limit');
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`PolicyLoader: invalid JSON in ${resolved} — ${err.message}`);
  }

  const result = _validateAndPrepare(parsed);
  const hash   = computePolicyHash(result);
  logLoad('LOAD', { count: result.length, source: resolved, hash });
  return result;
}

/**
 * Validate a raw parsed policy document. Exported for direct use in tests.
 *
 * @param {object} doc
 * @returns {ReadonlyArray}
 */
function validateAndPrepare(doc) {
  return _validateAndPrepare(doc);
}

function _validateAndPrepare(doc) {
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new Error('PolicyLoader: document root must be a plain object');
  }

  _rejectPoisonKeys('doc', doc);

  if (!Array.isArray(doc.policies) || doc.policies.length === 0) {
    throw new Error('PolicyLoader: policies must be a non-empty array');
  }
  if (doc.policies.length > MAX_POLICIES) {
    throw new Error(`PolicyLoader: policy count exceeds maximum of ${MAX_POLICIES}`);
  }

  const seenIds = new Set();
  const prepared = [];

  for (let i = 0; i < doc.policies.length; i++) {
    const raw = doc.policies[i];
    const tag = `policy[${i}]`;

    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new Error(`PolicyLoader: ${tag} must be a plain object`);
    }

    _rejectPoisonKeys(tag, raw);
    _rejectUnknownKeys(tag, raw, ALLOWED_ROOT_KEYS);

    // id
    if (typeof raw.id !== 'string' || !POLICY_ID_RE.test(raw.id)) {
      throw new Error(
        `PolicyLoader: ${tag}.id must match /^[A-Za-z0-9_-]{1,64}$/ — got: ${JSON.stringify(raw.id)}`
      );
    }
    if (seenIds.has(raw.id)) {
      throw new Error(`PolicyLoader: duplicate policy id "${raw.id}"`);
    }

    // type
    if (!REGISTRY[raw.type]) {
      throw new Error(`PolicyLoader: unknown type "${raw.type}" in policy "${raw.id}"`);
    }

    // priority
    if (!Number.isInteger(raw.priority) || raw.priority < 0 || raw.priority > 999_999) {
      throw new Error(
        `PolicyLoader: priority must be an integer in [0, 999999] in policy "${raw.id}"`
      );
    }

    // enabled
    if (typeof raw.enabled !== 'boolean') {
      throw new Error(`PolicyLoader: enabled must be boolean in policy "${raw.id}"`);
    }

    // config
    if (raw.config === null || typeof raw.config !== 'object' || Array.isArray(raw.config)) {
      throw new Error(`PolicyLoader: config must be a plain object in policy "${raw.id}"`);
    }
    _rejectPoisonKeys(`${raw.id}.config`, raw.config);
    if (Object.keys(raw.config).length > MAX_CONFIG_KEYS) {
      throw new Error(
        `PolicyLoader: config in "${raw.id}" has more than ${MAX_CONFIG_KEYS} keys`
      );
    }

    seenIds.add(raw.id);

    const evaluator = REGISTRY[raw.type];

    // Type-specific config validation
    try {
      _validateConfigLimits(raw.type, raw.config, raw.id);
      evaluator.validate(raw.config);
    } catch (err) {
      throw new Error(`PolicyLoader: invalid config in policy "${raw.id}" — ${err.message}`);
    }

    // Preprocess — inject policyId so evaluators can build namespaced store keys
    let processedConfig;
    try {
      processedConfig = evaluator.preprocess({ ...raw.config, policyId: raw.id });
    } catch (err) {
      throw new Error(`PolicyLoader: preprocess failed for policy "${raw.id}" — ${err.message}`);
    }

    _rejectPoisonKeys(`${raw.id}.processedConfig`, processedConfig);

    prepared.push(Object.freeze({
      id:       raw.id,
      type:     raw.type,
      priority: raw.priority,
      enabled:  raw.enabled,
      config:   Object.freeze(processedConfig),
    }));
  }

  // Fail-closed: at least one enabled REQUIRE_CONSENT policy is mandatory.
  if (!prepared.some(p => p.type === 'REQUIRE_CONSENT' && p.enabled)) {
    throw new Error(
      'PolicyLoader: at least one enabled REQUIRE_CONSENT policy is required'
    );
  }

  // Stable priority sort (Array.sort is stable in Node ≥ 11).
  prepared.sort((a, b) => a.priority - b.priority);

  return Object.freeze(prepared);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function _rejectPoisonKeys(tag, obj) {
  for (const key of Object.keys(obj)) {
    if (POISON_KEYS.has(key)) {
      throw new Error(`PolicyLoader: ${tag} contains forbidden key "${key}"`);
    }
  }
}

function _rejectUnknownKeys(tag, obj, allowed) {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) {
      throw new Error(`PolicyLoader: ${tag} contains unknown key "${key}"`);
    }
  }
}

function _validateConfigLimits(type, config, id) {
  switch (type) {
    case 'BLOCK_IP':
      if (Array.isArray(config.blocklist) && config.blocklist.length > MAX_BLOCKLIST_ENTRIES) {
        throw new Error(`blocklist exceeds ${MAX_BLOCKLIST_ENTRIES} entries`);
      }
      if (Array.isArray(config.cidrs) && config.cidrs.length > MAX_CIDR_ENTRIES) {
        throw new Error(`cidrs exceeds ${MAX_CIDR_ENTRIES} entries`);
      }
      break;
    case 'TIME_WINDOW':
      if (Array.isArray(config.allowedWindows) && config.allowedWindows.length > MAX_TIME_WINDOWS) {
        throw new Error(`allowedWindows exceeds ${MAX_TIME_WINDOWS} entries`);
      }
      break;
  }
}

module.exports = { loadPolicies, validateAndPrepare, resolvePolicyFilePath };
