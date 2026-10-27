'use strict';

/**
 * Tenant Policy Floor — (residual;
 *).
 *
 * made a tenant policy set REPLACE the global set for that tenant
 * (docs/architecture/multi-tenancy.md §8). Unmoderated, that let a tenant set drop
 * REQUIRE_CONSENT or any other global enforcement policy outright — the
 * tighten-only principle established for semantic config had no
 * counterpart at the policy layer. This module is that counterpart.
 *
 * ── The floor ────────────────────────────────────────────────────────────
 * Every currently-ENABLED global policy is floor material. This engine
 * (services/policy/engine.js) has exactly four policy types — REQUIRE_CONSENT,
 * BLOCK_IP, RATE_LIMIT, TIME_WINDOW — and all four are enforcement/denial by
 * construction (first-BLOCK-wins over the AND of every enabled policy; there
 * is no informational/advisory type). "REQUIRE_CONSENT plus every global
 * policy whose effect is enforcement/denial" is therefore exactly "every
 * enabled global policy" in this system, and the loader's own invariant
 * (services/policy/loader.js: "at least one enabled REQUIRE_CONSENT policy
 * is required") guarantees REQUIRE_CONSENT is always present in it.
 *
 * A DISABLED global policy is not floor material — it enforces nothing
 * today, so there is nothing for a tenant to bypass. Read LIVE off the
 * global store (src/core/policy/store.js#listEnabledPolicies), never a
 * hardcoded copy — the same live-read discipline
 * tenantSemanticRegistry.pinnedDefaults() already uses, so raising the
 * global bar raises every tenant's floor with zero extra code.
 *
 * ── Enforcement (mirrors's two layers exactly) ─────────────────────
 * checkEntryAgainstFloor() is the write-time invariant: PolicyGovernanceService
 * calls it at draft() and at publish() (defense in depth) for the one entry a
 * change request would produce, and REJECTS (VALIDATION_FAILED, naming the
 * floor policy) a CREATE/UPDATE that would leave a floor id disabled,
 * retyped, or config-loosened, and any DISABLE/ARCHIVE of a floor id.
 * Tightening a floor policy's parameters, or leaving it out of the tenant
 * set entirely, is always allowed — omission is closed by the read side.
 *
 * clampEntries() is the load-time defence: tenantConfigHydrator calls it on
 * every stored tenant policy set and restores (in place) any entry that
 * collides with a floor id but is non-compliant — belt and braces against a
 * tampered/hand-edited PG row, mirroring
 * tenantSemanticRegistry.clampToDefaults(). It never adds a floor id that is
 * simply absent — that is not a violation of anything stored, and would
 * inflate every admin policyCount read for no reason.
 *
 * mergeForEvaluation() is the actual floor union — floor ∪ tenant set — read
 * fresh on every /ai/chat evaluation (tenantPolicyRegistry.
 * getEffectivePoliciesForTenant), so a tenant whose set has never mentioned
 * REQUIRE_CONSENT (or any other floor policy) is still bound by it, with no
 * write-time gap and no cross-replica propagation delay.
 *
 * ── preprocessing moved to the write boundary ─────────────────────
 * mergeForEvaluation() preprocessing every entry (below) was, until
 * the ONLY place a tenant-native policy's config ever ran through its
 * evaluator's preprocess() step — the governed publish path
 * (PolicyGovernanceService._applyTenantPublish) and the hydrator
 * (tenantConfigHydrator._applyPolicySets) both wrote raw config straight
 * into tenantPolicyRegistry, so any future reader of
 * tenantPolicyRegistry.getPoliciesForTenant() (the raw getter) that called
 * evaluate() directly — bypassing getEffectivePoliciesForTenant() — would
 * reproduce the exact EVALUATOR_ERROR class this module was built to fix.
 * preprocessEntry() (exported below) is now the single shared
 * implementation: PolicyGovernanceService and tenantConfigHydrator both run
 * every tenant-native entry through it BEFORE calling
 * tenantPolicyRegistry.setPolicies(), so the in-memory registry itself is
 * evaluator-ready — "stored", not just "merged". PostgreSQL keeps storing
 * the RAW candidate config (human-diffable, JSON-safe — preprocess()'s
 * Set-typed derived fields, e.g. BLOCK_IP's _blocklistSet, do not survive a
 * JSON round trip), so hydration re-runs preprocessEntry() on every boot and
 * every periodic refresh regardless of whether the PG row predates the fix
 * — safe because every evaluator's preprocess() is idempotent (it derives
 * fields fresh from the surviving raw keys each time; verified by the
 * idempotency pin in tenantPolicyFloor.test.js). mergeForEvaluation() below
 * is UNCHANGED and keeps calling preprocessEntry() on every merged entry —
 * now a defensive second line (idempotent no-op for an already-preprocessed
 * tenant-native entry) rather than the only line, and still the ONLY place
 * floor entries (always raw — they come straight from
 * policyStore.listEnabledPolicies(), which never preprocesses) get made
 * evaluator-ready.
 */

const policyStore = require('../policy/store');
const evaluatorRegistry = require('../../../services/policy/evaluators');
const { computeRuleHash } = require('../../../services/policyHash');

function getFloorPolicies() {
  return policyStore.listEnabledPolicies();
}

function getFloorPolicy(id) {
  return getFloorPolicies().find((p) => p.id === id) || null;
}

function isFloorPolicyId(id) {
  return getFloorPolicies().some((p) => p.id === id);
}

function _isTimeWindowSubset(candidateWindows, floorWindows) {
  if (!Array.isArray(floorWindows) || floorWindows.length === 0) return true;
  if (!Array.isArray(candidateWindows)) return false;
  // Every floor window must be covered by an equal-or-narrower candidate
  // window on exactly the same set of days.
  return floorWindows.every((fw) => candidateWindows.some((cw) =>
    Array.isArray(cw?.days) && Array.isArray(fw?.days)
    && fw.days.every((d) => cw.days.includes(d))
    && cw.days.every((d) => fw.days.includes(d))
    && cw.start >= fw.start && cw.end <= fw.end));
}

/**
 * Is `config` at least as strict as `floorConfig` for `type`?
 * @returns {{ok: true} | {ok: false, reason: string}}
 */
function _configAtLeastAsStrict(type, config, floorConfig) {
  const cfg = (config && typeof config === 'object' && !Array.isArray(config)) ? config : {};
  const floorCfg = floorConfig || {};
  switch (type) {
    case 'REQUIRE_CONSENT':
      if (cfg.requireValidArtifact !== true) {
        return { ok: false, reason: 'requireValidArtifact must remain true' };
      }
      if (floorCfg.requiredScope != null && cfg.requiredScope !== floorCfg.requiredScope) {
        return { ok: false, reason: `requiredScope must remain "${floorCfg.requiredScope}"` };
      }
      return { ok: true };

    case 'BLOCK_IP': {
      const floorList  = new Set(floorCfg.blocklist || []);
      const floorCidrs = new Set(floorCfg.cidrs || []);
      const candList  = new Set(cfg.blocklist || []);
      const candCidrs = new Set(cfg.cidrs || []);
      for (const ip of floorList) if (!candList.has(ip)) return { ok: false, reason: `blocklist must still include "${ip}"` };
      for (const c of floorCidrs) if (!candCidrs.has(c)) return { ok: false, reason: `cidrs must still include "${c}"` };
      return { ok: true };
    }

    case 'RATE_LIMIT': {
      const fMax = floorCfg.maxRequests, fWin = floorCfg.windowSeconds;
      const cMax = cfg.maxRequests, cWin = cfg.windowSeconds;
      if (!(typeof cMax === 'number' && typeof cWin === 'number' && cWin > 0)) {
        return { ok: false, reason: 'maxRequests/windowSeconds must be present and numeric' };
      }
      if (!(typeof fMax === 'number' && typeof fWin === 'number' && fWin > 0)) {
        return { ok: true }; // floor itself has no comparable rate — nothing to be stricter than
      }
      const floorRate = fMax / fWin;
      const candRate  = cMax / cWin;
      if (candRate > floorRate) {
        return { ok: false, reason: `rate ${cMax}/${cWin}s exceeds the floor rate ${fMax}/${fWin}s` };
      }
      return { ok: true };
    }

    case 'TIME_WINDOW':
      return _isTimeWindowSubset(cfg.allowedWindows, floorCfg.allowedWindows)
        ? { ok: true }
        : { ok: false, reason: 'allowedWindows must stay within the floor window' };

    default: {
      // rule types added after the original four (DLP, ABAC, BUDGET, CONTENT_RULE, DATA_RESIDENCY, DATA_RETENTION) have no partial order of "stricter" -
      // a tenant entry that shares a floor id must carry exactly the floor's configuration (same canonical content hash). Anything else, and any unknown type, is refused.
      if (!evaluatorRegistry[type]) return { ok: false, reason: `unknown floor policy type "${type}"` };
      try {
        const h = (c) => computeRuleHash({ id: 'floor', type, priority: 0, enabled: true, config: c });
        return h(cfg) === h(floorCfg) ? { ok: true } : { ok: false, reason: `a ${type} floor policy cannot be changed per tenant (the configuration must equal the floor's)` };
      } catch { return { ok: false, reason: `a ${type} floor policy cannot be compared; refused` }; }
    }
  }
}

/**
 * Checks one hypothetical resulting tenant-policy entry — the outcome of a
 * single CREATE/UPDATE/ENABLE/DISABLE/ARCHIVE — against the floor. A no-op
 * ({ok:true}) whenever the entry's id is not a floor id at all.
 * @returns {{ok: true} | {ok: false, floorPolicyId: string, reason: string}}
 */
function checkEntryAgainstFloor(entry) {
  if (!entry || typeof entry.id !== 'string') return { ok: true };
  const floor = getFloorPolicy(entry.id);
  if (!floor) return { ok: true };

  if (entry.enabled !== true) {
    return { ok: false, floorPolicyId: floor.id, reason: `policy "${floor.id}" is a floor policy (${floor.type}) and cannot be disabled per tenant` };
  }
  if (entry.type !== floor.type) {
    return { ok: false, floorPolicyId: floor.id, reason: `policy "${floor.id}" is a floor policy of type ${floor.type} and cannot be retyped` };
  }
  const cmp = _configAtLeastAsStrict(floor.type, entry.config, floor.config);
  if (!cmp.ok) {
    return { ok: false, floorPolicyId: floor.id, reason: `policy "${floor.id}" is a floor policy — ${cmp.reason}` };
  }
  return { ok: true };
}

/**
 * Load-time clamp (hydration): restores, in place, any stored entry that
 * collides with a floor id but is non-compliant. Never adds a missing floor
 * id (that is not a stored violation — see module header). Never throws.
 * @returns {{policies: object[], changes: string[]}}
 */
function clampEntries(tenantPolicies) {
  const changes = [];
  const arr = Array.isArray(tenantPolicies) ? tenantPolicies.map((p) => ({ ...p })) : [];
  for (let i = 0; i < arr.length; i++) {
    const check = checkEntryAgainstFloor(arr[i]);
    if (!check.ok) {
      const floor = getFloorPolicy(arr[i].id);
      arr[i] = { ...arr[i], type: floor.type, priority: floor.priority, enabled: true, config: floor.config };
      changes.push(`${check.reason} — restored to the floor definition`);
    }
  }
  return { policies: arr, changes };
}

/**
 * Runs one policy entry's config through its evaluator's preprocess() step
 * — the same transform services/policy/loader.js applies to every GLOBAL
 * policy at load time (policyId injected into the config, then type-specific
 * derived fields: BLOCK_IP's _blocklistSet/_cidrRanges, etc.).
 *
 * Exported — the single shared implementation used at every write
 * boundary that populates tenantPolicyRegistry (PolicyGovernanceService's
 * governed publish, tenantConfigHydrator's boot/refresh hydration) AND by
 * mergeForEvaluation() below (defensive second line + the only place floor
 * entries, always raw, get preprocessed). Idempotent — safe to run twice on
 * an already-preprocessed entry, because every evaluator derives its
 * fields fresh from the surviving raw keys (config.blocklist, config.cidrs,
 * config.allowedWindows) rather than from any previous derived field.
 *
 *nothing ever ran this step over a STORED tenant policy —
 * store.js#validatePolicyCandidate() calls preprocess() internally for
 * VALIDATION only and discards the result, so BLOCK_IP's evaluate()
 * (config._blocklistSet.has(ip)) threw EVALUATOR_ERROR on every request
 * touching a floor or tenant-published BLOCK_IP entry, degrading to a
 * blanket BLOCK regardless of the actual IP. Discovered building this
 * module (AT-104's polled EXECUTE check is strict enough to catch it;
 * AT-103's looser "decision === BLOCK" assertion was not, until
 * tightened it). Never applied at the comparator (checkEntryAgainstFloor/
 * clampEntries stay on raw config, unaffected) or to what PostgreSQL stores
 * (preprocess()'s Set-typed derived fields are not JSON-safe).
 */
function preprocessEntry(entry) {
  const evaluator = evaluatorRegistry[entry.type];
  if (!evaluator || typeof evaluator.preprocess !== 'function') return entry;
  try {
    return { ...entry, config: evaluator.preprocess({ ...entry.config, policyId: entry.id }) };
  } catch {
    // A config that fails to preprocess surfaces via EVALUATOR_ERROR at
    // evaluation time either way — same fail-closed outcome as today,
    // just not masked as a silent pass-through here.
    // gate N-03: derived (underscore) keys are never trusted from a stored row - a forged `_appliesTo` / `_when` must not survive a failed preprocess
    const clean = {};
    for (const [k, v] of Object.entries(entry.config || {})) if (!k.startsWith('_')) clean[k] = v;
    return { ...entry, config: clean };
  }
}

/**
 * The effective policy set for evaluation: floor ∪ tenant set. Starts from
 * clampEntries() (so a tampered stored entry is repaired even here), then
 * appends any floor id the tenant set never mentioned at all, then
 * preprocesses every entry (floor and tenant-native alike) the same way the
 * global loader does. Recomputed fresh on every call — no write-time gap,
 * no cross-replica propagation delay (see module header).
 * @returns {object[]}
 */
function mergeForEvaluation(tenantPolicies) {
  const { policies: clamped } = clampEntries(tenantPolicies);
  const present = new Set(clamped.map((p) => p.id));
  const merged = clamped.slice();
  for (const f of getFloorPolicies()) {
    if (!present.has(f.id)) {
      merged.push({ id: f.id, type: f.type, priority: f.priority, enabled: true, config: f.config });
    }
  }
  // F8V-05: evaluation order is priority order (as the global loader sorts it), ties broken by id - never the stored order or "floor last"
  merged.sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0) || String(a.id).localeCompare(String(b.id)));
  return merged.map(preprocessEntry);
}

module.exports = {
  getFloorPolicies,
  getFloorPolicy,
  isFloorPolicyId,
  checkEntryAgainstFloor,
  clampEntries,
  mergeForEvaluation,
  preprocessEntry,
};
