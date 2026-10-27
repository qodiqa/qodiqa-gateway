'use strict';

/**
 * ErasureTargetRegistry — operator extension point for GDPR DSR execution
 *.
 *
 * QODIQA's built-in DSR services (ErasureService, PortabilityService) only
 * ever know about consent_records/consent_audit_log — the stores QODIQA
 * itself owns. Operators frequently hold actor-linked PII in systems QODIQA
 * has no knowledge of (a CRM, a ticketing system, a billing database, a
 * proprietary table). This registry is the formal, additive extension point
 * that lets an operator plug such a store into DSR erasure/export without
 * modifying QODIQA core code.
 *
 * This module is intentionally a *registry only*: it stores and returns
 * ErasureTarget objects and nothing else. It never calls a target's
 * callbacks, never touches DSRStore, never writes audit evidence — that
 * orchestration lives in ErasureService.js/PortabilityService.js, which are
 * the only code paths that invoke registered targets, exactly as they are
 * the only code paths that touch the built-in stores. Keeping business
 * logic out of the registry is what keeps it trivially safe to reason
 * about: register/unregister/list, nothing else.
 *
 * ─── The ErasureTarget interface ──────────────────────────────────────────
 *
 *   {
 *     id:     string,              // required, unique, stable across restarts
 *     name:   string,              // required, human-readable (for audit/logs)
 *     erase:  async (context) => any,   // required
 *     export: async (context) => any,   // optional — omit if the store does
 *                                        // not support portability
 *   }
 *
 * `context`, passed by the caller (ErasureService/PortabilityService) to
 * every callback, is intentionally minimal — just enough to perform an
 * actor-scoped operation, nothing about QODIQA's internal request/DB shape:
 *
 *   {
 *     actorId:     string,         // the data subject's actor_id
 *     tenantId:    string | null,  // tenant scope, if applicable
 *     requestId:   string,         // the DSR request this invocation belongs to
 *     requestType: 'ERASURE' | 'PORTABILITY',
 *     performedBy: string,         // the operator/actor executing the DSR request
 *   }
 *
 * A callback's return value is opaque to QODIQA: it is recorded verbatim as
 * that target's `result` in the DSR response and audit trail (so return
 * only what should be visible there — e.g. a count of rows erased, not raw
 * PII). A callback that throws causes that one target's invocation to be
 * recorded as a failure; it never aborts the rest of the DSR request (see
 * ErasureService.js/PortabilityService.js for the isolation boundary).
 *
 * ─── Registration model ───────────────────────────────────────────────────
 *
 * Explicit only. No filesystem scanning, no plugin loading, no reflection,
 * no DI container — an operator calls `registerTarget(myTarget)` directly
 * during application startup, exactly once per target. This keeps startup
 * deterministic and keeps "what stores does this deployment erase from"
 * fully visible by reading that startup code.
 *
 * ─── Determinism ──────────────────────────────────────────────────────────
 *
 * Targets are invoked in **registration order**. This is implemented with a
 * plain array (push/splice), never a plain-object key set, specifically so
 * ordering never depends on JavaScript's object-key iteration rules —
 * insertion order into an array is unambiguous and requires no special
 * knowledge of engine behavior to reason about.
 *
 * ─── Thread safety ────────────────────────────────────────────────────────
 *
 * All operations here are synchronous and mutate a single module-local
 * array. Node.js's single-threaded event loop means there is no
 * interleaving hazard as long as callers don't `await` in the middle of a
 * register/unregister call (they don't need to — both are synchronous).
 * `getTargets()` returns a shallow copy so callers can never mutate the
 * registry's internal state through the returned array.
 */

let _targets = [];

function _assertValidTarget(target) {
  if (!target || typeof target !== 'object') {
    throw new Error('ErasureTarget must be an object');
  }
  if (typeof target.id !== 'string' || target.id.trim() === '') {
    throw new Error('ErasureTarget.id is required and must be a non-empty string');
  }
  if (typeof target.name !== 'string' || target.name.trim() === '') {
    throw new Error(`ErasureTarget '${target.id}': name is required and must be a non-empty string`);
  }
  if (typeof target.erase !== 'function') {
    throw new Error(`ErasureTarget '${target.id}': erase must be a function`);
  }
  if (target.export !== undefined && typeof target.export !== 'function') {
    throw new Error(`ErasureTarget '${target.id}': export must be a function if provided`);
  }
}

/**
 * Register an operator-defined DSR extension target. Explicit, synchronous,
 * additive — call once per target during application startup.
 *
 * @param {object} target - see the ErasureTarget interface above
 * @returns {object} the registered target (unchanged)
 * @throws {Error} if the target is malformed or its id is already registered
 */
function registerTarget(target) {
  _assertValidTarget(target);
  if (_targets.some((t) => t.id === target.id)) {
    throw new Error(`ErasureTarget with id '${target.id}' is already registered`);
  }
  _targets.push(target);
  return target;
}

/**
 * Remove a previously-registered target by id.
 *
 * @param {string} id
 * @returns {boolean} true if a target was removed, false if no target had that id
 */
function unregisterTarget(id) {
  const index = _targets.findIndex((t) => t.id === id);
  if (index === -1) return false;
  _targets.splice(index, 1);
  return true;
}

/**
 * @returns {object[]} registered targets, in registration order. A shallow
 *   copy — mutating the returned array never affects the registry.
 */
function getTargets() {
  return _targets.slice();
}

/**
 * Test-only utility: reset the registry to empty. Not intended for
 * production use — a running deployment's registered targets are expected
 * to be stable for the process lifetime, set up once at startup.
 */
function clear() {
  _targets = [];
}

module.exports = { registerTarget, unregisterTarget, getTargets, clear };
