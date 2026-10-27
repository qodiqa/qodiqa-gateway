'use strict';

const fs = require('fs');
const path = require('path');

const CLASSIFIERS_DIR = path.join(__dirname, '..', 'classifier', 'classifiers');

let _autoDiscovered = null;
let _discoveryFailed = false;
let _discoveryErrorMessage = null;
let _forcedFailureMessage = null; // test-only, see _forceDiscoveryErrorForTests
const _registered = [];

/**
 * Dynamically discovers every classifier module under classifier/classifiers/.
 *
 * This is the architectural property that makes the engine extensible to
 * "hundreds of classifiers" without ever touching the engine itself: the
 * registry — not the engine — owns the list, and the list is derived from
 * the filesystem, not hardcoded. Dropping a new file in that directory is
 * the entire integration surface for adding a bundled classifier.
 *
 * remediation: discovery failure (missing/unreadable directory, a
 * classifier module that throws on require(), etc.) must never surface as
 * an uncaught exception here — that would either crash the request or, if
 * caught upstream and treated as "no classifiers," be silently interpreted
 * as "no attack" (see getClassifiersWithStatus()). Failure is recorded and
 * an empty list is returned instead; the caller is responsible for treating
 * that failure as a semantic-engine failure, never as a benign result.
 * Because failure is not memoized into `_autoDiscovered` (only success is),
 * a transient failure (e.g. a filesystem hiccup) self-heals on the very next
 * call without requiring a process restart.
 */
function _discover() {
  if (_forcedFailureMessage !== null) {
    _discoveryFailed = true;
    _discoveryErrorMessage = _forcedFailureMessage;
    return [];
  }
  if (_autoDiscovered) return _autoDiscovered;
  try {
    const discovered = fs.readdirSync(CLASSIFIERS_DIR)
      .filter((f) => f.endsWith('.js'))
      .map((f) => require(path.join(CLASSIFIERS_DIR, f)))
      .filter((mod) => mod && typeof mod.classify === 'function' && typeof mod.id === 'string');
    _autoDiscovered = discovered;
    _discoveryFailed = false;
    _discoveryErrorMessage = null;
    return _autoDiscovered;
  } catch (err) {
    _discoveryFailed = true;
    _discoveryErrorMessage = (err && err.message) || 'unknown classifier registry discovery error';
    return [];
  }
}

/**
 * Register an additional classifier at runtime. This is the extension point
 * for customer-specific plugins or versioned policy packs supplied outside
 * this directory (e.g. loaded from a separate npm package) — zero changes
 * to this module or to src/core/semantic/index.js are required to use it.
 *
 * @param {{ id: string, classify: (context: object) => object|null }} classifier
 */
function registerClassifier(classifier) {
  if (!classifier || typeof classifier.classify !== 'function' || typeof classifier.id !== 'string') {
    throw new Error('registerClassifier: classifier must implement { id, classify(context) }');
  }
  if (_registered.some((c) => c.id === classifier.id) || _discover().some((c) => c.id === classifier.id)) {
    throw new Error(`registerClassifier: a classifier with id "${classifier.id}" is already registered`);
  }
  _registered.push(classifier);
}

/**
 * @param {{ disabledClassifiers?: string[] }} [policy]
 * @returns {Array<{id:string, classify:Function}>}
 */
function getClassifiers(policy) {
  return getClassifiersWithStatus(policy).classifiers;
}

/**
 * Same as getClassifiers(), but also reports whether filesystem discovery
 * itself succeeded — the signal index.js needs to distinguish "the registry
 * legitimately has zero classifiers" (still a failure, remediation
 * requirement #6) from "discovery could not even run."
 *
 * @param {{ disabledClassifiers?: string[] }} [policy]
 * @returns {{ classifiers: Array<{id:string, classify:Function}>, registryStatus: 'OK'|'LOAD_FAILED', error: string|null }}
 */
function getClassifiersWithStatus(policy) {
  const discovered = _discover();
  const registryStatus = _discoveryFailed ? 'LOAD_FAILED' : 'OK';
  const disabled = new Set((policy && policy.disabledClassifiers) || []);
  const classifiers = [...discovered, ..._registered].filter((c) => !disabled.has(c.id));
  return {
    classifiers,
    registryStatus,
    error: _discoveryFailed ? _discoveryErrorMessage : null,
  };
}

// Test-only: clears runtime-registered classifiers between test files.
// Auto-discovered (bundled) classifiers are never cleared — they are a
// fixed property of the filesystem, not test-mutable state.
function _resetRegisteredForTests() {
  _registered.length = 0;
}

// Test-only: forces the next discovery attempt(s) to report failure without
// touching the real classifier files on disk — simulates "registry cannot
// be loaded" (unreadable directory, corrupt module, etc.) deterministically.
function _forceDiscoveryErrorForTests(message) {
  _forcedFailureMessage = message || 'forced test discovery failure';
  _autoDiscovered = null;
}

// Test-only: clears forced-failure state and the discovery cache so the
// next _discover() call re-reads the real classifier directory from scratch.
function _resetDiscoveryForTests() {
  _forcedFailureMessage = null;
  _autoDiscovered = null;
  _discoveryFailed = false;
  _discoveryErrorMessage = null;
}

module.exports = {
  getClassifiers,
  getClassifiersWithStatus,
  registerClassifier,
  _resetRegisteredForTests,
  _forceDiscoveryErrorForTests,
  _resetDiscoveryForTests,
};
