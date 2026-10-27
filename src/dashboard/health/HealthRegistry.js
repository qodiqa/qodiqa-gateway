'use strict';

/**
 * HealthRegistry — extensible component registration and status reporting.
 *
 * Components register themselves with a key, a human-readable display name,
 * and a zero-argument check function that returns a boolean.  The registry
 * calls each check lazily (at query time, not at registration time) so that
 * a component can report its current state.
 *
 * Check functions are always wrapped in try/catch — a throwing check is
 * treated as not ready (fail-closed).
 *
 * Designed for extension: any subsystem can register additional components
 * (e.g. database connections, external APIs, feature flags) without modifying
 * statusChecker.js.
 */
class HealthRegistry {
  constructor() {
    // Map<key, { displayName: string, check: () => boolean }>
    this._components = new Map();
  }

  /**
   * Register a health-check component.  Returns `this` for fluent chaining.
   *
   * @param {string}        key         — unique identifier (e.g. 'nonceStore')
   * @param {string}        displayName — human-readable label
   * @param {() => boolean} check       — returns true if the component is ready
   */
  register(key, displayName, check) {
    if (typeof key !== 'string' || !key)             throw new TypeError('HealthRegistry.register: key must be a non-empty string');
    if (typeof displayName !== 'string')             throw new TypeError('HealthRegistry.register: displayName must be a string');
    if (typeof check !== 'function')                 throw new TypeError('HealthRegistry.register: check must be a function');
    this._components.set(key, { displayName, check });
    return this;
  }

  /** Remove a component.  No-op if the key does not exist. */
  unregister(key) {
    this._components.delete(key);
    return this;
  }

  /** True if a component with the given key is registered. */
  has(key) {
    return this._components.has(key);
  }

  /** Keys of all registered components. */
  registeredKeys() {
    return [...this._components.keys()];
  }

  /**
   * Status for a single component.
   *
   * @returns {{ name: string, ready: boolean } | null}
   */
  getComponentStatus(key) {
    const comp = this._components.get(key);
    if (!comp) return null;
    let ready = false;
    try { ready = Boolean(comp.check()); } catch { ready = false; }
    return { name: comp.displayName, ready };
  }

  /**
   * Status for all registered components.
   *
   * @returns {Record<string, { name: string, ready: boolean }>}
   */
  getAllStatus() {
    const result = {};
    for (const key of this._components.keys()) {
      result[key] = this.getComponentStatus(key);
    }
    return result;
  }

  /**
   * True only when every registered component is ready.
   * Returns true when no components are registered (vacuously true).
   */
  isFullyReady() {
    for (const key of this._components.keys()) {
      const s = this.getComponentStatus(key);
      if (!s || !s.ready) return false;
    }
    return true;
  }

  /** executionIntegrity string: 'FULL' | 'DEGRADED' */
  executionIntegrity() {
    return this.isFullyReady() ? 'FULL' : 'DEGRADED';
  }
}

module.exports = { HealthRegistry };
