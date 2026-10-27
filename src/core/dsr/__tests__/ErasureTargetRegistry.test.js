'use strict';

/**
 * ErasureTargetRegistry — test suite.
 *
 * The registry itself contains no business logic — these tests cover only
 * registration/validation/ordering/lookup. Invocation behavior (erase/export
 * callbacks, failure isolation, audit trail) is covered where it actually
 * happens: src/core/dsr/__tests__/erasureTargetExtensions.test.js.
 */

describe('ErasureTargetRegistry', () => {
  let registry;

  beforeEach(() => {
    jest.resetModules();
    registry = require('../ErasureTargetRegistry');
    registry.clear();
  });

  afterEach(() => {
    registry.clear();
    jest.resetModules();
  });

  function target(overrides = {}) {
    return { id: 't1', name: 'Test Target', erase: jest.fn(), ...overrides };
  }

  test('registerTarget accepts a minimal valid target and getTargets returns it', () => {
    const t = target();
    expect(registry.registerTarget(t)).toBe(t);
    expect(registry.getTargets()).toEqual([t]);
  });

  test('export callback is optional', () => {
    const t = target();
    expect(t.export).toBeUndefined();
    expect(() => registry.registerTarget(t)).not.toThrow();
  });

  describe('validation', () => {
    test('rejects a non-object target', () => {
      expect(() => registry.registerTarget(null)).toThrow('must be an object');
      expect(() => registry.registerTarget('nope')).toThrow('must be an object');
    });

    test('rejects a missing/empty id', () => {
      expect(() => registry.registerTarget(target({ id: '' }))).toThrow('id is required');
      expect(() => registry.registerTarget(target({ id: undefined }))).toThrow('id is required');
    });

    test('rejects a missing/empty name', () => {
      expect(() => registry.registerTarget(target({ name: '' }))).toThrow('name is required');
    });

    test('rejects a target without an erase function', () => {
      expect(() => registry.registerTarget(target({ erase: undefined }))).toThrow('erase must be a function');
      expect(() => registry.registerTarget(target({ erase: 'nope' }))).toThrow('erase must be a function');
    });

    test('rejects a non-function export when provided', () => {
      expect(() => registry.registerTarget(target({ export: 'nope' }))).toThrow('export must be a function');
    });

    test('rejects a duplicate id', () => {
      registry.registerTarget(target({ id: 'dup' }));
      expect(() => registry.registerTarget(target({ id: 'dup' }))).toThrow("'dup' is already registered");
    });
  });

  describe('ordering', () => {
    test('getTargets returns targets in registration order, not id/alphabetical order', () => {
      registry.registerTarget(target({ id: 'zzz' }));
      registry.registerTarget(target({ id: 'aaa' }));
      registry.registerTarget(target({ id: 'mmm' }));

      expect(registry.getTargets().map((t) => t.id)).toEqual(['zzz', 'aaa', 'mmm']);
    });

    test('getTargets returns a copy — mutating it never affects the registry', () => {
      registry.registerTarget(target({ id: 't1' }));
      const snapshot = registry.getTargets();
      snapshot.push(target({ id: 'injected' }));

      expect(registry.getTargets().map((t) => t.id)).toEqual(['t1']);
    });
  });

  describe('unregisterTarget', () => {
    test('removes a registered target and returns true', () => {
      registry.registerTarget(target({ id: 't1' }));
      expect(registry.unregisterTarget('t1')).toBe(true);
      expect(registry.getTargets()).toEqual([]);
    });

    test('returns false for an id that is not registered', () => {
      expect(registry.unregisterTarget('missing')).toBe(false);
    });

    test('unregistering one target preserves registration order of the rest', () => {
      registry.registerTarget(target({ id: 'a' }));
      registry.registerTarget(target({ id: 'b' }));
      registry.registerTarget(target({ id: 'c' }));

      registry.unregisterTarget('b');

      expect(registry.getTargets().map((t) => t.id)).toEqual(['a', 'c']);
    });
  });

  test('clear() empties the registry', () => {
    registry.registerTarget(target({ id: 'a' }));
    registry.registerTarget(target({ id: 'b' }));
    registry.clear();
    expect(registry.getTargets()).toEqual([]);
  });
});
