'use strict';

const { HealthRegistry } = require('../health/HealthRegistry');

function makeRegistry(...components) {
  const r = new HealthRegistry();
  for (const [key, name, check] of components) r.register(key, name, check);
  return r;
}

describe('HealthRegistry — registration', () => {
  it('registers a component and reports it in registeredKeys()', () => {
    const r = new HealthRegistry();
    r.register('foo', 'Foo Service', () => true);
    expect(r.registeredKeys()).toContain('foo');
  });

  it('has() returns true for registered key', () => {
    const r = makeRegistry(['db', 'Database', () => true]);
    expect(r.has('db')).toBe(true);
  });

  it('has() returns false for unknown key', () => {
    const r = new HealthRegistry();
    expect(r.has('missing')).toBe(false);
  });

  it('register() is fluent (returns this)', () => {
    const r = new HealthRegistry();
    const ret = r.register('a', 'A', () => true);
    expect(ret).toBe(r);
  });

  it('throws on non-string key', () => {
    const r = new HealthRegistry();
    expect(() => r.register(123, 'X', () => true)).toThrow(TypeError);
  });

  it('throws on empty key', () => {
    const r = new HealthRegistry();
    expect(() => r.register('', 'X', () => true)).toThrow(TypeError);
  });

  it('throws on non-function check', () => {
    const r = new HealthRegistry();
    expect(() => r.register('x', 'X', 'not-a-fn')).toThrow(TypeError);
  });

  it('overwrites an existing key on re-register', () => {
    const r = new HealthRegistry();
    r.register('k', 'Old', () => false);
    r.register('k', 'New', () => true);
    expect(r.getComponentStatus('k').ready).toBe(true);
    expect(r.getComponentStatus('k').name).toBe('New');
  });

  it('unregister() removes the component', () => {
    const r = makeRegistry(['x', 'X', () => true]);
    r.unregister('x');
    expect(r.has('x')).toBe(false);
  });

  it('unregister() is a no-op for unknown keys', () => {
    const r = new HealthRegistry();
    expect(() => r.unregister('nope')).not.toThrow();
  });
});

describe('HealthRegistry — status', () => {
  it('returns null for unknown key', () => {
    const r = new HealthRegistry();
    expect(r.getComponentStatus('nope')).toBeNull();
  });

  it('reports ready: true when check returns true', () => {
    const r = makeRegistry(['c', 'C', () => true]);
    expect(r.getComponentStatus('c').ready).toBe(true);
  });

  it('reports ready: false when check returns false', () => {
    const r = makeRegistry(['c', 'C', () => false]);
    expect(r.getComponentStatus('c').ready).toBe(false);
  });

  it('treats a throwing check as not ready (fail-closed)', () => {
    const r = makeRegistry(['boom', 'Boom', () => { throw new Error('crash'); }]);
    expect(r.getComponentStatus('boom').ready).toBe(false);
  });

  it('check is called lazily on each getComponentStatus() call', () => {
    let val = false;
    const r = makeRegistry(['c', 'C', () => val]);
    expect(r.getComponentStatus('c').ready).toBe(false);
    val = true;
    expect(r.getComponentStatus('c').ready).toBe(true);
  });

  it('getAllStatus returns all components', () => {
    const r = makeRegistry(
      ['a', 'A', () => true],
      ['b', 'B', () => false],
    );
    const all = r.getAllStatus();
    expect(all).toHaveProperty('a');
    expect(all).toHaveProperty('b');
    expect(all.a.ready).toBe(true);
    expect(all.b.ready).toBe(false);
  });

  it('getAllStatus returns empty object when no components', () => {
    expect(new HealthRegistry().getAllStatus()).toEqual({});
  });
});

describe('HealthRegistry — isFullyReady / executionIntegrity', () => {
  it('isFullyReady() is true when all components ready', () => {
    const r = makeRegistry(
      ['a', 'A', () => true],
      ['b', 'B', () => true],
    );
    expect(r.isFullyReady()).toBe(true);
  });

  it('isFullyReady() is false when any component not ready', () => {
    const r = makeRegistry(
      ['a', 'A', () => true],
      ['b', 'B', () => false],
    );
    expect(r.isFullyReady()).toBe(false);
  });

  it('isFullyReady() is true with no components (vacuously)', () => {
    expect(new HealthRegistry().isFullyReady()).toBe(true);
  });

  it('executionIntegrity() returns FULL when all ready', () => {
    expect(makeRegistry(['a', 'A', () => true]).executionIntegrity()).toBe('FULL');
  });

  it('executionIntegrity() returns DEGRADED when any not ready', () => {
    expect(makeRegistry(['a', 'A', () => false]).executionIntegrity()).toBe('DEGRADED');
  });
});
