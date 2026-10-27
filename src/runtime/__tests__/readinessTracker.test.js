'use strict';

jest.mock('../../../services/logger', () => ({ emit: jest.fn() }));

const { emit }   = require('../../../services/logger');
const metrics    = require('../../observability/metrics');
const readinessTracker = require('../readinessTracker');

afterEach(() => {
  readinessTracker._reset();
  jest.clearAllMocks();
});

describe('readinessTracker.recordComponent', () => {
  it('does not log on the very first observation of a healthy component (no false "recovery")', () => {
    readinessTracker.recordComponent('nonceStore', true);
    expect(emit).not.toHaveBeenCalledWith('INFO', 'READINESS_DEPENDENCY_RECOVERED', expect.anything());
  });

  it('logs at INFO (not WARN) on the very first observation of an unhealthy component — this is startup, not an incident', () => {
    readinessTracker.recordComponent('persistenceStore', false);
    expect(emit).toHaveBeenCalledWith('INFO', 'READINESS_DEPENDENCY_LOST', { component: 'persistenceStore' });
  });

  it('logs READINESS_DEPENDENCY_LOST at WARN on a runtime transition from healthy to unhealthy', () => {
    readinessTracker.recordComponent('consentSubscriber', true);
    jest.clearAllMocks();
    readinessTracker.recordComponent('consentSubscriber', false);
    expect(emit).toHaveBeenCalledWith('WARN', 'READINESS_DEPENDENCY_LOST', { component: 'consentSubscriber' });
  });

  it('logs READINESS_DEPENDENCY_RECOVERED with downtimeMs on recovery from a runtime transition', () => {
    readinessTracker.recordComponent('persistenceStore', true);
    jest.clearAllMocks();
    readinessTracker.recordComponent('persistenceStore', false);
    readinessTracker.recordComponent('persistenceStore', true);
    const call = emit.mock.calls.find(c => c[1] === 'READINESS_DEPENDENCY_RECOVERED');
    expect(call).toBeDefined();
    expect(call[2].component).toBe('persistenceStore');
    expect(typeof call[2].downtimeMs).toBe('number');
    expect(call[2].downtimeMs).toBeGreaterThanOrEqual(0);
  });

  it('does not log or increment counters on repeated, unchanged observations (no spam under high probe frequency)', () => {
    readinessTracker.recordComponent('nonceStore', true);
    jest.clearAllMocks();
    for (let i = 0; i < 50; i++) readinessTracker.recordComponent('nonceStore', true);
    expect(emit).not.toHaveBeenCalled();
  });

  it('tracks each component independently — one failing does not affect another\'s transition state', () => {
    readinessTracker.recordComponent('nonceStore', true);
    readinessTracker.recordComponent('persistenceStore', true);
    jest.clearAllMocks();

    readinessTracker.recordComponent('persistenceStore', false);
    expect(emit).toHaveBeenCalledWith('WARN', 'READINESS_DEPENDENCY_LOST', { component: 'persistenceStore' });
    expect(emit).not.toHaveBeenCalledWith(expect.anything(), expect.anything(), { component: 'nonceStore' });
  });

  it('updates the qodiqa_readiness_component_up gauge on every call, not just on transitions', () => {
    readinessTracker.recordComponent('consentSubscriber', true);
    expect(metrics.readinessComponentUp._values.get('component="consentSubscriber"')).toBe(1);
    readinessTracker.recordComponent('consentSubscriber', false);
    expect(metrics.readinessComponentUp._values.get('component="consentSubscriber"')).toBe(0);
  });

  it('increments readinessDependencyFailuresTotal only on a healthy->unhealthy transition', () => {
    const before = metrics.readinessDependencyFailuresTotal._values.get('component="__test_pg__"') || 0;
    readinessTracker.recordComponent('__test_pg__', true);
    readinessTracker.recordComponent('__test_pg__', false);
    readinessTracker.recordComponent('__test_pg__', false); // repeat — must not increment again
    const after = metrics.readinessDependencyFailuresTotal._values.get('component="__test_pg__"') || 0;
    expect(after - before).toBe(1);
  });

  it('increments readinessDependencyRecoveryTotal only on an unhealthy->healthy transition', () => {
    const before = metrics.readinessDependencyRecoveryTotal._values.get('component="__test_sub__"') || 0;
    readinessTracker.recordComponent('__test_sub__', false);
    readinessTracker.recordComponent('__test_sub__', true);
    readinessTracker.recordComponent('__test_sub__', true); // repeat — must not increment again
    const after = metrics.readinessDependencyRecoveryTotal._values.get('component="__test_sub__"') || 0;
    expect(after - before).toBe(1);
  });

  it('never throws even if metrics/logger internals misbehave', () => {
    expect(() => readinessTracker.recordComponent(null, undefined)).not.toThrow();
    expect(() => readinessTracker.recordComponent('x', 'not-a-boolean')).not.toThrow();
  });
});

describe('readinessTracker.recordOverall', () => {
  it('logs the first not-ready observation at INFO — startup, not an incident', () => {
    readinessTracker.recordOverall(false);
    expect(emit).toHaveBeenCalledWith('INFO', 'READINESS_LOST', {});
  });

  it('logs a runtime ready->not_ready transition at WARN', () => {
    readinessTracker.recordOverall(true);
    jest.clearAllMocks();
    readinessTracker.recordOverall(false);
    expect(emit).toHaveBeenCalledWith('WARN', 'READINESS_LOST', {});
  });

  it('logs READINESS_RECOVERED at INFO on a not_ready->ready transition', () => {
    readinessTracker.recordOverall(false);
    jest.clearAllMocks();
    readinessTracker.recordOverall(true);
    expect(emit).toHaveBeenCalledWith('INFO', 'READINESS_RECOVERED', {});
  });

  it('does not log repeatedly for unchanged overall state across many probes', () => {
    readinessTracker.recordOverall(true);
    jest.clearAllMocks();
    for (let i = 0; i < 50; i++) readinessTracker.recordOverall(true);
    expect(emit).not.toHaveBeenCalled();
  });

  it('sets the qodiqa_readiness_state gauge on every call', () => {
    readinessTracker.recordOverall(true);
    expect(metrics.readinessState._values.get('')).toBe(1);
    readinessTracker.recordOverall(false);
    expect(metrics.readinessState._values.get('')).toBe(0);
  });

  it('increments readinessTransitionsTotal only on an actual state change', () => {
    const before = metrics.readinessTransitionsTotal._values.get('to="ready"') || 0;
    readinessTracker.recordOverall(false);
    readinessTracker.recordOverall(true);
    readinessTracker.recordOverall(true); // repeat — must not increment again
    const after = metrics.readinessTransitionsTotal._values.get('to="ready"') || 0;
    expect(after - before).toBe(1);
  });
});

describe('readinessTracker._reset', () => {
  it('clears prior state so the next observation is treated as a first observation again', () => {
    readinessTracker.recordOverall(false); // first observation -> INFO
    readinessTracker.recordOverall(true);
    readinessTracker._reset();
    jest.clearAllMocks();

    readinessTracker.recordOverall(false);
    expect(emit).toHaveBeenCalledWith('INFO', 'READINESS_LOST', {}); // treated as first again, not WARN
  });
});
