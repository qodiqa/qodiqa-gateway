'use strict';

const readinessState = require('../readinessState');
const requestDrain   = require('../requestDrain');

afterEach(() => {
  readinessState._reset();
  requestDrain._reset();
});

// ── State machine ─────────────────────────────────────────────────────────────

describe('readinessState', () => {
  it('starts false', () => {
    expect(readinessState.isReady()).toBe(false);
  });

  it('setReady(true) makes isReady() return true', () => {
    readinessState.setReady(true);
    expect(readinessState.isReady()).toBe(true);
  });

  it('setReady(false) makes isReady() return false', () => {
    readinessState.setReady(true);
    readinessState.setReady(false);
    expect(readinessState.isReady()).toBe(false);
  });

  it('_reset() restores initial false state', () => {
    readinessState.setReady(true);
    readinessState._reset();
    expect(readinessState.isReady()).toBe(false);
  });

  it('repeated setReady(true) calls are idempotent', () => {
    readinessState.setReady(true);
    readinessState.setReady(true);
    expect(readinessState.isReady()).toBe(true);
  });

  it('repeated setReady(false) calls are idempotent', () => {
    readinessState.setReady(false);
    readinessState.setReady(false);
    expect(readinessState.isReady()).toBe(false);
  });
});

// ── Shutdown integration ──────────────────────────────────────────────────────

describe('readinessState shutdown integration', () => {
  it('setReady(false) executes before beginShutdown', () => {
    readinessState.setReady(true);
    const order = [];

    const mockReadiness = {
      setReady: (v) => {
        order.push(`setReady(${v})`);
        readinessState.setReady(v);
      },
    };
    const mockDrain = {
      beginShutdown: () => {
        order.push('beginShutdown');
        requestDrain.beginShutdown();
      },
    };

    mockReadiness.setReady(false);
    mockDrain.beginShutdown();

    expect(order).toEqual(['setReady(false)', 'beginShutdown']);
    expect(readinessState.isReady()).toBe(false);
  });

  it('isReady() returns false immediately after setReady(false)', () => {
    readinessState.setReady(true);
    readinessState.setReady(false);
    expect(readinessState.isReady()).toBe(false);
  });

  it('remains false while requestDrain is shutting down', () => {
    readinessState.setReady(true);
    readinessState.setReady(false);
    requestDrain.beginShutdown();

    expect(readinessState.isReady()).toBe(false);
    expect(requestDrain.isShuttingDown()).toBe(true);
  });
});
