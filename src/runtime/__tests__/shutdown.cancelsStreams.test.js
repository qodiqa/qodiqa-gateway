'use strict';

/**
 * graceful shutdown cancels still-open SSE streams before the force-exit timer.
 *
 *   SD76-01  a drain that is still waiting at timeoutMs/2 (an open stream) → streamRegistry.cancelAll('server_shutdown')
 *            is called once; the stream's own cancelled path then lets the drain finish; shutdown exits 0 (no force exit)
 *   SD76-02  a drain that finishes early never cancels anything (the timer is cleared)
 *   SD76-03  streamCancelAfterMs overrides the half-window default
 */

jest.mock('../../../services/logger', () => ({ emit: jest.fn(), flush: jest.fn().mockResolvedValue(undefined) }));
jest.mock('../../core/audit/audit-log', () => ({ drainPendingWrites: jest.fn().mockResolvedValue(undefined) }));

const { executeShutdown, _reset } = require('../shutdown');
const { emit } = require('../../../services/logger');

function makeServer() { return { close: jest.fn((cb) => cb()) }; }

beforeEach(() => { _reset(); emit.mockClear(); });

test('SD76-01 an open stream is cancelled at timeoutMs/2 and shutdown completes cleanly', async () => {
  let releaseDrain;
  const drainP = new Promise((r) => { releaseDrain = r; });
  const registry = {
    activeCount: jest.fn(() => 1),
    cancelAll: jest.fn(() => { setTimeout(releaseDrain, 5); return 1; }), // the stream closes itself after its DECISION
  };
  const drain = { beginShutdown: jest.fn(), activeCount: jest.fn(() => 1), drain: jest.fn(() => drainP) };
  const exit = jest.fn();
  const t0 = Date.now();
  await executeShutdown(makeServer(), [], { timeoutMs: 400, _requestDrain: drain, _streamRegistry: registry, _exit: exit });
  expect(registry.cancelAll).toHaveBeenCalledTimes(1);
  expect(registry.cancelAll).toHaveBeenCalledWith('server_shutdown');
  expect(Date.now() - t0).toBeGreaterThanOrEqual(190);         // not before half the window
  expect(exit).toHaveBeenCalledTimes(1);
  expect(exit).toHaveBeenCalledWith(0);                         // clean exit, not the force-exit 1
  expect(emit.mock.calls.map((c) => c[1])).toContain('SHUTDOWN_STREAMS_CANCELLED');
  expect(emit.mock.calls.map((c) => c[1])).not.toContain('SHUTDOWN_TIMEOUT');
});

test('SD76-02 an early drain never cancels', async () => {
  const registry = { activeCount: jest.fn(() => 0), cancelAll: jest.fn(() => 0) };
  const drain = { beginShutdown: jest.fn(), activeCount: jest.fn(() => 0), drain: jest.fn().mockResolvedValue(undefined) };
  const exit = jest.fn();
  await executeShutdown(makeServer(), [], { timeoutMs: 200, _requestDrain: drain, _streamRegistry: registry, _exit: exit });
  await new Promise((r) => setTimeout(r, 150));
  expect(registry.cancelAll).not.toHaveBeenCalled();
  expect(exit).toHaveBeenCalledWith(0);
});

test('SD76-03 streamCancelAfterMs overrides the default', async () => {
  let releaseDrain;
  const drainP = new Promise((r) => { releaseDrain = r; });
  const registry = { activeCount: () => 1, cancelAll: jest.fn(() => { releaseDrain(); return 1; }) };
  const drain = { beginShutdown: jest.fn(), activeCount: () => 1, drain: () => drainP };
  const exit = jest.fn();
  const t0 = Date.now();
  await executeShutdown(makeServer(), [], { timeoutMs: 10_000, streamCancelAfterMs: 20, _requestDrain: drain, _streamRegistry: registry, _exit: exit });
  expect(registry.cancelAll).toHaveBeenCalledTimes(1);
  expect(Date.now() - t0).toBeLessThan(2000);
  expect(exit).toHaveBeenCalledWith(0);
});
