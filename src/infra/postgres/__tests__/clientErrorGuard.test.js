'use strict';

// a checked-out pg client's 'error' event must never be uncaught.

const { EventEmitter } = require('events');

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
// Setup files can load pool.js (and with it this guard, bound to the real logger) before this
// file runs; reset the registry so the guard under test binds to the mocked logger.
jest.resetModules();
const { emit } = require('../../../../services/logger');
const guard = require('../clientErrorGuard');

beforeEach(() => { guard._resetForTests(); emit.mockClear(); });

test('every physical client created by the pool gets a permanent error listener', () => {
  const pool = guard.guardPool(new EventEmitter(), 'app');
  const client = new EventEmitter();
  pool.emit('connect', client);
  expect(client.listenerCount('error')).toBe(1);
  // Without the guard EventEmitter#emit('error') with no listener THROWS — exactly the uncaught crash.
  expect(() => client.emit('error', Object.assign(new Error('Connection terminated unexpectedly'), { code: null }))).not.toThrow();
  expect(guard.clientErrorCount()).toBe(1);
  expect(emit).toHaveBeenCalledWith('ERROR', 'PG_CLIENT_CONNECTION_LOST', expect.objectContaining({ pool: 'app', error: 'Connection terminated unexpectedly' }));
});

test('negative control: an unguarded client error throws (the pre-fix behaviour)', () => {
  const client = new EventEmitter();
  expect(() => client.emit('error', new Error('Connection terminated unexpectedly'))).toThrow('Connection terminated unexpectedly');
});

test('a storm of errors is counted exactly but logged aggregated', () => {
  const pool = guard.guardPool(new EventEmitter(), 'system');
  const clients = Array.from({ length: 50 }, () => new EventEmitter());
  clients.forEach((c) => pool.emit('connect', c));
  clients.forEach((c) => c.emit('error', new Error('x')));
  expect(guard.clientErrorCount()).toBe(50);
  expect(emit.mock.calls.filter((c) => c[1] === 'PG_CLIENT_CONNECTION_LOST')).toHaveLength(1);
});

test('idempotent per pool; test doubles without .on pass through', () => {
  const pool = new EventEmitter();
  guard.guardPool(pool, 'a'); guard.guardPool(pool, 'a');
  expect(pool.listenerCount('connect')).toBe(1);
  const fake = { query() {} };
  expect(guard.guardPool(fake, 'x')).toBe(fake);
  expect(guard.guardPool(null, 'x')).toBe(null);
});
