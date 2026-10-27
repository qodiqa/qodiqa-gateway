'use strict';

// the timeout timer is cleared whichever side of the race wins, and it never holds the event loop open.
const { raceTimeout } = require('../raceTimeout');

describe('raceTimeout', () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  test('RT-01 work wins: resolves with its value and leaves no timer behind', async () => {
    const p = raceTimeout(Promise.resolve(42), 1000, () => new Error('T'));
    await expect(p).resolves.toBe(42);
    expect(jest.getTimerCount()).toBe(0);
  });

  test('RT-02 work fails first: rejects with the work error and leaves no timer behind', async () => {
    const p = raceTimeout(Promise.reject(new Error('boom')), 1000, () => new Error('T'));
    await expect(p).rejects.toThrow('boom');
    expect(jest.getTimerCount()).toBe(0);
  });

  test('RT-03 timer wins: rejects with the timeout error', async () => {
    const p = raceTimeout(new Promise(() => {}), 1000, () => new Error('AUDIT_TIMEOUT'));
    jest.advanceTimersByTime(1000);
    await expect(p).rejects.toThrow('AUDIT_TIMEOUT');
    expect(jest.getTimerCount()).toBe(0);
  });

  test('RT-04 the timer is unref\'d (never keeps the process alive)', () => {
    jest.useRealTimers();
    const spy = jest.spyOn(global, 'setTimeout');
    const p = raceTimeout(new Promise((r) => setImmediate(r)), 60_000, () => new Error('T'));
    const handle = spy.mock.results.find((r) => r.value && typeof r.value.hasRef === 'function').value;
    expect(handle.hasRef()).toBe(false);
    spy.mockRestore();
    return p;
  });
});
