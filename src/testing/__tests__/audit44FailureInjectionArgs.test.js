'use strict';

/** the latency wrappers dropped every argument of the wrapped store call. */

const { redisLatencyNonceStore, redisLatencyAnomalyStore } = require('../failureInjection');

describe('failureInjection latency wrappers forward their arguments', () => {
  test('FI-01 nonce store: register(nonce, ttl) reaches the wrapped store intact', async () => {
    const store = { register: jest.fn(async (...a) => a), isRegistered: jest.fn(async (...a) => a) };
    const wrapped = redisLatencyNonceStore(store, 1);
    expect(await wrapped.register('n-1', 60)).toEqual(['n-1', 60]);
    expect(await wrapped.isRegistered('n-1')).toEqual(['n-1']);
    expect(store.register).toHaveBeenCalledWith('n-1', 60);
  });
  test('FI-02 anomaly store: record/peek arguments are forwarded', async () => {
    const store = { record: jest.fn(async (...a) => a), peek: jest.fn(async (...a) => a) };
    const wrapped = redisLatencyAnomalyStore(store, 1);
    expect(await wrapped.record('k', { x: 1 })).toEqual(['k', { x: 1 }]);
    expect(await wrapped.peek('k')).toEqual(['k']);
  });
});
