'use strict';

const { withDeadline, SigningTimeoutError } = require('../withDeadline');

function delay(ms, value) {
  return new Promise((resolve) => setTimeout(() => resolve(value), ms));
}

describe('withDeadline — timeout enforcement', () => {
  test('resolves normally when fn settles well within the deadline', async () => {
    const result = await withDeadline(() => Promise.resolve('ok'), 200, { operation: 'sign' });
    expect(result).toBe('ok');
  });

  test('provider that never responds: rejects with SigningTimeoutError at the deadline, not later', async () => {
    const neverResolves = () => new Promise(() => {}); // simulates a hung KMS/Vault call
    const start = Date.now();
    await expect(withDeadline(neverResolves, 50, { provider: 'vault', operation: 'sign' }))
      .rejects.toBeInstanceOf(SigningTimeoutError);
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(200); // bounded — never falls back to a transport default
  });

  test('provider that responds AFTER the deadline: caller still gets the timeout error, not the late result', async () => {
    const respondsLate = () => delay(150, 'too-late');
    await expect(withDeadline(respondsLate, 30)).rejects.toBeInstanceOf(SigningTimeoutError);
  });

  test('late settlement after timeout does not produce an unhandled rejection', async () => {
    const unhandled = [];
    const handler = (err) => unhandled.push(err);
    process.on('unhandledRejection', handler);

    const rejectsLate = () => new Promise((_, reject) => setTimeout(() => reject(new Error('late failure')), 100));
    await expect(withDeadline(rejectsLate, 20)).rejects.toBeInstanceOf(SigningTimeoutError);

    // Give the late rejection time to surface if it were going to be unhandled.
    await delay(150);
    process.off('unhandledRejection', handler);
    expect(unhandled).toHaveLength(0);
  });

  test('cancellation: the AbortSignal passed to fn is aborted once the deadline fires', async () => {
    let observedSignal;
    const fn = (signal) => {
      observedSignal = signal;
      return new Promise(() => {});
    };
    await expect(withDeadline(fn, 20)).rejects.toBeInstanceOf(SigningTimeoutError);
    expect(observedSignal.aborted).toBe(true);
  });

  test('timeout error carries provider/operation metadata for structured logging', async () => {
    await expect(withDeadline(() => new Promise(() => {}), 20, { provider: 'aws-kms', operation: 'sign' }))
      .rejects.toMatchObject({
        isSigningTimeout: true,
        code: 'SIGNING_DEADLINE_EXCEEDED',
        provider: 'aws-kms',
        operation: 'sign',
        timeoutMs: 20,
      });
  });

  test('a synchronously-throwing fn is treated as an immediate rejection, not a timeout', async () => {
    const throwsSync = () => { throw new Error('bad input'); };
    await expect(withDeadline(throwsSync, 500)).rejects.toThrow('bad input');
  });
});
