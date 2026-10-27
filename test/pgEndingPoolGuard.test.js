'use strict';

/**
 * the ending-pool guard (test/helpers/pgEndingPoolGuard.js, installed by test/support/jest.setup.js) absorbs an error
 * raised by a pool AFTER end() was called, and ONLY then. No database needed: the error is emitted the way pg-pool's
 * idle listener emits it.
 *
 *   EG-01 a pool with no listener that errors after end() does not throw; the error is counted
 *   EG-02 a LIVE pool (end() not called) with no listener still throws — real faults stay loud
 *   EG-03 a pool with its own listener (every product pool) gets no extra listener
 */

const { Pool } = require('pg');
const { stats } = require('./helpers/pgEndingPoolGuard');

const fatal = () => Object.assign(new Error('terminating connection due to administrator command'), { code: '57P01' });

describe('ending-pool teardown guard', () => {
  test('EG-01 an error after end() is absorbed and counted', async () => {
    const pool = new Pool({ host: '127.0.0.1', port: 1 });
    const before = stats.absorbed;
    await pool.end();
    expect(() => pool.emit('error', fatal())).not.toThrow();
    expect(stats.absorbed).toBe(before + 1);
    expect(stats.codes['57P01']).toBeGreaterThan(0);
  });

  test('EG-02 a live pool with no listener still throws', () => {
    const pool = new Pool({ host: '127.0.0.1', port: 1 });
    expect(() => pool.emit('error', fatal())).toThrow(/administrator command/);
  });

  test('EG-03 a pool with its own error listener gets no extra listener', async () => {
    const pool = new Pool({ host: '127.0.0.1', port: 1 });
    const own = jest.fn();
    pool.on('error', own);
    await pool.end();
    expect(pool.listenerCount('error')).toBe(1);
    pool.emit('error', fatal());
    expect(own).toHaveBeenCalledTimes(1);
  });
});
