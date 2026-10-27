'use strict';

/** — a restore target must be explicit and must not be the backup source. */

const { assertSafeRestoreTarget } = require('../restoreTargetGuard');

const SRC = { QODIQA_PG_URL: 'postgresql://localhost:5432/qodiqa' };

describe('restoreTargetGuard', () => {
  test('RT-01 no target at all is refused (no fallback to QODIQA_PG_URL / DATABASE_URL / PG*)', () => {
    expect(() => assertSafeRestoreTarget(undefined, SRC)).toThrow(expect.objectContaining({ code: 'RESTORE_TARGET_REQUIRED' }));
    expect(() => assertSafeRestoreTarget(undefined, { PGHOST: 'h', PGDATABASE: 'd' })).toThrow(expect.objectContaining({ code: 'RESTORE_TARGET_REQUIRED' }));
  });

  test('RT-02 a target equal to the source database is refused, including loopback aliases', () => {
    expect(() => assertSafeRestoreTarget('postgresql://localhost:5432/qodiqa', SRC)).toThrow(expect.objectContaining({ code: 'RESTORE_TARGET_IS_SOURCE' }));
    expect(() => assertSafeRestoreTarget('postgresql://127.0.0.1:5432/qodiqa', SRC)).toThrow(expect.objectContaining({ code: 'RESTORE_TARGET_IS_SOURCE' }));
    const viaParts = { QODIQA_PG_HOST: 'localhost', QODIQA_PG_PORT: '5432', QODIQA_PG_DATABASE: 'qodiqa' };
    expect(() => assertSafeRestoreTarget('postgresql://localhost:5432/qodiqa', viaParts)).toThrow(expect.objectContaining({ code: 'RESTORE_TARGET_IS_SOURCE' }));
    const viaLibpq = { PGHOST: 'db', PGPORT: '5432', PGDATABASE: 'qodiqa' };
    expect(() => assertSafeRestoreTarget('postgresql://db:5432/qodiqa', viaLibpq)).toThrow(expect.objectContaining({ code: 'RESTORE_TARGET_IS_SOURCE' }));
  });

  test('RT-03 a different database on the same server, or the same name on another host/port, is accepted', () => {
    expect(assertSafeRestoreTarget('postgresql://localhost:5432/qodiqa_restore_validation', SRC)).toMatch(/qodiqa_restore_validation/);
    expect(assertSafeRestoreTarget('postgresql://localhost:55710/qodiqa', SRC)).toMatch(/55710/);
  });

  test('RT-04 QODIQA_PG_RESTORE_URL is honoured when no argument is passed; an invalid URL is refused', () => {
    expect(assertSafeRestoreTarget(undefined, { ...SRC, QODIQA_PG_RESTORE_URL: 'postgresql://localhost:5432/qodiqa_restore_validation' })).toMatch(/restore_validation/);
    expect(() => assertSafeRestoreTarget('not a url', SRC)).toThrow(expect.objectContaining({ code: 'RESTORE_TARGET_INVALID' }));
  });
});
