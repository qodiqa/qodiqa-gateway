'use strict';

/**
 * — the placeholder-credential probe against a REAL PostgreSQL.
 *
 * Uses its own disposable LOGIN role (qodiqa_ind01_<hex>), created and dropped here by the
 * qodiqa_test bootstrap role (CREATEROLE). No existing role is altered. It proves, end to end:
 *   - a role whose password is a published-style placeholder is classified ACCEPTED;
 *   - after ALTER ROLE … NOLOGIN it is NOT_PERMITTED (cannot log in, even with the right password);
 *   - after rotation to the operator tool's SCRAM verifier it is REJECTED for the placeholder,
 *     and the NEW secret logs in (the verifier format is accepted by PostgreSQL);
 *   - the probe never returns the password.
 * Serial component gate: it writes pg_authid (catalog-race class, see CLAUDE.md flake notes).
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).
const crypto = require('crypto');
const { Client } = require('pg');
const rc = require('../../src/infra/postgres/roleCredentials');
const { scramVerifier } = require('../../scripts/db/role-credentials');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true' && !!process.env.QODIQA_PG_TEST_USER;
const d = REAL_PG ? describe : describe.skip;

const HEX = crypto.randomBytes(4).toString('hex');
const ROLE = `qodiqa_ind01_${HEX}`;
const PLACEHOLDER = `REPLACE_WITH_VAULT_SECRET_IND01T${HEX.toUpperCase().replace(/[0-9]/g, 'X')}`;
const target = { host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10), database: 'postgres', ssl: false };
const spec = { role: ROLE, placeholder: PLACEHOLDER, migration: 'test' };

async function admin(fn) {
  const c = new Client({ ...target, user: process.env.QODIQA_PG_TEST_USER, password: process.env.QODIQA_PG_TEST_PASSWORD });
  c.on('error', () => {});
  await c.connect();
  try { return await fn(c); } finally { await c.end(); }
}

d('role-credential probe against real PostgreSQL', () => {
  beforeAll(async () => {
    await admin((c) => c.query(`CREATE ROLE ${ROLE} LOGIN PASSWORD ${c.escapeLiteral(PLACEHOLDER)}`));
  });
  afterAll(async () => {
    await admin((c) => c.query(`DROP ROLE IF EXISTS ${ROLE}`)); // own fixture
  });

  test('placeholder still set → ACCEPTED (the violation the gate refuses)', async () => {
    const r = await rc.probeRole(spec, target);
    expect(r.result).toBe('ACCEPTED');
    expect(JSON.stringify(r)).not.toContain(PLACEHOLDER);
    const agg = await rc.probeMigrationRoles({ roles: [spec], target });
    expect(agg.ok).toBe(false);
    expect(agg.violations.map((v) => v.role)).toEqual([ROLE]);
  });

  test('NOLOGIN → NOT_PERMITTED (safe even though the placeholder is still the password)', async () => {
    await admin((c) => c.query(`ALTER ROLE ${ROLE} NOLOGIN`));
    const r = await rc.probeRole(spec, target);
    expect(r.result).toBe('NOT_PERMITTED');
    expect((await rc.probeMigrationRoles({ roles: [spec], target })).proven).toBe(true);
  });

  test('rotated via the operator tool SCRAM verifier → placeholder REJECTED, new secret logs in', async () => {
    const secret = crypto.randomBytes(24).toString('hex');
    await admin((c) => c.query(`ALTER ROLE ${ROLE} LOGIN PASSWORD ${c.escapeLiteral(scramVerifier(secret))}`));
    expect((await rc.probeRole(spec, target)).result).toBe('REJECTED');
    const c = new Client({ ...target, user: ROLE, password: secret });
    c.on('error', () => {});
    await c.connect();
    const who = (await c.query('SELECT current_user AS u')).rows[0].u;
    await c.end();
    expect(who).toBe(ROLE);
  });

  test('unreachable server → INCONCLUSIVE, never reported as safe-and-proven', async () => {
    const dead = { ...target, port: 1 };
    const agg = await rc.probeMigrationRoles({ roles: [spec], target: dead, timeoutMs: 1000 });
    expect(agg.ok).toBe(true);
    expect(agg.proven).toBe(false);
    expect(agg.unproven[0].result).toBe('INCONCLUSIVE');
  });
});
