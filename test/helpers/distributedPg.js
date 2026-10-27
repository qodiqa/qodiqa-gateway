'use strict';

/**
 * phase 8 — one disposable, fully migrated PostgreSQL database per test/distributed/* suite, plus the
 * EXPLICIT environment its child processes get.
 *
 *   const db = await createMigratedDatabase('dof');
 *   db.childEnv({ QODIQA_AUDIT_ORDERING_MODE: 'distributed' })   // env for startIpcWorker / fork
 *   await db.admin.query('SELECT …')                             // superuser-side inspection pool on that database
 *   await db.drop()                                              // drops THIS database only (its own fixture)
 *
 * The migration chain runs in a separate `node` child (test/helpers/pgMigrateChild.js) as the migration/test role,
 * so the parent Jest worker never loads pool.js with elevated credentials. Workers then run as the ambient app role
 * (QODIQA_PG_USER), exactly as production does. Targets come only from test/helpers/disposableTargets.js (never
 * 127.0.0.1:5432, never .env).
 */

const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { Pool } = require('pg');
const { pgTarget } = require('./disposableTargets');
const { baseEnv } = require('./ipcWorker');
const { dropTestDatabase } = require('./dropTestDatabase');

function _pgPassThrough() {
  const out = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (/^QODIQA_PG_/.test(k) || k === 'QODIQA_ALLOW_PG_INTEGRATION_TESTS' || k === 'QODIQA_TEST_HARDEN_CLUSTER_ROLES') out[k] = v;
  }
  return out;
}

async function createMigratedDatabase(label) {
  const t = pgTarget();
  if (!t.available) throw new Error(`createMigratedDatabase: ${t.reason}`);
  const name = `qodiqa_p8_${label}_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
  if (!/^[a-z_][a-z0-9_]*$/.test(name)) throw new Error(`unexpected database name ${name}`);

  const maint = new Pool({ host: t.host, port: t.port, database: 'postgres', user: t.adminUser, password: t.adminPassword, connectionTimeoutMillis: 5000, max: 2 });
  await maint.query(`CREATE DATABASE "${name}"`);

  const childEnv = (extra = {}) => baseEnv({ ..._pgPassThrough(), QODIQA_PG_ENABLED: 'true', QODIQA_PG_DATABASE: name, ...extra });

  const mig = spawnSync(process.execPath, [path.join(__dirname, 'pgMigrateChild.js')], {
    env: childEnv({ QODIQA_PG_USER: t.adminUser, QODIQA_PG_PASSWORD: t.adminPassword }),
    encoding: 'utf8', timeout: 120_000,
  });
  if (mig.status !== 0) {
    await dropTestDatabase(maint, name).catch(() => {});
    await maint.end().catch(() => {});
    throw new Error(`migration of ${name} failed (exit ${mig.status}): ${(mig.stderr || '').slice(-1500)} ${(mig.stdout || '').slice(-1500)}`);
  }

  const admin = new Pool({ host: t.host, port: t.port, database: name, user: t.adminUser, password: t.adminPassword, connectionTimeoutMillis: 5000, max: 4 });

  return {
    name,
    admin,
    childEnv,
    async drop() {
      await admin.end().catch(() => {});
      const r = await dropTestDatabase(maint, name);
      await maint.end().catch(() => {});
      return r;
    },
  };
}

module.exports = { createMigratedDatabase };
