'use strict';

/**
 * Legacy JSON seed files. Read-only: in memory mode a collection
 * is seeded once from its legacy file, and scripts/controlPlane/import.js
 * imports the same files into PostgreSQL. Nothing in the running system
 * writes these files any more.
 */

const fs = require('fs');
const path = require('path');
const { emit } = require('../../../services/logger');

const DATA_DIR = path.join(__dirname, '..', '..', '..', 'data');

// store -> { env, default path, top-level key, shape: 'object' (id -> record) | 'array' }
const SEED_FILES = Object.freeze({
  rbac_user:          { env: 'QODIQA_RBAC_STORE_PATH',             file: path.join(process.cwd(), 'data', 'rbac-users.json'),          key: 'users',         shape: 'object' },
  rbac_custom_role:   { env: 'QODIQA_RBAC_CUSTOM_ROLE_STORE_PATH', file: path.join(process.cwd(), 'data', 'rbac-custom-roles.json'),   key: 'roles',         shape: 'object' },
  signing_identity:   { env: 'QODIQA_SIGNING_STORE_PATH',          file: path.join(process.cwd(), 'data', 'signing-identities.json'),  key: 'identities',    shape: 'object' },
  portal_user:        { env: 'QODIQA_PORTAL_USER_STORE_PATH',      file: path.join(process.cwd(), 'data', 'tenant-portal-users.json'), key: 'users',         shape: 'object' },
  tenant:             { env: 'TENANT_STORE_PATH',                  file: path.join(DATA_DIR, 'tenants.json'),                          key: 'tenants',       shape: 'array', idField: 'tenantId' },
  organization:       { env: 'ORG_STORE_PATH',                     file: path.join(DATA_DIR, 'organizations.json'),                    key: 'organizations', shape: 'array', idField: 'organizationId' },
  policy:             { env: 'QODIQA_POLICY_STORE',                file: path.join(DATA_DIR, 'policy-store.json'),                     key: 'policies',      shape: 'object' },
});

function seedPath(store, env = process.env) {
  const spec = SEED_FILES[store];
  if (!spec) throw new TypeError(`no seed file for ${store}`);
  return env[spec.env] || spec.file;
}

/**
 * @returns {{ path: string, exists: boolean, raw: string|null, records: Object<string, object> }}
 * A corrupt file yields no records (and an ERROR event) — never a partial set.
 */
function readSeed(store, env = process.env) {
  const spec = SEED_FILES[store];
  const p = seedPath(store, env);
  if (!fs.existsSync(p)) return { path: p, exists: false, raw: null, records: {} };
  let raw = null;
  try {
    raw = fs.readFileSync(p, 'utf8');
    const data = JSON.parse(raw);
    const body = data && data[spec.key];
    const records = {};
    if (spec.shape === 'array') {
      if (!Array.isArray(body)) return { path: p, exists: true, raw, records };
      for (const r of body) { if (r && typeof r[spec.idField] === 'string') records[r[spec.idField]] = r; }
    } else if (body && typeof body === 'object' && !Array.isArray(body)) {
      Object.assign(records, body);
    }
    return { path: p, exists: true, raw, records };
  } catch (err) {
    emit('ERROR', 'CONTROL_PLANE_SEED_READ_FAILED', { store, path: p, error: err.message });
    return { path: p, exists: true, raw, records: {} };
  }
}

/**
 * Write a seed FIXTURE (tests and offline dev tooling only — e.g. the
 * rbac-bootstrap-key / provision-signing-identity CLIs in memory mode, or a
 * Jest suite that re-requires modules). Never called by a running server.
 * Refused in production and whenever the control plane is PostgreSQL-backed,
 * where the file would be meaningless and misleading.
 */
function writeSeedFixture(store, records, env = process.env) {
  const cp = require('./index');
  if (env.NODE_ENV === 'production' || cp.resolveBackend(env) === 'pg') {
    throw new Error(`writeSeedFixture(${store}) refused: seed files are import-only outside dev/test memory mode`);
  }
  const spec = SEED_FILES[store];
  const p = seedPath(store, env);
  const body = spec.shape === 'array' ? Object.values(records) : records;
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify({ version: 1, [spec.key]: body }, null, 2), 'utf8');
  return p;
}

module.exports = { SEED_FILES, seedPath, readSeed, writeSeedFixture };
