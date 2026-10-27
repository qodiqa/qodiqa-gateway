#!/usr/bin/env node
'use strict';
/**
 * one-time, idempotent import of the legacy control-plane JSON
 * files into PostgreSQL (control_plane_records, migrations 065/066), with a
 * checksum-verified report. After the import the files are import-only: the
 * running system never writes them.
 *
 * Sources (same env overrides the stores read):
 *   rbac_user          QODIQA_RBAC_STORE_PATH             data/rbac-users.json
 *   rbac_custom_role   QODIQA_RBAC_CUSTOM_ROLE_STORE_PATH data/rbac-custom-roles.json
 *   signing_identity   QODIQA_SIGNING_STORE_PATH          data/signing-identities.json
 *   portal_user        QODIQA_PORTAL_USER_STORE_PATH      data/tenant-portal-users.json
 *   tenant             TENANT_STORE_PATH                  data/tenants.json
 *   organization       ORG_STORE_PATH                     data/organizations.json
 *   policy             QODIQA_POLICY_STORE                data/policy-store.json (else POLICY_FILE)
 *   signing_key_status QODIQA_KEYS_PATH / QODIQA_KEYS_ARCHIVE_PATH — status and
 *                      timestamps only; key material is never read or copied
 *
 * Records are copied verbatim from the files (see sourceRecords()). Inserts are create-only
 * (ON CONFLICT DO NOTHING): a re-run inserts nothing, and a row that already
 * exists with DIFFERENT data is never overwritten — it is reported as a
 * conflict, and the run exits 2.
 *
 * Checksums: per store, sha256 over the canonical JSON of the sorted
 * [id, record] pairs of the source, and the same over the rows read back from
 * PostgreSQL for those ids. verified = the two are equal.
 *
 * Usage:
 *   node scripts/controlPlane/import.js --database <name> [--report <path.json>]
 * Connects as qodiqa_control (QODIQA_PG_CONTROL_USER/_PASSWORD). The shared
 * database `qodiqa` is refused unless --live-approved is passed: importing into
 * LIVE is an design decision.
 */

require('dotenv').config({ quiet: true });
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

function arg(name) { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : null; }
const DATABASE = arg('--database');
const REPORT = arg('--report');
const LIVE_APPROVED = process.argv.includes('--live-approved');

function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  return JSON.stringify(v === undefined ? null : v);
}
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const setSha = (records) => sha(canonical(Object.keys(records).sort().map((id) => [id, records[id]])));
const fileSha = (p) => (fs.existsSync(p) ? sha(fs.readFileSync(p)) : null);

/**
 * Records per store, VERBATIM from the legacy files (the files were written by
 * the stores themselves, so they are already in the stores' record shape). No
 * runtime normalisation is re-applied here: several normalisations stamp the
 * current time, which would
 * make a re-run differ from the first run. A earlier key without an expiry is
 * given one on the first pull by the running store (versioned write).
 * The policy store, when it has no file of its own, is derived from POLICY_FILE
 * with a FIXED timestamp (that file's mtime) — the same records on every run.
 */
function sourceRecords() {
  process.env.QODIQA_CONTROL_PLANE_BACKEND = 'memory';
  const { readSeed } = require('../../src/core/controlPlane/seed');
  const out = {};
  for (const store of ['rbac_user', 'rbac_custom_role', 'signing_identity', 'portal_user', 'tenant', 'organization', 'policy']) {
    const s = readSeed(store);
    out[store] = { source: s.path, sourceSha256: s.exists ? sha(fs.readFileSync(s.path)) : null, records: s.records };
  }
  if (Object.keys(out.policy.records).length === 0) {
    const policyStore = require('../../src/core/policy/store');
    const pf = policyStore.policyFilePath();
    if (pf && fs.existsSync(pf)) {
      const fixed = fs.statSync(pf).mtime.toISOString();
      out.policy = { source: `${pf} (POLICY_FILE, no policy-store file)`, sourceSha256: sha(fs.readFileSync(pf)), records: policyStore.importRecordsFromPolicyFile(fixed) };
    }
  }
  out.signing_key_status = keyStatusRecords();
  return out;
}

function keyStatusRecords() {
  const keysPath = process.env.QODIQA_KEYS_PATH || path.join(__dirname, '..', '..', 'data', 'keys.json');
  const archivePath = process.env.QODIQA_KEYS_ARCHIVE_PATH || path.join(__dirname, '..', '..', 'data', 'key-archive.json');
  const records = {};
  if (fs.existsSync(keysPath)) {
    const doc = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    for (const [clientId, keys] of Object.entries(doc.clients || {})) {
      for (const [keyId, e] of Object.entries(keys || {})) {
        records[keyId] = {
          keyId, clientId, version: e.version ?? null, status: e.status,
          activatedAt: e.createdAt || null,
          deprecatedAt: e.status === 'deprecated' ? (e.retiredAt || null) : null,
          archivedAt: null,
          revokedAt: e.status === 'revoked' ? (e.revokedAt || e.retiredAt || null) : null,
        };
      }
    }
  }
  if (fs.existsSync(archivePath)) {
    const raw = fs.readFileSync(archivePath, 'utf8');
    const doc = raw.trim() ? JSON.parse(raw) : { entries: [] };
    for (const e of doc.entries || []) {
      if (!e || !e.keyId || records[e.keyId]) continue;
      records[e.keyId] = {
        keyId: e.keyId, clientId: e.clientId, version: e.version ?? null, status: 'archived',
        activatedAt: e.createdAt || null, deprecatedAt: e.retiredAt || null, archivedAt: e.purgedAt || null, revokedAt: null,
      };
    }
  }
  return { source: `${keysPath} + ${archivePath}`, sourceSha256: { keys: fileSha(keysPath), archive: fileSha(archivePath) }, records };
}

async function main() {
  if (!DATABASE) throw new Error('--database <name> is required (the import target is always named explicitly)');
  if (DATABASE === (process.env.QODIQA_PG_LIVE_DATABASE || 'qodiqa') && !LIVE_APPROVED) {
    throw new Error(`refusing to import into the shared database "${DATABASE}" without --live-approved (explicit approval required)`);
  }
  const src = sourceRecords();
  require('../lib/liveTargetGuard').assertExplicitNonLiveTarget('controlPlane/import.js'); // audit 2026-10-20 (3.4)
  const pool = new Pool({
    host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
    database: DATABASE, user: process.env.QODIQA_PG_CONTROL_USER || 'qodiqa_control', password: process.env.QODIQA_PG_CONTROL_PASSWORD,
    ssl: process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false, max: 2,
  });
  const report = { importedAt: new Date().toISOString(), database: DATABASE, stores: {}, verified: true, conflicts: 0 };
  try {
    for (const [store, { source, sourceSha256, records }] of Object.entries(src)) {
      const r = { source, sourceSha256: sourceSha256 || fileSha(source), records: Object.keys(records).length, inserted: 0, alreadyIdentical: 0, conflicting: [] };
      for (const [id, rec] of Object.entries(records)) {
        const ins = await pool.query(
          `INSERT INTO control_plane_records (store, record_id, data, version, updated_by)
           VALUES ($1, $2, $3::jsonb, 1, 'control-plane-import') ON CONFLICT (store, record_id) DO NOTHING`,
          [store, id, JSON.stringify(rec)]);
        if (ins.rowCount === 1) { r.inserted++; continue; }
        const cur = (await pool.query('SELECT data, deleted FROM control_plane_records WHERE store = $1 AND record_id = $2', [store, id])).rows[0];
        if (cur && !cur.deleted && canonical(cur.data) === canonical(rec)) r.alreadyIdentical++;
        else r.conflicting.push(id);
      }
      const ids = Object.keys(records);
      const back = ids.length
        ? (await pool.query('SELECT record_id, data FROM control_plane_records WHERE store = $1 AND record_id = ANY($2::text[]) AND NOT deleted', [store, ids])).rows
        : [];
      r.sourceSetSha256 = setSha(records);
      r.pgSetSha256 = setSha(Object.fromEntries(back.map((row) => [row.record_id, row.data])));
      r.verified = r.conflicting.length === 0 && r.sourceSetSha256 === r.pgSetSha256;
      report.conflicts += r.conflicting.length;
      if (!r.verified) report.verified = false;
      report.stores[store] = r;
    }
  } finally {
    await pool.end();
  }
  const text = JSON.stringify(report, null, 2);
  if (REPORT) { fs.mkdirSync(path.dirname(REPORT), { recursive: true }); fs.writeFileSync(REPORT, `${text}\n`); }
  console.log(text);
  process.exit(report.verified ? 0 : 2);
}

main().catch((err) => { console.error(`CONTROL_PLANE_IMPORT_FAILED: ${err.message}`); process.exit(1); });
