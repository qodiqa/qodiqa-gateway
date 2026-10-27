#!/usr/bin/env node
'use strict';

/**
 * QODIQA File → PostgreSQL Migration Script
 *
 * Migrates all file-based persistence to PostgreSQL in one idempotent pass.
 * Safe to run multiple times — uses ON CONFLICT DO NOTHING / DO UPDATE.
 *
 * Migration order (respects FK dependencies):
 *   1. RBAC users (no dependencies)
 *   2. Signing keys (no dependencies)
 *   3. Policies + versions + history (no dependencies)
 *   4. Investigations + artifacts + events (no dependencies)
 *   5. Audit chain (largest dataset — batched)
 *
 * Usage:
 *   QODIQA_PG_URL=postgres://... node scripts/migrate-files-to-pg.js
 *   QODIQA_PG_URL=postgres://... node scripts/migrate-files-to-pg.js --dry-run
 *   QODIQA_PG_URL=postgres://... node scripts/migrate-files-to-pg.js --validate
 *
 * Environment variables required:
 *   QODIQA_PG_URL or QODIQA_PG_HOST + QODIQA_PG_DATABASE + QODIQA_PG_MIG_USER + QODIQA_PG_MIG_PASSWORD
 *   QODIQA_AUDIT_LOG            — path to audit.log (NDJSON)
 *   QODIQA_KEYS_PATH            — path to data/keys.json
 *   QODIQA_POLICY_STORE         — path to data/policy-store.json
 *   QODIQA_INVESTIGATIONS_PATH  — path to data/investigations.json
 *   QODIQA_RBAC_STORE_PATH      — path to data/rbac-users.json
 */

require('dotenv').config();

const fs   = require('fs');
const path = require('path');
const { Pool } = require('pg');
const { projectEntryForMirror, MIRROR_ENCODING_ESCAPED } = require('../src/infra/postgres/mirrorProjection'); //

const DRY_RUN  = process.argv.includes('--dry-run');
const VALIDATE = process.argv.includes('--validate');
const BATCH_SIZE = 500;  // audit chain rows per INSERT batch

// ── Pool ──────────────────────────────────────────────────────────────────────

// no implicit localhost:5432 / LIVE target.
require('./lib/liveTargetGuard').assertOrExit('migrate-files-to-pg.js');

const pool = new Pool({
  connectionString: process.env.QODIQA_PG_URL,
  host:     process.env.QODIQA_PG_HOST      || 'localhost',
  port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  database: process.env.QODIQA_PG_DATABASE   || 'qodiqa',
  user:     process.env.QODIQA_PG_MIG_USER    || 'qodiqa_mig',
  password: process.env.QODIQA_PG_MIG_PASSWORD || process.env.QODIQA_PG_PASSWORD,
  ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
});

function log(level, msg, data = {}) {
  const prefix = { INFO: '✓', WARN: '⚠', ERROR: '✗' }[level] ?? '·';
  const extra  = Object.keys(data).length ? `  ${JSON.stringify(data)}` : '';
  console.log(`${prefix} ${msg}${extra}`);
}

function readJson(envVar, defaultPath) {
  const p = process.env[envVar] || defaultPath;
  if (!fs.existsSync(p)) { log('WARN', `File not found, skipping: ${p}`); return null; }
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (e) {
    log('ERROR', `Failed to parse ${p}: ${e.message}`);
    return null;
  }
}

// the audit log is a hash chain — a line that does not parse is a
// break in it, and every production verifier treats it as fatal. It used to be skipped silently
// here, migrating a chain with a hole in it. Now it aborts the migration, naming the line.
function readNdjson(filePath) {
  if (!fs.existsSync(filePath)) { log('WARN', `NDJSON not found: ${filePath}`); return []; }
  const lines = fs.readFileSync(filePath, 'utf8').split('\n');
  const entries = [];
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (!line) return;
    try { entries.push(JSON.parse(line)); } catch { throw new Error(`malformed audit line ${i + 1} in ${filePath} — refusing to migrate a broken chain`); }
  });
  return entries;
}

// ── Migration functions ───────────────────────────────────────────────────────

async function migrateRbacUsers(client) {
  const data = readJson('QODIQA_RBAC_STORE_PATH',
    path.join(process.cwd(), 'data', 'rbac-users.json'));
  if (!data?.users) return { migrated: 0 };

  const users = Object.values(data.users);
  log('INFO', `Migrating ${users.length} RBAC users`);

  let migrated = 0;
  for (const u of users) {
    if (!DRY_RUN) {
      await client.query(`
        INSERT INTO rbac_users (id, username, role, enabled, created_at, created_by, updated_at, updated_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (id) DO UPDATE SET
          username   = EXCLUDED.username,
          role       = EXCLUDED.role,
          enabled    = EXCLUDED.enabled,
          updated_at = EXCLUDED.updated_at,
          updated_by = EXCLUDED.updated_by
      `, [u.id, u.username, u.role, u.enabled ?? true,
          u.createdAt ?? new Date(), u.createdBy ?? 'migration',
          u.updatedAt ?? new Date(), u.updatedBy ?? 'migration']);
    }
    migrated++;
  }
  log('INFO', `RBAC users: ${migrated} rows migrated`);
  return { migrated };
}

async function migrateSigningKeys(client) {
  const data = readJson('QODIQA_KEYS_PATH',
    path.join(process.cwd(), 'data', 'keys.json'));
  if (!data?.clients) return { migrated: 0 };

  let migrated = 0;
  for (const [clientId, keys] of Object.entries(data.clients)) {
    for (const [keyId, key] of Object.entries(keys)) {
      const isActive = key.status === 'active';
      const enc      = key.encryptedPrivateKeyDer;

      if (!DRY_RUN) {
        await client.query(`
          INSERT INTO signing_keys (
            key_id, client_id, version, algorithm,
            public_key_der_b64, status, created_at,
            rotation_deadline, expires_at,
            enc_private_key_b64, enc_iv_b64, enc_auth_tag_b64, enc_kek_id
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
          ON CONFLICT (key_id) DO UPDATE SET
            status            = EXCLUDED.status,
            rotation_deadline = EXCLUDED.rotation_deadline,
            expires_at        = EXCLUDED.expires_at,
            enc_private_key_b64 = EXCLUDED.enc_private_key_b64,
            enc_iv_b64          = EXCLUDED.enc_iv_b64,
            enc_auth_tag_b64    = EXCLUDED.enc_auth_tag_b64
        `, [
          key.keyId ?? keyId,
          key.clientId ?? clientId,
          key.version ?? 1,
          key.algorithm ?? 'ed25519',
          key.publicKeyDer,
          key.status ?? 'active',
          key.createdAt ? new Date(key.createdAt) : new Date(),
          key.rotationDeadline ? new Date(key.rotationDeadline) : null,
          key.expiresAt ? new Date(key.expiresAt) : null,
          isActive ? (enc?.encryptedPrivateKey ?? null) : null,
          isActive ? (enc?.iv ?? null)                  : null,
          isActive ? (enc?.authTag ?? null)              : null,
          isActive ? (enc?.keyId ?? null)                : null,
        ]);
      }
      migrated++;
    }
  }

  // Migrate legacy map
  if (data.legacyMap) {
    for (const [oldId, newId] of Object.entries(data.legacyMap)) {
      if (!DRY_RUN) {
        await client.query(`
          INSERT INTO signing_key_legacy_map (old_key_id, new_key_id)
          VALUES ($1, $2)
          ON CONFLICT (old_key_id) DO UPDATE SET new_key_id = EXCLUDED.new_key_id
        `, [oldId, newId]);
      }
    }
  }

  log('INFO', `Signing keys: ${migrated} rows migrated`);
  return { migrated };
}

async function migratePolicies(client) {
  const data = readJson('QODIQA_POLICY_STORE',
    path.join(process.cwd(), 'data', 'policy-store.json'));
  if (!data?.policies) return { migrated: 0 };

  const policies = Object.values(data.policies);
  log('INFO', `Migrating ${policies.length} policies`);

  let migrated = 0;
  for (const p of policies) {
    if (!DRY_RUN) {
      await client.query(`
        INSERT INTO policies (
          id, name, description, type, priority, enabled, config,
          status, current_version, validation_status, validation_errors,
          created_at, created_by, updated_at, updated_by
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
        ON CONFLICT (id) DO UPDATE SET
          name               = EXCLUDED.name,
          description        = EXCLUDED.description,
          enabled            = EXCLUDED.enabled,
          config             = EXCLUDED.config,
          status             = EXCLUDED.status,
          current_version    = EXCLUDED.current_version,
          validation_status  = EXCLUDED.validation_status,
          validation_errors  = EXCLUDED.validation_errors,
          updated_at         = EXCLUDED.updated_at,
          updated_by         = EXCLUDED.updated_by
      `, [
        p.id, p.name, p.description ?? '', p.type,
        p.priority ?? 100, p.enabled ?? true,
        JSON.stringify(p.config ?? {}),
        p.status ?? 'ACTIVE', p.currentVersion ?? 1,
        p.validationStatus ?? 'VALID',
        JSON.stringify(p.validationErrors ?? []),
        p.createdAt ? new Date(p.createdAt) : new Date(),
        p.createdBy ?? 'migration',
        p.updatedAt ? new Date(p.updatedAt) : new Date(),
        p.updatedBy ?? 'migration',
      ]);

      // Policy versions
      for (const v of (p.versions ?? [])) {
        await client.query(`
          INSERT INTO policy_versions (policy_id, version_number, created_at, created_by, summary, snapshot, validation_status, validation_errors)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
          ON CONFLICT (policy_id, version_number) DO NOTHING
        `, [p.id, v.v ?? v.version ?? 1,
            v.createdAt ? new Date(v.createdAt) : new Date(),
            v.createdBy ?? 'migration', v.summary ?? '',
            JSON.stringify(v.snapshot ?? {}),
            v.validationStatus ?? 'VALID',
            JSON.stringify(v.validationErrors ?? [])]);
      }

      // Policy history
      for (const h of (p.history ?? [])) {
        await client.query(`
          INSERT INTO policy_history (policy_id, event, occurred_at, actor, version, comment, changes)
          VALUES ($1,$2,$3,$4,$5,$6,$7)
        `, [p.id, h.event ?? 'POLICY_CREATED',
            h.timestamp ? new Date(h.timestamp) : new Date(),
            h.actor ?? 'migration', h.version ?? 1,
            h.comment ?? null,
            JSON.stringify(h.changes ?? [])]);
      }
    }
    migrated++;
  }
  log('INFO', `Policies: ${migrated} rows migrated`);
  return { migrated };
}

async function migrateInvestigations(client) {
  const data = readJson('QODIQA_INVESTIGATIONS_PATH',
    path.join(process.cwd(), 'data', 'investigations.json'));
  if (!data?.investigations) return { migrated: 0 };

  const invs = Object.values(data.investigations);
  log('INFO', `Migrating ${invs.length} investigations`);

  let migrated = 0;
  for (const inv of invs) {
    if (!DRY_RUN) {
      await client.query(`
        INSERT INTO investigations (id, title, investigator, notes, status, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (id) DO UPDATE SET
          notes      = EXCLUDED.notes,
          status     = EXCLUDED.status,
          updated_at = EXCLUDED.updated_at
      `, [inv.id, inv.title, inv.investigator ?? 'unknown',
          inv.notes ?? '', inv.status ?? 'OPEN',
          inv.createdAt ? new Date(inv.createdAt) : new Date(),
          inv.updatedAt ? new Date(inv.updatedAt) : new Date()]);

      for (const artifactId of (inv.artifactIds ?? [])) {
        await client.query(`
          INSERT INTO investigation_artifacts (investigation_id, artifact_id)
          VALUES ($1, $2) ON CONFLICT DO NOTHING
        `, [inv.id, artifactId]);
      }

      for (const ev of (inv.auditEvents ?? [])) {
        await client.query(`
          INSERT INTO investigation_audit_events (investigation_id, event_type, recorded_at, payload)
          VALUES ($1, $2, $3, $4)
        `, [inv.id, ev.event ?? 'UNKNOWN',
            ev.recordedAt ? new Date(ev.recordedAt) : new Date(),
            JSON.stringify(ev)]);
      }
    }
    migrated++;
  }
  log('INFO', `Investigations: ${migrated} rows migrated`);
  return { migrated };
}

async function migrateAuditChain(client) {
  const logPath = process.env.QODIQA_AUDIT_LOG ||
    path.join(process.cwd(), 'audit.log');
  const entries = readNdjson(logPath);

  log('INFO', `Migrating ${entries.length} audit chain entries (batch size: ${BATCH_SIZE})`);

  let migrated = 0;
  for (let i = 0; i < entries.length; i += BATCH_SIZE) {
    const batch = entries.slice(i, i + BATCH_SIZE);

    if (!DRY_RUN) {
      // Build a multi-row INSERT for performance
      const values = [];
      const params = [];
      let   pi     = 1;

      for (const e of batch) {
        // "legacy" (pre-hash-chain) is derived from the line's shape (no inputHash), never
        // read from a stored `legacy` key — no writer persists one, so a line carrying it is
        // forged (the audit-log.js fix); refuse rather than silently skip it.
        if (Object.prototype.propertyIsEnumerable.call(e, 'legacy')) {
          throw new Error(`audit line for artifact ${e.artifactId} carries a stored "legacy" key (forged) — refusing to migrate`);
        }
        if (e.inputHash == null) continue;  // skip pre-hash (legacy-shaped) lines: no cryptographic fields
        // every column pg-audit-backend.js insertMirrorRow() writes. this INSERT
        // carried 15 of them — no public_key_id, no schema_version (so the column DEFAULT 1
        // applied: every v2+ entry was re-verified under the 9-field v1 set and failed), and none
        // of the schemaVersion 3–6 hashed columns.
        // (design §9/§11): per-field columns through the reversible projection P; canonical / hash / prev_hash verbatim
        const m = projectEntryForMirror(e);
        const cols = [
          e.hash, e.prevHash, e.canonical,
          m.artifactId, m.decision, new Date(e.timestamp), m.highResTime,
          m.inputHash, m.signature, m.requestHash, m.policyHash,
          e.verificationResult === true,
          m.nonce        ?? null,
          m.tenantId     ?? null,
          m.executionContext ? JSON.stringify(m.executionContext) : null,
          m.publicKeyId  ?? null,
          e.schemaVersion ?? 1,
          m.consentProvenance != null ? JSON.stringify(m.consentProvenance) : null,
          m.policyDecision    != null ? JSON.stringify(m.policyDecision)    : null,
          m.callerContext     != null ? JSON.stringify(m.callerContext)     : null,
          m.provider ?? null,
          m.model    ?? null,
          m.stage       ?? null,
          m.reason      ?? null,
          m.semantic    != null ? JSON.stringify(m.semantic)    : null,
          m.tokenUsage  != null ? JSON.stringify(m.tokenUsage)  : null,
          m.responseId  ?? null,
          // audit schema v7 (migration 075): without these a migrated v7 entry could never re-verify from PG
          m.entryType         ?? null,
          m.outputHash        ?? null,
          m.requestId         ?? null,
          m.organizationId    ?? null,
          m.executingProvider ?? null,
          MIRROR_ENCODING_ESCAPED,   // (R-F2)
          ...require('../src/infra/postgres/v8Columns').v8InsertValues(m),   // audit v8 (migration 083); NULL below v8
        ];
        values.push('(' + cols.map((_, k) => `$${pi + k}`).join(',') + ')');
        params.push(...cols);
        pi += cols.length;
      }

      if (values.length > 0) {
        await client.query(`
          INSERT INTO audit_chain (
            hash, prev_hash, canonical,
            artifact_id, decision, recorded_at, high_res_time,
            input_hash, signature, request_hash, policy_hash,
            verification_result, nonce, tenant_id, execution_context,
            public_key_id, schema_version, consent_provenance, policy_decision,
            caller_context, provider, model,
            stage, reason, semantic, token_usage, response_id,
            entry_type, output_hash, request_id, organization_id, executing_provider,
            mirror_encoding,
            issued_at, protocol_version, agent_id, session_id, action_seq, action_hash, approval_ref, dlp, bytes_delivered, completion_status
          ) VALUES ${values.join(',')}
          ON CONFLICT (hash) DO NOTHING
        `, params);
      }
    }

    migrated += batch.length;
    if (migrated % 5000 === 0) {
      log('INFO', `Audit chain progress: ${migrated}/${entries.length}`);
    }
  }

  log('INFO', `Audit chain: ${migrated} entries migrated`);
  return { migrated };
}

// ── Validation ────────────────────────────────────────────────────────────────

async function validate(client) {
  log('INFO', 'Running post-migration validation...');

  const checks = await client.query(`
    SELECT
      (SELECT count(*) FROM rbac_users)       AS rbac_users,
      (SELECT count(*) FROM signing_keys)     AS signing_keys,
      (SELECT count(*) FROM policies)         AS policies,
      (SELECT count(*) FROM policy_versions)  AS policy_versions,
      (SELECT count(*) FROM policy_history)   AS policy_history,
      (SELECT count(*) FROM investigations)   AS investigations,
      (SELECT count(*) FROM audit_chain)      AS audit_chain,
      -- Chain integrity: broken links
      (SELECT count(*) FROM audit_chain a
       WHERE a.prev_hash != 'GENESIS'
         AND NOT EXISTS (SELECT 1 FROM audit_chain b WHERE b.hash = a.prev_hash)
      ) AS broken_chain_links
  `);

  const r = checks.rows[0];
  log('INFO', 'Row counts:', {
    rbacUsers:      Number(r.rbac_users),
    signingKeys:    Number(r.signing_keys),
    policies:       Number(r.policies),
    policyVersions: Number(r.policy_versions),
    policyHistory:  Number(r.policy_history),
    investigations: Number(r.investigations),
    auditChain:     Number(r.audit_chain),
  });

  const broken = Number(r.broken_chain_links);
  if (broken > 0) {
    log('ERROR', `INTEGRITY FAILURE: ${broken} broken chain links detected!`);
    process.exitCode = 1;
  } else {
    log('INFO', 'Chain integrity: OK (all prev_hash links verified)');
  }

  return { brokenChainLinks: broken };
}

// ── Entry point ───────────────────────────────────────────────────────────────

async function main() {
  log('INFO', DRY_RUN ? 'DRY RUN — no writes will occur' : 'Starting migration', {
    database: process.env.QODIQA_PG_DATABASE || 'qodiqa',
  });

  const client = await pool.connect();
  try {
    if (VALIDATE) {
      await validate(client);
      return;
    }

    await migrateRbacUsers(client);
    await migrateSigningKeys(client);
    await migratePolicies(client);
    await migrateInvestigations(client);
    await migrateAuditChain(client);

    if (!DRY_RUN) {
      await validate(client);
    }

    log('INFO', 'Migration complete');
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch(e => {
  log('ERROR', `Migration FAILED: ${e.message}`);
  console.error(e.stack);
  process.exit(1);
});
