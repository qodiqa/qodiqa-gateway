#!/usr/bin/env node
'use strict';

/**
 * On-demand NDJSON snapshot export of the audit chain, for backup/DR in
 * QODIQA_AUDIT_ORDERING_MODE=distributed deployments.
 *
 * In distributed mode, PostgreSQL (audit_chain, ordered by seq — see
 * distributedOrdering.js / migration 026) is the sole ordering authority;
 * per-request local NDJSON writes are disabled (a per-replica partial file
 * isn't an independently-verifiable chain — see the "Local NDJSON file's new
 * role" section of docs/protocol/AUDIT-SCHEMA-V8.md's Decision
 * Update). This script replaces "always-on per-request file write" with
 * "periodic snapshot": dump the full ordered chain to a timestamped NDJSON
 * file plus a .sum checksum, in the same shape/format audit-log.js's
 * single-node file uses — point QODIQA_AUDIT_LOG at the output and
 * audit-log.js's existing verifyAuditChain()/startup validation can load and
 * verify it directly, no new verification code needed.
 *
 * Usage:
 *   node scripts/export-audit-chain-snapshot.js [outputDir]
 *   The read runs on the qodiqa_system role pool (src/infra/postgres/rolePools.js) — the only role
 *   granted the full-chain read (migration 061): QODIQA_PG_ENABLED=true, QODIQA_PG_SYSTEM_PASSWORD
 *   (QODIQA_PG_SYSTEM_USER defaults to qodiqa_system), and the target from QODIQA_PG_URL (host and
 *   database only — the system role's credentials replace the URL's) or QODIQA_PG_HOST/PORT/DATABASE.
 *
 * outputDir defaults to ./snapshots. Output files:
 *   audit-chain-snapshot-<timestamp>.ndjson
 *   audit-chain-snapshot-<timestamp>.ndjson.sum
 */

require('dotenv').config();

const fs   = require('fs');
const path = require('path');
const { orderByHashLinks } = require('../src/utils/hashLinkOrder');
// the full-chain read is qodiqa_system's (migration 061, PRIVILEGE-POLICY: "platform
// integrity, background, boot hydration" — the role loadChainFromPg() reads as), through the same
// role pool production uses, so the DEFINER call-site audit can see the role. The previous
// connection paired qodiqa_read with the APP password and, reading audit_chain directly, was bound
// by per-tenant RLS.
const rolePools = require('../src/infra/postgres/rolePools');

function log(level, msg, data = {}) {
  const prefix = { INFO: '✓', WARN: '⚠', ERROR: '✗' }[level] ?? '·';
  const extra  = Object.keys(data).length ? `  ${JSON.stringify(data)}` : '';
  console.log(`${prefix} ${msg}${extra}`);
}

async function main() {
  const outputDir = process.argv[2] || path.join(process.cwd(), 'snapshots');
  fs.mkdirSync(outputDir, { recursive: true });

  let rows;
  try {
    // read through qodiqa_audit_chain_full_read() — the SECURITY
    // DEFINER full read loadChainFromPg() uses — with EVERY hashed column. this script
    // selected FROM audit_chain directly, so audit_chain's per-tenant RLS returned only the
    // calling role's visible slice (run as qodiqa_app: 1 of 4 rows — a partial snapshot that still
    // "verified" as a shorter chain), and it omitted the schemaVersion 3–6 hashed columns, so any
    // v3+ entry with a non-null value there could never re-verify from the snapshot.
    const result = await rolePools.system.query(`
      SELECT
        hash, prev_hash AS "prevHash", canonical,
        artifact_id AS "artifactId", decision,
        high_res_time AS "highResTime",
        input_hash AS "inputHash",
        signature,
        request_hash AS "requestHash",
        policy_hash AS "policyHash",
        verification_result AS "verificationResult",
        nonce, tenant_id AS "tenantId",
        execution_context AS "executionContext",
        public_key_id AS "publicKeyId",
        schema_version AS "schemaVersion",
        consent_provenance AS "consentProvenance",
        policy_decision AS "policyDecision",
        caller_context AS "callerContext",
        provider, model,
        stage, reason, semantic,
        token_usage AS "tokenUsage",
        response_id AS "responseId",
        entry_type AS "entryType",
        output_hash AS "outputHash",
        request_id AS "requestId",
        organization_id AS "organizationId",
        executing_provider AS "executingProvider",
        issued_at AS "issuedAt", protocol_version AS "protocolVersion", agent_id AS "agentId", session_id AS "sessionId",
        action_seq AS "actionSeq", action_hash AS "actionHash", approval_ref AS "approvalRef", dlp,
        bytes_delivered AS "bytesDelivered", completion_status AS "completionStatus",
        mirror_encoding AS "mirrorEncoding"
      FROM qodiqa_audit_chain_full_read()
      ORDER BY seq ASC
    `, [], 'audit_snapshot_export');
    rows = result.rows;
  } finally {
    await rolePools.shutdownAll();
  }

  // `timestamp` is derived from the stored `canonical` JSON, not a separate
  // column — mirrors pg-audit-backend.js loadChainFromPg()'s fix: a
  // TIMESTAMPTZ round-trip through Postgres's text cast does not reproduce
  // the exact ISO-8601 string that was actually hashed. The hashed columns
  // keep loadChainFromPg()'s always-present-possibly-null shape.
  // (R-F3/R-F4): projected rows (mirror_encoding 1) are decoded back to their original per-field values first
  const { decodeMirrorRow } = require('../src/infra/postgres/mirrorProjection');
  const mapped = rows.map(r0 => {
    const r = decodeMirrorRow(r0, `audit_chain row ${r0.hash}`);
    let timestamp = null;
    try { timestamp = JSON.parse(r.canonical).timestamp ?? null; } catch { /* leaves null; downstream verification will flag it */ }
    return {
      ...r,
      timestamp,
      executionContext: r.executionContext ?? undefined,
      tenantId:        r.tenantId         ?? undefined,
      nonce:           r.nonce            ?? undefined,
      publicKeyId:       r.publicKeyId       ?? null,
      consentProvenance: r.consentProvenance ?? null,
      policyDecision:    r.policyDecision    ?? null,
      callerContext:     r.callerContext     ?? null,
      provider:          r.provider          ?? null,
      model:             r.model             ?? null,
      stage:             r.stage             ?? null,
      reason:            r.reason            ?? null,
      semantic:          r.semantic          ?? null,
      tokenUsage:        r.tokenUsage        ?? null,
      responseId:        r.responseId        ?? null,
      entryType:         r.entryType         ?? null,
      outputHash:        r.outputHash        ?? null,
      requestId:         r.requestId         ?? null,
      organizationId:    r.organizationId    ?? null,
      executingProvider: r.executingProvider ?? null,
    };
  });
  // hash-link order, as loadChainFromPg() — seq may be inverted on an earlier mirror.
  const entries = orderByHashLinks(mapped).rows;

  const ts       = new Date().toISOString().replace(/[:.]/g, '-');
  const filePath = path.join(outputDir, `audit-chain-snapshot-${ts}.ndjson`);
  const sumPath  = filePath + '.sum';

  const content = entries.map(e => JSON.stringify(e)).join('\n') + (entries.length ? '\n' : '');
  fs.writeFileSync(filePath, content, 'utf8');

  // Same { count, tailHash } shape as audit-log.js's own checksum file
  // (_saveChecksum), so this snapshot is a drop-in QODIQA_AUDIT_LOG target
  // for verification tooling that already understands that format.
  const tail = entries[entries.length - 1] ?? null;
  fs.writeFileSync(sumPath, JSON.stringify({ count: entries.length, tailHash: tail?.hash ?? null }), 'utf8');

  log('INFO', 'Snapshot written', { filePath, sumPath, entries: entries.length });
}

main().catch(e => {
  log('ERROR', `Snapshot export FAILED: ${e.message}`);
  console.error(e.stack);
  process.exit(1);
});
