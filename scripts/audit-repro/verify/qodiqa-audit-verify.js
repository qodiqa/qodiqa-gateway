#!/usr/bin/env node
'use strict';

/**
 * qodiqa-audit-verify — standalone, independent audit verifier.
 *
 * Imports nothing from src/ and no npm package (Node built-ins only: fs, path, crypto). It
 * re-derives every verdict from the documented contract:
 * canonicalization, schema versions, domain-separated hashing, chain linkage, the checksum
 * anchor, and — when given — transparency entries, roots, inclusion proofs and the
 * transparency ↔ audit cross-check.
 *
 * Usage:
 *   node scripts/audit-repro/verify/qodiqa-audit-verify.js --audit <file> [options]
 *
 *   --audit <file>              audit export: NDJSON file log (default), or a JSON PG export
 *   --format ndjson|pg-json     pg-json = an array of audit_chain rows, or {rows:[...]}
 *   --anchor <file>             checksum anchor ({count, tailHash, v2?}) — NDJSON only
 *   --transparency <file>       transparency_log_entries rows (JSON array or {rows|entries})
 *   --roots <file>              transparency_roots rows
 *   --proofs <file>             inclusion proofs (proofVersion 2), JSON array
 *   --keys <file>               transparency public keys (/.well-known/qodiqa/transparency-keys body); a key with
 * status "revoked" is not a trust anchor
 * --partial the transparency export deliberately omits leaves — a root covering ids not in
 *                               the export is then reported ENTRIES_NOT_EXPORTED instead of failing ENTRIES_MISSING, and
 *                               the audit→leaf completeness check is skipped
 *   --tolerate-legacy-prefix    accept pre-hash lines before the first chained entry as UNVERIFIED
 * --base <file> signed base record (audit.log.base.json) — the log starts at its checkpoint
 * --archive <dir[,dir…]> prune archives, oldest first — each re-verified from GENESIS / its prior base
 *                               to its signed checkpoint, and the last must end where the base (or the log) starts
 * --checkpoint-keys <file> checkpoint public keys (/.well-known/qodiqa/checkpoint-keys body, or the key file)
 * --anchors <file> customer-held anchor export (witness-cosigned checkpoints, JSONL) — needs
 *                               --checkpoint-keys and --witness-keys; detects rollback / rewrite / deleted or
 *                               re-signed checkpoints (see ./anchors.js)
 * --witness-keys <file> TRUSTED witness public keys ({keys:[{witnessId, keyId, publicKey, status}]})
 * --checkpoints <file> the live checkpoint sidecar (<audit.log>.checkpoints.jsonl) — enables
 *                               CHECKPOINT_DELETED / CHECKPOINT_REPLACED
 * --min-witnesses <n> trusted cosignatures required per anchor (default 1)
 *   --out <file>                write the full JSON report here (stdout gets the summary)
 *
 * Exit: 0 = every supplied input verifies · 1 = at least one verdict failed · 2 = usage/input error.
 */

const fs = require('fs');
const path = require('path');
const contract = require('./auditContract');
const transparency = require('./transparency');
const checkpoint = require('./checkpoint');
const anchorsV = require('./anchors');

const TOOL = { name: 'qodiqa-audit-verify', version: '1.0.0', contract: 'QODIQA audit entry schemaVersion 1–7' };

function parseArgs(argv) {
  const a = {};
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (!k.startsWith('--')) throw new Error(`unexpected argument ${k}`);
    const name = k.slice(2);
    if (name === 'tolerate-legacy-prefix' || name === 'partial') { a[name] = true; continue; }
    if (i + 1 >= argv.length) throw new Error(`${k} needs a value`);
    a[name] = argv[++i];
  }
  return a;
}

const readJson = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));
const rowsOf = (j) => (Array.isArray(j) ? j : j.rows || j.entries || j.roots || j.proofs || []);

function verify(args) {
  const report = { tool: TOOL, inputs: {}, base: null, archives: null, audit: null, anchor: null, transparency: null, verdict: null };
  const format = args.format || (args.audit && args.audit.endsWith('.json') ? 'pg-json' : 'ndjson');
  report.inputs = { audit: args.audit ? path.basename(args.audit) : null, format, anchor: args.anchor ? path.basename(args.anchor) : null,
    transparency: args.transparency ? path.basename(args.transparency) : null, roots: args.roots ? path.basename(args.roots) : null,
    proofs: args.proofs ? path.basename(args.proofs) : null, keys: args.keys ? path.basename(args.keys) : null,
    tolerateLegacyPrefix: !!args['tolerate-legacy-prefix'] };

  report.inputs.base = args.base ? path.basename(args.base) : null;
  report.inputs.archives = args.archive ? args.archive.split(',').map((d) => path.basename(d)) : null;
  report.inputs.checkpointKeys = args['checkpoint-keys'] ? path.basename(args['checkpoint-keys']) : null;

  // ── M3/M4: the signed base record and prune archives ─────────────────────────────────────────────────────────
  // FAIL CLOSED: a base record that cannot be verified (no key set, bad signature) invalidates the audit
  // verdict; a log that does not start at GENESIS without a base record is AUDIT_BASE_MISSING.
  const resolve = args['checkpoint-keys'] ? checkpoint.keyResolver(readJson(args['checkpoint-keys'])) : null;
  let base = null; // { headHash, chainLength, checkpointId } once verified
  if (args.base) {
    const rec = readJson(args.base);
    const v = resolve ? checkpoint.verifySignedCheckpoint(rec && rec.checkpoint, resolve) : { ok: false, reason: 'NO_CHECKPOINT_KEYS (--checkpoint-keys required)' };
    report.base = v.ok
      ? { valid: true, checkpointId: rec.checkpoint.payload.checkpointId, chainLength: rec.checkpoint.payload.chainLength, headHash: rec.checkpoint.payload.headHash }
      : { valid: false, reason: `AUDIT_BASE_SIGNATURE_INVALID:${v.reason}` };
    if (v.ok) base = report.base;
    // A second prune interrupted after writing its base record: the log still starts at the prior base (carried, signed).
    const prior = v.ok && rec.priorBase && rec.priorBase.checkpoint;
    if (prior) {
      const pv = checkpoint.verifySignedCheckpoint(prior, resolve);
      if (pv.ok) base.prior = { headHash: prior.payload.headHash, chainLength: prior.payload.chainLength };
      else { report.base = { valid: false, reason: `AUDIT_BASE_SIGNATURE_INVALID:prior:${pv.reason}` }; base = null; }
    }
  }
  if (args.archive) {
    report.archives = [];
    let expect = { hash: contract.GENESIS, count: 0 };
    for (const dir of args.archive.split(',')) {
      const a = resolve ? checkpoint.verifyArchive(dir, resolve, expect) : { dir: path.basename(dir), valid: false, reason: 'NO_CHECKPOINT_KEYS (--checkpoint-keys required)' };
      report.archives.push(a);
      if (!a.valid) break;
      expect = a.to;
    }
    const last = report.archives[report.archives.length - 1];
    if (last && last.valid && base && (last.to.hash !== base.headHash || last.to.count !== base.chainLength)) {
      last.valid = false; last.reason = 'ARCHIVES_DO_NOT_END_AT_BASE';
    }
    if (last && last.valid && !args.base) base = { headHash: last.to.hash, chainLength: last.to.count, checkpointId: last.checkpointId, fromArchive: true };
  }
  const baseFailed = report.base && !report.base.valid;

  let entries = null;
  let entryHashes = null;   // from the streamed pass when --anchors is given
  let auditOffset = 0; // lifetime count before the verified range (pruned prefix)
  if (args.audit) {
    if (format === 'ndjson') {
      // streamed — the log is never read into one string (a 3.2 GB log exceeded V8's maximum
      // string length) and no entry array is kept: one short pass reads the first entry (it decides the start state,
      // exactly as before), then ONE pass feeds the chain walker, the checksum-anchor checker, and — only when those
      // inputs were given — the entry hashes (--anchors) and a compact projection (transparency cross-check).
      // Same verdicts by construction: walkChain()/checkAnchor() are these same incremental checkers over an array.
      const s = verifyNdjsonStreaming(args, base, baseFailed);
      report.audit = s.audit || (baseFailed ? { valid: false, reason: report.base.reason } : null);
      if (s.anchor) report.anchor = s.anchor;
      entries = s.entries; entryHashes = s.entryHashes; auditOffset = s.offset;
    } else if (format === 'pg-json') {
      let rows = rowsOf(readJson(args.audit));
      // After a prune PG keeps the checkpoint's own row as the anchor; the verified chain starts after it.
      if (base) rows = rows.filter((r) => String(r.hash).trim() !== base.headHash);
      const { ordered, anomalies } = contract.orderPgRows(rows, base ? { start: base.headHash } : {});
      entries = ordered.map(contract.entryFromPgRow);
      auditOffset = base ? base.chainLength : 0;
      report.audit = baseFailed ? { valid: false, reason: report.base.reason } : contract.walkChain(entries, base ? { startPrevHash: base.headHash } : {});
      report.audit.pgRows = rows.length;
      report.audit.pgAnomalies = anomalies;
      const fatal = anomalies.filter((x) => x.severity !== 'WARN');
      if (fatal.length && report.audit.valid) { report.audit.valid = false; report.audit.reason = 'PG_CHAIN_' + fatal[0].type; }
    } else throw new Error(`unknown --format ${format}`);
  }

  if (args.transparency || args.roots || args.proofs) {
    report.transparency = transparency.verifyTransparency({
      entries: args.transparency ? rowsOf(readJson(args.transparency)) : [],
      roots: args.roots ? rowsOf(readJson(args.roots)) : [],
      proofs: args.proofs ? rowsOf(readJson(args.proofs)) : [],
      keys: args.keys ? readJson(args.keys) : [],
      auditEntries: entries,
      partial: !!args.partial,
    });
  }

  // witness-cosigned anchors (customer-held) against the verified log and the live checkpoint sidecar.
  if (args.anchors) {
    const readJsonl = (p) => fs.readFileSync(p, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    if (!entries) report.anchors = { valid: false, reason: 'ANCHORS_NEED_AUDIT (--audit required)' };
    else if (!resolve) report.anchors = { valid: false, reason: 'NO_CHECKPOINT_KEYS (--checkpoint-keys required)' };
    else if (!args['witness-keys']) report.anchors = { valid: false, reason: 'NO_WITNESS_KEYS (--witness-keys required: trusted witness public keys)' };
    else {
      report.anchors = anchorsV.verifyAnchors({
        anchors: readJsonl(args.anchors), entryHashes: entryHashes || entries.map((e) => (e && typeof e === 'object' ? e.hash : null)), offset: auditOffset,
        checkpoints: args.checkpoints ? readJsonl(args.checkpoints) : null, resolve, witnessKeys: readJson(args['witness-keys']),
        minWitnesses: args['min-witnesses'] ? Number(args['min-witnesses']) : 1,
      });
    }
  }

  const parts = [report.anchors ? report.anchors.valid : true, report.audit ? report.audit.valid : true, report.anchor ? report.anchor.ok : true, report.transparency ? report.transparency.valid : true,
    report.base ? report.base.valid : true, report.archives ? report.archives.every((a) => a.valid) : true];
  report.verdict = report.audit || report.transparency || report.archives ? (parts.every(Boolean) ? 'VALID' : 'INVALID') : 'NO_INPUT';
  return report;
}

// the NDJSON audit verification, streamed. Mirrors the previous branch structure line for line; the only
// differences are WHEN the quantities are computed (during one pass instead of over an in-memory array).
const PER_ENTRY_LIMIT = 100_000;   // reports for larger logs keep only the non-VERIFIED rows (perEntryTruncated)
function verifyNdjsonStreaming(args, base, baseFailed) {
  const file = args.audit;
  let first;
  const peek = contract.forEachNdjsonEntry(file, (e) => { first = e; return false; });
  if (!peek.ok) return { audit: { valid: false, reason: 'MALFORMED_JSON', line: peek.line }, entries: null, entryHashes: null, offset: 0, anchor: null };
  const firstModern = !!first && typeof first === 'object' && !contract.isLegacyShaped(first);
  const tol = !!args['tolerate-legacy-prefix'];
  // plan = which walk (if any), the lifetime offset, which absolute position to capture, how to finish
  let plan;
  if (baseFailed) plan = { walk: null, offset: 0, fixed: { valid: false, reason: null } };
  else if (!base && firstModern && first.prevHash !== contract.GENESIS) plan = { walk: { tolerateLegacyPrefix: tol }, offset: 0, hint: true };
  else if (base && (!first || (firstModern && first.prevHash === base.headHash))) plan = { walk: { startPrevHash: base.headHash }, offset: base.chainLength, rebased: true };
  else if (base && (!firstModern || first.prevHash === contract.GENESIS)) plan = { walk: { tolerateLegacyPrefix: tol }, offset: 0, fullFile: true, capture: base.chainLength - 1 };
  else if (base && base.prior && firstModern && first.prevHash === base.prior.headHash) plan = { walk: { startPrevHash: base.prior.headHash }, offset: base.prior.chainLength, prior: true, capture: base.chainLength - base.prior.chainLength - 1 };
  else if (base) plan = { walk: null, offset: 0, mismatch: true };
  else plan = { walk: { tolerateLegacyPrefix: tol }, offset: 0 };

  const walker = plan.walk ? contract.createChainWalker({ ...plan.walk, perEntryLimit: PER_ENTRY_LIMIT }) : null;
  const anchorChk = args.anchor ? contract.createAnchorChecker(JSON.parse(fs.readFileSync(args.anchor, 'utf8')), plan.offset) : null;
  const wantProjection = !!(args.transparency || args.roots || args.proofs);
  const hashes = args.anchors ? [] : null;
  const projection = wantProjection ? [] : null;
  let idx = 0; let captured;
  const pass = contract.forEachNdjsonEntry(file, (e, len) => {
    if (walker) walker.push(e);
    if (anchorChk) anchorChk.push(e, len);
    if (plan.capture !== undefined && idx === plan.capture) captured = e;
    if (hashes) hashes.push(e && typeof e === 'object' ? e.hash : null);
    if (projection) projection.push(e && typeof e === 'object'
      ? { hash: e.hash, decision: e.decision, schemaVersion: e.schemaVersion, entryType: e.entryType, requestId: e.requestId, artifactId: e.artifactId }
      : e);
    idx++;
  });
  if (!pass.ok) return { audit: { valid: false, reason: 'MALFORMED_JSON', line: pass.line }, entries: null, entryHashes: null, offset: 0, anchor: null };

  let audit;
  if (baseFailed) audit = null;   // filled by the caller's base verdict below
  else if (plan.mismatch) audit = { valid: false, reason: 'AUDIT_BASE_MISMATCH', detail: `first entry chains from ${first.prevHash}, the base ends at ${base.headHash}` };
  else {
    audit = walker.result();
    if (plan.hint) audit.baseHint = `AUDIT_BASE_MISSING: the first entry chains from ${first.prevHash}, not GENESIS — if this log was pruned, supply --base and --checkpoint-keys`;
    if (plan.rebased) { audit.startState = 'rebased'; audit.lifetimeStart = plan.offset; }
    if (plan.fullFile) {
      audit.startState = 'full-file';
      if (audit.valid && (!captured || captured.hash !== base.headHash)) { audit.valid = false; audit.reason = 'AUDIT_BASE_MISMATCH'; }
    }
    if (plan.prior) {
      audit.startState = 'full-file'; audit.lifetimeStart = plan.offset;
      if (audit.valid && (!captured || captured.hash !== base.headHash)) { audit.valid = false; audit.reason = 'AUDIT_BASE_MISMATCH'; }
    }
  }
  // the entries array downstream consumers (transparency cross-check, the anchors guard) need: the projection when the
  // transparency inputs were given, otherwise a non-null marker (only its truthiness is used)
  return { audit, entries: projection || [], entryHashes: hashes, offset: plan.offset, anchor: anchorChk ? anchorChk.result() : null };
}

function summary(r) {
  const lines = [`${TOOL.name} ${TOOL.version} — verdict: ${r.verdict}`];
  if (r.audit) {
    lines.push(`  audit: ${r.audit.valid ? 'VALID' : 'INVALID'}${r.audit.reason ? ' (' + r.audit.reason + (r.audit.failure && r.audit.failure.detail ? '/' + r.audit.failure.detail : '') + (r.audit.failure ? ' at index ' + r.audit.failure.index : '') + ')' : ''}` +
      (r.audit.total !== undefined ? ` · entries ${r.audit.total}, verified ${r.audit.entriesVerified}, legacy-unverified ${r.audit.legacyUnverified}` : ''));
    if (r.audit.schemaVersionCounts) lines.push(`  schemaVersion counts: ${JSON.stringify(r.audit.schemaVersionCounts)} (per-entry rows truncated to the non-verified ones)`);   //
    else if (r.audit.perEntry) {
      const byVersion = {};
      for (const e of r.audit.perEntry) byVersion[e.schemaVersion ?? 'none'] = (byVersion[e.schemaVersion ?? 'none'] || 0) + 1;
      lines.push(`  schemaVersion counts: ${JSON.stringify(byVersion)}`);
    }
    if (r.audit.pgAnomalies && r.audit.pgAnomalies.length) lines.push(`  pg anomalies: ${JSON.stringify(r.audit.pgAnomalies)}`);
  }
  if (r.base) lines.push(`  base: ${r.base.valid ? 'VALID checkpoint ' + r.base.checkpointId + ' at entry ' + r.base.chainLength : 'INVALID (' + r.base.reason + ')'}`);
  if (r.archives) for (const a of r.archives) lines.push(`  archive ${a.dir}: ${a.valid ? 'VALID entries ' + a.from.count + '..' + a.to.count : 'INVALID (' + a.reason + ')'}`);
  if (r.anchor) lines.push(`  anchor: ${r.anchor.ok ? 'OK' : 'FAIL ' + r.anchor.problems.join(',')}`);
  if (r.anchors) lines.push(`  anchors: ${r.anchors.valid ? 'VALID · ' + r.anchors.anchors + ' witnessed checkpoint(s) consistent with the log' : 'INVALID ' + (r.anchors.reason || r.anchors.findings.map((x) => x.code + '@' + x.anchor).join(','))}`);
  if (r.transparency) {
    const t = r.transparency;
    lines.push(`  transparency: ${t.valid ? 'VALID' : 'INVALID'} · entries ${t.entries.filter((e) => e.valid).length}/${t.entries.length} · roots ${t.roots.filter((e) => e.valid).length}/${t.roots.length} · proofs ${t.proofs.filter((e) => e.valid).length}/${t.proofs.length}` +
      (t.nonCanonicalSignatures ? ` · non-canonical signature encodings ${t.nonCanonicalSignatures}` : ''));
    if (t.crossCheck) lines.push(`  audit↔transparency: ${t.crossCheck.valid ? 'CONSISTENT' : 'INCONSISTENT'} · leaves with auditEntryHash ${t.crossCheck.leavesWithAuditHash}, matched ${t.crossCheck.matched}, missing ${t.crossCheck.missing.length}, mismatched ${t.crossCheck.mismatched.length}`);
  }
  return lines.join('\n');
}

if (require.main === module) {
  let args;
  try { args = parseArgs(process.argv.slice(2)); } catch (e) { console.error(`usage error: ${e.message}`); process.exit(2); }
  if (!args.audit && !args.transparency && !args.roots && !args.proofs) { console.error('usage error: nothing to verify (see the header of this file)'); process.exit(2); }
  let report;
  try { report = verify(args); } catch (e) { console.error(`input error: ${e.message}`); process.exit(2); }
  if (args.out) fs.writeFileSync(args.out, JSON.stringify(report, null, 1) + '\n');
  console.log(summary(report));
  process.exit(report.verdict === 'VALID' ? 0 : 1);
}

module.exports = { verify, summary, TOOL };
