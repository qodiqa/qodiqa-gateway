'use strict';

/**
 * replay GDPR erasures
 * after a restore, so a restored backup can never resurrect an erased subject.
 *
 * The restored database's own dsr_erasure_ledger only knows erasures made
 * BEFORE the backup. Erasures made after it must come from a surviving source:
 *   - a ledger export file (JSON Lines, `node scripts/dr/erasureLedger.js export`),
 *     shipped off-host like the WAL archive, or
 *   - a PostgreSQL connection string of a surviving database whose ledger is
 *     read through qodiqa_erasure_ledger_list.
 *
 * Replay, on the restore connection (the restore role runs the owner-run
 * functions; no request-serving role is involved):
 *   1. every restored-DB ledger row + every source row, de-duplicated by run_id;
 *      source rows missing from the restored ledger are re-inserted (it stays complete);
 *   2. qodiqa_erasure_subject_candidates() → every (tenant, identifier) still in
 *      plaintext; each is matched by subject_ref = HMAC(ledger key, …) —
 *      subjectPseudonym.subjectRef, keyed from QODIQA_DSR_PSEUDONYM_PEPPER;
 *   3. each match is erased again: consent_records (ConsentStore's own tombstone
 *      + record_hash logic), every catalog target (qodiqa_erase_subject until 0
 *      remain), dsr_requests pseudonymized, the subject key deleted.
 *
 * Nothing here prints an identifier; the report carries counts and subject_refs only.
 */

const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

const REPO = path.join(__dirname, '..', '..');
const subjectPseudonym = require(path.join(REPO, 'src', 'core', 'dsr', 'subjectPseudonym'));
const ConsentStore = require(path.join(REPO, 'src', 'core', 'consent', 'ConsentStore'));

const PAGE = 1000;

async function _ledgerFromClient(client) {
  const rows = [];
  for (let after = 0; ;) {
    const r = await client.query('SELECT * FROM qodiqa_erasure_ledger_list($1, $2)', [after, PAGE]);
    rows.push(...r.rows);
    if (r.rows.length < PAGE) return rows;
    after = Number(r.rows[r.rows.length - 1].id);
  }
}

/** Load ledger rows from a JSONL export file or a PostgreSQL connection string. */
async function loadLedgerSource(source) {
  if (!source) return [];
  if (/^postgres(ql)?:\/\//.test(source)) {
    const c = new Client({ connectionString: source });
    await c.connect();
    try { return await _ledgerFromClient(c); } finally { await c.end(); }
  }
  return fs.readFileSync(source, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
}

async function replayErasures({ connectionString, ledgerSource, erasedBy = 'dr-restore' }) {
  const client = new Client({ connectionString });
  await client.connect();
  const report = { ledgerRows: 0, importedLedgerRows: 0, candidates: 0, subjectsReErased: 0, subjectRefs: [], tables: {} };
  try {
    const restored = await _ledgerFromClient(client);
    const external = await loadLedgerSource(ledgerSource);
    const byRun = new Map();
    for (const r of [...restored, ...external]) byRun.set(String(r.run_id), r);
    report.ledgerRows = byRun.size;

    const haveRuns = new Set(restored.map((r) => String(r.run_id)));
    for (const r of external) {
      if (haveRuns.has(String(r.run_id))) continue;
      await client.query(
        `INSERT INTO dsr_erasure_ledger (tenant_id, subject_ref, request_id, run_id, erased_at, summary)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (run_id) DO NOTHING`,
        [r.tenant_id ?? null, r.subject_ref, r.request_id ?? null, r.run_id, r.erased_at, JSON.stringify(r.summary ?? {})],
      );
      haveRuns.add(String(r.run_id));
      report.importedLedgerRows += 1;
    }

    const erasedRefs = new Set([...byRun.values()].map((r) => `${r.tenant_id ?? ''}\u0000${r.subject_ref}`));
    if (!erasedRefs.size) return report;

    const candidates = (await client.query('SELECT * FROM qodiqa_erasure_subject_candidates()')).rows;
    report.candidates = candidates.length;
    for (const { tenant_id: tenantId, actor_id: actorId } of candidates) {
      const ref = subjectPseudonym.subjectRef(tenantId, actorId);
      if (!erasedRefs.has(`${tenantId ?? ''}\u0000${ref}`)) continue;

      await client.query('BEGIN');
      try {
        const pseudonym = await subjectPseudonym.pseudonymForWithClient(client, tenantId, actorId);
        for (;;) {
          const { erased } = await ConsentStore.eraseSubjectBatchWithClient(client, {
            actor_id: actorId, tenant_id: tenantId, pseudonym, erased_by: erasedBy, batch: 500,
          });
          report.tables['consent_records.actor_id'] = (report.tables['consent_records.actor_id'] || 0) + erased;
          if (erased === 0) break;
        }
        for (;;) {
          const rows = (await client.query('SELECT * FROM qodiqa_erase_subject($1, $2, $3, $4)', [tenantId, actorId, pseudonym, 500])).rows;
          let remaining = 0;
          for (const r of rows) { report.tables[r.target] = (report.tables[r.target] || 0) + Number(r.rows_updated); remaining += Number(r.remaining); }
          if (remaining === 0) break;
        }
        await client.query('UPDATE dsr_requests SET actor_id = $1 WHERE actor_id = $2 AND tenant_id IS NOT DISTINCT FROM $3', [pseudonym, actorId, tenantId]);
        await client.query('DELETE FROM subject_pseudonym_keys WHERE actor_id = $1 AND tenant_id IS NOT DISTINCT FROM $2', [actorId, tenantId]);
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        throw e;
      }
      report.subjectsReErased += 1;
      report.subjectRefs.push(ref);
    }
    return report;
  } finally {
    await client.end();
  }
}

module.exports = { replayErasures, loadLedgerSource };
