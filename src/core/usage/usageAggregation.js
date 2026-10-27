'use strict';

/**
 * Usage Aggregation — (Action 1: per-tenant usage aggregation).
 *
 * PURE, deterministic reduction of audit-chain evidence entries into a
 * per-tenant usage summary. This module is the single, canonical statement
 * of what "usage" means in QODIQA:
 *
 *   THE METERING SOURCE OF TRUTH IS THE EXISTING EXECUTION EVIDENCE.
 *
 * Every AI execution outcome QODIQA records lands as exactly one audit-chain
 * entry (entryBuilder.js; artifact_id is UNIQUE at the PG level — migration
 * 001's idx_audit_chain_artifact_id — and one-entry-per-decision by
 * construction in aiChat.js/streamEnforcer.js). Provider adapters normalize
 * token accounting into ProviderResponse.tokenUsage
 * ({inputTokens, outputTokens, totalTokens}, services/providers/
 * normalize.js) and the enforcement pipeline persists it VERBATIM at
 * executionContext.tokenUsage on the entry. No second token counter exists,
 * and this module does not introduce one — it only reads what is already
 * recorded.
 *
 * METERED ENTRY (deterministic definition):
 *   an entry whose executionContext owns a `tokenUsage` key. That key is
 *   written exactly by the evidence paths that attribute provider token
 *   accounting to a decision:
 *     - non-streaming ALLOW  (aiChat.js Step 6: tokenUsage object or null)
 * - output-semantic BLOCK
 *     - streaming ALLOW/BLOCK (streamEnforcer.js: tokenUsage null — the
 *       streaming adapters do not surface provider usage; metered as an
 *       execution contributing 0 tokens)
 *   Entries WITHOUT the key are deliberately not metered: pre-execution
 *   BLOCKs (validation / policy / input-semantic — no provider call
 *   happened) and provider-error/cancelled BLOCKs (a call was attempted but
 *   the provider reported no usage; evidence records none, and metering
 *   never invents token counts that are not in evidence).
 *
 * TOKEN FIELDS (verbatim from evidence; see normalize.js):
 *   inputTokens  — prompt/input tokens   (int ≥ 0 or null)
 *   outputTokens — completion/output tokens (int ≥ 0 or null)
 *   totalTokens  — total tokens          (int ≥ 0 or null)
 * Per-entry effective total (Action-1 derivation rule): totalTokens when the
 * provider reported it; otherwise, when at least one component is present,
 * the deterministic component sum (null components count 0); otherwise null.
 * A recorded totalTokens is NEVER reconstructed or second-guessed.
 *
 * TIME SEMANTICS: the entry's own hash-protected `timestamp` (ISO-8601 UTC,
 * assigned once at entry build — entryBuilder.js; recorded_at in PG). Day
 * bucketing is the UTC calendar date of that timestamp. The same entry
 * therefore always falls in the same period, on every backend, forever —
 * aggregation never depends on query time or server-local timezone.
 *
 * DUPLICATES / IDEMPOTENCY: the idempotency identity is the entry's
 * artifactId (the stable execution identifier; PG-unique, and the id the
 * idempotency gate replays against — a REPLAY writes NO new entry). This
 * reducer additionally dedupes defensively: if the same artifactId is ever
 * seen twice in one scan, only the FIRST occurrence (chain order) counts.
 * Aggregation is read-only and repeatable — re-running it never changes
 * what is counted.
 *
 * NUMERIC SAFETY: accumulation uses BigInt end-to-end; a total is emitted
 * as a JSON number only when it fits Number.MAX_SAFE_INTEGER, otherwise as
 * a decimal string (see toJsonSafeCount) — precision is never silently lost.
 *
 * The PostgreSQL path (pg-audit-backend.js aggregateUsageByTenantPg) states
 * these SAME rules in SQL; test/integration/usageMeteringPg.integration.test.js proves
 * the two agree on identical evidence.
 */

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

/** Non-negative-integer read of an evidence token field; anything else is null. */
function _tokenIntOrNull(v) {
  if (typeof v !== 'number' || !Number.isFinite(v) || v < 0) return null;
  return Math.round(v);
}

/** True when `entry` is a metered execution per the definition above. */
function isMeteredEntry(entry) {
  return !!(
    entry &&
    entry.executionContext &&
    typeof entry.executionContext === 'object' &&
    Object.prototype.hasOwnProperty.call(entry.executionContext, 'tokenUsage')
  );
}

/**
 * Per-entry usage contribution, or null when the entry is not metered or
 * carries no usable timestamp. Accepts entries from every audit backend
 * (in-memory window / file scan: ISO string timestamps; PG rows: Date).
 */
function usageContribution(entry) {
  if (!isMeteredEntry(entry)) return null;

  const raw = entry.timestamp;
  const ts  = raw instanceof Date ? raw.getTime() : Date.parse(raw);
  if (!Number.isFinite(ts)) return null;

  const tu     = entry.executionContext.tokenUsage;
  const input  = _tokenIntOrNull(tu && tu.inputTokens);
  const output = _tokenIntOrNull(tu && tu.outputTokens);
  const total  = _tokenIntOrNull(tu && tu.totalTokens);

  // Action-1 total derivation rule (see header): recorded total wins;
  // otherwise deterministic component sum when any component exists.
  const effectiveTotal = total !== null
    ? total
    : (input === null && output === null ? null : (input ?? 0) + (output ?? 0));

  return {
    artifactId:   typeof entry.artifactId === 'string' ? entry.artifactId : null,
    timestampMs:  ts,
    day:          new Date(ts).toISOString().slice(0, 10), // UTC calendar date
    inputTokens:  input,
    outputTokens: output,
    totalTokens:  effectiveTotal,
  };
}

/** BigInt count → JSON-safe value: number when exact, decimal string beyond 2^53-1. */
function toJsonSafeCount(big) {
  return big <= MAX_SAFE ? Number(big) : big.toString();
}

function _newBucket() {
  return { executions: 0n, inputTokens: 0n, outputTokens: 0n, totalTokens: 0n };
}

function _addTo(bucket, c) {
  bucket.executions += 1n;
  if (c.inputTokens  !== null) bucket.inputTokens  += BigInt(c.inputTokens);
  if (c.outputTokens !== null) bucket.outputTokens += BigInt(c.outputTokens);
  if (c.totalTokens  !== null) bucket.totalTokens  += BigInt(c.totalTokens);
}

function _emit(bucket) {
  return {
    executions:   toJsonSafeCount(bucket.executions),
    inputTokens:  toJsonSafeCount(bucket.inputTokens),
    outputTokens: toJsonSafeCount(bucket.outputTokens),
    totalTokens:  toJsonSafeCount(bucket.totalTokens),
  };
}

/**
 * Deterministically reduce evidence entries to { totals, series }.
 *
 * @param {Iterable<object>} entries — audit-chain entries (any backend shape)
 * @param {{fromMs: number, toMs: number}} range — half-open [fromMs, toMs)
 * @returns {{ totals: object, series: Array<object> }} series is one row per
 *   UTC day that has at least one metered execution, ascending by day.
 */
function reduceUsage(entries, { fromMs, toMs }) {
  const totals = _newBucket();
  const byDay  = new Map();
  const seen   = new Set(); // defensive artifactId dedupe — first occurrence wins

  for (const entry of entries) {
    const c = usageContribution(entry);
    if (!c) continue;
    if (c.timestampMs < fromMs || c.timestampMs >= toMs) continue;
    if (c.artifactId !== null) {
      if (seen.has(c.artifactId)) continue;
      seen.add(c.artifactId);
    }
    _addTo(totals, c);
    let bucket = byDay.get(c.day);
    if (!bucket) { bucket = _newBucket(); byDay.set(c.day, bucket); }
    _addTo(bucket, c);
  }

  const series = [...byDay.keys()].sort().map((day) => ({ day, ..._emit(byDay.get(day)) }));
  return { totals: _emit(totals), series };
}

/**
 * Merge the per-UTC-day rows returned by pg-audit-backend.js's
 * aggregateUsageByTenantPg (exact decimal strings, ascending by day) into
 * the same { totals, series } shape reduceUsage() produces — every count
 * travels through BigInt, never a lossy double. Kept here so the
 * distributed-mode read path shares this module's numeric policy and is
 * unit-testable next to the reducer it must agree with.
 */
function mergePgDailyRows(rows) {
  const totals = _newBucket();
  const series = rows.map((r) => {
    const day = {
      executions:   BigInt(r.executions ?? '0'),
      inputTokens:  BigInt(r.inputTokens ?? '0'),
      outputTokens: BigInt(r.outputTokens ?? '0'),
      totalTokens:  BigInt(r.totalTokens ?? '0'),
    };
    totals.executions   += day.executions;
    totals.inputTokens  += day.inputTokens;
    totals.outputTokens += day.outputTokens;
    totals.totalTokens  += day.totalTokens;
    return {
      day:          r.day,
      executions:   toJsonSafeCount(day.executions),
      inputTokens:  toJsonSafeCount(day.inputTokens),
      outputTokens: toJsonSafeCount(day.outputTokens),
      totalTokens:  toJsonSafeCount(day.totalTokens),
    };
  });
  return { totals: _emit(totals), series };
}

module.exports = { isMeteredEntry, usageContribution, reduceUsage, mergePgDailyRows, toJsonSafeCount };
