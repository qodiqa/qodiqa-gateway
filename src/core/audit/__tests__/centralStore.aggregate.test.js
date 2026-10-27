'use strict';

// the code under test reads the monotonic clock (src/infra/time/monotonicClock.js), which jest fake timers
// and Date.now spies do not move. Point it at Date.now so this suite keeps driving time the way it always has; the
// monotonic behaviour itself is pinned by src/infra/time/__tests__/monotonicSites.test.js.
jest.mock('../../../infra/time/monotonicClock', () => ({ monoNowMs: () => Date.now(), wallFromMono: (m) => m || null }));

/**
 * step 6 — per-minute aggregation of routine success events in
 * src/core/audit/centralStore.js (migration 068 adds aggregate_count).
 *
 *   AG-01  routine INFO success events of one (minute, type, tenant) become ONE row with aggregate_count = n,
 *          no correlation ids, payload.aggregated = true
 *   AG-02  keys are separate per tenant and per clock minute (of the event's own timestamp)
 *   AG-03  never aggregated: WARN or higher, a BLOCK/FAILURE/WARNING outcome (a SIGN_DECISION that blocked), any
 *          type not on the list — each stays one row with aggregate_count 1 and its correlation ids
 *   AG-04  a still-open minute is not written by the periodic drain, only once it closed (+ settle); flush() writes it
 *   AG-05  QODIQA_AUDIT_STORE_AGGREGATE=false restores per-row persistence (rollback switch)
 *   AG-06  the list is exactly the fourteen types measured at ad8f2606 (15 rows/request)
 */

const path = require('path');
const POOL_PATH   = path.resolve(__dirname, '..', '..', '..', 'infra', 'postgres', 'pool');
const STORE_PATH  = path.resolve(__dirname, '..', 'centralStore.js');
const LOGGER_PATH = path.resolve(__dirname, '..', '..', '..', '..', 'services', 'logger');
const COLS = 19;
const T0 = Date.UTC(2026, 8, 30, 12, 0, 10); // 12:00:10 UTC

describe('platform_audit_events aggregation', () => {
  let store; let calls;
  function load() {
    jest.resetModules();
    calls = [];
    jest.doMock(LOGGER_PATH, () => ({ emit: () => {} }));
    jest.doMock(POOL_PATH, () => ({ isEnabled: () => true, query: jest.fn((sql, params) => { calls.push({ sql, params }); return Promise.resolve({ rowCount: params.length / COLS }); }) }));
    store = require(STORE_PATH);
  }
  const rows = () => calls.filter((c) => c.sql.includes('INTO platform_audit_events')).flatMap((c) => Array.from({ length: c.params.length / COLS }, (_, i) => c.params.slice(i * COLS, (i + 1) * COLS)));
  const TCOLS = 9;
  const trails = () => calls.filter((c) => c.sql.includes('INTO request_trails')).flatMap((c) => Array.from({ length: c.params.length / TCOLS }, (_, i) => c.params.slice(i * TCOLS, (i + 1) * TCOLS)))
    .map((r) => ({ key: r[0], requestIds: r[1], artifactIds: r[2], tenantId: r[3], actorId: r[4], callerIp: r[5], steps: JSON.parse(r[6]), first: r[7], last: r[8] }));
  const row = (r) => ({ occurredAt: r[0], eventType: r[1], category: r[2], severity: r[3], requestId: r[5], tenantId: r[13], outcome: r[16], payload: JSON.parse(r[17]), aggregateCount: r[18] });
  const at = (ms) => new Date(ms).toISOString();
  afterEach(() => { delete process.env.QODIQA_AUDIT_STORE_AGGREGATE; jest.useRealTimers(); jest.dontMock(POOL_PATH); jest.dontMock(LOGGER_PATH); jest.resetModules(); });

  test('AG-01 n routine events of one minute/type/tenant → one row, aggregate_count n', async () => {
    load();
    for (let i = 0; i < 7; i++) {
      await store.ingest('INFO', 'POLICY_EXECUTE', { timestamp: at(T0 + i * 1000), requestId: `00000000-0000-4000-8000-00000000000${i}`, tenantId: 'tenant-a' });
    }
    await store.flush();
    const r = rows().map(row);
    expect(r).toHaveLength(1);
    expect(r[0]).toMatchObject({ eventType: 'POLICY_EXECUTE', category: 'POLICY', severity: 'INFO', tenantId: 'tenant-a', requestId: null, aggregateCount: 7 });
    expect(r[0].occurredAt.toISOString()).toBe('2026-09-30T12:00:00.000Z');
    expect(r[0].payload).toMatchObject({ aggregated: true, count: 7, windowStart: '2026-09-30T12:00:00.000Z', windowEnd: '2026-09-30T12:01:00.000Z',
      firstOccurredAt: at(T0), lastOccurredAt: at(T0 + 6000) });
  });

  test('AG-02 separate rows per tenant and per clock minute', async () => {
    load();
    await store.ingest('INFO', 'SIGN_AUTH_OK', { timestamp: at(T0), tenantId: 'a' });
    await store.ingest('INFO', 'SIGN_AUTH_OK', { timestamp: at(T0 + 1), tenantId: 'a' });
    await store.ingest('INFO', 'SIGN_AUTH_OK', { timestamp: at(T0 + 2), tenantId: 'b' });
    await store.ingest('INFO', 'SIGN_AUTH_OK', { timestamp: at(T0 + 60_000), tenantId: 'a' }); // next minute
    await store.flush();
    const r = rows().map(row).map((x) => `${x.tenantId}@${x.occurredAt.toISOString().slice(11, 16)}=${x.aggregateCount}`).sort();
    expect(r).toEqual(['a@12:00=2', 'a@12:01=1', 'b@12:00=1']);
  });

  test('AG-03 WARN+, blocking/failing outcomes and unlisted types stay one row each with their correlation', async () => {
    load();
    const rid = '11111111-1111-4111-8111-111111111111';
    await store.ingest('INFO', 'SIGN_DECISION', { timestamp: at(T0), requestId: rid, decision: 'BLOCK', tenantId: 't' });   // BLOCK outcome
    await store.ingest('WARN', 'POLICY_EXECUTE', { timestamp: at(T0), requestId: rid, tenantId: 't' });                    // WARN
    await store.ingest('INFO', 'AUDIT_BLOCK_RECORDED', { timestamp: at(T0), requestId: rid, decision: 'BLOCK' });          // unlisted
    await store.ingest('INFO', 'STREAM_AUDIT_RECORDED', { timestamp: at(T0), requestId: rid, decision: 'ALLOW' });         // unlisted
    await store.ingest('INFO', 'SIGN_DECISION', { timestamp: at(T0), requestId: rid, decision: 'ALLOW', tenantId: 't' });  // aggregated
    await store.flush();
    const r = rows().map(row);
    const single = r.filter((x) => x.aggregateCount === 1 && !x.payload.aggregated);
    expect(single.map((x) => `${x.eventType}/${x.severity}/${x.outcome}`).sort()).toEqual(
      ['AUDIT_BLOCK_RECORDED/INFO/BLOCK', 'POLICY_EXECUTE/WARN/null', 'SIGN_DECISION/INFO/BLOCK', 'STREAM_AUDIT_RECORDED/INFO/ALLOW']);
    expect(single.every((x) => x.requestId === rid)).toBe(true);
    const agg = r.filter((x) => x.payload.aggregated);
    expect(agg).toHaveLength(1);
    expect(agg[0]).toMatchObject({ eventType: 'SIGN_DECISION', outcome: 'ALLOW', aggregateCount: 1 });
  });

  test('AG-04 the periodic drain waits for the minute to close; flush() writes an open minute', async () => {
    jest.useFakeTimers({ now: T0 });
    load();
    await store.ingest('INFO', 'PROVIDER_EXECUTION_START', { timestamp: at(T0) });
    jest.advanceTimersByTime(5_000);                       // drain tick inside the same minute
    expect(rows()).toHaveLength(0);
    jest.setSystemTime(T0 + 50_000 + 2_000 + 5_000);       // 12:01:07 — minute 12:00 closed > 2 s ago
    jest.advanceTimersByTime(5_000);                       // next drain tick moves it to the write buffer
    jest.advanceTimersByTime(300);                         // the batch timer writes it
    await Promise.resolve();
    expect(rows().map(row).map((x) => x.aggregateCount)).toEqual([1]);
    jest.useRealTimers();
    load();
    await store.ingest('INFO', 'PROVIDER_EXECUTION_START', { timestamp: at(Date.now()) });
    await store.flush();
    expect(rows().map(row).map((x) => x.aggregateCount)).toEqual([1]);
  });

  test('AG-05 QODIQA_AUDIT_STORE_AGGREGATE=false restores per-row persistence', async () => {
    process.env.QODIQA_AUDIT_STORE_AGGREGATE = 'false';
    load();
    for (let i = 0; i < 3; i++) await store.ingest('INFO', 'POLICY_EXECUTE', { timestamp: at(T0 + i), tenantId: 'a' });
    await store.flush();
    const r = rows().map(row);
    expect(r).toHaveLength(3);
    expect(r.every((x) => x.aggregateCount === 1 && !x.payload.aggregated)).toBe(true);
  });

  // ── per-request trails ────────────────────────────────────────────────────────────────────
  const SIGN = '11111111-2222-4333-8444-555555555555';
  const CHAT = '99999999-8888-4777-8666-555555555555';
  async function oneRequest() {
    await store.ingest('INFO', 'SIGN_AUTH_OK', { timestamp: at(T0), requestId: SIGN, ip: '203.0.113.9', identityId: 'id-1', tenantId: 't1' });
    await store.ingest('INFO', 'SIGN_DECISION', { timestamp: at(T0 + 3), requestId: SIGN, artifactId: CHAT, decision: 'ALLOW', ip: '203.0.113.9', identityId: 'id-1', tenantId: 't1' });
    await store.ingest('INFO', 'POLICY_EXECUTE', { timestamp: at(T0 + 10), requestId: CHAT, decision: 'EXECUTE', reason: 'ok', policyId: 'p' });
    await store.ingest('INFO', 'PROVIDER_EXECUTION_COMPLETE', { timestamp: at(T0 + 20), requestId: CHAT, latencyMs: 7, usage: { total_tokens: 3 } });
    await store.ingest('INFO', 'AUDIT_EXECUTION_RECORDED', { timestamp: at(T0 + 30), requestId: CHAT, artifactId: CHAT, decision: 'ALLOW', policyHash: 'c'.repeat(64) });
    await store.ingest('INFO', 'EVIDENCE_CHAIN_RECORD_CREATED', { timestamp: at(T0 + 31), artifactId: CHAT, evidenceId: 'ev-1', evidenceHash: 'h' });
    await store.ingest('INFO', 'TRANSPARENCY_ENTRY_CREATED', { timestamp: at(T0 + 32), artifactId: CHAT, transparencyId: 'tr-1', entryHash: 'h' });
    await store.ingest('INFO', 'ANOMALY_STATE_INCREMENTED', { timestamp: at(T0 + 1), key: 'k', count: 1 });   // no ids → no trail step
  }

  test('TR-01 one trail row per root: steps keep type, time, ids, outcome and only the allow-listed fields', async () => {
    load();
    await oneRequest();
    await store.flush();
    const t = trails().sort((x, y) => x.key.localeCompare(y.key));
    expect(t.map((x) => x.key)).toEqual([SIGN, CHAT].sort());
    const chat = t.find((x) => x.key === CHAT);
    const sign = t.find((x) => x.key === SIGN);
    // one row per HTTP request: /sign (both SIGN_* steps, incl. SIGN_DECISION which carries the chat artifact id) and /ai/chat
    expect(sign.steps.map((s) => s.t)).toEqual(['SIGN_AUTH_OK', 'SIGN_DECISION']);
    expect(sign.requestIds).toEqual([SIGN]);
    expect(sign.artifactIds).toEqual([CHAT]);
    expect(chat.steps.map((s) => s.t)).toEqual(['POLICY_EXECUTE', 'PROVIDER_EXECUTION_COMPLETE', 'AUDIT_EXECUTION_RECORDED',
      'EVIDENCE_CHAIN_RECORD_CREATED', 'TRANSPARENCY_ENTRY_CREATED']);
    expect(chat.steps[1]).toEqual({ t: 'PROVIDER_EXECUTION_COMPLETE', at: at(T0 + 20), r: CHAT, a: null, tr: null, sp: null, o: 'SUCCESS', x: { latencyMs: 7 } });
    expect(chat.steps[3].x).toEqual({ evidenceId: 'ev-1' });
    expect(chat.steps[4].x).toEqual({ transparencyId: 'tr-1' });
    expect(chat.requestIds).toEqual([CHAT]);
    expect(chat.artifactIds).toEqual([CHAT]);
    // decision facts are NOT kept in the trail (they come from the audit chain)
    expect(JSON.stringify(chat.steps)).not.toMatch(/policyHash|"decision"|usage|reason|policyId/);
  });

  test('TR-02 caller IP and identity id live only in the row columns (erasable), never in the step JSON', async () => {
    load();
    await oneRequest();
    await store.flush();
    const all = trails();
    const sign = all.find((x) => x.key === SIGN); const chat = all.find((x) => x.key === CHAT);
    // the /sign row holds the steps that carried IP and identity: values in its COLUMNS only
    expect(sign).toMatchObject({ callerIp: '203.0.113.9', actorId: 'id-1', tenantId: 't1' });
    expect(sign.steps.every((s) => s.ip === 1 && s.id === 1)).toBe(true);
    // the chat row's steps carried neither, so it holds no personal data at all
    expect(chat).toMatchObject({ callerIp: null, actorId: null });
    expect(chat.steps.some((s) => s.ip || s.id)).toBe(false);
    for (const x of all) expect(JSON.stringify(x.steps)).not.toMatch(/203\.0\.113\.9|id-1/);
  });

  test('TR-03 a step whose IP or identity differs starts a new row of the same root', async () => {
    load();
    await store.ingest('INFO', 'SIGN_AUTH_OK', { timestamp: at(T0), requestId: SIGN, ip: '203.0.113.9', identityId: 'id-1' });
    await store.ingest('INFO', 'SIGN_AUTH_OK', { timestamp: at(T0 + 1), requestId: SIGN, ip: '198.51.100.2', identityId: 'id-1' });
    await store.flush();
    const t = trails();
    expect(t).toHaveLength(2);
    expect(t.map((x) => x.callerIp).sort()).toEqual(['198.51.100.2', '203.0.113.9']);
    expect(t.every((x) => x.key === SIGN && x.steps.length === 1)).toBe(true);
  });

  test('TR-04 a trail is written after TRAIL_IDLE_MS without steps, not while the request is still active', async () => {
    jest.useFakeTimers({ now: T0 });
    load();
    await store.ingest('INFO', 'POLICY_EXECUTE', { timestamp: at(T0), requestId: CHAT });
    jest.advanceTimersByTime(5_000);          // first drain tick: idle exactly 5 s → closed
    jest.advanceTimersByTime(300);
    await Promise.resolve(); await Promise.resolve();
    expect(trails()).toHaveLength(1);
  });

  test('TR-05 non-aggregated events never create trail steps (they stay full rows)', async () => {
    load();
    await store.ingest('INFO', 'SIGN_DECISION', { timestamp: at(T0), requestId: SIGN, decision: 'BLOCK', ip: '203.0.113.9' });
    await store.ingest('WARN', 'POLICY_EXECUTE', { timestamp: at(T0), requestId: SIGN });
    await store.flush();
    expect(trails()).toEqual([]);
    expect(rows()).toHaveLength(2);
  });

  test('AG-06 the aggregated list is exactly the fourteen routine success types measured at ad8f2606', () => {
    load();
    const src = require('fs').readFileSync(STORE_PATH, 'utf8');
    const list = src.match(/const AGGREGATED_EVENT_TYPES = Object\.freeze\(new Set\(\[([\s\S]*?)\]\)\)/)[1].match(/'([A-Z_]+)'/g).map((s) => s.slice(1, -1)).sort();
    expect(list).toEqual(['ANOMALY_STATE_INCREMENTED', 'AUDIT_EXECUTION_RECORDED', 'EVIDENCE_CHAIN_RECORD_CREATED', 'POLICY_EXECUTE', 'POLICY_HASH_BOUND',
      'PROVIDER_EXECUTION_COMPLETE', 'PROVIDER_EXECUTION_START', 'PROVIDER_REQUEST_VALIDATED', 'PROVIDER_ROUTING_DECISION', 'SIGN_AUTH_OK', 'SIGN_DECISION',
      'TRANSPARENCY_ENTRY_CREATED', 'TRANSPARENCY_ENTRY_REGISTERED', 'TRANSPARENCY_ROOT_SIGNED']);
  });
});
