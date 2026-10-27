'use strict';

/**
 * — the audit chain verifier's worker thread.
 *
 * Runs the UNCHANGED verifier (createVerifierRunner + ChainVerifier) off the request event loop:
 *   - audit-log.js is loaded as a READ-ONLY follower (QODIQA_AUDIT_FOLLOWER=true): no WAL recovery, no writes; it
 *     follows the lines the main thread commits (refreshFromDisk) and reads only complete lines;
 *   - PostgreSQL: the SAME pool.js / rolePools.js modules and the same env as the main thread → the same roles
 *     (qodiqa_app for the verifier state/lock, qodiqa_system / qodiqa_reporting for the DEFINER reads) (amendment 8);
 *     no migrations are run here;
 * - what needs the main thread goes over RPC: drainMirrorWriter() and memorySnapshot() (the
 *     FULL scan's memory-vs-disk verdict, taken as one consistent point in time);
 *   - events and verifier metrics are re-emitted by the host in the main thread (same names, same payloads), so
 *     alerting on AUDIT_CHAIN_CORRUPTED etc. is unchanged;
 *   - CPU: every cooperative yield is duty-cycled (verifierPacer), ≤ ~50% of one core; memory: the host's
 *     resourceLimits; time: the host terminates a run past its deadline.
 */

process.env.QODIQA_AUDIT_FOLLOWER = 'true';

const { parentPort, workerData } = require('worker_threads');
const pacer = require('../verifierPacer');

pacer.setDutyCycle(workerData && Number.isFinite(workerData.dutyCycle) ? workerData.dutyCycle : 0.5);

let _rpcSeq = 0;
const _rpcPending = new Map();
function rpc(call, args) {
  return new Promise((resolve, reject) => {
    const id = ++_rpcSeq;
    const timer = setTimeout(() => { _rpcPending.delete(id); reject(new Error(`VERIFIER_RPC_TIMEOUT ${call}`)); }, (workerData && workerData.rpcTimeoutMs) || 15_000);
    _rpcPending.set(id, { resolve, reject, timer });
    parentPort.postMessage({ t: 'rpc', id, call, args });
  });
}

const emit = (level, eventType, data) => parentPort.postMessage({ t: 'emit', level, eventType, data });
const _metrics = new Proxy({}, {
  get: (_, name) => ({
    inc: (labels, value) => parentPort.postMessage({ t: 'metric', name, op: 'inc', labels, value }),
    set: (labels, value) => parentPort.postMessage({ t: 'metric', name, op: 'set', labels, value }),
    observe: (labels, value) => parentPort.postMessage({ t: 'metric', name, op: 'observe', labels, value }),
  }),
});

const pgPool = require('../../../infra/postgres/pool');
if (process.env.QODIQA_PG_ENABLED === 'true') { try { pgPool.initialize(); } catch (e) { emit('WARN', 'AUDIT_CHAIN_VERIFIER_WORKER_PG_INIT_FAILED', { error: e.message }); } }

const auditLog = require('../audit-log');
const follow = () => { auditLog.refreshFromDisk(); };
const facade = {
  ORDERING_MODE: auditLog.ORDERING_MODE,
  getChainStart: () => auditLog.getChainStart(),   // M3: where the (possibly rebased) chain starts
  drainMirrorWriter: () => rpc('drainMirrorWriter'),
  getChainStats: () => { follow(); return auditLog.getChainStats(); },
  getModernChainPage: async (o) => { follow(); return auditLog.getModernChainPage(o); },
  getModernChainSlice: async (i) => { follow(); return auditLog.getModernChainSlice(i); },
  forEachModernChainPage: async (fn, o) => { follow(); return auditLog.forEachModernChainPage(fn, o); },
  getModernChain: async () => { follow(); return auditLog.getModernChain(); },
  verifyAuditChainDetailed: auditLog.verifyAuditChainDetailed,
  // the runtime mirror-checkpoint advancement (mirrorConsistencyCheck.advanceMirrorCheckpoint)
  createChainWalker: auditLog.createChainWalker,
  locateModernCursor: (pos) => { follow(); return auditLog.locateModernCursor(pos); },
  getModernEntryAt: async (pos) => { follow(); return auditLog.getModernEntryAt(pos); },
  verifyAuditChainDetailedChunked: auditLog.verifyAuditChainDetailedChunked,
  verifyFullChainFromDiskChunked: async (opts) => {
    const memory = await rpc('memorySnapshot');
    follow();
    return auditLog.verifyFullChainFromDiskChunked({ ...(opts || {}), memory });
  },
};

const { createVerifierRunner } = require('./index');
const { load: loadConfig } = require('./verifierConfig');
const config = { ...loadConfig(), ...((workerData && workerData.config) || {}), trackCompletion: false };
const runner = createVerifierRunner({
  config, _emit: emit, _metrics, _auditLog: facade,
  _onRunStart: (mode, trigger, deadlineMs) => parentPort.postMessage({ t: 'runStart', mode, trigger, deadlineMs, at: Date.now() }),
  _onRunEnd: (mode, trigger, result, outcome) => parentPort.postMessage({ t: 'runEnd', mode, trigger, outcome,
    success: !!(result && result.success !== false), skipped: !!(result && result.skipped),
    watermarkIndex: result && Number.isFinite(result.watermarkIndex) ? result.watermarkIndex : null,
    violations: result && Array.isArray(result.violations) ? result.violations.length : 0 }),
});

const _handlers = {
  start: async () => { await runner.start(); return runner.getStatus(); },
  stop: async () => { runner.stop(); return runner.getStatus(); },
  verifyNow: async ([mode]) => runner.verifyNow(mode),
  verifyPgDivergenceNow: async () => runner.verifyPgDivergenceNow(),
  advanceMirrorCheckpointNow: async () => runner.advanceMirrorCheckpointNow(),   //
  getStatus: async () => runner.getStatus(),
  // amendment 8: which roles/paths this worker's pools use, and what they see (tests + diagnostics)
  selfCheck: async () => {
    const backend = require('../../../infra/postgres/pg-audit-backend');
    const rolePools = require('../../../infra/postgres/rolePools');
    const out = { pgEnabled: pgPool.isEnabled(), follower: auditLog.isFollower(), roles: { app: process.env.QODIQA_PG_USER || 'qodiqa_app',
      system: process.env.QODIQA_PG_SYSTEM_USER || rolePools.ROLES.system.defaultUser } };
    if (pgPool.isEnabled()) out.chainRowsSeenBySystemRole = await backend.countChainRows();
    return out;
  },
};

parentPort.on('message', async (m) => {
  if (!m) return;
  if (m.t === 'rpcReply') {
    const p = _rpcPending.get(m.id);
    if (!p) return;
    _rpcPending.delete(m.id); clearTimeout(p.timer);
    if (m.error) p.reject(new Error(m.error)); else p.resolve(m.value);
    return;
  }
  if (m.t === 'call') {
    try {
      const h = _handlers[m.call];
      if (!h) throw new Error(`unknown call ${m.call}`);
      parentPort.postMessage({ t: 'callReply', id: m.id, value: JSON.parse(JSON.stringify((await h(m.args || [])) ?? null)) });
    } catch (e) {
      parentPort.postMessage({ t: 'callReply', id: m.id, error: e.message });
    }
  }
});

// A follower that finds the log shorter than what it read (a failed batch undone — crash point B') cannot continue:
// exit so the host restarts it and it reloads from disk.
process.on('unhandledRejection', (e) => { emit('ERROR', 'AUDIT_CHAIN_VERIFIER_WORKER_ERROR', { error: e && e.message }); if (/AUDIT_FOLLOWER_LOG_SHRANK/.test(String(e && e.message))) process.exit(3); });
parentPort.postMessage({ t: 'ready', status: runner.getStatus() });
