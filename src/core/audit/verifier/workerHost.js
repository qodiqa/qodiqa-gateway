'use strict';

/**
 * — main-thread host of the verifier worker.
 *
 * Same public API as createVerifierRunner() (start, stop, isRunning, isScanning, verifyNow, verifyPgDivergenceNow,
 * getStatus), so server/startup.js and the admin route are unchanged. The verifier runs in ./verifierWorker.js.
 *
 *   events / metrics   re-emitted here, in the main thread (same names, same payloads)
 *   RPC from worker    drainMirrorWriter(), memorySnapshot() — answered from the live audit-log module
 *   hard deadline      a run past its mode's deadline + 30 s grace → the worker is terminated (WARN
 *                      AUDIT_CHAIN_VERIFIER_WORKER_TERMINATED) and restarted; recorded as a TIMEOUT
 *   memory             resourceLimits.maxOldGenerationSizeMb (default 512)
 *   crash / OOM        restart with backoff 5 s → 5 min; 5 consecutive → CRITICAL AUDIT_CHAIN_VERIFIER_UNAVAILABLE
 *   completion + lag   tracked HERE (completionTracker) so an escalation survives worker restarts
 */

const path = require('path');
const { Worker } = require('worker_threads');
const { createCompletionTracker } = require('./completionTracker');

const SOURCE = 'AUDIT_CHAIN_VERIFIER';
const GRACE_MS = 30_000;

function createWorkerRunner(opts = {}) {
  const {
    _emit = require('../../../../services/logger').emit,
    _metrics = require('../../../observability/metrics'),
    _auditLog = require('../audit-log'),
    config: cfgOverride = {},
    memoryLimitMb = Number(process.env.QODIQA_AUDIT_VERIFIER_WORKER_MEMORY_MB) || 512,
    dutyCycle = Number(process.env.QODIQA_AUDIT_VERIFIER_WORKER_DUTY) || 0.5,
    backoffMs = [5_000, 15_000, 60_000, 300_000],
    _workerPath = path.join(__dirname, 'verifierWorker.js'),
  } = opts;
  const config = { ...cfgOverride, memoryLimitMb };

  const tracker = createCompletionTracker({
    emit: _emit, metrics: _metrics, notCompletingAfter: config.notCompletingAfter || 3, lagWarnEntries: config.lagWarnEntries || 60_000,
    getAppendedCount: () => { try { return _auditLog.getChainStats().modernLength; } catch { return null; } },
  });

  let worker = null; let ready = null; let running = false; let callSeq = 0;
  const calls = new Map();
  let lastStatus = null; let scanning = false; let currentRun = null; let deadlineTimer = null;
  let consecutiveFailures = 0; let unavailableRaised = false; let restartTimer = null; let restarts = 0;
  let stopping = false;

  function applyMetric(m) { try { const t = _metrics[m.name]; if (t && typeof t[m.op] === 'function') t[m.op](m.labels, m.value); } catch { /* metrics never affect verification */ } }

  async function answerRpc(m) {
    let value = null; let error = null;
    try {
      if (m.call === 'drainMirrorWriter') { await _auditLog.drainMirrorWriter(); value = true; }
      else if (m.call === 'memorySnapshot') value = _auditLog.memorySnapshot();
      else error = `unknown rpc ${m.call}`;
    } catch (e) { error = e.message; }
    if (worker) worker.postMessage({ t: 'rpcReply', id: m.id, value, error });
  }

  function spawn() {
    // env: the HOST's process.env explicitly (Node's default reads the process-level env, which a sandboxed host
    // such as Jest does not share) — the worker must see exactly the PG/audit settings its host sees (amendment 8).
    const w = new Worker(_workerPath, { env: process.env, workerData: { config, dutyCycle }, resourceLimits: { maxOldGenerationSizeMb: memoryLimitMb } });
    worker = w;
    ready = new Promise((resolve, reject) => {
      const onMsg = (m) => { if (m && m.t === 'ready') { w.off('message', onMsg); resolve(); } };
      w.on('message', onMsg);
      w.once('error', reject);
      w.once('exit', (code) => reject(new Error(`verifier worker exited during start (code ${code})`)));
    });
    ready.catch(() => {});
    w.on('message', (m) => {
      if (!m) return;
      if (m.t === 'emit') _emit(m.level, m.eventType, m.data);
      else if (m.t === 'metric') applyMetric(m);
      else if (m.t === 'rpc') answerRpc(m);
      else if (m.t === 'callReply') { const c = calls.get(m.id); if (c) { calls.delete(m.id); if (m.error) c.reject(new Error(m.error)); else c.resolve(m.value); } }
      else if (m.t === 'runStart') {
        scanning = true; currentRun = { mode: m.mode, trigger: m.trigger, startedAt: m.at, deadlineMs: m.deadlineMs };
        clearTimeout(deadlineTimer);
        if (m.deadlineMs) deadlineTimer = setTimeout(() => onDeadline(m), m.deadlineMs + GRACE_MS);
        if (deadlineTimer.unref) deadlineTimer.unref();
      } else if (m.t === 'runEnd') {
        scanning = false; currentRun = null; clearTimeout(deadlineTimer);
        consecutiveFailures = 0; unavailableRaised = false;
        if (!m.skipped) tracker.record(m.mode, m.outcome, m.outcome === 'TIMEOUT' ? { deadlineMs: config.deadlinesMs?.[m.mode] } : {});
        if (m.mode === 'INCREMENTAL' && Number.isFinite(m.watermarkIndex)) tracker.recordWatermark(m.watermarkIndex);
      }
    });
    w.on('error', (e) => _emit('ERROR', 'AUDIT_CHAIN_VERIFIER_WORKER_ERROR', { source: SOURCE, error: e.message, code: e.code || null }));
    w.on('exit', (code) => onExit(w, code));
    return w;
  }

  function onDeadline(m) {
    _emit('WARN', 'AUDIT_CHAIN_VERIFIER_WORKER_TERMINATED', { source: SOURCE, mode: m.mode, trigger: m.trigger, deadlineMs: m.deadlineMs, graceMs: GRACE_MS,
      message: 'A verifier run exceeded its deadline; the worker was terminated and will restart.' });
    tracker.record(m.mode, 'TIMEOUT', { deadlineMs: m.deadlineMs, terminated: true });
    const w = worker;
    if (w) w.terminate().catch(() => {});
  }

  function onExit(w, code) {
    if (w !== worker) return;
    worker = null; scanning = false; currentRun = null; clearTimeout(deadlineTimer);
    for (const [, c] of calls) c.reject(new Error(`verifier worker exited (code ${code})`));
    calls.clear();
    if (stopping || !running) return;
    consecutiveFailures++;
    _emit('WARN', 'AUDIT_CHAIN_VERIFIER_WORKER_EXITED', { source: SOURCE, code, consecutiveFailures });
    if (consecutiveFailures >= 5 && !unavailableRaised) {
      unavailableRaised = true;
      _emit('CRITICAL', 'AUDIT_CHAIN_VERIFIER_UNAVAILABLE', { source: SOURCE, consecutiveFailures, message: 'The audit chain verifier worker keeps failing: the chain is not being verified.' });
    }
    const delay = backoffMs[Math.min(consecutiveFailures - 1, backoffMs.length - 1)];
    restartTimer = setTimeout(async () => {
      restarts++;
      try { spawn(); await ready; await call('start'); } catch (e) { _emit('ERROR', 'AUDIT_CHAIN_VERIFIER_WORKER_RESTART_FAILED', { source: SOURCE, error: e.message }); }
    }, delay);
    if (restartTimer.unref) restartTimer.unref();
  }

  function call(name, ...args) {
    if (!worker) return Promise.reject(new Error('verifier worker not running'));
    return new Promise((resolve, reject) => {
      const id = ++callSeq;
      calls.set(id, { resolve, reject });
      worker.postMessage({ t: 'call', id, call: name, args });
    }).then((v) => { if (v && typeof v === 'object' && 'running' in v) lastStatus = v; return v; });
  }

  return {
    async start() {
      if (running) { _emit('WARN', 'AUDIT_CHAIN_VERIFIER_ALREADY_RUNNING', { source: SOURCE }); return this; }
      running = true; stopping = false;
      spawn();
      await ready;
      await call('start');
      _emit('INFO', 'AUDIT_CHAIN_VERIFIER_WORKER_STARTED', { source: SOURCE, memoryLimitMb, dutyCycle });
      return this;
    },
    stop() {
      if (!running) return this;
      running = false; stopping = true;
      clearTimeout(restartTimer); clearTimeout(deadlineTimer);
      const w = worker;
      if (w) { call('stop').catch(() => {}).finally(() => { w.terminate().catch(() => {}); }); }
      return this;
    },
    isRunning() { return running; },
    isScanning() { return scanning; },
    async verifyNow(mode) { if (!worker) { spawn(); await ready; } return call('verifyNow', mode || 'INCREMENTAL'); },
    async verifyPgDivergenceNow() { if (!worker) { spawn(); await ready; } return call('verifyPgDivergenceNow'); },
    async advanceMirrorCheckpointNow() { if (!worker) { spawn(); await ready; } return call('advanceMirrorCheckpointNow'); },   //
    async selfCheck() { if (!worker) { spawn(); await ready; } return call('selfCheck'); },
    getStatus() {
      return Object.freeze({ ...(lastStatus || {}), running, scanning, host: 'worker-thread', memoryLimitMb, dutyCycle, restarts, consecutiveFailures,
        currentRun, completion: tracker.state() });
    },
    _terminateForTests() { if (worker) return worker.terminate(); return Promise.resolve(); },
  };
}

module.exports = { createWorkerRunner };
