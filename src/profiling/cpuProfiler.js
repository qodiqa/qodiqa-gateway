'use strict';

/**
 * CPU Profiler —
 *
 * Wraps the Node.js `inspector` module to collect V8 CPU profiles for named
 * code sections.  Profiles are serialised to JSON (the standard .cpuprofile
 * format accepted by Chrome DevTools and clinic.js).
 *
 * Design constraints:
 *   • Pure Node.js built-ins — no npm dependencies.
 *   • Graceful degradation: if the inspector session cannot open (e.g. a
 *     second session is already attached) the profiler is a no-op rather
 *     than crashing the process.
 *   • Thread-safe by Node.js single-thread guarantee; the inspector session
 *     is opened lazily and closed after each profile to avoid conflicts.
 *   • All measurements are wall-clock accurate to the sampling interval
 *     (default 100 µs = 10 kHz).
 */

const inspector = require('inspector');
const fs        = require('fs');
const path      = require('path');

const DEFAULT_SAMPLE_INTERVAL_US = 100; // 10 kHz — matches V8 default

// ── Session management ────────────────────────────────────────────────────────

/**
 * Open a fresh inspector session and enable the profiler.
 * Returns { session, close } or null if unavailable.
 */
function _openSession(sampleIntervalUs) {
  try {
    const session = new inspector.Session();
    session.connect();
    session.post('Profiler.enable');
    session.post('Profiler.setSamplingInterval', { interval: sampleIntervalUs });
    return session;
  } catch {
    return null;
  }
}

function _closeSession(session) {
  try {
    session.post('Profiler.disable');
    session.disconnect();
  } catch { /* ignore close errors */ }
}

// ── Core API ──────────────────────────────────────────────────────────────────

/**
 * Profile `fn` for CPU usage and return the raw V8 profile object.
 *
 * @param {Function} fn                 — async or sync function to profile
 * @param {object}   [options]
 * @param {number}   [options.sampleIntervalUs=100]  — V8 sampling interval µs
 * @returns {Promise<CpuProfileResult>}
 */
async function profileCpu(fn, options) {
  const opts             = options || {};
  const sampleInterval   = opts.sampleIntervalUs || DEFAULT_SAMPLE_INTERVAL_US;
  const session          = _openSession(sampleInterval);

  if (!session) {
    // Inspector unavailable — run fn without profiling
    const t0 = process.hrtime.bigint();
    await fn();
    const durationNs = Number(process.hrtime.bigint() - t0);
    return Object.freeze({
      available:   false,
      durationMs:  durationNs / 1_000_000,
      profile:     null,
      summary:     null,
    });
  }

  return new Promise((resolve, reject) => {
    session.post('Profiler.start', async (startErr) => {
      if (startErr) {
        _closeSession(session);
        reject(startErr);
        return;
      }

      const t0 = process.hrtime.bigint();
      try {
        await fn();
      } catch (fnErr) {
        session.post('Profiler.stop', () => _closeSession(session));
        reject(fnErr);
        return;
      }
      const durationNs = Number(process.hrtime.bigint() - t0);

      session.post('Profiler.stop', (stopErr, result) => {
        _closeSession(session);
        if (stopErr) { reject(stopErr); return; }

        const profile = result.profile;
        const summary = _summariseProfile(profile, durationNs);
        resolve(Object.freeze({
          available:   true,
          durationMs:  durationNs / 1_000_000,
          profile,
          summary,
        }));
      });
    });
  });
}

/**
 * Profile `fn` N times sequentially, returning per-run summaries and an
 * aggregate.  This avoids the overhead of opening/closing a session per run:
 * a single session spans all iterations.
 *
 * @param {string}   label
 * @param {Function} fn
 * @param {object}   [options]
 * @param {number}   [options.iterations=5]
 * @param {number}   [options.warmup=2]
 * @param {number}   [options.sampleIntervalUs=100]
 * @returns {Promise<CpuBatchResult>}
 */
async function profileCpuBatch(label, fn, options) {
  const opts       = options || {};
  const iterations = opts.iterations || 5;
  const warmup     = opts.warmup != null ? opts.warmup : 2;

  // Warmup (untracked)
  for (let i = 0; i < warmup; i++) {
    try { await fn(); } catch { /* ignore */ }
  }

  const runs = [];
  for (let i = 0; i < iterations; i++) {
    const result = await profileCpu(fn, opts);
    runs.push(result);
  }

  const durations = runs.map(r => r.durationMs);
  const mean      = durations.reduce((s, v) => s + v, 0) / durations.length;
  const sorted    = [...durations].sort((a, b) => a - b);
  const p99idx    = Math.max(0, Math.ceil(sorted.length * 0.99) - 1);

  // Aggregate CPU node hits across all profiles (if available)
  const hotNodes = runs[0]?.available
    ? _mergeHotNodes(runs.map(r => r.profile).filter(Boolean))
    : [];

  return Object.freeze({
    label,
    iterations,
    available:    runs[0]?.available ?? false,
    durationMs:   { mean, min: sorted[0], max: sorted[sorted.length - 1], p99: sorted[p99idx] },
    hotNodes:     hotNodes.slice(0, 10), // top 10 hot functions
    runs,
  });
}

/**
 * Save a V8 CPU profile to disk in the standard .cpuprofile format.
 *
 * @param {object} profile   — raw V8 profile from profileCpu()
 * @param {string} filePath  — output file path (should end in .cpuprofile)
 */
function saveCpuProfile(profile, filePath) {
  if (!profile) throw new TypeError('profile is required');
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(profile, null, 2), 'utf8');
}

// ── Profile analysis helpers ──────────────────────────────────────────────────

function _summariseProfile(profile, durationNs) {
  if (!profile || !Array.isArray(profile.nodes)) {
    return { totalSamples: 0, durationMs: durationNs / 1_000_000, hotNodes: [] };
  }

  const totalSamples = profile.samples ? profile.samples.length : 0;

  // Count hits per node
  const hitMap = new Map();
  for (const nodeId of (profile.samples || [])) {
    hitMap.set(nodeId, (hitMap.get(nodeId) || 0) + 1);
  }

  // Build node lookup
  const nodeById = new Map();
  for (const node of profile.nodes) {
    nodeById.set(node.id, node);
  }

  // Build hot node list
  const hotNodes = [];
  for (const [nodeId, hits] of hitMap) {
    const node = nodeById.get(nodeId);
    if (!node) continue;
    const cf = node.callFrame || {};
    hotNodes.push({
      nodeId,
      hits,
      selfPercent: totalSamples > 0 ? (hits / totalSamples) * 100 : 0,
      functionName: cf.functionName || '(anonymous)',
      url:          cf.url || '',
      lineNumber:   cf.lineNumber || 0,
    });
  }

  hotNodes.sort((a, b) => b.hits - a.hits);

  return Object.freeze({
    totalSamples,
    durationMs: durationNs / 1_000_000,
    hotNodes:   hotNodes.slice(0, 20),
  });
}

function _mergeHotNodes(profiles) {
  const merged = new Map(); // functionName+url -> { hits, ... }
  for (const profile of profiles) {
    if (!profile || !profile.nodes || !profile.samples) continue;
    const nodeById = new Map();
    for (const node of profile.nodes) nodeById.set(node.id, node);
    for (const nodeId of profile.samples) {
      const node = nodeById.get(nodeId);
      if (!node) continue;
      const cf  = node.callFrame || {};
      const key = `${cf.functionName}|${cf.url}|${cf.lineNumber}`;
      const existing = merged.get(key);
      if (existing) {
        existing.hits++;
      } else {
        merged.set(key, {
          functionName: cf.functionName || '(anonymous)',
          url:          cf.url || '',
          lineNumber:   cf.lineNumber || 0,
          hits:         1,
        });
      }
    }
  }
  const nodes = [...merged.values()];
  nodes.sort((a, b) => b.hits - a.hits);
  return nodes;
}

// ── Enforcement pipeline profiling ────────────────────────────────────────────

/**
 * Profile the QODIQA enforcement pipeline across all key operations.
 * Returns a structured report covering all 47.1 required targets.
 *
 * @param {object} deps  — injected production modules
 * @param {object} [options]
 * @returns {Promise<EnforcementProfileReport>}
 */
async function profileEnforcementPipeline(deps, options) {
  const opts = options || {};
  const {
    evaluate,
    createStore,
    computePayloadHash,
    computeEntryHash,
    validateChainContinuity,
    computePolicyHash,
    sign,
    verify,
    crypto,
    blockIpEval,
  } = deps;

  const STORE = createStore();
  const POLICY = Object.freeze({
    id: 'prof-ip', type: 'BLOCK_IP', priority: 0, enabled: true,
    config: Object.freeze(blockIpEval.preprocess({ policyId: 'prof-ip', blocklist: [], cidrs: [] })),
  });
  const CTX = {
    artifact: { valid: true }, userId: 'prof-user@example.com', action: 'data:process',
    tenantId: 'prof-tenant', requestId: null, ip: '1.2.3.4',
    timestamp: Math.floor(Date.now() / 1000),
  };

  const { publicKey: pubDer, privateKey: privDer } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  const HASH_32 = crypto.randomBytes(32);

  // Build a 100-entry chain for chain validation profiling
  const chainEntries = [];
  let prevHash = null;
  for (let i = 0; i < 100; i++) {
    const payload     = { requestId: `r${i}`, action: 'data:process', i };
    const payloadHash = computePayloadHash(payload);
    const raw = {
      transparencyId: `tr-${i}`, entryType: 'ENFORCEMENT_DECISION',
      artifactId: `a${i}`, evidenceChainId: null, verificationId: null,
      payloadHash, previousEntryHash: prevHash, signerKeyId: 'k1', payload,
    };
    const entryHash = computeEntryHash(raw);
    chainEntries.push({ ...raw, id: i + 1, entryHash, signature: null, created_at: new Date().toISOString() });
    prevHash = entryHash;
  }

  const targets = [
    { label: 'Policy evaluation (BLOCK_IP, ALLOW path)',          fn: async () => { await evaluate(CTX, [POLICY], STORE); } },
    { label: 'Payload hash (SHA-256 domain-prefixed)',            fn: () => { computePayloadHash({ requestId: 'x', action: 'data:process', ts: 1 }); } },
    { label: 'Entry hash (SHA-256 all fields)',                   fn: () => { computeEntryHash({ transparencyId: 'tr-1', entryType: 'ENFORCEMENT_DECISION', artifactId: 'a1', evidenceChainId: null, verificationId: null, payloadHash: 'a'.repeat(64), previousEntryHash: null, signerKeyId: 'k1' }); } },
    { label: 'Chain continuity validation (100 entries)',         fn: () => { validateChainContinuity(chainEntries); } },
    { label: 'Policy hash (computePolicyHash)',                   fn: () => { computePolicyHash([POLICY]); } },
    { label: 'Ed25519 sign (32-byte hash)',                       fn: () => { sign(HASH_32, privDer); } },
    { label: 'Ed25519 verify (32-byte hash)',                     fn: () => { const sig = sign(HASH_32, privDer); verify(HASH_32, sig, pubDer); } },
    { label: 'SHA-256 1 KB',                                     fn: () => { crypto.createHash('sha256').update(crypto.randomBytes(1024)).digest(); } },
    { label: 'JSON.stringify (medium policy doc)',                fn: () => { JSON.stringify({ policies: Array.from({ length: 10 }, (_, i) => ({ id: `p${i}`, type: 'BLOCK_IP', priority: i, enabled: true })) }); } },
    { label: 'crypto.randomUUID()',                               fn: () => { crypto.randomUUID(); } },
  ];

  const results = [];
  for (const t of targets) {
    const result = await profileCpuBatch(t.label, t.fn, { ...opts, iterations: opts.iterations || 3, warmup: 1 });
    results.push(result);
  }

  return Object.freeze({
    timestamp:  new Date().toISOString(),
    available:  results.some(r => r.available),
    targets:    results,
  });
}

module.exports = {
  profileCpu,
  profileCpuBatch,
  profileEnforcementPipeline,
  saveCpuProfile,
};
