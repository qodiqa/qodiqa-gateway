'use strict';

/**
 * file-mode replay/duplicate horizon is the bounded audit window.
 *
 * design decision: in single-node FILE mode there
 * is NO durable on-disk nonce index — the in-memory window is the
 * explicit replay horizon, announced by a boot WARN. This suite PINS that
 * decision as documented behaviour, in both directions:
 *
 *   H1  IN-window nonce reuse is still rejected (`replay_detected`) and
 *       in-window artifactId reuse is still rejected (`already_executed`) —
 *       the backstop works exactly as before inside the horizon.
 *   H2  A nonce OLDER than the window is ACCEPTED on append — the documented
 *       limitation, not a bug: the entry lands as a new, correctly-chained
 *       entry and the chain stays valid. Same for an evicted artifactId.
 *       (If this test ever fails because old reuse is suddenly rejected,
 * file mode has grown durable dedup — update's register entry
 *       and the ADR/runbook language BEFORE "fixing" this test.)
 *   H3  The boot WARN exists: server/startup.js announces the horizon
 *       (AUDIT_REPLAY_HORIZON_BOUNDED) in non-distributed mode, naming the
 *       window size, and skips it for the unbounded escape hatch.
 *
 * PG-authoritative (distributed) mode keeps durable uniqueness via PG UNIQUE
 * constraints regardless of window size — pinned against real PostgreSQL in
 * test/integration/replayHorizonPgUniqueness.integration.test.js (component gate).
 *
 * Same real-filesystem pattern as boundedWindow.test.js: the horizon
 * under test lives in _nonceSet/_byArtifactId eviction, which fs mocks
 * would bypass.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');

function uuid() { return crypto.randomUUID(); }

function allowParams(overrides = {}) {
  return {
    artifactId:         uuid(),
    inputHash:          'a'.repeat(64),
    decision:           'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
    signature:          's'.repeat(64),
    requestHash:        'r'.repeat(64),
    policyHash:         'p'.repeat(64),
    verificationResult: true,
    ...overrides,
  };
}

const ENV_KEYS = ['QODIQA_AUDIT_LOG', 'QODIQA_AUDIT_WINDOW_SIZE'];
let _savedEnv;

beforeEach(() => {
  _savedEnv = {};
  for (const k of ENV_KEYS) _savedEnv[k] = process.env[k];
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (_savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = _savedEnv[k];
  }
});

function freshAudit({ window } = {}) {
  const logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-f30-'));
  process.env.QODIQA_AUDIT_LOG = path.join(logDir, 'audit.log');
  if (window !== undefined) process.env.QODIQA_AUDIT_WINDOW_SIZE = window;
  else delete process.env.QODIQA_AUDIT_WINDOW_SIZE;

  let audit;
  jest.isolateModules(() => { audit = require('../audit-log'); });
  return { audit, logDir };
}

describe('H1: in-window reuse is still rejected (the backstop works inside the horizon)', () => {
  test('nonce reuse inside the window throws replay_detected', async () => {
    const { audit } = freshAudit({ window: '5' });
    const nonce = `f30-nonce-${uuid()}`;
    await audit.append(allowParams({ nonce }));
    await expect(audit.append(allowParams({ nonce })))
      .rejects.toThrow(/^replay_detected/);
  });

  test('artifactId reuse inside the window throws already_executed', async () => {
    const { audit } = freshAudit({ window: '5' });
    const first = await audit.append(allowParams());
    await expect(audit.append(allowParams({ artifactId: first.artifactId })))
      .rejects.toThrow(/^already_executed/);
  });
});

describe('H2: reuse OLDER than the window is accepted — the documented file-mode limitation', () => {
  test('a nonce evicted from the window is accepted on re-append, and the chain stays valid', async () => {
    const { audit } = freshAudit({ window: '3' });
    const nonce = `f30-old-nonce-${uuid()}`;
    await audit.append(allowParams({ nonce }));
    // Evict it: 4 more appends > window 3.
    for (let i = 0; i < 4; i++) await audit.append(allowParams());
    expect(audit.getWindowStats().windowLength).toBe(3);

    // The documented limitation: reuse from beyond the horizon is APPENDED,
    // not rejected — as a new, correctly-chained entry.
    const reused = await audit.append(allowParams({ nonce }));
    expect(reused.nonce).toBe(nonce);
    const report = audit.validateChainIntegrity();
    expect(report.chainValid).toBe(true);
    expect(report.chainLength).toBe(6);
    expect(report.tailHash).toBe(reused.hash);
  });

  test('an artifactId evicted from the window is accepted on re-append (in-memory horizon only)', async () => {
    const { audit } = freshAudit({ window: '3' });
    const first = await audit.append(allowParams());
    for (let i = 0; i < 4; i++) await audit.append(allowParams());

    const reused = await audit.append(allowParams({ artifactId: first.artifactId }));
    expect(reused.artifactId).toBe(first.artifactId);
    expect(audit.validateChainIntegrity().chainValid).toBe(true);
  });
});

describe('H3: the boot WARN announces the horizon (static pin over server/startup.js)', () => {
  let source;
  beforeAll(() => {
    source = fs.readFileSync(path.join(__dirname, '..', '..', '..', '..', 'server', 'startup.js'), 'utf8');
  });

  test('AUDIT_REPLAY_HORIZON_BOUNDED is emitted as WARN in the non-distributed branch', () => {
    const idx = source.indexOf("'AUDIT_REPLAY_HORIZON_BOUNDED'");
    expect(idx).toBeGreaterThan(-1);
    // The emit sits inside an ordering-mode guard that excludes distributed
    // mode (PG-authoritative deployments keep durable uniqueness — no
    // horizon to announce there).
    const guardIdx = source.lastIndexOf("_AUDIT_ORDERING_MODE !== 'distributed'", idx);
    expect(guardIdx).toBeGreaterThan(-1);
    expect(idx - guardIdx).toBeLessThan(1500);
    const window = source.slice(guardIdx, idx + 1500);
    expect(window).toMatch(/emit\('WARN',\s*'AUDIT_REPLAY_HORIZON_BOUNDED'/);
    // It names the window size (the horizon), sourced from the audit module,
    // and skips the unbounded escape hatch (Infinity has no finite horizon).
    expect(window).toMatch(/WINDOW_SIZE/);
    expect(window).toMatch(/Number\.isFinite\(WINDOW_SIZE\)/);
    expect(window).toMatch(/windowSize:\s*WINDOW_SIZE/);
    expect(window).toMatch(/QODIQA_AUDIT_WINDOW_SIZE/);
  });
});

describe('H4: the production profile does NOT categorically avoid the horizon', () => {
  //'s production gate (server/startup.js's REQUIRE_DURABLE_EVIDENCE)
  // only requires pgPool.isEnabled() — it does not require distributed
  // ordering. A NODE_ENV=production deployment can therefore legitimately
  // run with QODIQA_DEPLOYMENT_MODE=single-node + QODIQA_PG_ENABLED=true,
  // which satisfies while auditOrderingMode stays 'single-node' — so
  // the file-mode replay horizon (and its boot WARN) still applies. This
  // was previously mis-documented (in this file's own prior text and in
  // server/startup.js's comment) as "the production profile cannot reach
  // file mode at all" — corrected 2026-09-10 after verifying against the
  // real resolver below, not by inspection alone.
  const { getResolvedDeploymentConfig, _resetForTests } = require('../../../infra/config/deploymentMode');

  afterEach(() => { _resetForTests(); });

  test('QODIQA_DEPLOYMENT_MODE=single-node + QODIQA_PG_ENABLED=true resolves to non-distributed ordering', () => {
    const config = getResolvedDeploymentConfig({
      NODE_ENV: 'production',
      QODIQA_DEPLOYMENT_MODE: 'single-node',
      QODIQA_PG_ENABLED: 'true',
    });
    expect(config.pgEnabled).toBe(true);
    expect(config.auditOrderingMode).toBe('single-node');
  });

  test('the legacy-var path (no QODIQA_DEPLOYMENT_MODE) reaches the same non-distributed state under production + PG enabled', () => {
    const config = getResolvedDeploymentConfig({
      NODE_ENV: 'production',
      QODIQA_PG_ENABLED: 'true',
      // QODIQA_AUDIT_ORDERING_MODE deliberately left unset.
    });
    expect(config.pgEnabled).toBe(true);
    expect(config.auditOrderingMode).toBe('single-node');
  });

  test('only an explicit distributed ordering setting removes the horizon under production + PG enabled', () => {
    const config = getResolvedDeploymentConfig({
      NODE_ENV: 'production',
      QODIQA_DEPLOYMENT_MODE: 'distributed',
    });
    expect(config.pgEnabled).toBe(true);
    expect(config.auditOrderingMode).toBe('distributed');
  });
});
