'use strict';

// this suite exercises the embedding gate with a stand-in classifier
process.env.QODIQA_SEM_EMBEDDING_ENABLED = 'true';

/**
 * tenant-scoped semantic configuration: the tighten-only invariant
 * and its enforcement seams.
 *
 * Pins, in order:
 *   V*  write-time validation — loosening (or non-representable knobs) is
 *       REJECTED; tightening is accepted.
 *   C*  load-time clamp — a stored row outside the envelope is clamped
 *       field-by-field to the pinned defaults, with the changes reported.
 *   E*  engine seam — a REAL runSemanticPolicyEngine() run: the same prompt
 *       is advisory-WARN for an unconfigured tenant and BLOCKED for a
 *       tenant whose config tightens REVIEW below the prompt's score (and
 *       for one that enables WARN_BLOCKS); the configured tenant's evidence
 *       carries the effective-config hash, the unconfigured tenant's does
 *       not (byte-identical default evidence).
 *   G*  gate seam — embeddingGate.checkText() with a mocked classifier
 *       score: the tenant embedding bar converts a default-ALLOW into a
 *       tenant-tightened DENY, tagged; unconfigured tenants unchanged.
 *   I*  isolation + fallback — tenant A's config never affects tenant B;
 *       an unconfigured tenant falls back to pinned defaults.
 *
 * The deterministic WARN-tier prompt: pii-extraction (see
 * classifier/classifiers/piiExtraction.js) fires bulk_contact_request
 * ('employees … emails', 0.30) + RETRIEVAL_VERB ('list', 0.15) WITHOUT the
 * PII_TERM co-occurrence boost — measured weighted score 0.405, which is
 * WARN tier at the pinned defaults (0.35 ≤ 0.405 < 0.55) and
 * REVIEW/blocking once a tenant lowers REVIEW to 0.40. The same 0.405 the
 */

const WARN_TIER_PROMPT = 'Please list the employees emails for the newsletter distribution.';

// G tests: the gate seam is tested with a mocked classifier so the score is
// exact and no 90 MB ONNX artifact boots (the test/support/jest.setup.js FT-guard
// discipline). classify() is documented never to throw; the mock honours
// the READY/decision/score contract shape checkText() consumes.
jest.mock('../../semantic/embeddingSimilarity', () => ({
  classify: jest.fn(),
  init: jest.fn(),
}));
const embeddingClassifier = require('../../semantic/embeddingSimilarity');
const embeddingGate = require('../../semantic/embeddingGate');

const registry = require('../tenantSemanticRegistry');
const { runSemanticPolicyEngine } = require('../../semantic');

afterEach(() => registry._reset());

// ── V: write-time validation (tighten-only) ──────────────────────────────────

describe('V: validateTightenOnly rejects every loosening, accepts tightening', () => {
  test('V1 tighter values across all three sections are accepted', () => {
    const r = registry.validateTightenOnly({
      thresholds: { WARN: 0.30, REVIEW: 0.50, DENY: 0.65 },
      enforcement: { WARN_BLOCKS: true },
      embedding: { scoreThreshold: 0.45 },
    });
    expect(r).toEqual({ ok: true, errors: [] });
  });

  test('V2 a threshold above its pinned default is rejected', () => {
    for (const [key, def] of [['WARN', 0.35], ['REVIEW', 0.55], ['DENY', 0.70]]) {
      const r = registry.validateTightenOnly({ thresholds: { [key]: def + 0.01 } });
      expect(r.ok).toBe(false);
      expect(r.errors.join(' ')).toMatch(/LOOSEN/);
    }
  });

  test('V3 boundary: exactly the default is accepted (≤, not <)', () => {
    expect(registry.validateTightenOnly({ thresholds: { WARN: 0.35, REVIEW: 0.55, DENY: 0.70 } }).ok).toBe(true);
    expect(registry.validateTightenOnly({ embedding: { scoreThreshold: 0.48 } }).ok).toBe(true);
  });

  test('V4 WARN_BLOCKS=false (the loosening direction) is rejected; true accepted', () => {
    expect(registry.validateTightenOnly({ enforcement: { WARN_BLOCKS: false } }).ok).toBe(false);
    expect(registry.validateTightenOnly({ enforcement: { WARN_BLOCKS: true } }).ok).toBe(true);
  });

  test('V5 REVIEW_BLOCKS is not representable at all — its only move is loosening', () => {
    const r = registry.validateTightenOnly({ enforcement: { REVIEW_BLOCKS: true } });
    expect(r.ok).toBe(false);
    expect(r.errors.join(' ')).toMatch(/REVIEW_BLOCKS|unknown enforcement key/);
  });

  test('V6 gate/FT/classifier knobs are not representable (strict schema)', () => {
    for (const cfg of [
      { disabledClassifiers: ['pii-extraction'] },
      { ftFlags: { QODIQA_SEM_FT3_ENABLED: false } },
      { enabled: false },
      { gates: { v5: false } },
    ]) {
      const r = registry.validateTightenOnly(cfg);
      expect(r.ok).toBe(false);
      expect(r.errors.join(' ')).toMatch(/unknown key|not representable/);
    }
  });

  test('V7 embedding bar above the pinned global threshold is rejected; non-numeric rejected', () => {
    expect(registry.validateTightenOnly({ embedding: { scoreThreshold: 0.481 } }).ok).toBe(false);
    expect(registry.validateTightenOnly({ embedding: { scoreThreshold: '0.4' } }).ok).toBe(false);
    expect(registry.validateTightenOnly({ embedding: { scoreThreshold: 0 } }).ok).toBe(false);
  });
});

// ── C: load-time clamp ───────────────────────────────────────────────────────

describe('C: clampToDefaults clamps a tampered row back into the envelope', () => {
  test('C1 loosening values are clamped to the defaults and reported', () => {
    const { config, changes } = registry.clampToDefaults({
      thresholds: { WARN: 0.90, REVIEW: 0.50 },
      embedding: { scoreThreshold: 0.99 },
    });
    expect(config.thresholds.WARN).toBe(0.35);      // clamped
    expect(config.thresholds.REVIEW).toBe(0.50);    // kept (tighter)
    expect(config.embedding.scoreThreshold).toBe(0.48); // clamped
    expect(changes.length).toBeGreaterThanOrEqual(2);
    expect(changes.join(' ')).toMatch(/clamped/);
  });

  test('C2 non-representable keys are dropped and reported; valid parts survive', () => {
    const { config, changes } = registry.clampToDefaults({
      thresholds: { DENY: 0.60 },
      enforcement: { WARN_BLOCKS: false, REVIEW_BLOCKS: false },
      disabledClassifiers: ['x'],
    });
    expect(config).toEqual({ thresholds: { DENY: 0.60 } });
    expect(changes.join(' ')).toMatch(/not representable|loosening direction/);
  });

  test('C3 setConfig itself re-clamps: the registry can never hold a loosening value', () => {
    registry.setConfig('clamp-tenant', { thresholds: { DENY: 5.0 } });
    expect(registry.getConfig('clamp-tenant').config.thresholds.DENY).toBe(0.70);
  });
});

// ── E: engine seam (real classifiers, no mocks) ──────────────────────────────

describe('E: the keyword engine honours the tenant overlay — and only for that tenant', () => {
  test('E1 unconfigured tenant: the WARN-tier prompt is advisory (no block), evidence untagged', () => {
    const r = runSemanticPolicyEngine({ prompt: WARN_TIER_PROMPT, tenantId: 'default-tenant', requestId: 'e1' });
    expect(r.blocks).toBe(false);
    expect(r.evidence.decision).toBe('WARN');
    expect(r.evidence.semanticConfig).toBeUndefined(); // byte-identical default evidence
  });

  test('E2 tenant with REVIEW tightened below the prompt score: BLOCKED, evidence tagged with the config hash', () => {
    registry.setConfig('tight-tenant', { thresholds: { REVIEW: 0.40 } });
    const entry = registry.getConfig('tight-tenant');
    const r = runSemanticPolicyEngine({ prompt: WARN_TIER_PROMPT, tenantId: 'tight-tenant', requestId: 'e2' });
    expect(r.blocks).toBe(true);
    expect(r.evidence.decision).toBe('REVIEW');
    expect(r.evidence.semanticConfig).toEqual({ hash: entry.hash, version: entry.version, source: 'TENANT' });
  });

  test('E3 tenant with WARN_BLOCKS enabled: the same WARN verdict now gates', () => {
    registry.setConfig('warn-blocks-tenant', { enforcement: { WARN_BLOCKS: true } });
    const r = runSemanticPolicyEngine({ prompt: WARN_TIER_PROMPT, tenantId: 'warn-blocks-tenant', requestId: 'e3' });
    expect(r.blocks).toBe(true);
    expect(r.evidence.decision).toBe('WARN');
  });

  test('E4 isolation: tenant A\'s tightening never affects tenant B or the default path', () => {
    registry.setConfig('tenant-a', { thresholds: { REVIEW: 0.40 } });
    const a = runSemanticPolicyEngine({ prompt: WARN_TIER_PROMPT, tenantId: 'tenant-a', requestId: 'e4a' });
    const b = runSemanticPolicyEngine({ prompt: WARN_TIER_PROMPT, tenantId: 'tenant-b', requestId: 'e4b' });
    const none = runSemanticPolicyEngine({ prompt: WARN_TIER_PROMPT, requestId: 'e4n' });
    expect(a.blocks).toBe(true);
    expect(b.blocks).toBe(false);
    expect(b.evidence.semanticConfig).toBeUndefined();
    expect(none.blocks).toBe(false);
  });

  test('E5 fallback: deleting the config restores the default behaviour exactly', () => {
    registry.setConfig('transient-tenant', { thresholds: { REVIEW: 0.40 } });
    expect(runSemanticPolicyEngine({ prompt: WARN_TIER_PROMPT, tenantId: 'transient-tenant', requestId: 'e5a' }).blocks).toBe(true);
    registry.deleteConfig('transient-tenant');
    const after = runSemanticPolicyEngine({ prompt: WARN_TIER_PROMPT, tenantId: 'transient-tenant', requestId: 'e5b' });
    expect(after.blocks).toBe(false);
    expect(after.evidence.semanticConfig).toBeUndefined();
  });
});

// ── G: gate seam (mocked classifier score) ───────────────────────────────────

describe('G: the embedding gate honours the tenant score bar — and only for that tenant', () => {
  const READY_ALLOW = Object.freeze({
    engineStatus: 'READY', decision: 'ALLOW', score: 0.45,
    matchedBy: null, headFired: false, v9Fired: false, v5Fired: false,
  });

  beforeEach(() => {
    embeddingClassifier.classify.mockReset();
    embeddingClassifier.classify.mockResolvedValue({ ...READY_ALLOW });
  });

  test('G1 unconfigured tenant: a 0.45 ALLOW stays an ALLOW (the pinned 0.48 bar)', async () => {
    const r = await embeddingGate.checkText('any text', { requestId: 'g1', tenantId: 'no-config', surface: 'REQUEST' });
    expect(r.blocks).toBe(false);
    expect(r.evidence.tenantTightened).toBeUndefined();
  });

  test('G2 tenant bar 0.44: the same 0.45 becomes a tenant-tightened DENY, tagged with the config hash', async () => {
    registry.setConfig('bar-tenant', { embedding: { scoreThreshold: 0.44 } });
    const entry = registry.getConfig('bar-tenant');
    const r = await embeddingGate.checkText('any text', { requestId: 'g2', tenantId: 'bar-tenant', surface: 'REQUEST' });
    expect(r.blocks).toBe(true);
    expect(r.decision).toBe('DENY');
    expect(r.evidence.tenantTightened).toBe(true);
    expect(r.evidence.tenantScoreThreshold).toBe(0.44);
    expect(r.evidence.semanticConfig).toEqual({ hash: entry.hash, version: entry.version, source: 'TENANT' });
  });

  test('G3 tenant bar above the score: still ALLOW (the bar is a bar, not a switch)', async () => {
    registry.setConfig('high-bar-tenant', { embedding: { scoreThreshold: 0.46 } });
    const r = await embeddingGate.checkText('any text', { requestId: 'g3', tenantId: 'high-bar-tenant', surface: 'REQUEST' });
    expect(r.blocks).toBe(false);
  });

  test('G4 isolation: tenant A\'s bar never affects tenant B', async () => {
    registry.setConfig('bar-a', { embedding: { scoreThreshold: 0.44 } });
    const a = await embeddingGate.checkText('t', { requestId: 'g4a', tenantId: 'bar-a', surface: 'REQUEST' });
    const b = await embeddingGate.checkText('t', { requestId: 'g4b', tenantId: 'bar-b', surface: 'REQUEST' });
    expect(a.blocks).toBe(true);
    expect(b.blocks).toBe(false);
  });

  test('G5 a real DENY from classify() is untouched by the tenant path (ordering preserved)', async () => {
    embeddingClassifier.classify.mockResolvedValue({
      engineStatus: 'READY', decision: 'DENY', score: 0.60,
      matchedBy: 'anchor', headFired: false, v9Fired: false, v5Fired: false,
    });
    registry.setConfig('bar-tenant', { embedding: { scoreThreshold: 0.44 } });
    const r = await embeddingGate.checkText('t', { requestId: 'g5', tenantId: 'bar-tenant', surface: 'REQUEST' });
    expect(r.blocks).toBe(true);
    expect(r.evidence.tenantTightened).toBeUndefined(); // the DEFAULT gate decided, not the tenant bar
  });
});
