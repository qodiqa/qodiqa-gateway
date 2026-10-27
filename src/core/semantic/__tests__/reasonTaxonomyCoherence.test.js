'use strict';

/**
 * remediation.
 *
 * Proves the taxonomy-coherence properties was opened against, so a
 * future change can't silently reintroduce an orphan code or a many-to-one
 * classifier/reason collision without a test failing:
 *
 *   1. Every declared SEMANTIC_REASONS code has exactly one producer —
 *      either a bundled classifier (registry-discovered) or the embedding
 *      gate's own dedicated reason.
 *   2. No two bundled classifiers report the same reason (one-reason-per-
 *      classifier, the converse direction: also one-classifier-per-reason).
 *   3. Every bundled classifier's `.reason` is drawn from SEMANTIC_REASONS
 *      (no ad-hoc string reasons among the bundled set — that liberty is
 *      reserved for registerClassifier()'s plugin-extensibility path).
 */

const { SEMANTIC_REASONS } = require('../reasons');
const { getClassifiersWithStatus } = require('../registry/classifierRegistry');

describe('SEMANTIC_REASONS taxonomy coherence', () => {
  const { classifiers, registryStatus } = getClassifiersWithStatus({});

  test('registry discovery succeeded', () => {
    expect(registryStatus).toBe('OK');
  });

  test('every bundled classifier reason is a declared SEMANTIC_REASONS value', () => {
    const declared = new Set(Object.values(SEMANTIC_REASONS));
    for (const c of classifiers) {
      expect(declared.has(c.reason)).toBe(true);
    }
  });

  test('no two bundled classifiers share a reason (one-classifier-per-reason)', () => {
    const byReason = new Map();
    for (const c of classifiers) {
      if (byReason.has(c.reason)) {
        throw new Error(
          `reason ${c.reason} is produced by both "${byReason.get(c.reason)}" and "${c.id}"`
        );
      }
      byReason.set(c.reason, c.id);
    }
    expect(byReason.size).toBe(classifiers.length);
  });

  test('every declared SEMANTIC_REASONS code has exactly one producer', () => {
    const producedByClassifier = new Set(classifiers.map((c) => c.reason));
    // EMBEDDING_SIMILARITY_MATCH is produced by embeddingGate.js, a separate
    // detection layer outside the classifier registry — see embeddingGate.js
    // and embeddingGate.test.js's 'DENY match' case for its own coverage.
    const producedElsewhere = new Set([SEMANTIC_REASONS.EMBEDDING_SIMILARITY_MATCH]);

    for (const reason of Object.values(SEMANTIC_REASONS)) {
      const hasProducer = producedByClassifier.has(reason) || producedElsewhere.has(reason);
      expect(hasProducer).toBe(true);
    }
  });

  test('taxonomy size: 14 declared codes, 13 bundled classifiers + 1 embedding-gate reason', () => {
    expect(Object.keys(SEMANTIC_REASONS).length).toBe(14);
    expect(classifiers.length).toBe(13);
  });

  test('UNAUTHORIZED_TOOL_REQUEST is backed by its own dedicated classifier, not tool-abuse', () => {
    const producer = classifiers.find((c) => c.reason === SEMANTIC_REASONS.UNAUTHORIZED_TOOL_REQUEST);
    expect(producer).toBeDefined();
    expect(producer.id).toBe('unauthorized-tool-request');

    const toolAbuse = classifiers.find((c) => c.id === 'tool-abuse');
    expect(toolAbuse).toBeDefined();
    expect(toolAbuse.reason).toBe(SEMANTIC_REASONS.TOOL_ABUSE_ATTEMPT);
  });

  test('the five F-18-removed codes are gone from the taxonomy', () => {
    const removed = [
      'ROLE_ESCALATION_ATTEMPT',
      'SECRET_EXTRACTION',
      'CHAIN_OF_THOUGHT_REQUEST',
      'MODEL_MANIPULATION',
      'PROVIDER_ESCAPE_ATTEMPT',
    ];
    for (const code of removed) {
      expect(Object.prototype.hasOwnProperty.call(SEMANTIC_REASONS, code)).toBe(false);
      expect(Object.values(SEMANTIC_REASONS)).not.toContain(code);
    }
  });
});
