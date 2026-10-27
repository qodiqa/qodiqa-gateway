'use strict';

/**
 * SEM-C — boot-load and readiness-state behavior (pre-init only; no real
 * backend load).
 *
 * Real-model boot verification (init() actually reaching READY against the
 * real @xenova/transformers backend) lives in
 * verify/runRealModelVerification.js instead of here — Jest's sandboxed VM
 * test context and @xenova/transformers' native ONNX runtime binding hit a
 * realm-identity incompatibility (`instanceof Float32Array` fails across
 * Jest's VM sandbox boundary) that has nothing to do with this module's own
 * correctness. See that script's header comment for the full explanation
 * and npm run test:embeddingSimilarity to run it.
 */

const embeddingClassifier = require('../index');
const { BOOT_STATUS } = embeddingClassifier;

describe('SEM-C embedding-similarity classifier — boot', () => {
  beforeEach(() => {
    embeddingClassifier._resetForTests();
  });

  test('reports UNINITIALIZED before init() is called', () => {
    const status = embeddingClassifier.getStatus();
    expect(status.status).toBe(BOOT_STATUS.UNINITIALIZED);
    expect(status.anchorCount).toBe(0);
  });

  test('classify() fails closed (DENY) when called before init()', async () => {
    const result = await embeddingClassifier.classify('What is the capital of France?');
    expect(result.decision).toBe('DENY');
    expect(result.engineStatus).toBe('UNAVAILABLE');
    expect(result.failureReason).toBe('EMBEDDING_CLASSIFIER_NOT_READY');
    expect(result.score).toBeNull();
  });
});
