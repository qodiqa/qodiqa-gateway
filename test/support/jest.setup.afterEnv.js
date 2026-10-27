'use strict';

// ── Embedding-similarity classifier: fast, deterministic test double ─────────
// (SEM-C session 3)
//
// Production servers block on embeddingClassifier.init() reaching READY
// (server/startup.js) before accepting any request. Test harnesses that
// build the Express app directly (supertest against src/app.js) never run
// that startup sequence — without this file, every request that reaches
// src/core/semantic/embeddingGate.js would fail closed with
// EMBEDDING_CLASSIFIER_NOT_READY, turning every existing ALLOW-path test
// across the whole suite into an unexpected 403/BLOCK, unrelated to
// whatever that test actually verifies. (Confirmed empirically: without
// this file, 17 suites / 88 tests failed this exact way on this session's
// first full baseline run after wiring the gate in.)
//
// The real backend (@xenova/transformers, ONNX MiniLM) is additionally
// unusable here regardless: it's pure ESM with no CJS build and cannot be
// loaded inside Jest's module runtime without --experimental-vm-modules
// (see embeddingSimilarity/verify/runRealModelVerification.js's header),
// and even with that flag, real inference is far too slow to run at boot
// for every one of this suite's ~290 test files.
//
// Fix: replace the ONNX backend (embeddingBackend.js) with a fast,
// deterministic fake BEFORE anything requires it, then boot the classifier
// for real (real anchorSet.js, real windowing/scoring logic in
// embeddingSimilarity/index.js — only the embedding math itself is faked).
// cosineSim() always returns 0 — every request the embedding gate
// evaluates is unconditionally ALLOWed by this fake, exactly restoring
// this suite's pre-session-3 behavior for every test that doesn't care
// about the embedding layer specifically.
//
// This file is setupFilesAfterEnv (not setupFiles): the test framework
// (describe/beforeAll/etc.) must already be installed to register the
// beforeAll() below, and — critically — Jest awaits every global beforeAll
// registered here before running any test in any file, which a fire-and-
// forget async call from a plain setupFiles script could not guarantee.
//
// Individual test files that want the REAL fail-closed/threshold/windowing
// behavior already build their own fully-isolated instance via
// jest.resetModules() + jest.doMock('../embeddingBackend', ownFactory) (see
// src/core/semantic/embeddingSimilarity/__tests__/ and
// src/core/semantic/__tests__/embeddingGate.test.js) — jest.resetModules()
// clears the module INSTANCE cache but not this file's mock FACTORY
// registration, so those files' own later jest.doMock() calls for the same
// path correctly override this default, only for that file.
// The vector is 384-dim, not a 1-element placeholder, because · B-3
// put the ensemble head on the decision path and the head does real
// arithmetic over every dimension. embeddingBackend.embed() has always been
// documented as returning a 384-dim L2-normalised vector; a shorter stand-in
// only ever worked because nothing downstream read past index 0. It does now,
// and a short vector yields NaN -> the classifier's non-finite guard -> a
// spurious DENY. An all-zero vector scores sigmoid(bias) = 0.2228, far under
// the head's 0.838629 bar, so the head never fires and suites using this
// default keep observing exactly the behaviour they were written against.
jest.mock('../../src/core/semantic/embeddingSimilarity/embeddingBackend', () => require('../../src/testing/embedBatchDouble')({
  loadModel: jest.fn().mockResolvedValue(undefined),
  embed: jest.fn().mockResolvedValue(new Array(384).fill(0)),
  cosineSim: jest.fn().mockReturnValue(0),
  MODEL: 'test-double-model',
}));

// beforeEach, not beforeAll: some existing test files call jest.resetModules()
// mid-file for unrelated reasons (e.g. to re-mock a different dependency for
// one specific test) — that clears the module INSTANCE cache, which means
// the NEXT require() of embeddingSimilarity returns a fresh, uninitialized
// instance. A one-time beforeAll would leave every test AFTER that reset
// poisoned (embedding gate fails closed as NOT_READY) for the rest of the
// file, even for tests with no reset of their own. beforeEach re-checks
// before every single test, so only tests that reset-and-use the classifier
// within their OWN single test body (a narrower case — see e.g.
// providerMutationTest.test.js's own local jest.doMock('../embeddingGate')
// override) need a file-local fix.
beforeEach(async () => {
  try {
    const embeddingClassifier = require('../../src/core/semantic/embeddingSimilarity');
    if (embeddingClassifier.getStatus().status !== 'READY') {
      await embeddingClassifier.init();
    }
  } catch (_) {
    // embeddingSimilarity unavailable — tests manage their own
    // initialization (see the file-level jest.doMock() pattern above).
  }
});

// The artifact-revocation module opens a lazy Redis connection when REDIS_URL is set; close the one this test file used so the
// process can exit (it is also closed by the graceful shutdown of the server).
afterAll(async () => {
  try { await require('../../src/core/artifactRevocation').close(); } catch { /* the module was mocked or never loaded */ }
});
