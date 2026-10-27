'use strict';

/**
 * Finding D fix — unit-level branch-selection proof, complementary to the
 * frozen default-path lock-in test (serverEntrypointGate.lockin.test.js,
 * left unmodified) and to the process-spawn stash-cycle proof in
 * test/acceptance (the historical-symptom negative test — see
 *).
 *
 * This file asserts the OPPOSITE branch: when QODIQA_KMS_PROVIDER is a
 * non-local provider AND keyProviderFactory.isInitialized() is false (i.e.
 * `node server.js` run directly, without start.js having already wired
 * anything), server.js must call keyProviderFactory.bootstrapOrExit() before
 * building the app — never take the synchronous fast path.
 */

const path = require('path');

const SERVER_JS_PATH = path.join(__dirname, '..', '..', '..', '..', 'server.js');

const mockCtx = Object.freeze({ marker: 'mock-startup-ctx' });
const mockStartServerInner = jest.fn().mockResolvedValue(undefined);
const mockAppInstance = { marker: 'mock-app-instance' };
const mockCreateApp = jest.fn(() => mockAppInstance);

const mockKpfInitialize = jest.fn().mockResolvedValue(undefined);
const mockKpfWireIntoSecretsProvider = jest.fn().mockResolvedValue(undefined);
const mockKpfBootstrapOrExit = jest.fn().mockResolvedValue(undefined);
const mockKpfIsInitialized = jest.fn().mockReturnValue(false);

jest.mock('../../../../server/startup', () => ({
  ctx: mockCtx,
  startServer: (app) => mockStartServerInner(app),
}));

jest.mock('../../../../src/app', () => ({
  createApp: (ctx) => mockCreateApp(ctx),
}));

jest.mock('../keyProviderFactory', () => ({
  initialize: (...args) => mockKpfInitialize(...args),
  wireIntoSecretsProvider: (...args) => mockKpfWireIntoSecretsProvider(...args),
  bootstrapOrExit: (...args) => mockKpfBootstrapOrExit(...args),
  isInitialized: (...args) => mockKpfIsInitialized(...args),
  getNativeSigningProvider: () => null,
  isNativeSigning: () => false,
  healthCheck: jest.fn(),
  getResilienceSnapshot: jest.fn(),
  shutdown: jest.fn(),
  rotateWrappingKey: jest.fn(),
}));

jest.mock('../../../../services/logger', () => ({
  emit: jest.fn(),
}));

describe('server.js Finding-D branch — non-local + not-yet-initialized', () => {
  const savedEnv = {};

  beforeEach(() => {
    jest.resetModules();
    mockStartServerInner.mockClear();
    mockCreateApp.mockClear();
    mockKpfInitialize.mockClear();
    mockKpfWireIntoSecretsProvider.mockClear();
    mockKpfBootstrapOrExit.mockClear();
    mockKpfIsInitialized.mockClear();
    mockKpfIsInitialized.mockReturnValue(false);
    savedEnv.QODIQA_KMS_PROVIDER = process.env.QODIQA_KMS_PROVIDER;
    process.env.QODIQA_KMS_PROVIDER = 'aws-kms';
  });

  afterEach(() => {
    if (savedEnv.QODIQA_KMS_PROVIDER === undefined) {
      delete process.env.QODIQA_KMS_PROVIDER;
    } else {
      process.env.QODIQA_KMS_PROVIDER = savedEnv.QODIQA_KMS_PROVIDER;
    }
  });

  test('module.exports is a Promise (not the app synchronously) and bootstrapOrExit() is called before createApp()', async () => {
    // eslint-disable-next-line global-require
    const exported = require(SERVER_JS_PATH);

    expect(typeof exported.then).toBe('function');
    // createApp must not have run yet — bootstrapOrExit() hasn't resolved.
    expect(mockCreateApp).not.toHaveBeenCalled();

    const app = await exported;

    expect(mockKpfBootstrapOrExit).toHaveBeenCalledTimes(1);
    expect(mockCreateApp).toHaveBeenCalledTimes(1);
    expect(mockKpfInitialize).not.toHaveBeenCalled(); // bootstrapOrExit is mocked as a single unit here
    expect(app).toBe(mockAppInstance);
    expect(typeof app.startServer).toBe('function');
  });

  test('when keyProviderFactory.isInitialized() is already true (start.js already ran), the synchronous fast path is taken instead', () => {
    mockKpfIsInitialized.mockReturnValue(true);

    // eslint-disable-next-line global-require
    const exported = require(SERVER_JS_PATH);

    expect(typeof exported.then).not.toBe('function');
    expect(exported).toBe(mockAppInstance);
    expect(mockKpfBootstrapOrExit).not.toHaveBeenCalled();
    expect(mockCreateApp).toHaveBeenCalledTimes(1);
  });
});
