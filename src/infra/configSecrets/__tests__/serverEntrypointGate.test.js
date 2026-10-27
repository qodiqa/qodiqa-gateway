'use strict';

/**
 * server.js entrypoint gate — config-secrets branch.
 *
 * Mirrors src/infra/keys/__tests__/serverEntrypointGate.{lockin,findingD}.test.js
 * exactly (same mock shapes, same relative depth), extended to also mock
 * configSecretsFactory so both independent bootstraps — KMS (Finding D) and
 * config secrets — can be exercised in isolation and in combination.
 *
 * The pre-existing lock-in/findingD tests for keyProviderFactory are left
 * completely unmodified elsewhere — this file only adds coverage for the
 * NEW config-secrets branch server.js now also has.
 */

const path = require('path');

const SERVER_JS_PATH = path.join(__dirname, '..', '..', '..', '..', 'server.js');

const mockCtx = Object.freeze({ marker: 'mock-startup-ctx' });
const mockStartServerInner = jest.fn().mockResolvedValue(undefined);
const mockAppInstance = { marker: 'mock-app-instance' };
const mockCreateApp = jest.fn(() => mockAppInstance);

const mockKpfIsInitialized = jest.fn().mockReturnValue(true); // KMS side inert by default in this file
const mockKpfBootstrapOrExit = jest.fn().mockResolvedValue(undefined);

const mockCsfIsInitialized = jest.fn().mockReturnValue(false);
const mockCsfBootstrapOrExit = jest.fn().mockResolvedValue(undefined);

jest.mock('../../../../server/startup', () => ({
  ctx: mockCtx,
  startServer: (app) => mockStartServerInner(app),
}));

jest.mock('../../../../src/app', () => ({
  createApp: (ctx) => mockCreateApp(ctx),
}));

jest.mock('../../../../src/infra/keys/keyProviderFactory', () => ({
  initialize: jest.fn().mockResolvedValue(undefined),
  wireIntoSecretsProvider: jest.fn().mockResolvedValue(undefined),
  bootstrapOrExit: (...args) => mockKpfBootstrapOrExit(...args),
  isInitialized: (...args) => mockKpfIsInitialized(...args),
  getNativeSigningProvider: () => null,
  isNativeSigning: () => false,
  healthCheck: jest.fn(),
  getResilienceSnapshot: jest.fn(),
  shutdown: jest.fn(),
  rotateWrappingKey: jest.fn(),
}));

jest.mock('../configSecretsFactory', () => ({
  initialize: jest.fn().mockResolvedValue(undefined),
  apply: jest.fn().mockResolvedValue(undefined),
  isApplied: jest.fn().mockReturnValue(true),
  bootstrapOrExit: (...args) => mockCsfBootstrapOrExit(...args),
  isInitialized: (...args) => mockCsfIsInitialized(...args),
  getProviderName: jest.fn(),
  healthCheck: jest.fn(),
  shutdown: jest.fn(),
}));

jest.mock('../../../../services/logger', () => ({
  emit: jest.fn(),
}));

function resetAllMocks() {
  mockStartServerInner.mockClear();
  mockCreateApp.mockClear();
  mockKpfIsInitialized.mockClear();
  mockKpfIsInitialized.mockReturnValue(true); // KMS side stays inert (local/already-initialized)
  mockKpfBootstrapOrExit.mockClear();
  mockCsfIsInitialized.mockClear();
  mockCsfIsInitialized.mockReturnValue(false);
  mockCsfBootstrapOrExit.mockClear();
}

describe('server.js entrypoint gate — config-secrets branch (KMS held inert)', () => {
  const savedEnv = {};

  beforeEach(() => {
    jest.resetModules();
    resetAllMocks();
    savedEnv.QODIQA_KMS_PROVIDER = process.env.QODIQA_KMS_PROVIDER;
    savedEnv.QODIQA_CONFIG_SECRETS_PROVIDER = process.env.QODIQA_CONFIG_SECRETS_PROVIDER;
    delete process.env.QODIQA_KMS_PROVIDER; // 'local' — KMS branch never triggers here
  });

  afterEach(() => {
    for (const k of ['QODIQA_KMS_PROVIDER', 'QODIQA_CONFIG_SECRETS_PROVIDER']) {
      if (savedEnv[k] === undefined) delete process.env[k];
      else process.env[k] = savedEnv[k];
    }
  });

  test('QODIQA_CONFIG_SECRETS_PROVIDER unset (default "env"): configSecretsFactory is never touched, sync export unchanged', () => {
    delete process.env.QODIQA_CONFIG_SECRETS_PROVIDER;

    // eslint-disable-next-line global-require
    const exported = require(SERVER_JS_PATH);

    expect(mockCsfBootstrapOrExit).not.toHaveBeenCalled();
    expect(mockKpfBootstrapOrExit).not.toHaveBeenCalled();
    expect(typeof exported.then).not.toBe('function');
    expect(exported).toBe(mockAppInstance);
    expect(mockCreateApp).toHaveBeenCalledTimes(1);
  });

  test('QODIQA_CONFIG_SECRETS_PROVIDER="vault-kv" and not yet initialized: bootstrapOrExit() runs before createApp(), export is a Promise', async () => {
    process.env.QODIQA_CONFIG_SECRETS_PROVIDER = 'vault-kv';
    mockCsfIsInitialized.mockReturnValue(false);

    // eslint-disable-next-line global-require
    const exported = require(SERVER_JS_PATH);

    expect(typeof exported.then).toBe('function');
    expect(mockCreateApp).not.toHaveBeenCalled(); // not yet — bootstrap hasn't resolved

    const app = await exported;

    expect(mockCsfBootstrapOrExit).toHaveBeenCalledTimes(1);
    expect(mockKpfBootstrapOrExit).not.toHaveBeenCalled(); // KMS side stayed inert
    expect(mockCreateApp).toHaveBeenCalledTimes(1);
    expect(app).toBe(mockAppInstance);
    expect(typeof app.startServer).toBe('function');
  });

  test('QODIQA_CONFIG_SECRETS_PROVIDER="vault-kv" but configSecretsFactory.isInitialized() already true (start.js already ran): sync fast path, bootstrapOrExit never called', () => {
    process.env.QODIQA_CONFIG_SECRETS_PROVIDER = 'vault-kv';
    mockCsfIsInitialized.mockReturnValue(true);

    // eslint-disable-next-line global-require
    const exported = require(SERVER_JS_PATH);

    expect(typeof exported.then).not.toBe('function');
    expect(exported).toBe(mockAppInstance);
    expect(mockCsfBootstrapOrExit).not.toHaveBeenCalled();
    expect(mockCreateApp).toHaveBeenCalledTimes(1);
  });

  test('exported startServer() drives startup\'s startServer(app) after the config-secrets bootstrap resolved', async () => {
    process.env.QODIQA_CONFIG_SECRETS_PROVIDER = 'vault-kv';
    mockCsfIsInitialized.mockReturnValue(false);

    // eslint-disable-next-line global-require
    const exported = require(SERVER_JS_PATH);
    const app = await exported;
    await app.startServer();

    expect(mockStartServerInner).toHaveBeenCalledTimes(1);
    expect(mockStartServerInner).toHaveBeenCalledWith(mockAppInstance);
  });
});
