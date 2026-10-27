'use strict';

/**
 * LOCK-IN TEST — Items 21/22, Finding D (server.js silently ignoring
 * QODIQA_KMS_PROVIDER when run directly via `npm start`/`node server.js`).
 *
 * Written and verified against server.js BEFORE any Finding-D remediation
 * touched it, and left UNMODIFIED through that remediation. Its purpose is
 * narrow and deliberate: prove that for the default boot path —
 * QODIQA_KMS_PROVIDER unset, or explicitly "local" — requiring server.js
 * executes IDENTICAL code to before the fix. It does not (and, given
 * server/startup.js's real Postgres/Redis/etc. side effects, cannot without
 * heavy additional mocking well beyond this change's scope) re-verify
 * server/startup.js's own internal FATAL-gate sequence — that is covered
 * exclusively by test/acceptance's spawned-process suites (e.g. AT-001),
 * outside npm run test:unit's src/-only scope. See
 * for the full
 * boundary/epistemic-limits discussion.
 *
 * What "identical" means here, precisely:
 *   - keyProviderFactory.initialize() / .wireIntoSecretsProvider() /
 *     .bootstrapOrExit() are NEVER invoked for the default path — the whole
 *     point of the Finding-D fix is that the KMS bootstrap machinery is
 *     reachable when a non-local provider is selected, while remaining
 *     completely inert (not merely successful — UNCALLED) when it is not.
 *   - require('../../../../server.js') still resolves synchronously (never
 *     a thenable/Promise) to the exact object src/app.js's createApp()
 *     returned, with .app and .startServer attached to that same object —
 *     matching server.js's pre-existing module.exports contract relied on
 *     by start.js and test/harness/shutdownIpcWrapper.js.
 *   - createApp() and server/startup's ctx are used exactly once, with no
 *     new env reads inserted ahead of them that could alter outcomes.
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

function resetAllMocks() {
  mockStartServerInner.mockClear();
  mockCreateApp.mockClear();
  mockKpfInitialize.mockClear();
  mockKpfWireIntoSecretsProvider.mockClear();
  mockKpfBootstrapOrExit.mockClear();
  mockKpfIsInitialized.mockClear();
  mockKpfIsInitialized.mockReturnValue(false);
}

describe('server.js entrypoint gate — default (local/unset) path is inert w.r.t. keyProviderFactory', () => {
  const savedEnv = {};

  beforeEach(() => {
    jest.resetModules();
    resetAllMocks();
    savedEnv.QODIQA_KMS_PROVIDER = process.env.QODIQA_KMS_PROVIDER;
    delete process.env.QODIQA_KMS_PROVIDER;
  });

  afterEach(() => {
    if (savedEnv.QODIQA_KMS_PROVIDER === undefined) {
      delete process.env.QODIQA_KMS_PROVIDER;
    } else {
      process.env.QODIQA_KMS_PROVIDER = savedEnv.QODIQA_KMS_PROVIDER;
    }
  });

  test.each([
    ['unset', undefined],
    ['explicit "local"', 'local'],
  ])('QODIQA_KMS_PROVIDER %s: keyProviderFactory is never touched, app export shape is unchanged', (_label, value) => {
    if (value === undefined) {
      delete process.env.QODIQA_KMS_PROVIDER;
    } else {
      process.env.QODIQA_KMS_PROVIDER = value;
    }

    // eslint-disable-next-line global-require
    const exported = require(SERVER_JS_PATH);

    // ── keyProviderFactory must be completely inert on this path ──────────
    expect(mockKpfInitialize).not.toHaveBeenCalled();
    expect(mockKpfWireIntoSecretsProvider).not.toHaveBeenCalled();
    expect(mockKpfBootstrapOrExit).not.toHaveBeenCalled();

    // ── createApp/ctx used exactly once, synchronously ─────────────────────
    expect(mockCreateApp).toHaveBeenCalledTimes(1);
    expect(mockCreateApp).toHaveBeenCalledWith(mockCtx);

    // ── export shape: unchanged synchronous contract ───────────────────────
    expect(typeof exported.then).not.toBe('function'); // never a thenable/Promise
    expect(exported).toBe(mockAppInstance);
    expect(exported.app).toBe(mockAppInstance);
    expect(typeof exported.startServer).toBe('function');
  });

  test.each([
    ['unset', undefined],
    ['explicit "local"', 'local'],
  ])('QODIQA_KMS_PROVIDER %s: exported startServer() drives server/startup\'s startServer(app) directly, with no KMS bootstrap step first', async (_label, value) => {
    if (value === undefined) {
      delete process.env.QODIQA_KMS_PROVIDER;
    } else {
      process.env.QODIQA_KMS_PROVIDER = value;
    }

    // eslint-disable-next-line global-require
    const exported = require(SERVER_JS_PATH);
    await exported.startServer();

    expect(mockStartServerInner).toHaveBeenCalledTimes(1);
    expect(mockStartServerInner).toHaveBeenCalledWith(mockAppInstance);
    expect(mockKpfInitialize).not.toHaveBeenCalled();
    expect(mockKpfWireIntoSecretsProvider).not.toHaveBeenCalled();
    expect(mockKpfBootstrapOrExit).not.toHaveBeenCalled();
  });
});
