'use strict';

/**
 * Tests for src/core/rateLimit/startupGuard.js.
 *
 * Modeled on src/core/audit/__tests__/multiInstanceGuard.test.js's
 * fail-closed pattern: _exit is asserted to have already fired synchronously
 * by the time checkNoLegacyRateLimiters() returns, before the (still
 * pending) notify promise settles.
 */

jest.mock('../../../runtime/rawStderrDiagnostic', () => ({
  writeDiagnostic: jest.fn(),
}));
jest.mock('../../../runtime/earlyCriticalNotify', () => ({
  notifyCriticalStartupFailure: jest.fn(),
}));

const express = require('express');
const { writeDiagnostic } = require('../../../runtime/rawStderrDiagnostic');
const { notifyCriticalStartupFailure } = require('../../../runtime/earlyCriticalNotify');
// The guard looks for this tag on a mounted handler; the legacy limiter that used to carry it is no longer part of the product.
const createRateLimit = () => Object.assign((_req, _res, next) => next(), { _legacyPublicRateLimiter: true });
const { checkNoLegacyRateLimiters } = require('../startupGuard');

beforeEach(() => {
  jest.clearAllMocks();
  notifyCriticalStartupFailure.mockImplementation(() => new Promise((resolve) => setTimeout(resolve, 5)));
});

function cleanApp() {
  const app = express();
  app.use((_req, _res, next) => next());
  const sub = express.Router();
  sub.get('/x', (_req, res) => res.status(200).end());
  app.use('/mounted', sub);
  return app;
}

function appWithTopLevelLegacyLimiter() {
  const app = express();
  app.use(createRateLimit({ max: 10, windowMs: 60_000 }));
  app.get('/probe', (_req, res) => res.status(200).end());
  return app;
}

function appWithNestedLegacyLimiter() {
  // Mirrors real production shape: a router mounted with app.use('/x',
  // router), where the legacy limiter is applied via router.use(...) or
  // router.get('/y', limiter, handler) inside that nested router — see
  // src/api/routes/audit.js / auditViewer.js pre-migration.
  const app = express();
  const sub = express.Router();
  sub.get('/records', createRateLimit({ max: 10, windowMs: 60_000 }), (_req, res) => res.status(200).end());
  app.use('/evidence-chain', sub);
  return app;
}

describe('startupGuard — checkNoLegacyRateLimiters', () => {
  test('single-node mode: never inspects the app, always returns true (no false positives)', () => {
    const _exit = jest.fn();
    const ok = checkNoLegacyRateLimiters(appWithTopLevelLegacyLimiter(), { _orderingMode: 'single-node', _exit });

    expect(ok).toBe(true);
    expect(_exit).not.toHaveBeenCalled();
    expect(writeDiagnostic).not.toHaveBeenCalled();
  });

  test('distributed mode, no legacy limiter anywhere: returns true, does not exit', () => {
    const _exit = jest.fn();
    const ok = checkNoLegacyRateLimiters(cleanApp(), { _orderingMode: 'distributed', _exit });

    expect(ok).toBe(true);
    expect(_exit).not.toHaveBeenCalled();
    expect(writeDiagnostic).not.toHaveBeenCalled();
    expect(notifyCriticalStartupFailure).not.toHaveBeenCalled();
  });

  test('distributed mode, top-level legacy limiter: fails closed synchronously', () => {
    const _exit = jest.fn();
    const ok = checkNoLegacyRateLimiters(appWithTopLevelLegacyLimiter(), { _orderingMode: 'distributed', _exit });

    expect(ok).toBe(false);
    expect(writeDiagnostic).toHaveBeenCalledWith(
      'FATAL',
      'RATE_LIMIT_LEGACY_LIMITER_IN_DISTRIBUTED_MODE',
      expect.objectContaining({ offenders: expect.arrayContaining([expect.any(String)]) }),
    );
    // Critical property: _exit already happened by the time this synchronous
    // call returns — not after the (still-pending) notify promise.
    expect(_exit).toHaveBeenCalledWith(1);
    expect(notifyCriticalStartupFailure).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'RATE_LIMIT_LEGACY_LIMITER_IN_DISTRIBUTED_MODE', deploymentMode: 'distributed' }),
    );
  });

  test('distributed mode, legacy limiter nested inside a mounted sub-router: still detected', () => {
    const _exit = jest.fn();
    const ok = checkNoLegacyRateLimiters(appWithNestedLegacyLimiter(), { _orderingMode: 'distributed', _exit });

    expect(ok).toBe(false);
    expect(_exit).toHaveBeenCalledWith(1);
  });
});
