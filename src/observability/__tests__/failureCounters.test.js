'use strict';

/**
 * 2026-10-06 —.
 * Each new failure counter increments at its write site with the expected bounded label, and the write sites keep
 * their existing behaviour (the counter is a best-effort side effect, never a decision input).
 *
 *   FC-01 rbac.js        RBAC 403 → qodiqa_rbac_denials_total{action,reason}
 *   FC-02 opsAuth.js     missing credential / invalid token → qodiqa_ops_auth_failures_total{reason}
 *   FC-03 mfaStepUp.js   step-up denied / error → qodiqa_mfa_events_total{outcome=step_up_denied|step_up_error}
 *   FC-04 mfa.js         wrong codes → {outcome=failed} per failure, {outcome=locked} once at the lock
 *   FC-05 mirrorCountReconciler.js  drift → qodiqa_audit_mirror_count_drift_total{reason}; in-sync → no increment
 *   FC-06 pgLagMonitor.js           lag check → qodiqa_audit_pg_lag_entries = lag (0 in sync, never negative)
 *   FC-07 a metrics failure never changes the write site's outcome
 */

jest.mock('../../../services/logger', () => ({ emit: jest.fn() }));

const request = require('supertest');
const express = require('express');
const metrics = require('../metrics');
const { createRequirePermission } = require('../../middleware/rbac');
const { createOpsAuthMiddleware } = require('../../middleware/opsAuth');
const { createMfaStepUp } = require('../../middleware/mfaStepUp');
const { reconcileOnce } = require('../../core/audit/mirrorCountReconciler');
const pgLag = require('../../core/audit/pgLagMonitor');

const val = (m, key) => m._values.get(key) || 0;

describe('failure counters', () => {
  test('FC-01 an RBAC denial increments rbac_denials_total with the permission and reason', async () => {
    const key = 'action="audit:read",reason="INSUFFICIENT_ROLE"';
    const before = val(metrics.rbacDenialsTotal, key);
    const requirePermission = createRequirePermission({ isPermitted: () => false, isValidPermission: () => true });
    const app = express();
    app.use((req, _res, next) => { req.rbacUser = { username: 'u', role: 'viewer' }; next(); });
    app.get('/x', requirePermission('audit:read'), (_req, res) => res.json({ ok: true }));
    const res = await request(app).get('/x');
    expect(res.status).toBe(403);
    expect(val(metrics.rbacDenialsTotal, key)).toBe(before + 1);
  });

  test('FC-02 ops-auth failures increment ops_auth_failures_total by reason', async () => {
    const app = express();
    app.use(createOpsAuthMiddleware({ token: 'test-ops-token-at-least-32-chars-long' }));
    app.get('/probe', (_req, res) => res.json({ ok: true }));
    const missing0 = val(metrics.opsAuthFailuresTotal, 'reason="missing_credentials"');
    const invalid0 = val(metrics.opsAuthFailuresTotal, 'reason="invalid_token"');
    expect((await request(app).get('/probe')).status).toBe(401);
    expect((await request(app).get('/probe').set('Authorization', 'Bearer wrong-token-wrong-token-wrong-token')).status).toBe(401);
    expect((await request(app).get('/probe').set('Authorization', 'Bearer test-ops-token-at-least-32-chars-long')).status).toBe(200);
    expect(val(metrics.opsAuthFailuresTotal, 'reason="missing_credentials"')).toBe(missing0 + 1);
    expect(val(metrics.opsAuthFailuresTotal, 'reason="invalid_token"')).toBe(invalid0 + 1);
  });

  test('FC-03 MFA step-up denials and errors increment mfa_events_total', async () => {
    let verify = async () => ({ ok: false, reason: 'MFA_INVALID' });
    const mfa = { isRequired: () => true, status: () => ({ enrolled: true }), verifyStepUp: (...a) => verify(...a) };
    const app = express();
    app.use((req, _res, next) => { req.rbacUser = { id: 'u1', username: 'u' }; next(); });
    app.use(createMfaStepUp({ mfa }));
    app.post('/m', (_req, res) => res.json({ ok: true }));
    const denied0 = val(metrics.mfaEventsTotal, 'outcome="step_up_denied"');
    const error0 = val(metrics.mfaEventsTotal, 'outcome="step_up_error"');
    expect((await request(app).post('/m')).status).toBe(401);                          // no code → denied
    expect((await request(app).post('/m').set('X-QODIQA-OTP', '123456')).status).toBe(401); // wrong code → denied
    verify = async () => { throw new Error('store down'); };
    expect((await request(app).post('/m').set('X-QODIQA-OTP', '123456')).status).toBe(503); // error
    verify = async () => ({ ok: true, method: 'totp' });
    expect((await request(app).post('/m').set('X-QODIQA-OTP', '123456')).status).toBe(200); // success: no increment
    expect(val(metrics.mfaEventsTotal, 'outcome="step_up_denied"')).toBe(denied0 + 2);
    expect(val(metrics.mfaEventsTotal, 'outcome="step_up_error"')).toBe(error0 + 1);
  });

  test('FC-04 wrong MFA codes count as failed, and the lock as locked (once)', async () => {
    const store = require('../../core/rbac/store');
    const mfa = require('../../core/rbac/mfa');
    const T0 = Date.parse('2026-09-28T12:00:00Z');
    const u = store.createUser({ username: `fc04-${Date.now()}`, role: 'admin' });
    const user = { id: u.id, username: u.username };
    const { secret } = await mfa.beginEnrollment(user);
    const raw = mfa.base32Decode(secret);
    await mfa.confirmEnrollment(user, mfa.totp(raw, T0), undefined, T0);
    const now = T0 + 120_000;
    const valid = new Set([-3, -2, -1, 0, 1, 2, 3].map((d) => mfa.totp(raw, now + d * 30_000)));
    const wrong = ['000000', '111111', '222222', '333333'].find((c) => !valid.has(c));
    const failed0 = val(metrics.mfaEventsTotal, 'outcome="failed"');
    const locked0 = val(metrics.mfaEventsTotal, 'outcome="locked"');
    const results = [];
    for (let i = 0; i < 5; i++) results.push(await mfa.verifyStepUp(user, wrong, undefined, now)); // eslint-disable-line no-await-in-loop
    expect(results.slice(0, 4).every((r) => r.ok === false && r.reason === 'MFA_INVALID')).toBe(true);
    expect(results[4]).toMatchObject({ ok: false, reason: 'MFA_LOCKED' });
    expect(val(metrics.mfaEventsTotal, 'outcome="failed"')).toBe(failed0 + 5);
    expect(val(metrics.mfaEventsTotal, 'outcome="locked"')).toBe(locked0 + 1);
  });

  test('FC-05 mirror count drift increments by reason; an in-sync run does not', async () => {
    const opts = { emitFn: () => {}, pgEnabled: () => true };
    const mis0 = val(metrics.auditMirrorCountDriftTotal, 'reason="MISMATCH"');
    const miss0 = val(metrics.auditMirrorCountDriftTotal, 'reason="COUNTER_MISSING"');
    expect((await reconcileOnce({ ...opts, check: async () => ({ stored: 10, exact: 11, inSync: false }) })).status).toBe('DRIFT');
    expect((await reconcileOnce({ ...opts, check: async () => ({ stored: null, exact: 11, inSync: false }) })).reason).toBe('COUNTER_MISSING');
    expect((await reconcileOnce({ ...opts, check: async () => ({ stored: 11, exact: 11, inSync: true }) })).status).toBe('IN_SYNC');
    expect(val(metrics.auditMirrorCountDriftTotal, 'reason="MISMATCH"')).toBe(mis0 + 1);
    expect(val(metrics.auditMirrorCountDriftTotal, 'reason="COUNTER_MISSING"')).toBe(miss0 + 1);
  });

  test('FC-06 the PG lag gauge tracks every successful lag check', async () => {
    pgLag._resetState();
    const emitted = [];
    const emitFn = (lvl, ev) => emitted.push(ev);
    await pgLag._checkOnce({ getFileCount: () => 100, queryFn: async () => ({ rows: [{ cnt: 40 }] }), emitFn, lagThreshold: 5 });
    expect(val(metrics.auditPgLagEntries, '')).toBe(60);
    expect(emitted).toContain('AUDIT_PG_SYNC_LAG');
    await pgLag._checkOnce({ getFileCount: () => 100, queryFn: async () => ({ rows: [{ cnt: 100 }] }), emitFn, lagThreshold: 5 });
    expect(val(metrics.auditPgLagEntries, '')).toBe(0);
    await pgLag._checkOnce({ getFileCount: () => 100, queryFn: async () => ({ rows: [{ cnt: 105 }] }), emitFn, lagThreshold: 5 });
    expect(val(metrics.auditPgLagEntries, '')).toBe(0); // PG ahead (file rotated) is not negative lag
    // a failed query leaves the last measured value (it is a "last successful check" gauge)
    await pgLag._checkOnce({ getFileCount: () => 100, queryFn: async () => { throw new Error('down'); }, emitFn, lagThreshold: 5 });
    expect(val(metrics.auditPgLagEntries, '')).toBe(0);
    pgLag._resetState();
  });

  test('FC-07 a throwing metric never changes the write site outcome', async () => {
    const spy = jest.spyOn(metrics.auditMirrorCountDriftTotal, 'inc').mockImplementation(() => { throw new Error('boom'); });
    const lagSpy = jest.spyOn(metrics.auditPgLagEntries, 'set').mockImplementation(() => { throw new Error('boom'); });
    try {
      const r = await reconcileOnce({ emitFn: () => {}, pgEnabled: () => true, check: async () => ({ stored: 1, exact: 2, inSync: false }) });
      expect(r).toMatchObject({ status: 'DRIFT', reason: 'MISMATCH' });
      pgLag._resetState();
      const emitted = [];
      await pgLag._checkOnce({ getFileCount: () => 50, queryFn: async () => ({ rows: [{ cnt: 1 }] }), emitFn: (l, e) => emitted.push(e), lagThreshold: 5 });
      expect(emitted).toEqual(['AUDIT_PG_SYNC_LAG']);
    } finally {
      spy.mockRestore();
      lagSpy.mockRestore();
      pgLag._resetState();
    }
  });
});
