'use strict';

/**
 * operator API-key expiry at the ops auth layer, with the real
 * RBAC store (per-file temp path): valid → 200; expiring → 200 + warning header
 * + RBAC_API_KEY_EXPIRING; old key in rotation grace → 200 + RBAC_API_KEY_GRACE_USED;
 * expired / grace-over → 401 API_KEY_EXPIRED + RBAC_API_KEY_EXPIRED_USED, counted
 * as an auth failure.
 */

jest.mock('../../../services/logger', () => ({ emit: jest.fn() }));

const request = require('supertest');
const express = require('express');
const { emit } = require('../../../services/logger');
const rbacStore = require('../../core/rbac/store');
const { createOpsAuthMiddleware } = require('../opsAuth');

const DAY = 86_400_000;
const lockout = { precheck: jest.fn(async () => ({ locked: false, backoffDelayMs: 0 })), recordFailure: jest.fn(async () => {}), recordSuccess: jest.fn(async () => {}) };

function app() {
  const a = express();
  a.use((req, _res, next) => { req.requestId = 'r'; req.clientIp = '127.0.0.1'; next(); });
  a.use(createOpsAuthMiddleware({ token: null }, rbacStore, lockout));
  a.get('/probe', (req, res) => res.json({ user: req.rbacUser && req.rbacUser.id }));
  return a;
}
const events = () => emit.mock.calls.map((c) => c[1]);
let nowSpy = null;
const at = (ms) => { if (nowSpy) nowSpy.mockRestore(); nowSpy = jest.spyOn(Date, 'now').mockImplementation(() => ms); };

beforeEach(() => { emit.mockClear(); lockout.recordFailure.mockClear(); });
afterEach(() => { if (nowSpy) nowSpy.mockRestore(); nowSpy = null; });

test('valid → 200, no warning', async () => {
  const u = rbacStore.createUser({ username: `ke-valid-${Date.now()}`, role: 'viewer' });
  const { plaintext } = rbacStore.issueApiKey(u.id);
  const r = await request(app()).get('/probe').set('Authorization', `Bearer ${plaintext}`);
  expect(r.status).toBe(200); expect(r.headers['x-qodiqa-key-expires']).toBeUndefined();
});

test('expiring (≤14 d) → 200 with X-QODIQA-Key-Expires and RBAC_API_KEY_EXPIRING', async () => {
  const u = rbacStore.createUser({ username: `ke-exp-${Date.now()}`, role: 'viewer' });
  const t0 = Date.now(); const { plaintext } = rbacStore.issueApiKey(u.id);
  at(t0 + 80 * DAY);
  const r = await request(app()).get('/probe').set('Authorization', `Bearer ${plaintext}`);
  expect(r.status).toBe(200); expect(r.headers['x-qodiqa-key-expires']).toBeTruthy();
  expect(events()).toContain('RBAC_API_KEY_EXPIRING');
});

test('expired → 401 API_KEY_EXPIRED, audited event, counted as failure', async () => {
  const u = rbacStore.createUser({ username: `ke-dead-${Date.now()}`, role: 'viewer' });
  const t0 = Date.now(); const { plaintext } = rbacStore.issueApiKey(u.id);
  at(t0 + 91 * DAY);
  const r = await request(app()).get('/probe').set('Authorization', `Bearer ${plaintext}`);
  expect(r.status).toBe(401); expect(JSON.stringify(r.body)).toContain('API_KEY_EXPIRED');
  expect(events()).toContain('RBAC_API_KEY_EXPIRED_USED');
  expect(lockout.recordFailure).toHaveBeenCalled();
});

test('rotation: old key works 24 h (grace event), then 401', async () => {
  const u = rbacStore.createUser({ username: `ke-rot-${Date.now()}`, role: 'viewer' });
  const t0 = Date.now();
  const old = rbacStore.issueApiKey(u.id).plaintext;
  const fresh = rbacStore.issueApiKey(u.id).plaintext;
  let r = await request(app()).get('/probe').set('Authorization', `Bearer ${old}`);
  expect(r.status).toBe(200); expect(events()).toContain('RBAC_API_KEY_GRACE_USED');
  at(t0 + 25 * 3_600_000);
  r = await request(app()).get('/probe').set('Authorization', `Bearer ${old}`);
  expect(r.status).toBe(401);
  r = await request(app()).get('/probe').set('Authorization', `Bearer ${fresh}`);
  expect(r.status).toBe(200);
});
