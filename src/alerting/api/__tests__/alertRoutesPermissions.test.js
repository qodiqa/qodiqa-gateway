'use strict';

// (NF-8): alert mutations need MANAGE_ALERTS, not just the READ_AUDIT the
// /alerts mount requires — the read-only auditor role could
// acknowledge, resolve, suppress or mark alerts false-positive. Suppressing
// additionally passes the MFA step-up middleware. Uses the real permission matrix.

const mockEngine = {
  acknowledgeAlert: jest.fn(async (id) => ({ id, status: 'ACKNOWLEDGED' })),
  resolveAlert: jest.fn(async (id) => ({ id, status: 'RESOLVED' })),
  suppressAlert: jest.fn(async (id) => ({ id, status: 'SUPPRESSED' })),
  markFalsePositive: jest.fn(async (id) => ({ id, status: 'FALSE_POSITIVE' })),
};
jest.mock('../../engine/AlertEngine', () => mockEngine);
jest.mock('../../storage/AlertStore', () => ({ getAlert: jest.fn(async (id) => ({ id })) }));
jest.mock('../../notification/NotificationService', () => ({ testChannel: jest.fn() }));
jest.mock('../../detection/AnomalyDetector', () => ({}));

const request = require('supertest');
const express = require('express');
const { isPermitted } = require('../../../core/rbac/roles');
const { createAlertRouter } = require('../alertRoutes');

const ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const stepUp = jest.fn((_req, _res, next) => next());

function app(role) {
  const a = express();
  a.use(express.json());
  a.use((req, _res, next) => { req.rbacUser = { id: 'u1', username: 'op', role }; next(); });
  const requirePermission = (p) => (req, res, next) => (isPermitted(req.rbacUser.role, p) ? next() : res.status(403).json({ error: 'FORBIDDEN' }));
  a.use('/alerts', requirePermission('READ_AUDIT'), createAlertRouter({ requirePermission, stepUp }));
  return a;
}

beforeEach(() => jest.clearAllMocks());

describe('NF-8: alert mutations require MANAGE_ALERTS', () => {
  test.each(['acknowledge', 'resolve', 'suppress', 'false-positive'])('auditor (READ_AUDIT only) is refused POST /alerts/:id/%s', async (action) => {
    await request(app('auditor')).post(`/alerts/${ID}/${action}`).send({}).expect(403);
    for (const fn of Object.values(mockEngine)) expect(fn).not.toHaveBeenCalled();
  });

  test.each(['admin', 'compliance'])('%s may acknowledge', async (role) => {
    await request(app(role)).post(`/alerts/${ID}/acknowledge`).send({}).expect(200);
    expect(mockEngine.acknowledgeAlert).toHaveBeenCalledTimes(1);
  });

  test('suppress passes the MFA step-up middleware; acknowledge does not', async () => {
    await request(app('compliance')).post(`/alerts/${ID}/suppress`).send({}).expect(200);
    expect(stepUp).toHaveBeenCalledTimes(1);
    stepUp.mockClear();
    await request(app('compliance')).post(`/alerts/${ID}/acknowledge`).send({}).expect(200);
    expect(stepUp).not.toHaveBeenCalled();
  });

  test('a refusing step-up blocks the suppression', async () => {
    stepUp.mockImplementationOnce((_req, res) => res.status(403).json({ error: 'MFA_REQUIRED' }));
    await request(app('admin')).post(`/alerts/${ID}/suppress`).send({}).expect(403);
    expect(mockEngine.suppressAlert).not.toHaveBeenCalled();
  });

  test('the permission matrix: MANAGE_ALERTS = admin + compliance; auditor, operator and viewer lack it', () => {
    expect(['admin', 'compliance'].every((r) => isPermitted(r, 'MANAGE_ALERTS'))).toBe(true);
    expect(['auditor', 'operator', 'viewer'].some((r) => isPermitted(r, 'MANAGE_ALERTS'))).toBe(false);
  });
});

// the recorded handler is the AUTHENTICATED operator; a body-supplied `actor` cannot name someone else.
describe('audit 4.4: alert actor attribution', () => {
  test.each(['acknowledge', 'resolve', 'suppress', 'false-positive'])('POST /alerts/:id/%s records the authenticated operator, ignoring body.actor', async (action) => {
    await request(app('admin')).post(`/alerts/${ID}/${action}`).send({ actor: 'someone-else', note: 'n' }).expect(200);
    const fn = { acknowledge: 'acknowledgeAlert', resolve: 'resolveAlert', suppress: 'suppressAlert', 'false-positive': 'markFalsePositive' }[action];
    expect(mockEngine[fn]).toHaveBeenCalledWith(ID, expect.objectContaining({ actor: 'op' }));
    expect(mockEngine[fn].mock.calls[0][1].actor).not.toBe('someone-else');
  });
});
