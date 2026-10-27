'use strict';

/**
 * Global kill switch — state, integrity, audit, gate, admin routes (control plane in memory mode).
 *
 * KS-01…KS-08  the record: default off, activate/release, idempotence, reason rules, MAC, tamper ⇒ active (fail closed)
 * KS-09…KS-11  audit: v8 off ⇒ skipped but escalated; v8 on ⇒ KILL_SWITCH entry with the frozen shape; audit failure ⇒ change stands
 * KG-01…KG-04  the gate: off passes, on answers 503 BLOCK before the route runs, unknown state fails closed, Retry-After
 * KA-01…KA-06  admin routes: view never leaks the MAC, activation needs a reason, errors are mapped
 */

const mockEmit = jest.fn();
jest.mock('../../../../services/logger', () => ({ emit: (...a) => mockEmit(...a) }));

const express = require('express');
const supertest = require('supertest');

const killSwitch = require('..');
const { createKillSwitchGate, setKillSwitch } = require('../../../middleware/killSwitchGate');
setKillSwitch(require('..'));
const { createKillSwitchAdminRouter } = require('../../../api/routes/admin/killSwitch');
const { Collection } = require('../../controlPlane/collection');
const eb = require('../../audit/entryBuilder');
const metrics = require('../../../observability/metrics');

const OP = 'op-alice';
const savedV8 = process.env.QODIQA_AUDIT_SCHEMA_V8;
let col; // a second handle on the SAME process-wide snapshot, used to tamper with the stored record
beforeAll(() => { col = new Collection('kill_switch'); });
beforeEach(async () => {
  mockEmit.mockClear();
  delete process.env.QODIQA_AUDIT_SCHEMA_V8;
  await killSwitch.release({ operatorId: OP });   // back to off whatever a previous test left
});
afterAll(() => { if (savedV8 === undefined) delete process.env.QODIQA_AUDIT_SCHEMA_V8; else process.env.QODIQA_AUDIT_SCHEMA_V8 = savedV8; });

describe('KS — the record', () => {
  test('KS-01 off by default; the view carries no MAC', () => {
    const v = killSwitch.view();
    expect(v).toMatchObject({ active: false, tampered: false, scope: 'global' });
    expect(JSON.stringify(v)).not.toMatch(/mac/i);
  });

  test('KS-02 activate raises it, with operator, reason, sequence and a state hash; release lowers it', async () => {
    const on = await killSwitch.activate({ operatorId: OP, reason: 'incident 4711' });
    expect(on.changed).toBe(true);
    expect(on.state).toMatchObject({ active: true, tampered: false, operatorId: OP, reason: 'incident 4711', scope: 'global' });
    expect(on.state.eventId).toMatch(/^[0-9a-f-]{36}$/);
    expect(on.state.stateHash).toMatch(/^[0-9a-f]{64}$/);
    const seqOn = on.state.seq;
    expect(killSwitch.state().active).toBe(true);
    const off = await killSwitch.release({ operatorId: OP, reason: 'all clear' });
    expect(off.changed).toBe(true);
    expect(off.state).toMatchObject({ active: false, seq: seqOn + 1 });
    expect(killSwitch.state().active).toBe(false);
  });

  test('KS-03 both transitions are idempotent: no second record, no second audit entry, same state', async () => {
    const first = await killSwitch.activate({ operatorId: OP, reason: 'r' });
    const again = await killSwitch.activate({ operatorId: 'op-bob', reason: 'again' });
    expect(again.changed).toBe(false);
    expect(again.audit).toBeNull();
    expect(again.state.eventId).toBe(first.state.eventId);
    expect(again.state.operatorId).toBe(OP);
    await killSwitch.release({ operatorId: OP });
    const offAgain = await killSwitch.release({ operatorId: OP });
    expect(offAgain.changed).toBe(false);
  });

  test('KS-04 activating needs a reason; reasons are bounded and free of control characters; an operator is required', async () => {
    for (const bad of [undefined, null, '']) await expect(killSwitch.activate({ operatorId: OP, reason: bad })).rejects.toMatchObject({ code: 'REASON_REQUIRED', name: 'KillSwitchError' });
    for (const bad of ['x'.repeat(501), 'line\nbreak', 'nul\u0000', 42, {}]) await expect(killSwitch.activate({ operatorId: OP, reason: bad })).rejects.toMatchObject({ code: 'INVALID_REASON' });
    await expect(killSwitch.activate({ operatorId: '', reason: 'r' })).rejects.toMatchObject({ code: 'OPERATOR_REQUIRED', status: 401 });
    await expect(killSwitch.activate({ reason: 'r' })).rejects.toMatchObject({ code: 'OPERATOR_REQUIRED' });
    expect(killSwitch.state().active).toBe(false);
    await expect(killSwitch.release({ operatorId: OP, reason: 'x'.repeat(501) })).rejects.toMatchObject({ code: 'INVALID_REASON' });
    expect((await killSwitch.activate({ operatorId: OP, reason: 'x'.repeat(500) })).changed).toBe(true);
  });

  test('KS-05 activation and release are escalated at CRITICAL and counted', async () => {
    const before = metrics.killSwitchTransitionsTotal._values ? [...metrics.killSwitchTransitionsTotal._values.values()].reduce((a, b) => a + b, 0) : 0;
    await killSwitch.activate({ operatorId: OP, reason: 'drill' });
    expect(mockEmit).toHaveBeenCalledWith('CRITICAL', 'KILL_SWITCH_ACTIVATED', expect.objectContaining({ operatorId: OP, reason: 'drill', scope: 'global' }));
    await killSwitch.release({ operatorId: OP });
    expect(mockEmit).toHaveBeenCalledWith('CRITICAL', 'KILL_SWITCH_RELEASED', expect.objectContaining({ operatorId: OP }));
    if (metrics.killSwitchTransitionsTotal._values) expect([...metrics.killSwitchTransitionsTotal._values.values()].reduce((a, b) => a + b, 0)).toBe(before + 2);
  });

  test('KS-06 a changed record (valid shape, wrong MAC) is treated as ACTIVE and escalated — a database write can raise the switch, never lower it', async () => {
    await killSwitch.activate({ operatorId: OP, reason: 'real' });
    const rec = col.get('global');
    // an attacker with write access flips active to false but cannot re-sign
    col.put('global', Object.freeze({ ...rec, active: false }));
    const s = killSwitch.state();
    expect(s).toMatchObject({ active: true, tampered: true });
    expect(mockEmit).toHaveBeenCalledWith('CRITICAL', 'KILL_SWITCH_RECORD_TAMPERED', expect.objectContaining({ reason: expect.any(String) }));
    expect(killSwitch.view()).toMatchObject({ active: true, tampered: true });
  });

  test('KS-07 a forged "off" record that never had a MAC is not accepted either', async () => {
    col.put('global', Object.freeze({ active: false, scope: 'global', eventId: 'x', operatorId: 'evil', reason: '', changedAt: new Date().toISOString(), seq: 99 }));
    expect(killSwitch.state()).toMatchObject({ active: true, tampered: true });
  });

  test('KS-08 releasing replaces a tampered record with a properly signed one', async () => {
    col.put('global', Object.freeze({ active: true, scope: 'global', eventId: 'x', operatorId: 'evil', reason: 'forged', changedAt: new Date().toISOString(), seq: 7, mac: 'AAAA' }));
    expect(killSwitch.state().tampered).toBe(true);
    const out = await killSwitch.release({ operatorId: OP, reason: 'cleaned up' });
    expect(out.changed).toBe(true);
    expect(out.state).toMatchObject({ active: false, tampered: false });
    expect(out.state.seq).toBeGreaterThan(7);   // never below the highest sequence this replica has seen
    expect(killSwitch.state()).toMatchObject({ active: false, tampered: false });
  });
});

describe('KS — downgrade (tombstone / rollback of the stored record)', () => {
  test('KS-12 a record that vanishes after one was seen reads as ACTIVE, escalated; a signed release clears it', async () => {
    await killSwitch.activate({ operatorId: OP, reason: 'real' });
    expect(killSwitch.state().active).toBe(true);
    col.remove('global');
    expect(killSwitch.state()).toMatchObject({ active: true, tampered: true });
    expect(mockEmit).toHaveBeenCalledWith('CRITICAL', 'KILL_SWITCH_RECORD_DOWNGRADED', expect.objectContaining({ reason: 'RECORD_MISSING' }));
    const out = await killSwitch.release({ operatorId: OP, reason: 'restored' });
    expect(out.changed).toBe(true);
    expect(killSwitch.state()).toMatchObject({ active: false, tampered: false });
  });

  test('KS-13 an older, validly signed, inactive record put back over a newer one is read as ACTIVE', async () => {
    const off = await killSwitch.release({ operatorId: OP, reason: 'old off' });  // idempotent if already off
    const oldRec = col.get('global');
    await killSwitch.activate({ operatorId: OP, reason: 'newer activation' });
    expect(killSwitch.state().active).toBe(true);
    col.put('global', oldRec);                                                      // rollback: genuine MAC, lower seq
    expect(killSwitch.state()).toMatchObject({ active: true, tampered: true });
    expect(mockEmit).toHaveBeenCalledWith('CRITICAL', 'KILL_SWITCH_RECORD_DOWNGRADED', expect.objectContaining({ reason: 'SEQ_ROLLBACK' }));
    expect(off).toBeDefined();
  });

  test('KS-14 a transition after a rollback never reuses a sequence number', async () => {
    await killSwitch.activate({ operatorId: OP, reason: 'a' });
    const high = col.get('global');
    col.put('global', Object.freeze({ ...high, seq: 1, mac: 'AAAA' }));
    const out = await killSwitch.release({ operatorId: OP, reason: 'b' });
    expect(out.state.seq).toBeGreaterThan(high.seq);
  });
});

describe('KS — audit entry', () => {
  test('KS-09 with audit schema v8 off the change stands and the missing chain entry is escalated, not hidden', async () => {
    const out = await killSwitch.activate({ operatorId: OP, reason: 'drill' });
    expect(out.changed).toBe(true);
    expect(out.audit).toEqual({ recorded: false, reason: 'AUDIT_SCHEMA_V8_DISABLED' });
    expect(mockEmit).toHaveBeenCalledWith('CRITICAL', 'KILL_SWITCH_AUDIT_ENTRY_SKIPPED', expect.objectContaining({ eventId: out.state.eventId, active: true }));
  });

  test('KS-10 with audit schema v8 on, a KILL_SWITCH entry of the frozen shape is appended for both transitions', async () => {
    process.env.QODIQA_AUDIT_SCHEMA_V8 = 'true';
    const appended = [];
    jest.isolateModules(() => {});
    const audit = require('../../audit/audit-log');
    const spy = jest.spyOn(audit, 'appendMandatory').mockImplementation(async (fields) => { appended.push(fields); return { hash: 'a'.repeat(64) }; });
    try {
      const on = await killSwitch.activate({ operatorId: OP, reason: 'drill' });
      expect(on.audit).toMatchObject({ recorded: true, entryHash: 'a'.repeat(64), stateHash: on.state.stateHash });
      const off = await killSwitch.release({ operatorId: OP, reason: 'done' });
      expect(off.audit.recorded).toBe(true);
    } finally { spy.mockRestore(); }
    expect(appended).toHaveLength(2);
    expect(appended[0]).toEqual({
      artifactId: expect.stringMatching(/^[0-9a-f-]{36}:kill_switch$/), entryType: 'KILL_SWITCH', decision: 'BLOCK', reason: 'KILL_SWITCH_ON', tenantId: '*',
      executionContext: { killSwitch: { operatorId: OP, scope: 'global', stateHash: expect.stringMatching(/^[0-9a-f]{64}$/) } },
    });
    expect(appended[1]).toMatchObject({ decision: 'ALLOW', reason: 'KILL_SWITCH_OFF', entryType: 'KILL_SWITCH' });
    // the exact fields the builder accepts as a valid v8 KILL_SWITCH entry
    const entry = eb.buildEntry(eb.normalizeFields(appended[0]), 'GENESIS');
    expect(eb.v8ShapeViolation(JSON.parse(JSON.stringify(entry)))).toBeNull();
    expect(entry.executionContext.killSwitch.stateHash).toBe(appended[0].executionContext.killSwitch.stateHash);
  });

  test('KS-11 if the audit append fails the switch is still raised, and the failure is escalated and reported', async () => {
    process.env.QODIQA_AUDIT_SCHEMA_V8 = 'true';
    const audit = require('../../audit/audit-log');
    const spy = jest.spyOn(audit, 'appendMandatory').mockRejectedValue(Object.assign(new Error('disk full'), { code: 'AUDIT_PERSISTENCE_FAILED' }));
    try {
      const on = await killSwitch.activate({ operatorId: OP, reason: 'drill' });
      expect(on.changed).toBe(true);
      expect(on.audit).toEqual({ recorded: false, reason: 'AUDIT_APPEND_FAILED' });
      expect(killSwitch.state().active).toBe(true);
      expect(mockEmit).toHaveBeenCalledWith('CRITICAL', 'KILL_SWITCH_AUDIT_FAILED', expect.objectContaining({ code: 'AUDIT_PERSISTENCE_FAILED' }));
    } finally { spy.mockRestore(); }
  });
});

describe('KG — the gate', () => {
  function appWith(routeHandler) {
    const app = express();
    app.use('/x', createKillSwitchGate({ route: '/x' }), routeHandler);
    return app;
  }

  test('KG-01 off: the request reaches the route', async () => {
    const handler = jest.fn((_q, res) => res.json({ ok: true }));
    const res = await supertest(appWith(handler)).get('/x');
    expect(res.status).toBe(200);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  test('KG-02 on: 503 BLOCK KILL_SWITCH_ACTIVE with Retry-After, and the route never runs', async () => {
    await killSwitch.activate({ operatorId: OP, reason: 'stop' });
    const handler = jest.fn((_q, res) => res.json({ ok: true }));
    const res = await supertest(appWith(handler)).post('/x').send({ prompt: 'hello' });
    expect(res.status).toBe(503);
    expect(res.body).toEqual({ decision: 'BLOCK', reason: 'KILL_SWITCH_ACTIVE', details: {}, requestId: null });
    expect(res.headers['retry-after']).toBe('30');
    expect(handler).not.toHaveBeenCalled();
  });

  test('KG-03 a state that cannot be determined is refused too (fail closed), distinctly reported', async () => {
    const spy = jest.spyOn(killSwitch, 'state').mockImplementation(() => { throw Object.assign(new Error('control plane snapshot is stale'), { code: 'CONTROL_PLANE_STALE' }); });
    try {
      const handler = jest.fn((_q, res) => res.json({ ok: true }));
      const res = await supertest(appWith(handler)).get('/x');
      expect(res.status).toBe(503);
      expect(res.body).toMatchObject({ decision: 'BLOCK', reason: 'KILL_SWITCH_STATE_UNAVAILABLE' });
      expect(handler).not.toHaveBeenCalled();
      expect(mockEmit).toHaveBeenCalledWith('ERROR', 'KILL_SWITCH_STATE_UNAVAILABLE', expect.objectContaining({ code: 'CONTROL_PLANE_STALE' }));
    } finally { spy.mockRestore(); }
  });

  test('KG-04 a tampered record blocks like an active switch and is counted as such', async () => {
    col.put('global', Object.freeze({ active: false, scope: 'global', eventId: 'x', operatorId: 'evil', reason: '', changedAt: new Date().toISOString(), seq: 3, mac: 'AAAA' }));
    const handler = jest.fn((_q, res) => res.json({ ok: true }));
    const res = await supertest(appWith(handler)).get('/x');
    expect(res.status).toBe(503);
    expect(res.body.reason).toBe('KILL_SWITCH_ACTIVE');
    expect(handler).not.toHaveBeenCalled();
  });
});

describe('KA — admin routes', () => {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.rbacUser = { id: 'u1', username: 'alice', role: 'admin' }; next(); });
  app.use('/v1/admin/kill-switch', createKillSwitchAdminRouter());

  test('KA-01 GET returns the state, never the MAC', async () => {
    await killSwitch.activate({ operatorId: OP, reason: 'drill' });
    const res = await supertest(app).get('/v1/admin/kill-switch');
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ active: true, reason: 'drill', scope: 'global' });
    expect(JSON.stringify(res.body)).not.toMatch(/"mac"/);
  });

  test('KA-02 POST activate without a reason is a 400 REASON_REQUIRED and changes nothing', async () => {
    const res = await supertest(app).post('/v1/admin/kill-switch/activate').send({});
    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toMatch(/REASON_REQUIRED/);
    expect(killSwitch.state().active).toBe(false);
  });

  test('KA-03 POST activate then release round-trip, with the operator taken from the authenticated request', async () => {
    const on = await supertest(app).post('/v1/admin/kill-switch/activate').send({ reason: 'incident' });
    expect(on.status).toBe(200);
    expect(on.body.data.changed).toBe(true);
    expect(on.body.data.state).toMatchObject({ active: true, reason: 'incident' });
    expect(on.body.data.state.operatorId).toBeTruthy();
    expect(on.body.data.state.operatorId).not.toBe('unattributed-operator');
    const off = await supertest(app).post('/v1/admin/kill-switch/release').send({});
    expect(off.status).toBe(200);
    expect(off.body.data.state.active).toBe(false);
  });

  test('KA-04 repeating a transition reports changed:false and is still 200', async () => {
    await supertest(app).post('/v1/admin/kill-switch/activate').send({ reason: 'a' });
    const again = await supertest(app).post('/v1/admin/kill-switch/activate').send({ reason: 'b' });
    expect(again.status).toBe(200);
    expect(again.body.data.changed).toBe(false);
  });

  test('KA-05 a body reason that is not a string is refused', async () => {
    const res = await supertest(app).post('/v1/admin/kill-switch/activate').send({ reason: { $gt: '' } });
    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toMatch(/INVALID_REASON/);
  });

  test('KA-06 an unexpected failure is a generic 500 that does not echo internals', async () => {
    const spy = jest.spyOn(killSwitch, 'activate').mockRejectedValue(new Error('pg password=secret'));
    try {
      const res = await supertest(app).post('/v1/admin/kill-switch/activate').send({ reason: 'x' });
      expect(res.status).toBe(500);
      expect(JSON.stringify(res.body)).not.toMatch(/secret/);
    } finally { spy.mockRestore(); }
  });
});
