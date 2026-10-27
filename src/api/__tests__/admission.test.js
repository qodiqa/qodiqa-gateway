'use strict';

/**
 * admission control unit contract (src/api/admission.js).
 *
 *   AD-01  under the limit: admitted immediately, slot held until 'finish'
 *   AD-02  at the limit: queued FIFO; a released slot admits the OLDEST waiter
 *   AD-03  queue full: 503 SERVER_OVERLOADED + Retry-After, counted as queue_full, next() never called
 *   AD-04  queue wait expires: 503 + counted as queue_timeout, the waiter never runs
 *   AD-05  a slot is released exactly once even when both 'finish' and 'close' fire
 *   AD-06  a queued client that disconnects leaves the queue (never admitted, never counted as a refusal)
 *   AD-07  saturated() is true exactly while the queue is full (drives GET /ready)
 *   AD-08  defaults: /ai/chat 16 in flight + 32 queued, /sign 64 + 128, 1,000 ms wait, Retry-After 1
 *   AD-09  audit mirror backlog engaged: 503 SERVER_OVERLOADED, cause audit_backlog, next() never called, no slot held
 * AD-10 every family has defaults and its own environment prefix; an unknown family is refused
 * AD-11 the limiter is the FIRST layer of /verify, /v1/actions and /v1/tools (before authentication and any work); the boot rule knows every family's variables
 * AD-12 one family at its limit does not refuse another (a stalled tool call cannot starve /verify or /sign)
 */

jest.mock('../../../services/logger', () => ({ emit: jest.fn() }));
const { EventEmitter } = require('events');
const { createAdmission, configFor } = require('../admission');

function reqRes() {
  const req = new EventEmitter(); req.requestId = 'r';
  const res = new EventEmitter();
  res.headers = {}; res.headersSent = false; res.statusCode = 200; res.body = null;
  res.set = (k, v) => { res.headers[k] = v; return res; };
  res.status = (c) => { res.statusCode = c; return res; };
  res.json = (b) => { res.body = b; res.headersSent = true; return res; };
  return { req, res };
}
const CFG = { maxInFlight: 2, maxQueue: 2, queueTimeoutMs: 50, retryAfterSec: 1 };
// The audit-backlog probe is injected so these unit tests never load the audit chain.
const mk = (route, cfg, backlog = () => false) => createAdmission(route, cfg, { auditBacklog: backlog });

describe('admission control', () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  test('AD-01 under the limit: admitted immediately and held until finish', () => {
    const a = mk('t', CFG);
    const { req, res } = reqRes(); const next = jest.fn();
    a.middleware(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(a.stats().inFlight).toBe(1);
    res.emit('finish');
    expect(a.stats().inFlight).toBe(0);
  });

  test('AD-02 at the limit: FIFO queue, a released slot admits the oldest waiter', () => {
    const a = mk('t', CFG);
    const r = [reqRes(), reqRes(), reqRes(), reqRes()]; const order = [];
    r.forEach((x, i) => a.middleware(x.req, x.res, () => order.push(i)));
    expect(order).toEqual([0, 1]);
    expect(a.stats()).toMatchObject({ inFlight: 2, queued: 2 });
    r[1].res.emit('finish');
    expect(order).toEqual([0, 1, 2]);
    r[0].res.emit('finish');
    expect(order).toEqual([0, 1, 2, 3]);
    expect(a.stats()).toMatchObject({ inFlight: 2, queued: 0 });
  });

  test('AD-03 queue full: 503 SERVER_OVERLOADED with Retry-After, never next()', () => {
    const a = mk('t', CFG);
    for (let i = 0; i < 4; i++) { const x = reqRes(); a.middleware(x.req, x.res, () => {}); }
    const { req, res } = reqRes(); const next = jest.fn();
    a.middleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(503);
    expect(res.headers['Retry-After']).toBe('1');
    expect(res.body).toEqual({ decision: 'BLOCK', reason: 'SERVER_OVERLOADED', details: {}, requestId: 'r' });
    expect(a.stats().rejected).toEqual({ queue_full: 1, queue_timeout: 0, audit_backlog: 0 });
  });

  test('AD-04 wait expires: 503 queue_timeout, the waiter never runs', () => {
    const a = mk('t', CFG);
    for (let i = 0; i < 2; i++) { const x = reqRes(); a.middleware(x.req, x.res, () => {}); }
    const { req, res } = reqRes(); const next = jest.fn();
    a.middleware(req, res, next);
    jest.advanceTimersByTime(51);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(503);
    expect(a.stats()).toMatchObject({ queued: 0, rejected: { queue_full: 0, queue_timeout: 1, audit_backlog: 0 } });
  });

  test('AD-05 a slot is released exactly once', () => {
    const a = mk('t', CFG);
    const x = reqRes(); a.middleware(x.req, x.res, () => {});
    x.res.emit('finish'); x.res.emit('close');
    expect(a.stats().inFlight).toBe(0);
  });

  test('AD-06 a queued client that disconnects leaves the queue and is not a refusal', () => {
    const a = mk('t', CFG);
    const held = [reqRes(), reqRes()]; held.forEach((x) => a.middleware(x.req, x.res, () => {}));
    const w = reqRes(); const next = jest.fn();
    a.middleware(w.req, w.res, next);
    // the disconnect signal is the RESPONSE's 'close' (req 'close' also fires when the body has merely been read)
    w.req.emit('close');
    expect(a.stats().queued).toBe(1);
    w.res.emit('close');
    expect(a.stats().queued).toBe(0);
    held[0].res.emit('finish');
    expect(next).not.toHaveBeenCalled();
    expect(a.stats().rejected).toEqual({ queue_full: 0, queue_timeout: 0, audit_backlog: 0 });
  });

  test('AD-07 saturated() exactly while the queue is full', () => {
    const a = mk('t', CFG);
    const xs = [];
    for (let i = 0; i < 4; i++) { const x = reqRes(); xs.push(x); a.middleware(x.req, x.res, () => {}); expect([i, a.saturated()]).toEqual([i, i === 3]); }
    xs[0].res.emit('finish');
    expect(a.saturated()).toBe(false);
  });

  test('AD-08 defaults', () => {
    const saved = { ...process.env };
    for (const k of Object.keys(process.env)) if (k.startsWith('QODIQA_ADMISSION_')) delete process.env[k];
    try {
      expect(configFor('ai_chat')).toEqual({ maxInFlight: 16, maxQueue: 32, queueTimeoutMs: 1000, retryAfterSec: 1 });
      expect(configFor('sign')).toEqual({ maxInFlight: 64, maxQueue: 128, queueTimeoutMs: 1000, retryAfterSec: 1 });
    } finally { Object.assign(process.env, saved); }
  });

  test('AD-09 audit mirror backlog engaged: refused up front with cause audit_backlog, admitted again once released', () => {
    let engaged = true;
    const a = mk('t', CFG, () => engaged);
    const x = reqRes(); const next = jest.fn();
    a.middleware(x.req, x.res, next);
    expect(next).not.toHaveBeenCalled();
    expect(x.res.statusCode).toBe(503);
    expect(x.res.body).toMatchObject({ decision: 'BLOCK', reason: 'SERVER_OVERLOADED' });
    expect(x.res.headers['Retry-After']).toBe('1');
    expect(a.stats()).toMatchObject({ inFlight: 0, queued: 0, rejected: { queue_full: 0, queue_timeout: 0, audit_backlog: 1 } });
    engaged = false;
    const y = reqRes(); const next2 = jest.fn();
    a.middleware(y.req, y.res, next2);
    expect(next2).toHaveBeenCalledTimes(1);
    expect(a.stats().inFlight).toBe(1);
  });
  test('AD-10 families: defaults and environment prefixes', () => {
    const { FAMILIES } = require('../admission');
    expect(Object.keys(FAMILIES).sort()).toEqual(['actions', 'ai_chat', 'sign', 'tools', 'verify']);
    const saved = { ...process.env };
    for (const k of Object.keys(process.env)) if (k.startsWith('QODIQA_ADMISSION_')) delete process.env[k];
    try {
      expect(configFor('verify')).toEqual({ maxInFlight: 64, maxQueue: 128, queueTimeoutMs: 1000, retryAfterSec: 1 });
      expect(configFor('actions')).toEqual({ maxInFlight: 64, maxQueue: 128, queueTimeoutMs: 1000, retryAfterSec: 1 });
      expect(configFor('tools')).toEqual({ maxInFlight: 16, maxQueue: 32, queueTimeoutMs: 1000, retryAfterSec: 1 });
      process.env.QODIQA_ADMISSION_TOOLS_MAX_INFLIGHT = '3'; process.env.QODIQA_ADMISSION_TOOLS_QUEUE = '0'; process.env.QODIQA_ADMISSION_TOOLS_QUEUE_TIMEOUT_MS = '250';
      expect(configFor('tools')).toMatchObject({ maxInFlight: 3, maxQueue: 0, queueTimeoutMs: 250 });
      expect(configFor('verify').maxInFlight).toBe(64);        // another family is not affected
      expect(() => configFor('nope')).toThrow(/unknown admission route family/);
    } finally { for (const k of Object.keys(process.env)) if (k.startsWith('QODIQA_ADMISSION_')) delete process.env[k]; Object.assign(process.env, saved); }
  });

  test('AD-11 wiring: first layer of the three new surfaces; the boot rule validates every family', () => {
    const fs = require('fs'); const path = require('path');
    const src = (f) => fs.readFileSync(path.join(__dirname, '..', 'routes', f), 'utf8');
    for (const [file, family] of [['actions.js', 'actions'], ['tools.js', 'tools']]) {
      const t = src(file);
      const iAdm = t.indexOf(`admission').get('${family}').middleware`);
      expect({ file, present: iAdm > 0 }).toEqual({ file, present: true });
      expect({ file, beforeAuth: iAdm < t.indexOf('createSignAuthMiddleware({') }).toEqual({ file, beforeAuth: true });
    }
    const v = src('verify.js');
    expect(v.indexOf("admission').get('verify').middleware")).toBeGreaterThan(0);
    expect(v.indexOf("admission').get('verify').middleware")).toBeLessThan(v.indexOf("router.post('/v2'"));
    const { validateBoot } = require('../../infra/config/bootValidator');
    for (const f of ['VERIFY', 'ACTIONS', 'TOOLS']) for (const suffix of ['MAX_INFLIGHT', 'QUEUE', 'QUEUE_TIMEOUT_MS']) {
      const n = `QODIQA_ADMISSION_${f}_${suffix}`;
      expect({ n, fatal: validateBoot({ NODE_ENV: 'development', [n]: 'abc' }).fatal.some((x) => x.variable === n) }).toEqual({ n, fatal: true });
      expect({ n, fatal: validateBoot({ NODE_ENV: 'development', [n]: '5' }).fatal.some((x) => x.variable === n) }).toEqual({ n, fatal: false });
    }
  });

  test('AD-12 families are independent: a saturated tools limiter leaves verify and sign open', () => {
    const tools = mk('tools', { maxInFlight: 1, maxQueue: 0, queueTimeoutMs: 50, retryAfterSec: 1 });
    const verify = mk('verify', { maxInFlight: 1, maxQueue: 0, queueTimeoutMs: 50, retryAfterSec: 1 });
    const a = reqRes(); const b = reqRes(); const c = reqRes();
    let ran = 0; const next = () => { ran += 1; };
    tools.middleware(a.req, a.res, next);          // takes the only tools slot
    tools.middleware(b.req, b.res, next);          // refused
    expect(b.res.statusCode).toBe(503);
    verify.middleware(c.req, c.res, next);         // unaffected
    expect(c.res.statusCode).toBe(200);
    expect(ran).toBe(2);
  });
});
