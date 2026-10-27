'use strict';

/** (D7 = B) — optional admin auth: anonymous passes through, a credential must pass the full stack. */

const express = require('express');
const request = require('supertest');
const { createOptionalAuth } = require('../optionalAuth');

function app(layers) {
  const a = express();
  a.post('/v', createOptionalAuth(layers), (req, res) => res.json({ user: req.rbacUser ? req.rbacUser.id : null }));
  return a;
}
const setUser = (req, _res, next) => { req.rbacUser = { id: 'u1' }; next(); };
const deny = (code) => (_req, res) => res.status(code).json({ denied: code });

test('no credential → anonymous, stack not run', async () => {
  const spy = jest.fn((_q, _s, n) => n());
  const r = await request(app([spy])).post('/v');
  expect(r.status).toBe(200); expect(r.body.user).toBeNull(); expect(spy).not.toHaveBeenCalled();
});

test('empty header values count as no credential', async () => {
  const spy = jest.fn((_q, _s, n) => n());
  const r = await request(app([spy])).post('/v').set('x-ops-token', '');
  expect(r.status).toBe(200); expect(spy).not.toHaveBeenCalled();
});

test('Authorization presented → layers run in order and set the identity', async () => {
  const order = [];
  const l = (n) => (_q, _s, next) => { order.push(n); next(); };
  const r = await request(app([l(1), l(2), setUser])).post('/v').set('Authorization', 'Bearer ok_x');
  expect(r.body.user).toBe('u1'); expect(order).toEqual([1, 2]);
});

test.each([401, 403, 429])('a presented-but-rejected credential is refused (%i), never downgraded', async (code) => {
  const r = await request(app([deny(code), setUser])).post('/v').set('x-ops-token', 'bad');
  expect(r.status).toBe(code); expect(r.body.denied).toBe(code);
});

test('an async layer rejection reaches the error handler', async () => {
  const a = express();
  a.post('/v', createOptionalAuth([async () => { throw new Error('boom'); }]), (_q, res) => res.json({ ok: true }));
  a.use((err, _q, res, _n) => res.status(500).json({ err: err.message })); // eslint-disable-line no-unused-vars
  const r = await request(a).post('/v').set('Authorization', 'Bearer x');
  expect(r.status).toBe(500);
});

test('rejects a non-array layer list at construction', () => {
  expect(() => createOptionalAuth(null)).toThrow(TypeError);
  expect(() => createOptionalAuth([1])).toThrow(TypeError);
});
