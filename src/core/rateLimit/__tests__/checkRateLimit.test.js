'use strict';

/**
 * the limiter core as used in-handler (checkRateLimit):
 *   - RL_ENABLED=false → always allowed (the only off switch);
 *   - failMode 'closed' + Redis unavailable → refused (security buckets);
 *   - failMode 'degrade' + Redis unavailable → per-process fallback that still
 *     limits, with the degraded gauge raised and a CRITICAL event;
 *   - an injected evaluator (Redis up) decides normally.
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn(), eventBus: { emit: jest.fn(), on: jest.fn(), setMaxListeners: jest.fn() } }));

const { emit } = require('../../../../services/logger');
const rl = require('..');
const { MemoryStorage } = require('../storage');

let saved;
beforeEach(() => { saved = process.env.RL_ENABLED; process.env.RL_ENABLED = 'true'; rl._resetDegradedForTest(); emit.mockClear(); });
afterEach(() => { process.env.RL_ENABLED = saved; rl.loadConfig(); rl._resetDegradedForTest(); });

const ctx = (id = 'signingkey:k1') => ({ identity: id, reqId: 'r', path: '/ai/chat', method: 'POST' });

test('RL_ENABLED=false → allowed without touching storage', async () => {
  process.env.RL_ENABLED = 'false';
  const evalFn = jest.fn();
  expect((await rl.checkRateLimit('sign', ctx(), { _evalFn: evalFn })).allowed).toBe(true);
  expect(evalFn).not.toHaveBeenCalled();
});

test('closed surface + Redis unavailable → refused', async () => {
  rl.loadConfig({ surfaces: { certification_evaluate: { maxRequests: 5, windowSeconds: 60, failMode: 'closed' } } });
  const v = await rl.checkRateLimit('certification_evaluate', ctx());
  expect(v.allowed).toBe(false);
  expect(rl._isDegraded('certification_evaluate')).toBe(false);
});

test('degrade surface + Redis unavailable → in-process limiting, gauge + CRITICAL event', async () => {
  rl.loadConfig({ surfaces: { ai_chat_identity: { maxRequests: 3, windowSeconds: 60, failMode: 'degrade' } } });
  const out = [];
  for (let i = 0; i < 5; i++) out.push((await rl.checkRateLimit('ai_chat_identity', ctx())).allowed);
  expect(out).toEqual([true, true, true, false, false]);
  expect(rl._isDegraded('ai_chat_identity')).toBe(true);
  expect(emit.mock.calls.some((c) => c[0] === 'CRITICAL' && c[1] === 'RATE_LIMIT_DEGRADED')).toBe(true);
});

test('identities are limited independently', async () => {
  rl.loadConfig({ surfaces: { ai_chat_identity: { maxRequests: 1, windowSeconds: 60, failMode: 'degrade' } } });
  expect((await rl.checkRateLimit('ai_chat_identity', ctx('signingkey:a'))).allowed).toBe(true);
  expect((await rl.checkRateLimit('ai_chat_identity', ctx('signingkey:a'))).allowed).toBe(false);
  expect((await rl.checkRateLimit('ai_chat_identity', ctx('signingkey:b'))).allowed).toBe(true);
});

test('a working evaluator (Redis up) decides normally and reports Retry-After when limited', async () => {
  rl.loadConfig({ surfaces: { sign: { maxRequests: 2, windowSeconds: 60 } } });
  const mem = new MemoryStorage();
  const evalFn = (...a) => mem.eval(...a);
  const r = [];
  for (let i = 0; i < 3; i++) r.push(await rl.checkRateLimit('sign', ctx(), { _evalFn: evalFn }));
  expect(r.map((x) => x.allowed)).toEqual([true, true, false]);
  expect(r[2].retryAfterSeconds).toBeGreaterThan(0);
  expect(rl._isDegraded('sign')).toBe(false);
});

test('an unknown surface throws (no silent no-op)', async () => {
  await expect(rl.checkRateLimit('no_such_surface', ctx())).rejects.toThrow();
});
