'use strict';

/**
 * custom content-blocking rules.
 *   CR-01  the rule: validation, hash
 *   CR-02  matching: words, phrases, regex, case, normalisation (invisible characters, fullwidth, spaces), distinct items only, weights
 *   CR-03  thresholds: default, per model, per purpose; scope; an unknown model or a missing declaration counts as in scope
 *   CR-04  direction, DETECT vs BLOCK, nothing but ids leaves the stage
 *   CR-05  fail closed on text the pattern engine cannot scan completely
 *   CR-06  on the real /ai/chat route (input, output, per-model threshold, stream)
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const stage = require('../contentStage');
const rule = require('../../../../services/policy/evaluators/contentRule');
const { computePolicyHash } = require('../../../../services/policyHash');

const items = (...xs) => xs.map((x, i) => (typeof x === 'string' ? { id: `i${i}`, kind: 'phrase', value: x } : x));
const mk = (config, id = 'CR', priority = 10) => { const c = { contentFormat: 1, direction: 'input', action: 'BLOCK', ...config }; rule.validate(c); return { id, type: 'CONTENT_RULE', priority, enabled: true, config: rule.preprocess(c) }; };
const ZW = String.fromCharCode(0x200b);

describe('CR-01 the rule', () => {
  test('valid configs pass; every kind of bad config is refused', () => {
    expect(() => rule.validate({ contentFormat: 1, direction: 'both', action: 'DETECT', items: items('x') })).not.toThrow();
    const base = { contentFormat: 1, direction: 'input', action: 'BLOCK', items: items('x') };
    for (const bad of [{ contentFormat: 2 }, { direction: 'x' }, { action: 'REDACT' }, { items: [] }, { items: Array.from({ length: 201 }, (_, i) => ({ id: `i${i}`, kind: 'word', value: 'w' })) },
      { items: [{ id: 'a', kind: 'word', value: 'two words' }] }, { items: [{ id: 'a', kind: 'phrase', value: '' }] }, { items: [{ id: 'a b', kind: 'phrase', value: 'x' }] },
      { items: [{ id: 'a', kind: 'phrase', value: 'x' }, { id: 'a', kind: 'word', value: 'y' }] }, { items: [{ id: 'a', kind: 'glob', value: 'x' }] }, { items: [{ id: 'a', kind: 'regex', value: '(?=x)' }] },
      { items: [{ id: 'a', kind: 'regex', value: '(a+' }] }, { items: [{ id: 'a', kind: 'phrase', value: 'x', weight: 0 }] }, { threshold: 0 }, { threshold: 5 }, { thresholds: [{ threshold: 1 }] },
      { thresholds: [{ models: [], threshold: 1 }] }, { scope: { colours: ['red'] } }, { extra: 1 }])
      expect(() => rule.validate({ ...base, ...bad })).toThrow();
    expect(rule.evaluate()).toEqual({ pass: true });
  });
  test('policyHash covers the items; compiled patterns do not change it', () => {
    const raw = { id: 'R', type: 'CONTENT_RULE', priority: 1, enabled: true, config: { contentFormat: 1, direction: 'input', action: 'BLOCK', items: [{ id: 'a', kind: 'regex', value: 'foo+' }] } };
    expect(computePolicyHash([{ ...raw, config: rule.preprocess(raw.config) }])).toBe(computePolicyHash([raw]));
    expect(computePolicyHash([{ ...raw, config: { ...raw.config, items: [{ id: 'a', kind: 'regex', value: 'fo+' }] } }])).not.toBe(computePolicyHash([raw]));
  });
});

describe('CR-02 matching', () => {
  const run = (cfg, text, dir = 'input') => stage.check([text], [mk(cfg)], dir);
  test('phrase (substring), word (whole word), regex; case-insensitive by default', () => {
    expect(run({ items: items('secret project') }, 'about the SECRET   Project today').blocked).toBe(true);
    expect(run({ items: [{ id: 'w', kind: 'word', value: 'cat' }] }, 'a cat sat').blocked).toBe(true);
    expect(run({ items: [{ id: 'w', kind: 'word', value: 'cat' }] }, 'a category of things, concatenate').blocked).toBe(false);
    expect(run({ items: [{ id: 'w', kind: 'word', value: 'cat' }] }, 'cat').blocked).toBe(true);
    expect(run({ items: [{ id: 'r', kind: 'regex', value: 'proj-[0-9]{4}' }] }, 'see PROJ-1234 now').blocked).toBe(true);
    expect(run({ items: [{ id: 'r', kind: 'regex', value: 'proj-[0-9]{4}' }] }, 'see PROJ-12 now').blocked).toBe(false);
    expect(run({ items: [{ id: 'w', kind: 'word', value: 'Cat', caseInsensitive: false }] }, 'a cat sat').blocked).toBe(false);
  });
  test('normalisation: invisible characters, fullwidth forms, runs of spaces and line breaks do not hide an item', () => {
    const cfg = { items: items('secret project') };
    expect(run(cfg, `sec${ZW}ret proj${ZW}ect`).blocked).toBe(true);
    expect(run(cfg, 'ｓｅｃｒｅｔ ｐｒｏｊｅｃｔ').blocked).toBe(true);
    expect(run(cfg, 'secret\n\n   project').blocked).toBe(true);
    expect(run({ items: [{ id: 'r', kind: 'regex', value: 'ab+c' }] }, `a${ZW}bbbc`).blocked).toBe(true);
  });
  test('distinct items add up with their weights; the same item twice counts once', () => {
    const cfg = { items: [{ id: 'a', kind: 'word', value: 'alpha', weight: 1 }, { id: 'b', kind: 'word', value: 'beta', weight: 2 }, { id: 'c', kind: 'word', value: 'gamma', weight: 1 }], threshold: 3 };
    expect(run(cfg, 'alpha alpha alpha').blocked).toBe(false);
    expect(run(cfg, 'alpha beta').blocked).toBe(true);
    expect(run(cfg, 'beta gamma').blocked).toBe(true);
    expect(run(cfg, 'beta').blocked).toBe(false);
  });
  test('texts of a conversation are searched together (an item in any message counts)', () => {
    const r = stage.check(['hello', 'my secret project', 'bye'], [mk({ items: items('secret project') })], 'input');
    expect(r.blocked).toBe(true);
  });
});

describe('CR-03 thresholds and scope', () => {
  const cfg = { items: [{ id: 'a', kind: 'word', value: 'alpha' }, { id: 'b', kind: 'word', value: 'beta' }, { id: 'c', kind: 'word', value: 'gamma' }], threshold: 2,
    thresholds: [{ models: ['strict-model'], threshold: 1 }, { purposes: ['legal'], threshold: 3 }] };
  const p = [mk(cfg)];
  test('default, per model and per purpose (the first matching entry wins)', () => {
    expect(stage.check(['alpha'], p, 'input', { model: 'other' }).blocked).toBe(false);
    expect(stage.check(['alpha beta'], p, 'input', { model: 'other' }).blocked).toBe(true);
    expect(stage.check(['alpha'], p, 'input', { model: 'strict-model' }).blocked).toBe(true);
    expect(stage.check(['alpha beta'], p, 'input', { model: 'other', purpose: 'legal' }).blocked).toBe(false);
    expect(stage.check(['alpha beta gamma'], p, 'input', { model: 'other', purpose: 'legal' }).blocked).toBe(true);
    expect(stage.check(['alpha'], p, 'input', { model: 'strict-model', purpose: 'legal' }).blocked).toBe(true);        // the model entry comes first
  });
  test('scope: applies only to the listed models/purposes; an unknown model or a missing declaration counts as in scope', () => {
    const s = [mk({ items: items('forbidden'), scope: { models: ['m1'], purposes: ['support'] } })];
    expect(stage.check(['forbidden'], s, 'input', { model: 'm2', purpose: 'support' }).blocked).toBe(false);
    expect(stage.check(['forbidden'], s, 'input', { model: 'm1', purpose: 'billing' }).blocked).toBe(false);
    expect(stage.check(['forbidden'], s, 'input', { model: 'm1', purpose: 'support' }).blocked).toBe(true);
    expect(stage.check(['forbidden'], s, 'input', { purpose: 'support' }).blocked).toBe(true);
    expect(stage.check(['forbidden'], s, 'input', { model: 'm1' }).blocked).toBe(true);
  });
});

describe('CR-04 direction, action, no text leaves', () => {
  test('direction both/input/output', () => {
    const i = [mk({ direction: 'input', items: items('bad') })]; const o = [mk({ direction: 'output', items: items('bad') })]; const b = [mk({ direction: 'both', items: items('bad') })];
    expect(stage.check(['bad'], i, 'output').blocked).toBe(false); expect(stage.check(['bad'], o, 'output').blocked).toBe(true); expect(stage.check(['bad'], b, 'input').blocked).toBe(true); expect(stage.check(['bad'], b, 'output').blocked).toBe(true);
  });
  test('DETECT reports and does not block; a disabled rule is ignored; priority order decides which BLOCK is reported', () => {
    const r = stage.check(['bad'], [mk({ action: 'DETECT', items: items('bad') })], 'input');
    expect(r).toMatchObject({ blocked: false }); expect(r.hits[0]).toMatchObject({ ruleId: 'CR', action: 'DETECT', items: ['i0'] });
    expect(stage.check(['bad'], [{ ...mk({ items: items('bad') }), enabled: false }], 'input').blocked).toBe(false);
    const two = [mk({ items: items('bad') }, 'Z', 20), mk({ items: items('bad') }, 'A', 10)];
    expect(stage.check(['bad'], two, 'input').hits[0].ruleId).toBe('A');
  });
  test('only ids, score and threshold leave the stage - never the matched text', () => {
    const r = stage.check(['my SECRET project here'], [mk({ items: items('secret project') })], 'input');
    expect(JSON.stringify(r)).not.toMatch(/secret project/i); expect(r.hits[0]).toEqual({ ruleId: 'CR', action: 'BLOCK', items: ['i0'], score: 1, threshold: 1 });
  });
});

describe('CR-05 fail closed', () => {
  test('text the pattern engine cannot scan completely: BLOCK rule refuses, DETECT rule is skipped', () => {
    const big = 'a'.repeat(300_000);
    expect(stage.check([big], [mk({ items: [{ id: 'r', kind: 'regex', value: 'zzz' }] })], 'input')).toMatchObject({ blocked: true, reason: 'CONTENT_RULE_UNAVAILABLE' });
    expect(stage.check([big], [mk({ action: 'DETECT', items: [{ id: 'r', kind: 'regex', value: 'zzz' }] })], 'input')).toMatchObject({ blocked: false });
    expect(stage.check([big], [mk({ items: items('zzz') })], 'input').blocked).toBe(false);                      // a phrase has no such bound
  });
});
