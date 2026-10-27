'use strict';

/**
 * the ABAC rule type.
 *   AB-01  the condition language: every operator, every refusal at load time, the bounds
 *   AB-02  missing attributes: DENY does not fire, REQUIRE refuses (fail closed)
 *   AB-03  the rule through the real loader and engine; policyHash covers it; derived fields do not change the hash
 *   AB-04  the ready-made rules (templates) load and decide as documented
 *   AB-05  supplied attributes are catalogued, typed and bounded
 */

const cond = require('../condition');
const attrs = require('../attributes');
const abac = require('../../evaluators/abac');
const T = require('../templates');
const { validateAndPrepare } = require('../../loader');
const { evaluate } = require('../../engine');
const { computePolicyHash } = require('../../../policyHash');

const NOW = Math.floor(Date.UTC(2026, 9, 22, 14, 30) / 1000);            // Thursday 14:30 UTC
const ctx = (over = {}, attributes) => ({ artifact: { valid: true }, userId: 'default:key_v1', callerId: 'caller-1', action: 'openai', tenantId: 'default', requestId: '11111111-1111-4111-8111-111111111111', ip: '203.0.113.9', timestamp: NOW, ...(attributes ? { attributes: attrs.sanitizeSupplied(attributes) } : {}), ...over });
const run = (node, c) => cond.evaluate(cond.prepare(node), c);
const bad = (node) => { try { cond.validate(node); return null; } catch (e) { return e.message; } };

describe('AB-01 condition language', () => {
  test('every operator', () => {
    const c = ctx({}, { 'request.model': 'gpt-4o-mini', 'request.promptChars': 500, 'request.stream': true, 'resource.categories': ['EMAIL', 'CARD'], 'request.purpose': 'support' });
    const t = (n) => expect(run(n, c)).toBe(true); const f = (n) => expect(run(n, c)).toBe(false);
    t({ attr: 'request.model', op: 'eq', value: 'gpt-4o-mini' }); f({ attr: 'request.model', op: 'ne', value: 'gpt-4o-mini' });
    t({ attr: 'request.model', op: 'in', value: ['a', 'gpt-4o-mini'] }); t({ attr: 'request.model', op: 'notIn', value: ['a', 'b'] });
    t({ attr: 'request.promptChars', op: 'lt', value: 501 }); t({ attr: 'request.promptChars', op: 'lte', value: 500 }); f({ attr: 'request.promptChars', op: 'gt', value: 500 }); t({ attr: 'request.promptChars', op: 'gte', value: 500 });
    t({ attr: 'request.promptChars', op: 'between', value: [100, 500] }); f({ attr: 'request.promptChars', op: 'between', value: [501, 900] });
    t({ attr: 'request.model', op: 'startsWith', value: 'gpt' }); t({ attr: 'request.model', op: 'endsWith', value: 'mini' }); t({ attr: 'request.model', op: 'contains', value: '4o' });
    t({ attr: 'resource.categories', op: 'contains', value: 'CARD' }); t({ attr: 'resource.categories', op: 'hasAny', value: ['IBAN', 'CARD'] }); f({ attr: 'resource.categories', op: 'hasAll', value: ['CARD', 'IBAN'] }); t({ attr: 'resource.categories', op: 'hasAll', value: ['CARD', 'EMAIL'] });
    t({ attr: 'request.stream', op: 'eq', value: true }); t({ attr: 'request.purpose', op: 'exists' }); f({ attr: 'request.purpose', op: 'notExists' });
    t({ attr: 'env.ip', op: 'cidr', value: ['198.51.100.0/24', '203.0.113.0/24'] }); f({ attr: 'env.ip', op: 'cidr', value: ['10.0.0.0/8'] });
    t({ attr: 'env.hour', op: 'between', value: [9, 17] }); t({ attr: 'env.dow', op: 'eq', value: 4 });
    t({ attr: 'subject.userId', op: 'startsWith', value: 'default:' }); t({ attr: 'tenant.id', op: 'eq', value: 'default' }); t({ attr: 'request.provider', op: 'eq', value: 'openai' });
  });
  test('combinators', () => {
    const c = ctx({}, { 'request.model': 'm1' });
    const a = { attr: 'request.model', op: 'eq', value: 'm1' }; const b = { attr: 'request.model', op: 'eq', value: 'm2' };
    expect(run({ all: [a, a] }, c)).toBe(true); expect(run({ all: [a, b] }, c)).toBe(false); expect(run({ any: [b, a] }, c)).toBe(true); expect(run({ any: [b, b] }, c)).toBe(false);
    expect(run({ not: b }, c)).toBe(true); expect(run({ not: { all: [a, { not: b }] } }, c)).toBe(false);
  });
  test('IPv6 CIDR; an IPv4 attribute never matches an IPv6 range', () => {
    expect(run({ attr: 'env.ip', op: 'cidr', value: ['2001:db8::/32'] }, ctx({ ip: '2001:db8::1' }))).toBe(true);
    expect(run({ attr: 'env.ip', op: 'cidr', value: ['2001:db8::/32'] }, ctx({ ip: '203.0.113.9' }))).toBe(false);
  });
  test('refused when the policy is loaded', () => {
    expect(bad({ attr: 'request.nope', op: 'eq', value: 'x' })).toMatch(/unknown attribute/);
    expect(bad({ attr: 'request.model', op: 'matches', value: '.*' })).toMatch(/unknown operator/);
    expect(bad({ attr: 'request.model', op: 'gt', value: 3 })).toMatch(/number attribute/);
    expect(bad({ attr: 'request.promptChars', op: 'eq', value: '5' })).toMatch(/must be number/);
    expect(bad({ attr: 'request.promptChars', op: 'between', value: [9, 1] })).toMatch(/between/);
    expect(bad({ attr: 'request.model', op: 'in', value: [] })).toMatch(/non-empty array/);
    expect(bad({ attr: 'request.model', op: 'in', value: [1] })).toMatch(/must be string/);
    expect(bad({ attr: 'resource.categories', op: 'in', value: ['A'] })).toMatch(/hasAny/);
    expect(bad({ attr: 'resource.categories', op: 'eq', value: 'A' })).toMatch(/string\[\]/);
    expect(bad({ attr: 'env.ip', op: 'cidr', value: ['not-a-cidr'] })).toMatch(/cidr/);
    expect(bad({ attr: 'request.model', op: 'exists', value: 1 })).toMatch(/no value/);
    expect(bad({ attr: 'request.model', op: 'eq' })).toMatch(/needs a value/);
    expect(bad({ all: [] })).toMatch(/non-empty/);
    expect(bad({ all: [{ attr: 'request.model', op: 'exists' }], any: [] })).toMatch(/stands alone/);
    expect(bad({ attr: 'request.model', op: 'exists', extra: 1 })).toMatch(/unknown key/);
    expect(bad('x')).toMatch(/object/);
    expect(bad({ attr: 'request.model', op: 'eq', value: 'x'.repeat(300) })).toMatch(/must be string/);
  });
  test('bounds: depth, node count, __proto__ keys', () => {
    let deep = { attr: 'request.model', op: 'exists' }; for (let i = 0; i < 7; i++) deep = { not: deep };
    expect(bad(deep)).toMatch(/deeper than/);
    expect(bad({ all: Array.from({ length: 101 }, () => ({ attr: 'request.model', op: 'exists' })) })).toMatch(/nodes|non-empty array/);
    expect(bad(JSON.parse('{"attr":"request.model","op":"exists","__proto__":{"x":1}}'))).toMatch(/unknown key/);
  });
});

describe('AB-02 missing attributes', () => {
  const rule = (effect) => abac.preprocess({ abacFormat: 1, effect, reason: 'X', when: { attr: 'request.purpose', op: 'eq', value: 'support' } });
  test('DENY does not fire on a missing attribute; REQUIRE refuses', () => {
    expect(abac.evaluate(ctx(), rule('DENY'))).toEqual({ pass: true });
    expect(abac.evaluate(ctx(), rule('REQUIRE'))).toEqual({ pass: false, reason: 'ABAC_X' });
    expect(abac.evaluate(ctx({}, { 'request.purpose': 'support' }), rule('DENY'))).toEqual({ pass: false, reason: 'ABAC_X' });
    expect(abac.evaluate(ctx({}, { 'request.purpose': 'support' }), rule('REQUIRE'))).toEqual({ pass: true });
  });
  test('ne / notIn / notExists are true for an absent attribute (their plain meaning)', () => {
    expect(run({ attr: 'request.model', op: 'ne', value: 'x' }, ctx())).toBe(true);
    expect(run({ attr: 'request.model', op: 'notIn', value: ['x'] }, ctx())).toBe(true);
    expect(run({ attr: 'request.model', op: 'notExists' }, ctx())).toBe(true);
    expect(run({ attr: 'request.model', op: 'eq', value: 'x' }, ctx())).toBe(false);
  });
});

describe('AB-03 through the loader and the engine', () => {
  const consent = { id: 'C', type: 'REQUIRE_CONSENT', priority: 100, enabled: true, config: { requireValidArtifact: true } };
  const load = (...rules) => validateAndPrepare({ policies: [consent, ...rules] }).filter((p) => p.type !== 'REQUIRE_CONSENT');
  test('refused at load: bad format, effect, label, appliesTo, unknown key, bad condition', () => {
    const base = { abacFormat: 1, effect: 'DENY', reason: 'X', when: { attr: 'request.model', op: 'exists' } };
    for (const b of [{ abacFormat: 2 }, { effect: 'ALLOW' }, { reason: 'lower' }, { reason: '' }, { reason: 'X'.repeat(33) }, { appliesTo: 'both' }, { extra: 1 }, { when: { attr: 'x', op: 'eq', value: 1 } }])
      expect(() => abac.validate({ ...base, ...b })).toThrow();
    expect(() => load({ id: 'A', type: 'ABAC', priority: 1, enabled: true, config: { ...base, effect: 'NOPE' } })).toThrow();
  });
  test('first refusal in priority order decides; the reason is ABAC_<label>', async () => {
    const set = load(T.operationalDeny(['maintenance'], { priority: 1 }), T.modelAllowList(['gpt-4o-mini'], { priority: 2 }), T.purposeRequired(['support'], { priority: 3 }));
    const ok = await evaluate(ctx({}, { 'request.model': 'gpt-4o-mini', 'request.purpose': 'support' }), set);
    expect(ok.decision).toBe('EXECUTE');
    const wrongModel = await evaluate(ctx({}, { 'request.model': 'big', 'request.purpose': 'support' }), set);
    expect(wrongModel).toMatchObject({ decision: 'BLOCK', reason: 'ABAC_MODEL_NOT_ALLOWED', policyId: 'ABAC_MODEL_ALLOW' });
    const noPurpose = await evaluate(ctx({}, { 'request.model': 'gpt-4o-mini' }), set);
    expect(noPurpose).toMatchObject({ decision: 'BLOCK', reason: 'ABAC_PURPOSE_NOT_DECLARED' });
  });
  test('operational context: ops mode from the process', async () => {
    const set = load(T.operationalDeny(['maintenance', 'incident']));
    process.env.QODIQA_OPS_MODE = 'maintenance';
    try { expect(await evaluate(ctx(), set)).toMatchObject({ decision: 'BLOCK', reason: 'ABAC_OPERATIONAL_MODE' }); } finally { delete process.env.QODIQA_OPS_MODE; }
    expect((await evaluate(ctx(), set)).decision).toBe('EXECUTE');
    process.env.QODIQA_OPS_MODE = 'bogus'; try { expect(attrs.opsMode()).toBe('normal'); } finally { delete process.env.QODIQA_OPS_MODE; }
  });
  test('policyHash covers the condition; the prepared (derived) fields do not change it', () => {
    const r = T.userDenyList(['a:key_v1']);
    const live = { ...r, config: abac.preprocess(r.config) };
    expect(computePolicyHash([live])).toBe(computePolicyHash([r]));
    expect(computePolicyHash([T.userDenyList(['b:key_v1'])])).not.toBe(computePolicyHash([r]));
    expect(computePolicyHash([{ ...r, config: { ...r.config, effect: 'REQUIRE' } }])).not.toBe(computePolicyHash([r]));
  });
  test('tool-scope rules do not apply to /ai/chat', async () => {
    const set = load(T.toolClassDeny(['command']));
    expect((await evaluate(ctx(), set)).decision).toBe('EXECUTE');
  });
});

describe('AB-04 ready-made rules', () => {
  const live = (r) => ({ ...r, config: abac.preprocess(r.config) });
  test('every template validates', () => {
    for (const r of [T.userAllowList(['k']), T.userDenyList(['k']), T.modelAllowList(['m']), T.modelDenyList(['m']), T.purposeRequired(['p']), T.dataRegionAllow(['eu']), T.dataClassLimit('INTERNAL'),
      T.dataClassLimit('CONFIDENTIAL', { providers: ['openai'] }), T.dataCategoryDeny(['CARD']), T.toolAllowList([{ server: 's', name: 'n' }]), T.toolClassDeny(['command']), T.operationalDeny(['incident'])])
      expect(() => abac.validate(r.config)).not.toThrow();
    expect(() => T.dataClassLimit('RESTRICTED')).toThrow();
  });
  test('data classification limit, optionally toward some providers only', () => {
    const all = live(T.dataClassLimit('INTERNAL')); const some = live(T.dataClassLimit('INTERNAL', { providers: ['openai'] }));
    const c = (provider, level) => ctx({ action: provider }, { 'resource.classification': level });
    expect(abac.evaluate(c('openai', 'CONFIDENTIAL'), all.config).pass).toBe(false); expect(abac.evaluate(c('openai', 'INTERNAL'), all.config).pass).toBe(true);
    expect(abac.evaluate(c('openai', 'RESTRICTED'), some.config).pass).toBe(false); expect(abac.evaluate(c('local', 'RESTRICTED'), some.config).pass).toBe(true);
    expect(abac.evaluate(ctx(), all.config).pass).toBe(true);                                   // classification unknown: a DENY rule does not fire (use a REQUIRE rule to demand it)
  });
  test('data category deny and data region allow', () => {
    expect(abac.evaluate(ctx({}, { 'resource.categories': ['CARD'] }), live(T.dataCategoryDeny(['CARD', 'IBAN'])).config).pass).toBe(false);
    expect(abac.evaluate(ctx({}, { 'resource.categories': ['EMAIL'] }), live(T.dataCategoryDeny(['CARD', 'IBAN'])).config).pass).toBe(true);
    expect(abac.evaluate(ctx({}, { 'request.dataRegion': 'eu' }), live(T.dataRegionAllow(['eu'])).config).pass).toBe(true);
    expect(abac.evaluate(ctx({}, { 'request.dataRegion': 'us' }), live(T.dataRegionAllow(['eu'])).config).pass).toBe(false);
    expect(abac.evaluate(ctx(), live(T.dataRegionAllow(['eu'])).config).pass).toBe(false);      // not declared: refused
  });
  test('tool scope: allow-list and class deny through evaluateTool', () => {
    const set = [live(T.toolAllowList([{ server: 'files', name: 'read_file' }])), live(T.toolClassDeny(['command']))];
    const tool = (server, name, cls) => ctx({ action: null }, { 'tool.server': server, 'tool.name': name, 'tool.class': cls, 'tool.reversible': true, 'agent.id': 'a1' });
    expect(abac.evaluateTool(set, tool('files', 'read_file', 'file')).pass).toBe(true);
    expect(abac.evaluateTool(set, tool('files', 'delete_file', 'file'))).toMatchObject({ pass: false, reason: 'ABAC_TOOL_NOT_ALLOWED', policyId: 'ABAC_TOOL_ALLOW' });
    expect(abac.evaluateTool([live(T.toolClassDeny(['command']))], tool('x', 'y', 'command'))).toMatchObject({ pass: false, reason: 'ABAC_TOOL_CLASS_DENIED' });
    expect(abac.evaluateTool([], tool('x', 'y', 'read')).pass).toBe(true);
  });
});

describe('AB-05 supplied attributes', () => {
  test('catalogued, typed, bounded', () => {
    expect(attrs.sanitizeSupplied({ 'request.model': 'm', 'request.stream': false, 'resource.categories': ['A'], 'request.promptChars': 3 })).toEqual({ 'request.model': 'm', 'request.stream': false, 'resource.categories': ['A'], 'request.promptChars': 3 });
    for (const b of [{ 'subject.userId': 'x' }, { nope: 1 }, { 'request.model': 5 }, { 'request.stream': 'yes' }, { 'request.promptChars': NaN }, { 'resource.categories': 'A' }, { 'request.model': 'x'.repeat(300) }, { 'resource.categories': Array(40).fill('A') }])
      expect(() => attrs.sanitizeSupplied(b)).toThrow();
    expect(attrs.sanitizeSupplied(null)).toEqual({});
  });
  test('an invalid supplied attribute makes the whole evaluation fail closed (INVALID_CONTEXT)', async () => {
    const consent = { id: 'C', type: 'REQUIRE_CONSENT', priority: 100, enabled: true, config: { requireValidArtifact: true } };
    const set = validateAndPrepare({ policies: [consent, T.modelDenyList(['x'])] }).filter((p) => p.type !== 'REQUIRE_CONSENT');
    const c = { ...ctx(), attributes: { 'request.model': 12 } };
    expect(await evaluate(c, set)).toMatchObject({ decision: 'BLOCK', reason: 'INVALID_CONTEXT' });
  });
  test('the catalogue documents every attribute', () => { for (const [k, v] of Object.entries(attrs.CATALOGUE)) { expect(v.doc).toBeTruthy(); expect(['string', 'number', 'boolean', 'string[]']).toContain(v.type); expect(k).toMatch(/^[a-z]+\.[A-Za-z]+$/); } });
});
