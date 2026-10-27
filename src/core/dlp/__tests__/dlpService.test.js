'use strict';

/**
 * the DLP stage and the DLP policy rule.
 *   DS-01  the rule: strict validation, derived defaults do not change policyHash, a changed DLP setting changes it
 *   DS-02  input: prompt and conversations, REDACT / MASK / BLOCK / DETECT, events carry both hashes and never the values
 *   DS-03  output
 *   DS-04  fail closed: module missing, REDACT without a key
 *   DS-05  audit: a structured event always; DLP_TRANSFORM chain entries under schema v8
 *   DS-06  isolation: nothing but the extension point reaches enterprise/dlp
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const fs = require('fs');
const path = require('path');
const { emit } = require('../../../../services/logger');
const ext = require('../extensionPoint');
const svc = require('../dlpService');
const dlpRule = require('../../../../services/policy/evaluators/dlp');
const { computePolicyHash } = require('../../../../services/policyHash');
const { luhn } = require('../../../../enterprise/dlp/detectors');

const KEYSTR = 'k'.repeat(40);
const card = (() => { const b = '411111111111111'; for (let c = 0; c < 10; c++) { const t = b + c; if (luhn(t)) return t; } throw new Error('no card'); })();
const MAIL = 'jane.roe@example.org';
const rule = (config, over = {}) => ({ id: 'DLP_1', type: 'DLP', priority: 10, enabled: true, config: { dlpFormat: 1, direction: 'input', action: 'REDACT', rules: ['EMAIL', 'FINANCIAL'], ...config }, ...over });
const live = (p) => ({ ...p, config: dlpRule.preprocess(p.config) });

beforeEach(() => { process.env.QODIQA_DLP_TOKEN_KEY = KEYSTR; ext._set(undefined); emit.mockClear(); });
afterAll(() => { delete process.env.QODIQA_DLP_TOKEN_KEY; ext._set(undefined); });

describe('DS-01 the policy rule', () => {
  test('valid config passes; every kind of bad config is refused', () => {
    expect(() => dlpRule.validate(rule({}).config)).not.toThrow();
    for (const bad of [{ dlpFormat: 2 }, { direction: 'sideways' }, { action: 'DELETE' }, { rules: [] }, { rules: ['NOPE'] }, { rules: [7] }, { minConfidence: 2 }, { onTruncated: 'MAYBE' }, { extra: true }]) {
      expect(() => dlpRule.validate({ ...rule({}).config, ...bad })).toThrow();
    }
    expect(() => dlpRule.validate({ ...rule({}).config, rules: ['*'] })).not.toThrow();
  });
  test('derived defaults are underscore fields: the hash of the live rule equals the hash of the loaded rule; a changed setting changes the hash', () => {
    const base = rule({});
    expect(computePolicyHash([live(base)])).toBe(computePolicyHash([base]));
    expect(computePolicyHash([rule({ action: 'BLOCK' })])).not.toBe(computePolicyHash([base]));
    expect(computePolicyHash([rule({ rules: ['EMAIL'] })])).not.toBe(computePolicyHash([base]));
  });
  test('the engine treats the rule as a pass (content is enforced by the DLP stage) and the registry knows the type', () => {
    expect(dlpRule.evaluate({}, {})).toEqual({ pass: true });
    expect(require('../../../../services/policy/evaluators').DLP).toBe(dlpRule);
  });
});

describe('DS-02 input', () => {
  test('REDACT a prompt: stable token, original untouched, both hashes, no value in the events', () => {
    const body = { prompt: `mail ${MAIL} card ${card}`, model: 'm' };
    const r = svc.applyToBody(body, [live(rule({}))]);
    expect(r.blocked).toBe(false); expect(r.changed).toBe(true);
    expect(r.body.prompt).toMatch(/^mail \[\[EMAIL:[0-9a-f]{12}\]\] card \[\[CARD:[0-9a-f]{12}\]\]$/); expect(r.body.model).toBe('m');
    expect(body.prompt).toContain(MAIL);
    expect(r.events).toHaveLength(1);
    expect(r.events[0]).toMatchObject({ action: 'REDACT', direction: 'input', rules: ['CARD', 'EMAIL'], findings: 2, blocked: false });
    expect(r.events[0].inputHashBefore).toMatch(/^[0-9a-f]{64}$/); expect(r.events[0].inputHashAfter).not.toBe(r.events[0].inputHashBefore);
    expect(JSON.stringify(r.events)).not.toContain('jane'); expect(JSON.stringify(r.events)).not.toContain(card);
  });
  test('a conversation: system and every message are screened; roles and order are kept', () => {
    const body = { system: `you are ${MAIL}`, messages: [{ role: 'user', content: `hi ${MAIL}` }, { role: 'assistant', content: 'ok' }, { role: 'user', content: `card ${card}` }] };
    const r = svc.applyToBody(body, [live(rule({}))]);
    expect(r.body.messages.map((m) => m.role)).toEqual(['user', 'assistant', 'user']);
    expect(r.body.messages[1].content).toBe('ok');
    expect(JSON.stringify(r.body)).not.toContain('jane'); expect(JSON.stringify(r.body)).not.toContain(card);
    expect(r.events[0].findings).toBe(3);
  });
  test('BLOCK withholds; DETECT passes and still records; no DLP rule = no change and no events', () => {
    const b = svc.applyToBody({ prompt: MAIL }, [live(rule({ action: 'BLOCK' }))]);
    expect(b).toMatchObject({ blocked: true, reason: 'DLP_BLOCKED' }); expect(b.events[0]).toMatchObject({ action: 'BLOCK', blocked: true });
    const d = svc.applyToBody({ prompt: MAIL }, [live(rule({ action: 'DETECT' }))]);
    expect(d.blocked).toBe(false); expect(d.body.prompt).toBe(MAIL); expect(d.events[0].action).toBe('DETECT'); expect(d.changed).toBe(false);
    const none = svc.applyToBody({ prompt: MAIL }, [{ id: 'X', type: 'BLOCK_IP', enabled: true, config: {} }]);
    expect(none).toMatchObject({ blocked: false, events: [] }); expect(none.body.prompt).toBe(MAIL);
  });
  test('rules apply in priority order; a disabled rule and an output rule are skipped for input', () => {
    const r = svc.applyToBody({ prompt: `${MAIL} ${card}` }, [live(rule({ rules: ['EMAIL'], action: 'MASK' }, { id: 'B', priority: 20 })), live(rule({ rules: ['CARD'], action: 'REDACT' }, { id: 'A', priority: 10 })),
      live(rule({ action: 'BLOCK' }, { id: 'C', enabled: false })), live(rule({ direction: 'output', action: 'BLOCK' }, { id: 'D' }))]);
    expect(r.blocked).toBe(false); expect(r.events.map((e) => e.policyId)).toEqual(['A', 'B']);
    expect(r.body.prompt).toMatch(/^j\*+@example\.org \[\[CARD:/);
  });
  test('a rule that finds nothing leaves no event', () => { expect(svc.applyToBody({ prompt: 'nothing' }, [live(rule({}))])).toMatchObject({ blocked: false, events: [], changed: false }); });
});

describe('DS-03 output', () => {
  test('direction both applies to the answer too; an input-only rule does not', () => {
    const r = svc.applyToText(`write to ${MAIL}`, [live(rule({ direction: 'both' }))]);
    expect(r.text).toMatch(/^write to \[\[EMAIL:/); expect(r.events[0].direction).toBe('output');
    expect(svc.applyToText(`x ${MAIL}`, [live(rule({ direction: 'input' }))])).toMatchObject({ blocked: false, events: [], text: `x ${MAIL}` });
  });
});

describe('DS-04 fail closed', () => {
  test('REDACT without a usable token key blocks instead of skipping', () => {
    delete process.env.QODIQA_DLP_TOKEN_KEY;
    expect(svc.applyToBody({ prompt: 'hello' }, [live(rule({}))])).toMatchObject({ blocked: true, reason: 'DLP_UNAVAILABLE' });
    process.env.QODIQA_DLP_TOKEN_KEY = 'short';
    expect(svc.applyToBody({ prompt: 'hello' }, [live(rule({}))])).toMatchObject({ blocked: true, reason: 'DLP_UNAVAILABLE' });
    expect(svc.applyToBody({ prompt: 'hello' }, [live(rule({ action: 'DETECT' }))]).blocked).toBe(false);
  });
  test('module not installed: a configured rule blocks, no rule is a no-op, and a DLP policy does not load', () => {
    ext._set(null);
    expect(svc.applyToBody({ prompt: 'hello' }, [live(rule({}))])).toMatchObject({ blocked: true, reason: 'DLP_UNAVAILABLE' });
    expect(svc.applyToBody({ prompt: 'hello' }, [])).toMatchObject({ blocked: false });
    expect(() => dlpRule.validate(rule({}).config)).toThrow(/not installed/);
  });
});

describe('DS-05 audit', () => {
  test('a structured DLP_TRANSFORM event is emitted and carries no value', async () => {
    const r = svc.applyToBody({ prompt: MAIL }, [live(rule({}))]);
    await svc.recordEvents(r.events, { requestId: 'r1', tenantId: 't1' });
    const ev = emit.mock.calls.find((c) => c[1] === 'DLP_TRANSFORM'); expect(ev).toBeTruthy(); expect(JSON.stringify(ev)).not.toContain('jane');
  });
  test('under schema v8 a chain entry with the dlp field is appended per event', async () => {
    jest.resetModules();
    const appended = [];
    jest.doMock('../../audit/entryBuilder', () => ({ currentSchemaVersion: () => 8 }));
    jest.doMock('../../audit/audit-log', () => ({ appendMandatory: async (e) => { appended.push(e); return { hash: 'h' }; } }));
    jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));
    const s2 = require('../dlpService');
    await s2.recordEvents([{ policyId: 'P', direction: 'input', action: 'REDACT', rules: ['EMAIL'], findings: 1, blocked: false, inputHashBefore: 'a'.repeat(64), inputHashAfter: 'b'.repeat(64) },
      { policyId: 'P', direction: 'output', action: 'BLOCK', rules: ['CARD'], findings: 1, blocked: true, inputHashBefore: 'c'.repeat(64), inputHashAfter: 'c'.repeat(64) }], { requestId: 'req-1', tenantId: 't1' });
    expect(appended[0]).toMatchObject({ artifactId: 'req-1:dlp_in_1', entryType: 'DLP_TRANSFORM', decision: 'ALLOW', reason: 'DLP_REDACT', dlp: { rules: ['EMAIL'], action: 'REDACT', inputHashBefore: 'a'.repeat(64), inputHashAfter: 'b'.repeat(64) } });
    expect(appended[1]).toMatchObject({ artifactId: 'req-1:dlp_out_2', decision: 'BLOCK', reason: 'DLP_BLOCK' });
    jest.dontMock('../../audit/entryBuilder'); jest.dontMock('../../audit/audit-log');
  });
});

describe('DS-06 isolation', () => {
  test('only src/core/dlp/extensionPoint.js (and enterprise/dlp itself) import enterprise/dlp', () => {
    const root = path.join(__dirname, '..', '..', '..', '..');
    const hits = [];
    const skip = new Set(['node_modules', '.git', 'coverage', 'dist', 'build']);
    (function walk(d) {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        if (skip.has(e.name)) continue;
        const p = path.join(d, e.name);
        if (e.isDirectory()) walk(p);
        else if (/\.(js|ts)$/.test(e.name) && !/__tests__|\.test\./.test(p) && /require\(['"][./]*\/enterprise\/dlp/.test(fs.readFileSync(p, 'utf8'))) hits.push(path.relative(root, p).split(path.sep).join('/'));
      }
    }(root));
    expect(hits.filter((h) => !h.startsWith('enterprise/dlp/'))).toEqual(['src/core/dlp/extensionPoint.js']);
  });
});

describe('DS-07 tool path repairs after the independent verification', () => {
  const AWS = 'AK' + 'IA' + 'ABCDEFGHIJKLMNOP';
  const evalr = require('../../../../services/policy/evaluators/dlp');
  const mk = (direction, action, extra = {}) => { const c = { dlpFormat: 1, direction, action, rules: ['*'], ...extra }; evalr.validate(c); return { id: 'T', type: 'DLP', priority: 1, enabled: true, config: evalr.preprocess(c) }; };

  test('result: the text of an embedded resource is scanned and redacted', () => {
    const r = svc.applyToToolResult({ content: [{ type: 'resource', resource: { uri: 'file:///x', text: `key ${AWS}` } }] }, [mk('tool_output', 'REDACT')]);
    expect(r.blocked).toBe(false); expect(JSON.stringify(r.raw)).not.toContain(AWS); expect(r.raw.content[0].resource.text).toMatch(/\[\[KEY_AWS_ACCESS:/);
  });
  test('result: more leaves than the cap withholds the result under REDACT/BLOCK (it is not "clean"), but a DETECT-only rule does not fail the call', () => {
    const sc = {}; for (let i = 0; i < 2100; i++) sc[`k${i}`] = i === 2099 ? AWS : 'v';
    expect(svc.applyToToolResult({ content: [], structuredContent: sc }, [mk('tool_output', 'REDACT')])).toMatchObject({ blocked: true, reason: 'DLP_BLOCKED' });
    expect(svc.applyToToolResult({ content: [], structuredContent: sc }, [mk('tool_output', 'DETECT')]).blocked).toBe(false);
  });
  test('result: a secret in a JSON KEY withholds the result; a card as a JSON NUMBER is redacted', () => {
    expect(svc.applyToToolResult({ content: [], structuredContent: { [`key ${AWS}`]: 'v' } }, [mk('tool_output', 'REDACT')]).blocked).toBe(true);
    const n = svc.applyToToolResult({ content: [], structuredContent: { card: 4111111111111111 } }, [mk('tool_output', 'REDACT')]);
    expect(n.blocked).toBe(false); expect(JSON.stringify(n.raw)).not.toContain('4111111111111111'); expect(n.raw.structuredContent.card).toMatch(/^\[\[CARD:/);
  });
  test('args: keys, numbers and a value in leaf #2101 are all seen by a BLOCK rule', () => {
    const p = [mk('tool_input', 'BLOCK')];
    expect(svc.applyToToolArgs({ [`k ${AWS}`]: 'v' }, p).blocked).toBe(true);
    expect(svc.applyToToolArgs({ card: 4111111111111111 }, p).blocked).toBe(true);
    const many = {}; for (let i = 0; i < 2100; i++) many[`k${i}`] = i === 2099 ? AWS : 'v';
    expect(svc.applyToToolArgs(many, p).blocked).toBe(true);
    expect(svc.applyToToolArgs({ a: 'plain', b: 3 }, p).blocked).toBe(false);
  });
  test('very deep nesting does not throw: it is refused (fail closed) when a protecting rule exists', () => {
    let deep = { v: AWS }; for (let i = 0; i < 20_000; i++) deep = { n: deep };
    expect(() => svc.applyToToolArgs(deep, [mk('tool_input', 'BLOCK')])).not.toThrow();
    expect(svc.applyToToolArgs(deep, [mk('tool_input', 'BLOCK')]).blocked).toBe(true);
    expect(svc.applyToToolResult({ content: [], structuredContent: deep }, [mk('tool_output', 'REDACT')]).blocked).toBe(true);
  });
});
