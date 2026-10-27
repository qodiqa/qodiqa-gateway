'use strict';

/**
 * Audit remediation 2026-10-27, item 4: the five engine-loop no-op policy types. Four have a real application point
 * (stage module required and called by aiChat.js); DATA_RETENTION has none and must stay documented as not applied.
 */
const fs = require('fs');
const path = require('path');
const REGISTRY = require('../services/policy/evaluators');
const { validatePolicyCandidate } = require('../src/core/policy/store');

const root = path.join(__dirname, '..');
const aiChat = fs.readFileSync(path.join(root, 'src/api/routes/aiChat.js'), 'utf8');

describe('policy type enforcement map', () => {
  test.each([
    ['DLP', 'dlpStage.', 'src/core/dlp/dlpService.js'],
    ['CONTENT_RULE', 'contentStage.check(', 'src/core/content/contentStage.js'],
    ['BUDGET', 'budgetStage.reserve(', 'src/core/budget/budgetStage.js'],
    ['ROUTING', 'routingStage.resolve(', 'src/core/routing/routingStage.js'],
  ])('%s always passes in the engine loop and is applied by its stage', (type, call, stageFile) => {
    expect(REGISTRY[type].evaluate({})).toEqual({ pass: true });
    expect(fs.existsSync(path.join(root, stageFile))).toBe(true);
    expect(aiChat).toContain(call);
  });

  test('DATA_RETENTION passes in the loop and has no production caller of applyRetention', () => {
    expect(REGISTRY.DATA_RETENTION.evaluate({})).toEqual({ pass: true });
    const hits = [];
    const walk = (d) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        if (['node_modules', '.git', '__tests__', 'evidence', 'eval', '_quarantine', '.claude', '.local-scratch', 'PLAN'].includes(e.name)) continue;
        const f = path.join(d, e.name);
        if (e.isDirectory()) walk(f);
        else if (/\.js$/.test(e.name) && !/\.test\.js$/.test(e.name) && /applyRetention\(/.test(fs.readFileSync(f, 'utf8'))) hits.push(path.relative(root, f).split(path.sep).join('/'));
      }
    };
    for (const d of ['src', 'services', 'middleware', 'scripts']) walk(path.join(root, d));
    expect(hits).toEqual(['src/core/dataGovernance/categories.js']);   // the definition only
  });

  test('validating a DATA_RETENTION candidate warns that it is not applied automatically', () => {
    const r = validatePolicyCandidate({ id: 'ret-1', type: 'DATA_RETENTION', priority: 10, enabled: true, config: { retentionFormat: 1, byCategory: { audit_operational: 90 } } }, null);
    expect(r.warnings.some((w) => /not applied automatically/.test(w))).toBe(true);
  });
});
