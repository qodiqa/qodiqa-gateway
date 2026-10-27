'use strict';

// Re-audit A3-01: the deployment name (Azure) and the model id (Gemini) are URL path segments; a value that could change the path or the query is refused
// before any request is built.
describe('provider model names that travel in a URL path', () => {
  test('MP-01 Azure accepts plain deployment names and refuses path or query tricks', () => {
    const { _spec } = require('../azure');
    const ok = (model) => _spec.transformRequest({ model, messages: [{ role: 'user', content: 'x' }] });
    expect(ok('gpt-4o-prod').model).toBe('gpt-4o-prod');
    for (const bad of ['dep?api-version=2020-01-01', 'dep/../../fine_tuning/jobs', 'dep/x', '../x', 'a b', '', 'dep#frag', 'dep%2e%2e']) {
      expect(() => ok(bad)).toThrow(/PROVIDER_MODEL_NOT_ALLOWED/);
    }
  });

  test('MP-02 Gemini builds its URL only from a plain model id', () => {
    const gemini = require('../gemini');
    const exec = (p, ctx) => gemini._spec.execute(p, ctx);
    process.env.GEMINI_API_KEY = ['g', 'k'].join('') + '-test';
    for (const bad of ['gemini-pro?key=x', 'gemini-pro:generateContent/../x', 'm/../../v1/other', 'a b']) {
      expect(() => exec({ contents: [] }, { model: bad })).toThrow(/PROVIDER_MODEL_NOT_ALLOWED/);
    }
    delete process.env.GEMINI_API_KEY;
  });
});
