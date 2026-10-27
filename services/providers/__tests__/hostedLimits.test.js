'use strict';

/**
 * Launch plan R-23 (post-launch prep): opt-in output-token caps for the hosted adapters, mirroring R-06.
 * Unset → every outbound body is exactly what it was before.
 */

function loadWith(env, fn) {
  const saved = {};
  for (const k of Object.keys(env)) { saved[k] = process.env[k]; if (env[k] === undefined) delete process.env[k]; else process.env[k] = env[k]; }
  let out;
  try {
    jest.isolateModules(() => {
      const spec = (m) => m._spec;
      out = fn({
        config: require('../config'),
        openai: spec(require('../openai')), openaiStream: spec(require('../openai.stream')),
        mistral: spec(require('../mistral')), mistralStream: spec(require('../mistral.stream')),
        llama: spec(require('../llama')), llamaStream: spec(require('../llama.stream')),
        gemini: spec(require('../gemini')),
      });
    });
  } finally {
    for (const k of Object.keys(saved)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  }
  return out;
}

const BODY = { model: 'm', messages: [{ role: 'user', content: 'hi' }] };
const OFF = { OPENAI_MAX_TOKENS: undefined, MISTRAL_MAX_TOKENS: undefined, LLAMA_MAX_TOKENS: undefined, GEMINI_MAX_TOKENS: undefined };

describe('hosted provider output caps (R-23 prep)', () => {
  test('unset → no max_tokens / generationConfig anywhere (unchanged bodies)', () => {
    const r = loadWith(OFF, (m) => ({
      oa: m.openai.transformRequest(BODY), oas: m.openaiStream.transformRequest(BODY),
      mi: m.mistral.transformRequest(BODY), mis: m.mistralStream.transformRequest(BODY),
      ll: m.llama.transformRequest(BODY), lls: m.llamaStream.transformRequest(BODY),
      ge: m.gemini.transformRequest(BODY),
      cfg: ['openai', 'mistral', 'llama', 'gemini'].map((n) => m.config.getProviderConfig(n).maxTokens),
    }));
    for (const k of ['oa', 'mi', 'll']) expect(r[k]).toEqual({ model: 'm', messages: BODY.messages });
    for (const k of ['oas', 'mis', 'lls']) expect(r[k]).toEqual({ model: 'm', messages: BODY.messages, stream: true });
    expect(r.ge).not.toHaveProperty('generationConfig');
    expect(r.cfg).toEqual([null, null, null, null]);
  });

  test('set → max_tokens on OpenAI-compatible bodies (normal + stream), maxOutputTokens for Gemini', () => {
    const r = loadWith({ OPENAI_MAX_TOKENS: '100', MISTRAL_MAX_TOKENS: '200', LLAMA_MAX_TOKENS: '300', GEMINI_MAX_TOKENS: '400' }, (m) => ({
      oa: m.openai.transformRequest(BODY).max_tokens, oas: m.openaiStream.transformRequest(BODY).max_tokens,
      mi: m.mistral.transformRequest(BODY).max_tokens, mis: m.mistralStream.transformRequest(BODY).max_tokens,
      ll: m.llama.transformRequest(BODY).max_tokens, lls: m.llamaStream.transformRequest(BODY).max_tokens,
      ge: m.gemini.transformRequest(BODY).generationConfig,
    }));
    expect(r).toEqual({ oa: 100, oas: 100, mi: 200, mis: 200, ll: 300, lls: 300, ge: { maxOutputTokens: 400 } });
  });

  test.each(['0', 'abc', '8193', '-1'])('invalid value %s → ignored (no cap), production boot refuses it', (v) => {
    const cap = loadWith({ OPENAI_MAX_TOKENS: v }, (m) => m.config.getProviderConfig('openai').maxTokens);
    expect(cap).toBeNull();
    const { validateBoot } = require('../../../src/infra/config/bootValidator');
    const boot = validateBoot({ NODE_ENV: 'development', LOCAL_BASE_URL: 'http://127.0.0.1:11434/v1', OPENAI_MAX_TOKENS: v });
    expect([...boot.fatal, ...boot.warnings].some((x) => x.variable === 'OPENAI_MAX_TOKENS')).toBe(true);
  });
});
