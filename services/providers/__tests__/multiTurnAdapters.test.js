'use strict';

/**
 * the six provider adapters carry a whole conversation (system, user, assistant turns, in order), not just one prompt. Transport is simulated (the OpenAI SDK
 * mock for openai / mistral / llama / local, native fetch mock for anthropic / gemini); the real local model is exercised separately (docs: evidence).
 */

jest.mock('../../logger', () => ({ emit: jest.fn() }));
jest.mock('openai');

const { OpenAI } = require('openai');

const CONV = [
  { role: 'system', content: 'Answer briefly.' },
  { role: 'user', content: 'What is Ed25519?' },
  { role: 'assistant', content: 'A signature scheme.' },
  { role: 'user', content: 'Why is it fast?' },
];
const META = { requestId: 'req-f6a', requestHash: 'a'.repeat(64), policyHash: 'b'.repeat(64) };

function sdkCreate() {
  const create = jest.fn().mockResolvedValue({ id: 'r1', model: 'm', choices: [{ message: { role: 'assistant', content: 'fine' }, finish_reason: 'stop' }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } });
  OpenAI.mockImplementation(() => ({ chat: { completions: { create } } }));
  return create;
}

beforeEach(() => { jest.clearAllMocks(); });
afterEach(() => {
  for (const k of ['OPENAI_API_KEY', 'MISTRAL_API_KEY', 'LLAMA_BASE_URL', 'LOCAL_BASE_URL', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY']) delete process.env[k];
  delete global.fetch;
});

describe('provider adapters carry the conversation', () => {
  test.each([
    ['openai', 'gpt-4o', () => { process.env.OPENAI_API_KEY = 'sk-test'; const m = require('../openai'); m._resetClient(); return (b) => m.callOpenAI(b, META); }],
    ['mistral', 'mistral-large-latest', () => { process.env.MISTRAL_API_KEY = 'ms-test'; const m = require('../mistral'); m._resetClient(); return (b) => m.callMistral(b, META); }],
    ['llama', 'llama3.2', () => { process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1'; const m = require('../llama'); m._resetClient(); return (b) => m.callLlama(b, META); }],
    ['local', 'llama3.2', () => { process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1'; const m = require('../local'); m._resetClient(); return (b) => m.callLocal(b, META); }],
  ])('%s (OpenAI-compatible transport): every turn, role and order reach the SDK call', async (_name, model, setup) => {
    const create = sdkCreate();
    const call = setup();
    const out = await call({ model, messages: CONV });
    expect(out.output).toBe('fine');
    expect(create.mock.calls[0][0].messages).toEqual(CONV);
  });

  test('anthropic: the system turn becomes the top-level system field, user/assistant turns keep their roles and order', async () => {
    process.env.ANTHROPIC_API_KEY = 'test-key';
    global.fetch = jest.fn().mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ id: 'm', type: 'message', role: 'assistant', model: 'claude-3-5-sonnet-20241022', content: [{ type: 'text', text: 'fine' }], usage: { input_tokens: 1, output_tokens: 1 } }) });
    const { callAnthropic } = require('../anthropic');
    await callAnthropic({ model: 'claude-3-5-sonnet-20241022', messages: CONV }, META);
    const sent = JSON.parse(global.fetch.mock.calls[0][1].body);
    expect(sent.system).toBe('Answer briefly.');
    expect(sent.messages).toEqual([{ role: 'user', content: 'What is Ed25519?' }, { role: 'assistant', content: 'A signature scheme.' }, { role: 'user', content: 'Why is it fast?' }]);
  });

  test('gemini: the system turn becomes systemInstruction, the assistant turn is mapped to "model", order is kept', async () => {
    process.env.GEMINI_API_KEY = 'gm-test';
    global.fetch = jest.fn().mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ candidates: [{ content: { parts: [{ text: 'fine' }], role: 'model' }, finishReason: 'STOP' }], usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1, totalTokenCount: 2 } }) });
    const { callGemini } = require('../gemini');
    await callGemini({ model: 'gemini-1.5-flash', messages: CONV }, META);
    const sent = JSON.parse(global.fetch.mock.calls[0][1].body);
    expect(sent.systemInstruction.parts[0].text).toBe('Answer briefly.');
    expect(sent.contents.map((c) => [c.role, c.parts[0].text])).toEqual([['user', 'What is Ed25519?'], ['model', 'A signature scheme.'], ['user', 'Why is it fast?']]);
  });

  test('the shared outbound validation still bounds a conversation (count, size, roles)', () => {
    const { validateOutboundMessages, MAX_MESSAGES } = require('../baseAdapter');
    expect(validateOutboundMessages({ model: 'm', messages: CONV })).toBeNull();
    expect(validateOutboundMessages({ model: 'm', messages: Array.from({ length: MAX_MESSAGES + 1 }, () => ({ role: 'user', content: 'x' })) })).not.toBeNull();
    expect(validateOutboundMessages({ model: 'm', messages: [{ role: 'tool', content: 'x' }] })).not.toBeNull();
  });
});
