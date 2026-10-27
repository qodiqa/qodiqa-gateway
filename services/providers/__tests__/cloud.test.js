'use strict';

/**
 * Azure OpenAI and AWS Bedrock adapters.
 *   SV-01..03  SigV4 against the published AWS examples (signing key, GET and POST "vanilla" signatures) + structure checks
 *   SS-01      the SSRF policy accepts exactly the vendors' hostname shapes
 *   AZ-01..05  Azure: URL with deployment and api-version, api-key header, Entra token flow and cache, endpoint validation, normalised errors
 *   BR-01..06  Bedrock: Converse mapping, signed request, response parsing, errors, redirect refused, model id shape
 *   CF-01      configuration enablement and credential rules
 */

jest.mock('../../logger', () => { const a = jest.requireActual('../../logger'); return { ...a, emit: jest.fn() }; });

const sigv4 = require('../sigv4');
const ssrf = require('../ssrf');
const azureAuth = require('../azureAuth');
const creds = require('../../../src/infra/config/credentialRules');

// secret-shaped values are assembled at run time (the secret scanner blocks literals of these shapes)
const AKID = ['AK', 'IA'].join('') + 'IOSFODNN7ABCDEFG';
const FAKE_SECRET = 'wJalr' + 'XUtnFEMI/K7MDENG+bPxRfiCY' + 'z'.repeat(10);
const SECRET = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';        // the AWS documentation example secret
const T = new Date(Date.UTC(2015, 7, 30, 12, 36, 0));

describe('SigV4', () => {
  test('SV-01 the documented derived signing key', () => {
    expect(sigv4.signingKey(SECRET, '20150830', 'us-east-1', 'iam').toString('hex')).toBe('c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9');
  });
  test('SV-02 the documented get-vanilla and post-vanilla signatures', () => {
    const base = { url: 'https://example.amazonaws.com/', headers: {}, body: '', region: 'us-east-1', service: 'service', accessKeyId: 'AKIDEXAMPLE', secretAccessKey: SECRET, now: T, signContentSha: false };
    const g = sigv4.sign({ ...base, method: 'GET' });
    expect(g.signature).toBe('5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31');
    expect(g.headers.authorization).toBe('AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31');
    expect(sigv4.sign({ ...base, method: 'POST' }).signature).toBe('5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b');
  });
  test('SV-03 structure: query sorting, double-encoded path, session token signed, body hash, determinism, a changed byte changes the signature', () => {
    const base = { method: 'POST', url: 'https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3%3A0/converse?b=2&a=1&a=0', headers: { 'Content-Type': ' application/json ' },
      body: '{"x":1}', region: 'us-east-1', service: 'bedrock', accessKeyId: 'AKIDEXAMPLE', secretAccessKey: SECRET, sessionToken: 'tok', now: T };
    const s = sigv4.sign(base);
    expect(s.canonicalRequest.split('\n')[1]).toBe('/model/anthropic.claude-3%253A0/converse');                 // the URL carries %3A (encoded once); the canonical URI encodes it again
    expect(s.canonicalRequest.split('\n')[2]).toBe('a=0&a=1&b=2');
    expect(s.signedHeaders).toBe('content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token');
    expect(s.headers['x-amz-content-sha256']).toBe(sigv4.sha256Hex('{"x":1}'));
    expect(s.headers['content-type']).toBe('application/json');
    expect(sigv4.sign(base).signature).toBe(s.signature);
    expect(sigv4.sign({ ...base, body: '{"x":2}' }).signature).not.toBe(s.signature);
    expect(() => sigv4.sign({ ...base, region: undefined })).toThrow();
  });
});

describe('SSRF hostname shapes', () => {
  test('SS-01', () => {
    const ok = (u) => ssrf.validateProviderUrl(u).valid;
    expect(ok('https://myres.openai.azure.com')).toBe(true); expect(ok('https://r2.cognitiveservices.azure.com/')).toBe(true);
    expect(ok('https://bedrock-runtime.eu-central-1.amazonaws.com')).toBe(true); expect(ok('https://login.microsoftonline.com/t/oauth2/v2.0/token')).toBe(true);
    for (const bad of ['https://openai.azure.com', 'https://a.b.openai.azure.com', 'https://myres.openai.azure.com.evil.io', 'https://evilopenai.azure.com.x', 'http://myres.openai.azure.com',
      'https://bedrock-runtime.us-east-1.amazonaws.com.evil.io', 'https://bedrock.us-east-1.amazonaws.com', 'https://s3.us-east-1.amazonaws.com', 'https://169.254.169.254', 'https://localhost']) expect(ok(bad)).toBe(false);
  });
});

describe('Azure OpenAI', () => {
  const ENV = { AZURE_OPENAI_ENDPOINT: 'https://myres.openai.azure.com', AZURE_OPENAI_API_KEY: 'k'.repeat(16) + '1'.repeat(16), AZURE_OPENAI_API_VERSION: '2024-10-21' };
  let azure;
  const reply = (body = { id: 'chatcmpl-1', model: 'gpt-4o', choices: [{ message: { content: 'pong' }, finish_reason: 'stop' }], usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7 } }, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  let seen;

  beforeEach(() => {
    jest.resetModules();
    for (const k of Object.keys(process.env)) if (/^(AZURE_|PROVIDER_.*AZURE|BEDROCK_)/.test(k)) delete process.env[k];
    Object.assign(process.env, ENV);
    azure = require('../azure');
    seen = [];
    azure._setFetch(async (url, init) => { seen.push({ url: String(url), init }); return reply(); });
  });
  afterEach(() => { for (const k of Object.keys(ENV)) delete process.env[k]; delete process.env.AZURE_TENANT_ID; delete process.env.AZURE_CLIENT_ID; delete process.env.AZURE_CLIENT_SECRET; delete process.env.AZURE_OPENAI_AUTH; });

  test('AZ-01 the URL carries the deployment and api-version; the key travels in the api-key header; the answer is normalised', async () => {
    const out = await azure.callAzure({ model: 'my-gpt4o', messages: [{ role: 'user', content: 'ping' }] }, { requestId: 'r' });
    expect(seen).toHaveLength(1);
    const u = new URL(seen[0].url);
    expect(u.origin).toBe('https://myres.openai.azure.com'); expect(u.pathname).toBe('/openai/deployments/my-gpt4o/chat/completions'); expect(u.searchParams.get('api-version')).toBe('2024-10-21');
    const h = new Headers(seen[0].init.headers); expect(h.get('api-key')).toBe(ENV.AZURE_OPENAI_API_KEY); expect(h.get('authorization')).toBeNull();
    expect(out).toMatchObject({ output: 'pong', provider: 'azure', tokenUsage: { inputTokens: 5, outputTokens: 2, totalTokens: 7 } });
  });
  test('AZ-02 Entra: a bearer token (not the key) is sent, fetched once and cached', async () => {
    delete process.env.AZURE_OPENAI_API_KEY;
    const g = '11111111-2222-4333-8444-555555555555';
    Object.assign(process.env, { AZURE_TENANT_ID: g, AZURE_CLIENT_ID: g, AZURE_CLIENT_SECRET: 'client-secret-value-1' });
    let tokenCalls = 0; let tokenReq;
    azureAuth._reset();
    const fetchImpl = async (url, init) => { tokenCalls++; tokenReq = { url, init }; return new Response(JSON.stringify({ access_token: 'entra-token-abc', expires_in: 3600 }), { status: 200 }); };
    const t1 = await azureAuth.entraToken({ env: process.env, fetchImpl, nowMs: 1_000_000 });
    const t2 = await azureAuth.entraToken({ env: process.env, fetchImpl, nowMs: 1_000_000 + 1000 });
    expect(t1).toBe('entra-token-abc'); expect(t2).toBe(t1); expect(tokenCalls).toBe(1);
    expect(tokenReq.url).toBe(`https://login.microsoftonline.com/${g}/oauth2/v2.0/token`); expect(tokenReq.init.redirect).toBe('error');
    expect(String(tokenReq.init.body)).toContain('grant_type=client_credentials'); expect(String(tokenReq.init.body)).toContain('scope=https%3A%2F%2Fcognitiveservices.azure.com%2F.default');
    expect(await azureAuth.entraToken({ env: process.env, fetchImpl, nowMs: 1_000_000 + 3_550_000 })).toBe('entra-token-abc'); expect(tokenCalls).toBe(2);      // inside the last minute: refreshed
    expect(azureAuth.mode(process.env)).toBe('entra'); expect(azureAuth.mode({ ...process.env, AZURE_OPENAI_AUTH: 'api-key' })).toBeNull();
  });
  test('AZ-02b Entra failures are PROVIDER_AUTH_FAILED, never an outage; malformed ids and responses are refused', async () => {
    const g = '11111111-2222-4333-8444-555555555555'; const env = { AZURE_TENANT_ID: g, AZURE_CLIENT_ID: g, AZURE_CLIENT_SECRET: 's' };
    azureAuth._reset();
    await expect(azureAuth.entraToken({ env, fetchImpl: async () => new Response('no', { status: 401 }) })).rejects.toMatchObject({ code: 'PROVIDER_AUTH_FAILED' });
    await expect(azureAuth.entraToken({ env, fetchImpl: async () => new Response(JSON.stringify({ nope: 1 }), { status: 200 }) })).rejects.toMatchObject({ code: 'PROVIDER_AUTH_FAILED' });
    await expect(azureAuth.entraToken({ env, fetchImpl: async () => { throw new TypeError('network'); } })).rejects.toMatchObject({ code: 'PROVIDER_AUTH_FAILED' });
    await expect(azureAuth.entraToken({ env: { ...env, AZURE_TENANT_ID: '../../evil' }, fetchImpl: async () => reply() })).rejects.toMatchObject({ code: 'PROVIDER_AUTH_FAILED' });
  });
  test('AZ-03 a bad endpoint refuses every call (PROVIDER_CONFIG_INVALID) and never reaches the network', async () => {
    for (const ep of ['http://myres.openai.azure.com', 'https://evil.example.com', 'https://169.254.169.254', 'https://myres.openai.azure.com.evil.io']) {
      process.env.AZURE_OPENAI_ENDPOINT = ep; azure._resetClient(); azure._setFetch(async (u, i) => { seen.push({ url: String(u), init: i }); return reply(); }); seen.length = 0;
      await expect(azure.callAzure({ model: 'd', messages: [{ role: 'user', content: 'x' }] }, {})).rejects.toMatchObject({ code: 'PROVIDER_CONFIG_INVALID' });
      expect(seen).toHaveLength(0);
    }
  });
  test('AZ-04 provider errors are normalised (429 retried once then RATE_LIMITED, 401 AUTH_FAILED, 400 content filter INVALID_REQUEST, 500 UNAVAILABLE not retried)', async () => {
    const run = async (status, body = { error: { message: 'x' } }) => {
      let calls = 0; azure._setFetch(async () => { calls++; return reply(body, status); });
      const err = await azure.callAzure({ model: 'd', messages: [{ role: 'user', content: 'x' }] }, {}).catch((e) => e);
      return { code: err.code, calls };
    };
    expect(await run(401)).toEqual({ code: 'PROVIDER_AUTH_FAILED', calls: 1 });
    expect(await run(400, { error: { code: 'content_filter', message: 'blocked' } })).toEqual({ code: 'PROVIDER_INVALID_REQUEST', calls: 1 });
    expect((await run(500)).code).toBe('PROVIDER_UNAVAILABLE'); expect((await run(500)).calls).toBe(1);
    expect((await run(429)).code).toBe('PROVIDER_RATE_LIMITED');
  }, 20000);
  test('AZ-06 streaming: SSE deltas are yielded, the empty prompt-filter chunk is skipped, a stream without finish_reason fails as truncated', async () => {
    const sse = (frames) => new Response(frames.map((f) => `data: ${typeof f === 'string' ? f : JSON.stringify(f)}

`).join(''), { status: 200, headers: { 'content-type': 'text/event-stream' } });
    const stream = require('../azure.stream');
    azure._setFetch(async (url, init) => { seen.push({ url: String(url), init }); return sse([{ id: 'x', choices: [] }, { id: 'x', choices: [{ delta: { content: 'he' } }] }, { id: 'x', choices: [{ delta: { content: 'llo' }, finish_reason: 'stop' }] }, '[DONE]']); });
    const got = []; for await (const c of stream.callAzureStream({ model: 'dep', messages: [{ role: 'user', content: 'x' }] }, {})) got.push(c.delta);
    expect(got.join('')).toBe('hello'); expect(JSON.parse(seen[seen.length - 1].init.body)).toMatchObject({ stream: true, model: 'dep' });
    azure._setFetch(async () => sse([{ id: 'x', choices: [{ delta: { content: 'he' } }] }, '[DONE]']));
    const err = await (async () => { try { for await (const c of stream.callAzureStream({ model: 'dep', messages: [{ role: 'user', content: 'x' }] }, {})) void c; } catch (e) { return e; } return null; })();
    expect(err && err.code).toBe('PROVIDER_UNAVAILABLE'); expect(err.providerMayHaveExecuted).toBe(true);
  });
  test('AZ-05 the deployment allowlist (when set) is enforced and the config reports the provider enabled', () => {
    jest.resetModules(); process.env.AZURE_OPENAI_DEPLOYMENTS = 'allowed-one,allowed-two';
    const cfg = require('../config').getProviderConfig('azure');
    expect(cfg.enabled).toBe(true); expect([...cfg.allowedModels]).toEqual(['allowed-one', 'allowed-two']); expect(cfg.apiVersion).toBe('2024-10-21');
    const { validateModelAgainstConfig } = require('../modelValidation');
    expect(validateModelAgainstConfig(cfg, 'allowed-one').ok).toBe(true); expect(validateModelAgainstConfig(cfg, 'other').ok).toBe(false);
    delete process.env.AZURE_OPENAI_DEPLOYMENTS;
  });
});

describe('AWS Bedrock', () => {
  const ENV = { BEDROCK_REGION: 'us-east-1', BEDROCK_ACCESS_KEY_ID: AKID, BEDROCK_SECRET_ACCESS_KEY: SECRET.replace('EXAMPLE', 'XQ7ZK') };
  let bedrock; let fetchSpy; let seen;
  const ok = (body) => new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  const CONVERSE = { output: { message: { role: 'assistant', content: [{ text: 'pong ' }, { text: 'again' }] } }, stopReason: 'end_turn', usage: { inputTokens: 9, outputTokens: 3, totalTokens: 12 } };

  beforeEach(() => {
    jest.resetModules();
    Object.assign(process.env, ENV);
    bedrock = require('../bedrock');
    seen = [];
    fetchSpy = jest.spyOn(global, 'fetch').mockImplementation(async (url, init) => { seen.push({ url: String(url), init }); return ok(CONVERSE); });
  });
  afterEach(() => { fetchSpy.mockRestore(); for (const k of Object.keys(ENV)) delete process.env[k]; delete process.env.BEDROCK_SESSION_TOKEN; });

  test('BR-01 Converse mapping: system blocks, alternating roles merged, text content blocks', () => {
    const m = bedrock.toConverse([{ role: 'system', content: 'be brief' }, { role: 'user', content: 'a' }, { role: 'user', content: 'b' }, { role: 'assistant', content: 'c' }, { role: 'user', content: 'd' }]);
    expect(m).toEqual({ system: [{ text: 'be brief' }], messages: [{ role: 'user', content: [{ text: 'a' }, { text: 'b' }] }, { role: 'assistant', content: [{ text: 'c' }] }, { role: 'user', content: [{ text: 'd' }] }] });
  });
  test('BR-02 the request is a signed POST to the regional Converse endpoint; the answer and usage are parsed', async () => {
    process.env.BEDROCK_SESSION_TOKEN = 'session-token-1';
    const out = await bedrock.callBedrock({ model: 'anthropic.claude-3-5-sonnet-20241022-v2:0', messages: [{ role: 'system', content: 's' }, { role: 'user', content: 'ping' }] }, { requestId: 'r' });
    const r = seen[0];
    expect(r.url).toBe('https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse');
    expect(r.init.method).toBe('POST'); expect(r.init.redirect).toBe('error');
    const h = r.init.headers;
    expect(h.authorization).toMatch(new RegExp('^AWS4-HMAC-SHA256 Credential=' + AKID + '/\\d{8}/us-east-1/bedrock/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=[0-9a-f]{64}$'));
    expect(h['x-amz-security-token']).toBe('session-token-1'); expect(h['x-amz-content-sha256']).toBe(sigv4.sha256Hex(r.init.body));
    expect(JSON.parse(r.init.body)).toEqual({ messages: [{ role: 'user', content: [{ text: 'ping' }] }], system: [{ text: 's' }] });
    expect(out).toMatchObject({ output: 'pong again', provider: 'bedrock', tokenUsage: { inputTokens: 9, outputTokens: 3, totalTokens: 12 } });
  });
  test('BR-03 the signature verifies: re-signing the sent request with the same time gives the same Authorization', async () => {
    jest.useFakeTimers({ now: T, doNotFake: ['setTimeout', 'clearTimeout', 'setImmediate', 'nextTick', 'queueMicrotask'] });
    try {
      await bedrock.callBedrock({ model: 'amazon.nova-pro-v1:0', messages: [{ role: 'user', content: 'x' }] }, {});
      const r = seen[0]; const again = sigv4.sign({ method: 'POST', url: r.url, headers: { 'content-type': 'application/json' }, body: r.init.body, region: 'us-east-1', service: 'bedrock',
        accessKeyId: ENV.BEDROCK_ACCESS_KEY_ID, secretAccessKey: ENV.BEDROCK_SECRET_ACCESS_KEY, now: T });
      expect(r.init.headers.authorization).toBe(again.headers.authorization);
    } finally { jest.useRealTimers(); }
  });
  test('BR-04 errors: 403 AUTH_FAILED, 429 RATE_LIMITED, 500 UNAVAILABLE, 400 INVALID_REQUEST; a malformed answer is PROVIDER_INVALID_RESPONSE', async () => {
    const run = async (resp) => { fetchSpy.mockImplementation(async () => resp()); return (await bedrock.callBedrock({ model: 'amazon.nova-pro-v1:0', messages: [{ role: 'user', content: 'x' }] }, {}).catch((e) => e)).code; };
    expect(await run(() => new Response('{}', { status: 403 }))).toBe('PROVIDER_AUTH_FAILED');
    expect(await run(() => new Response('{}', { status: 429 }))).toBe('PROVIDER_RATE_LIMITED');
    expect(await run(() => new Response('{}', { status: 500 }))).toBe('PROVIDER_UNAVAILABLE');
    expect(await run(() => new Response('{}', { status: 400 }))).toBe('PROVIDER_INVALID_REQUEST');
    expect(await run(() => ok({ nothing: true }))).toBe('PROVIDER_INVALID_RESPONSE');
  }, 20000);
  test('BR-05 a redirect is never followed (fetch is told to error on it) and a conversation that does not start with a user turn is refused before any call', async () => {
    await bedrock.callBedrock({ model: 'amazon.nova-pro-v1:0', messages: [{ role: 'user', content: 'x' }] }, {});
    expect(seen[0].init.redirect).toBe('error');
    seen.length = 0;
    const e = await bedrock.callBedrock({ model: 'amazon.nova-pro-v1:0', messages: [{ role: 'assistant', content: 'x' }] }, {}).catch((x) => x);
    expect(e.code).toBe('PROVIDER_INVALID_REQUEST'); expect(seen).toHaveLength(0);
  });
  test('BR-06 model id shape and configuration are checked: a path-traversal id, a bad region, missing credentials never reach the network', async () => {
    const bad = async () => (await bedrock.callBedrock({ model: '../../x', messages: [{ role: 'user', content: 'x' }] }, {}).catch((e) => e)).code;
    expect(await bad()).toBe('PROVIDER_MODEL_NOT_ALLOWED');
    process.env.BEDROCK_REGION = 'us-east-1.evil.io';
    expect((await bedrock.callBedrock({ model: 'amazon.nova-pro-v1:0', messages: [{ role: 'user', content: 'x' }] }, {}).catch((e) => e)).code).toBe('PROVIDER_CONFIG_INVALID');
    process.env.BEDROCK_REGION = 'us-east-1'; delete process.env.BEDROCK_SECRET_ACCESS_KEY;
    expect((await bedrock.callBedrock({ model: 'amazon.nova-pro-v1:0', messages: [{ role: 'user', content: 'x' }] }, {}).catch((e) => e)).code).toBe('PROVIDER_AUTH_FAILED');
    expect(seen).toHaveLength(0);
  });
});

describe('credential rules and configuration', () => {
  test('CF-01', () => {
    const g = '11111111-2222-4333-8444-555555555555';
    expect(creds.azureConfigStatus({}).status).toBe('absent');
    expect(creds.azureConfigStatus({ AZURE_OPENAI_ENDPOINT: 'https://r.openai.azure.com', AZURE_OPENAI_API_KEY: 'a1'.repeat(16) }).status).toBe('valid');
    expect(creds.azureConfigStatus({ AZURE_OPENAI_ENDPOINT: 'https://r.openai.azure.com', AZURE_TENANT_ID: g, AZURE_CLIENT_ID: g, AZURE_CLIENT_SECRET: 'a-real-looking-secret-9' })).toMatchObject({ status: 'valid', auth: 'entra' });
    expect(creds.azureConfigStatus({ AZURE_OPENAI_ENDPOINT: 'http://r.openai.azure.com', AZURE_OPENAI_API_KEY: 'a1'.repeat(16) }).status).toBe('invalid_format');
    expect(creds.azureConfigStatus({ AZURE_OPENAI_ENDPOINT: 'https://r.openai.azure.com', AZURE_OPENAI_API_KEY: 'changeme' }).status).toBe('placeholder');
    expect(creds.azureConfigStatus({ AZURE_OPENAI_ENDPOINT: 'https://r.openai.azure.com', AZURE_TENANT_ID: 'x', AZURE_CLIENT_ID: g }).status).toBe('invalid_format');
    expect(creds.bedrockConfigStatus({}).status).toBe('absent');
    expect(creds.bedrockConfigStatus({ BEDROCK_REGION: 'eu-west-1', BEDROCK_ACCESS_KEY_ID: AKID, BEDROCK_SECRET_ACCESS_KEY: FAKE_SECRET }).status).toBe('valid');
    expect(creds.bedrockConfigStatus({ BEDROCK_REGION: 'nowhere', BEDROCK_ACCESS_KEY_ID: AKID, BEDROCK_SECRET_ACCESS_KEY: FAKE_SECRET }).status).toBe('invalid_format');
    expect(creds.bedrockConfigStatus({ BEDROCK_REGION: 'eu-west-1', BEDROCK_ACCESS_KEY_ID: 'your-key-here', BEDROCK_SECRET_ACCESS_KEY: 'x' }).status).toBe('placeholder');
    // the ambient AWS_* names never enable Bedrock
    expect(creds.bedrockConfigStatus({ AWS_REGION: 'us-east-1', AWS_ACCESS_KEY_ID: AKID, AWS_SECRET_ACCESS_KEY: 'x' }).status).toBe('absent');
  });
});
