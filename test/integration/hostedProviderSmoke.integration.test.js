'use strict';

/**
 * R-23: real end-to-end smoke test of each HOSTED provider
 * through the real gateway (bootstrap-dev → /sign → /ai/chat), with the output cap applied.
 *
 * NEVER runs by default. It needs ALL of:
 *   HOSTED_PROVIDER_SMOKE=1  and, per provider, its real key in the process environment (never .env):
 *   OPENAI_API_KEY · ANTHROPIC_API_KEY · GEMINI_API_KEY · MISTRAL_API_KEY — use keys with a hard SPEND CAP.
 *   Optional: HOSTED_SMOKE_MODEL_<PROVIDER> (else the provider's configured default model), HOSTED_SMOKE_MAX_TOKENS (16).
 * Plus the usual PG opt-in (pl-env.sh). Each provider gets its own boot with EXACTLY that one provider configured
 * (single-provider inference). One tiny request per provider; the key never appears in any assertion or record.
 * The base URLs of OpenAI/Anthropic/Gemini are hard-coded (SSRF policy) and cannot be pointed at a local stand-in, so
 * this cannot be rehearsed without real keys.
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const { PRODUCTION_DEFAULT_FLAGS } = require('../helpers/productionDefaultFlags');
const { startDisposableRedis, waitForReplayBarrier } = require('../harness/redis');

const PROVIDERS = [
  { name: 'openai', keyVar: 'OPENAI_API_KEY', capVar: 'OPENAI_MAX_TOKENS' },
  { name: 'anthropic', keyVar: 'ANTHROPIC_API_KEY', capVar: null }, // Anthropic's adapter always sends max_tokens
  { name: 'gemini', keyVar: 'GEMINI_API_KEY', capVar: 'GEMINI_MAX_TOKENS' },
  { name: 'mistral', keyVar: 'MISTRAL_API_KEY', capVar: 'MISTRAL_MAX_TOKENS' },
];
const OPT_IN = process.env.HOSTED_PROVIDER_SMOKE === '1' && process.env.QODIQA_PG_ENABLED === 'true' && !!process.env.QODIQA_PG_TEST_USER;
const CAP = process.env.HOSTED_SMOKE_MAX_TOKENS || '16';
const EVIDENCE_DIR = process.env.HOSTED_SMOKE_EVIDENCE_DIR || null;
jest.setTimeout(300000);

async function req(base, p, headers, body) {
  const r = await fetch(new URL(p, base), { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
  const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch { /* */ }
  return { status: r.status, json };
}

describe('R-23 hosted-provider smoke (opt-in, real keys with spend caps)', () => {
  test('is skipped unless explicitly enabled with real keys (default gate behaviour)', () => {
    if (!OPT_IN) expect(PROVIDERS.filter((p) => process.env[p.keyVar] && process.env.HOSTED_PROVIDER_SMOKE === '1')).toEqual([]);
  });

  for (const p of PROVIDERS) {
    const run = OPT_IN && !!process.env[p.keyVar];
    (run ? test : test.skip)(`${p.name}: one capped request through the real gateway → EXECUTE, answer within the cap`, async () => {
      const redis = await startDisposableRedis();
      const { prepareRigStores } = require('../../scripts/e2e/lib/rig');
      const rig = prepareRigStores(fs.mkdtempSync(path.join(os.tmpdir(), `hosted-${p.name}-`)));
      const others = Object.fromEntries(PROVIDERS.filter((x) => x !== p).map((x) => [x.keyVar, '']));
      const env = { ...rig.env, ...PRODUCTION_DEFAULT_FLAGS, QODIQA_PG_DATABASE: '', REDIS_URL: redis.url, LOCAL_BASE_URL: '', LLAMA_BASE_URL: '',
        ...others, [p.keyVar]: process.env[p.keyVar], ...(p.capVar ? { [p.capVar]: CAP } : {}) };
      const { startBootstrapped } = require('../harness/server');
      const srv = await startBootstrapped({ timeoutMs: 180000, env });
      try {
        await waitForReplayBarrier();
        const KEY = ((srv.startupResult.output || '').match(/Authorization: Bearer (\S+)/) || [])[1];
        expect(KEY).toBeTruthy();
        const model = process.env[`HOSTED_SMOKE_MODEL_${p.name.toUpperCase()}`];
        const body = { prompt: 'Reply with exactly one word: ok', provider: p.name, ...(model ? { model } : {}) };
        const s = await req(srv.baseUrl, '/sign', { Authorization: `Bearer ${KEY}` }, { request: { method: 'POST', path: '/ai/chat', body }, payload: { provider: p.name } });
        expect(s.status).toBe(200);
        const artifact = Buffer.from(JSON.stringify(s.json.artifact || s.json.data?.artifact || s.json)).toString('base64');
        const c = await req(srv.baseUrl, '/ai/chat', { 'x-qodiqa-artifact': artifact }, body);
        const out = c.json && (c.json.response || c.json.output || c.json.text || '');
        const record = { provider: p.name, model: model || '(provider default)', cap: CAP, status: c.status, decision: c.json && c.json.decision, reason: c.json && c.json.reason, answerChars: String(out).length };
        if (EVIDENCE_DIR) { fs.mkdirSync(EVIDENCE_DIR, { recursive: true }); fs.writeFileSync(path.join(EVIDENCE_DIR, `hosted-${p.name}.json`), JSON.stringify(record, null, 1)); }
        expect(record.decision).toBe('EXECUTE');
        // ~4 characters per token is generous; a 16-token cap cannot produce a long essay
        expect(record.answerChars).toBeLessThanOrEqual(Number(CAP) * 12);
      } finally {
        await srv.stop();
        if (redis.stop) await redis.stop();
      }
    });
  }
});
