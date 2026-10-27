'use strict';

/**
 * SDK smoke test against a RUNNING gateway: the TypeScript SDK (sdk/javascript/dist, build it first) end to end.
 * Env: QODIQA_BASE_URL, QODIQA_SIGN_TOKEN (sk_...), QODIQA_API_KEY (ok_...). Prints one line per check; exits 1 if any failed.
 */

const sdk = require('../../../../../sdk/javascript/dist/index.js');

const base = process.env.QODIQA_BASE_URL;
const results = [];
const check = async (name, fn) => { try { const d = await fn(); results.push(['PASS', name, d || '']); } catch (e) { results.push(['FAIL', name, e && e.message]); } };

(async () => {
  const c = new sdk.QodiqaClient({ baseUrl: base, apiKey: process.env.QODIQA_API_KEY, signToken: process.env.QODIQA_SIGN_TOKEN, maxRetries: 1, timeout: 20000 });
  let artifact; let b64; let keys;
  await check('health + ready', async () => { const h = await c.healthCheck(); const r = await c.readinessCheck(); if (!r.ready) throw new Error('not ready'); return `health=${JSON.stringify(h).slice(0, 40)}`; });
  await check('public keys', async () => { keys = await c.getPublicKeys(); if (!keys.keys.length) throw new Error('no keys'); return `${keys.keys.length} keys`; });
  await check('sign', async () => { const s = await c.sign.sign({ request: { method: 'POST', path: '/ai/chat', body: { prompt: 'js sdk' } }, payload: { userId: 'smoke-js' }, ttl: 60000 }); artifact = s.artifact; b64 = Buffer.from(JSON.stringify(artifact)).toString('base64'); return s.artifactId; });
  await check('offline verification of the artifact against /public-keys', async () => {
    const v = await sdk.verifyArtifact(artifact, { clockToleranceMs: 5000, keys: new sdk.StaticKeyProvider(keys.keys.map((k) => ({ keyId: k.keyId, algorithm: k.algorithm, publicKey: k.publicKey, status: k.status }))) });
    if (v.verificationStatus !== 'valid') throw new Error(`${v.verificationStatus} ${v.failedStage}`);
    return 'valid';
  });
  await check('request hash binding (artifact guard input)', async () => { if (artifact.payload.requestHash !== sdk.requestHash('POST', '/ai/chat', { prompt: 'js sdk' })) throw new Error('requestHash differs'); });
  await check('chat through the sandbox provider', async () => { const r = await c.chat.create(b64, { prompt: 'js sdk' }); if (r.decision !== 'EXECUTE' || !String(r.aiText).startsWith('[sandbox] js sdk')) throw new Error(JSON.stringify(r).slice(0, 200)); return r.aiText; });
  await check('replay of the same artifact is refused', async () => { const r = await c.chat.create(b64, { prompt: 'js sdk' }).catch((e) => e); if (!(r instanceof Error) && r.decision !== 'BLOCK') throw new Error('replay accepted'); return r instanceof Error ? r.reason || r.message : r.reason; });
  await check('generic operation: client.operations.listAlerts (operator key)', async () => { const r = await c.operations.listAlerts(); if (!r) throw new Error('empty'); return 'ok'; });
  await check('error mapping: a wrong signing key is an AuthenticationError', async () => {
    const bad = new sdk.QodiqaClient({ baseUrl: base, signToken: `sk_${'0'.repeat(64)}`, maxRetries: 0 });
    const e = await bad.sign.sign({ request: { method: 'POST', path: '/ai/chat', body: {} } }).catch((x) => x);
    if (!(e instanceof sdk.AuthenticationError)) throw new Error(`got ${e && e.constructor && e.constructor.name}`);
  });
  for (const [s, n, d] of results) console.log(`${s}  js: ${n}${d ? `  (${String(d).slice(0, 80)})` : ''}`);
  process.exit(results.some(([s]) => s === 'FAIL') ? 1 : 0);
})();
