// JavaScript SDK live contract probe. Run by scripts/contract/live-contract.js against a real server it booted:
// the BUILT SDK (sdk/javascript/dist, `npm run build`) exercises the SDK-facing flows and asserts the parsed shapes.
// Env: QODIQA_CONTRACT_BASE, QODIQA_CONTRACT_SIGN_KEY (sk_…), QODIQA_CONTRACT_OPS_KEY (ok_…). Prints one JSON line.
import { pathToFileURL } from 'node:url';
import path from 'node:path';

const dist = pathToFileURL(path.join(process.cwd(), 'sdk', 'javascript', 'dist', 'index.mjs')).href;
const { QodiqaClient, AuthenticationError } = await import(dist);
const base = process.env.QODIQA_CONTRACT_BASE;
const checks = [];
// Paced (400 ms): the transparency public bucket allows a burst of 15 per 5 s (src/core/rateLimit/config.js) — the probe
// respects the real limiter rather than relaxing it.
const check = async (name, fn) => {
  await new Promise((r) => setTimeout(r, 400));
  try { const detail = await fn(); checks.push({ name, ok: true, ...(detail !== undefined ? { detail } : {}) }); }
  catch (e) { checks.push({ name, ok: false, error: String(e && (e.message || e)).slice(0, 400), code: e && e.code }); }
};
const assert = (cond, msg) => { if (!cond) throw new Error(`assertion failed: ${msg}`); };
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64');

const client = new QodiqaClient({ baseUrl: base, signToken: process.env.QODIQA_CONTRACT_SIGN_KEY, apiKey: process.env.QODIQA_CONTRACT_OPS_KEY, maxRetries: 0, timeout: 20000 });
const anon = new QodiqaClient({ baseUrl: base, maxRetries: 0, timeout: 20000 });
const body = { prompt: 'What is the capital of Italy?', provider: 'llama', model: 'stub-model' };
let artifactId = null;

await check('healthCheck', async () => { const h = await client.healthCheck(); assert(h.status === 'ok', 'status ok'); });
await check('getPublicKeys', async () => { const k = await client.getPublicKeys(); assert(Array.isArray(k.keys ?? k) , 'keys array'); });
await check('sign.sign + chat.create EXECUTE', async () => {
  const s = await client.sign.sign({ request: { method: 'POST', path: '/ai/chat', body }, payload: { provider: 'llama' } });
  assert(s.artifact && typeof s.artifact.signature === 'string' && s.artifact.signature.length === 88, 'canonical 88-char signature');
  assert(typeof s.meta.effectiveTtlMs === 'number', 'meta.effectiveTtlMs');
  const r = await client.chat.create(b64(s.artifact), body);
  assert(r.decision === 'EXECUTE', `EXECUTE, got ${r.decision} ${r.reason}`);
  artifactId = r.artifactId;
  return { decision: r.decision, artifactId };
});
await new Promise((r) => setTimeout(r, 1500));
let tid = null;
await check('transparency.listEntries', async () => { const r = await client.transparency.listEntries({ page: 1, pageSize: 5 }); assert(Array.isArray(r.data.entries) && r.data.entries.length > 0, 'entries'); tid = r.data.entries[0].transparency_id; });
await check('transparency.getEntry', async () => { const r = await client.transparency.getEntry(tid); assert(r.data.entry.transparency_id === tid, 'entry id'); });
let gen = null;
await check('transparency.generateRoot', async () => { gen = (await client.transparency.generateRoot()).data; assert(/^[0-9a-f]{64}$/.test(gen.rootHash), 'rootHash'); });
await check('transparency.listRoots', async () => {
  const r = await client.transparency.listRoots({ page: 1, pageSize: 10 });
  assert(Array.isArray(r.data.roots) && r.data.roots.length > 0, 'data.roots non-empty');
  assert(r.data.roots.some((x) => x.root_hash === gen.rootHash), 'generated root listed');
  assert(typeof r.data.page === 'number' && typeof r.data.total === 'number', 'pagination meta');
  return { roots: r.data.roots.length };
});
await check('transparency.getRoot (latest)', async () => { const r = await client.transparency.getRoot(); assert(r.data.root && /^[0-9a-f]{64}$/.test(r.data.root.root_hash), 'root row'); });
await check('transparency.getRoot(rootId)', async () => { const r = await client.transparency.getRoot(gen.rootId); assert(r.data.root.root_id === gen.rootId, 'root by id'); });
await check('transparency.getProof', async () => { const r = await client.transparency.getProof(tid); assert(r.data.proof === null || (Array.isArray(r.data.proof.proof.merklePath) && /^[0-9a-f]{64}$/.test(r.data.proof.proof.merkleRoot)), 'proof document'); return { proof: r.data.proof ? 'present' : 'null' }; });
await check('transparency.verifyEntry', async () => { const r = await client.transparency.verifyEntry(tid); assert(['VALID', 'INVALID', 'PARTIAL', 'ERROR'].includes(r.data.result) && Array.isArray(r.data.integrityChecks), 'verification doc'); return { result: r.data.result }; });
await check('transparency.validateChain (transparency validator)', async () => { const r = await client.transparency.validateChain(); assert(r.data.chainValidation && r.data.chainValidation.valid === true, 'chainValidation.valid'); });
await check('getAuditChain (success envelope)', async () => { const r = await client.getAuditChain(artifactId); assert(r.status === 'success' && r.data, 'envelope with data'); });
await check('certification.evaluate sends ops credential (not 401)', async () => {
  try { await client.certification.evaluate({ artifacts: [] }); } catch (e) { if (e instanceof AuthenticationError) throw e; return { nonAuthError: e.constructor.name }; }
  return { ok: true };
});
await check('attestation.verifyChain sends ops credential (not 401)', async () => {
  try { await client.attestation.verifyChain({ evidenceIds: [] }); } catch (e) { if (e instanceof AuthenticationError) throw e; return { nonAuthError: e.constructor.name }; }
  return { ok: true };
});
await check('ops-only call without credentials → AuthenticationError', async () => {
  try { await anon.transparency.stats(); } catch (e) { assert(e instanceof AuthenticationError, `AuthenticationError, got ${e.constructor.name}`); return; }
  throw new Error('expected AuthenticationError');
});

const failed = checks.filter((c) => !c.ok);
process.stdout.write(`${JSON.stringify({ sdk: 'javascript', checks, failed: failed.length })}\n`);
process.exit(failed.length ? 1 : 0);
