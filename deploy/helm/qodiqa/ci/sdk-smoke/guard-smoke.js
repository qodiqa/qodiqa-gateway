'use strict';

/**
 * the Express artifact guard (sdk/javascript/dist) in front of a REAL Express app, trusting the RUNNING gateway's published keys (RemoteKeyProvider) and accepting only artifacts
 * the gateway signed for exactly that request. Env: QODIQA_BASE_URL, QODIQA_SIGN_TOKEN.
 */

const path = require('path');
const express = require(path.join(__dirname, '..', '..', '..', '..', '..', 'node_modules', 'express'));
const sdk = require('../../../../../sdk/javascript/dist/index.js');

const base = process.env.QODIQA_BASE_URL;
const out = []; const check = (ok, name, d) => out.push([ok ? 'PASS' : 'FAIL', name, d || '']);

(async () => {
  const keys = new sdk.RemoteKeyProvider({ discoveryUrl: `${base}/.well-known/qodiqa/keys` });
  const app = express();
  app.use(express.json());
  app.use('/protected', sdk.artifactGuard({ keys, clockToleranceMs: 5000 }));
  app.post('/protected/echo', (req, res) => res.json({ tenant: req.qodiqa.payload.tenantId, echo: req.body }));
  const srv = app.listen(0, '127.0.0.1');
  await new Promise((r) => srv.once('listening', r));
  const url = `http://127.0.0.1:${srv.address().port}/protected/echo`;

  const c = new sdk.QodiqaClient({ baseUrl: base, signToken: process.env.QODIQA_SIGN_TOKEN, maxRetries: 0 });
  const body = { prompt: 'guarded' };
  const s = await c.sign.sign({ request: { method: 'POST', path: '/protected/echo', body }, payload: { userId: 'guard-smoke' }, ttl: 60000 });
  const hdr = Buffer.from(JSON.stringify(s.artifact)).toString('base64');
  const post = (b, h) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...(h ? { 'x-qodiqa-artifact': h } : {}) }, body: JSON.stringify(b) });

  let r = await post(body, hdr); const ok = await r.json();
  check(r.status === 200 && ok.echo.prompt === 'guarded', 'a gateway-signed artifact bound to this request passes (keys fetched from the live gateway)', JSON.stringify(ok).slice(0, 80));
  r = await post({ prompt: 'tampered' }, hdr);
  check(r.status === 403 && (await r.json()).error.code === 'QODIQA_REQUEST_MISMATCH', 'the same artifact with another body is refused (403 QODIQA_REQUEST_MISMATCH)');
  r = await post(body);
  check(r.status === 401, 'no artifact is refused (401)');
  srv.close();
  for (const [st, n, d] of out) console.log(`${st}  guard: ${n}${d ? `  (${d})` : ''}`);
  process.exit(out.some(([st]) => st === 'FAIL') ? 1 : 0);
})().catch((e) => { console.error('FAIL  guard:', e.message); process.exit(1); });
