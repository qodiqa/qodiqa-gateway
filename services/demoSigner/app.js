'use strict';

/**
 * Demo signer HTTP app (launch plan R-02).
 *
 *   POST /v1/demo/sign   {scenario, prompt}  ->  {scenario, request, artifactHeader, artifactId, expiresAt}
 *   GET  /v1/demo/status                     ->  {enabled, scenarios, limits}
 *   GET  /healthz                            ->  {ok}
 *
 * The signer signs exactly request = {method:'POST', path:<chatPath>, body:{prompt}} with the scenario's demo identity
 * and hands the artifact back. The BROWSER then sends exactly request.body to request.path on the gateway with
 * header `x-qodiqa-artifact: <artifactHeader>`, so every visitor action runs the gateway's full enforcement path
 * (signature, binding, replay, consent, policy, semantic, execution invariant). The signer never proxies /ai/chat.
 *
 * Order of checks on /v1/demo/sign: enabled -> body shape -> quota (fail-closed) -> gateway /sign.
 * Body validation runs BEFORE the quota so malformed requests cannot burn other visitors' global budget.
 */

const express = require('express');
const { resolveClientIp, parseTrustedProxyConfig } = require('../../src/infra/network/clientIpResolver');
const { hashClient, QuotaUnavailableError } = require('./quota');

const ALLOWED_FIELDS = new Set(['scenario', 'prompt']);
// eslint-disable-next-line no-control-regex
const FORBIDDEN_CONTROL_RE = /[\u0000-\u0008\u000B-\u001F\u007F]/;

function _err(res, status, code, extra) {
  return res.status(status).json({ error: code, ...(extra || {}) });
}

function validateSignBody(body, { scenarios, maxPromptChars }) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { code: 'DEMO_INVALID_REQUEST' };
  for (const k of Object.keys(body)) {
    if (k === 'stream' || k === 'model') return { code: 'DEMO_FIELD_NOT_ALLOWED', field: k };
    if (!ALLOWED_FIELDS.has(k)) return { code: 'DEMO_INVALID_REQUEST', field: k };
  }
  if (typeof body.scenario !== 'string' || !scenarios.includes(body.scenario)) return { code: 'DEMO_UNKNOWN_SCENARIO' };
  const p = body.prompt;
  if (typeof p !== 'string' || p.trim().length === 0) return { code: 'DEMO_INVALID_PROMPT' };
  if ([...p].length > maxPromptChars) return { code: 'DEMO_PROMPT_TOO_LONG', maxPromptChars };
  if (FORBIDDEN_CONTROL_RE.test(p)) return { code: 'DEMO_INVALID_PROMPT' };
  return null;
}

/**
 * @param {object} deps
 * @param {object} deps.config        loadConfig() result
 * @param {{ check: Function }} [deps.quota]
 * @param {{ sign: Function }} [deps.gatewayClient]
 * @param {(event: object) => void} [deps.log]
 * @param {() => number} [deps.now]
 */
function createDemoSignerApp({ config, quota, gatewayClient, log = () => {}, now = Date.now }) {
  const app = express();
  app.disable('x-powered-by');
  const trust = parseTrustedProxyConfig(config.trustedProxy);

  // CORS: one explicit origin, no credentials, JSON POST only. No origin configured -> same-origin only.
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (config.allowedOrigin && origin === config.allowedOrigin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      res.setHeader('Access-Control-Max-Age', '600');
    }
    if (req.method === 'OPTIONS') return res.status(204).end();
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    return next();
  });

  app.get('/healthz', (_req, res) => res.json({ ok: true }));

  app.get('/v1/demo/status', (_req, res) => res.json({
    enabled: config.enabled,
    scenarios: config.scenarios,
    limits: { perClientPerMinute: config.perIpPerMin, perClientPerDay: config.perIpPerDay, maxPromptChars: config.maxPromptChars },
    chatPath: config.chatPath,
  }));

  app.post('/v1/demo/sign',
    (req, res, next) => {
      if (!config.enabled) return _err(res, 503, 'DEMO_DISABLED');
      return next();
    },
    express.json({ limit: '16kb', strict: true, type: 'application/json' }),
    async (req, res) => {
      const started = now();
      const clientHash = hashClient(resolveClientIp(req, trust), config.ipHashSecret);
      const event = { event: 'DEMO_SIGN', ipHash: clientHash.slice(0, 16) };

      const invalid = validateSignBody(req.body, config);
      if (invalid) {
        log({ ...event, outcome: invalid.code, status: 400 });
        return _err(res, 400, invalid.code, invalid.field ? { field: invalid.field } : invalid.maxPromptChars ? { maxPromptChars: invalid.maxPromptChars } : undefined);
      }
      const { scenario, prompt } = req.body;
      event.scenario = scenario;

      let q;
      try {
        q = await quota.check(clientHash);
      } catch (err) {
        if (err instanceof QuotaUnavailableError) {
          log({ ...event, outcome: 'DEMO_QUOTA_UNAVAILABLE', status: 503 });
          return _err(res, 503, 'DEMO_QUOTA_UNAVAILABLE');
        }
        throw err;
      }
      if (!q.allowed) {
        res.setHeader('Retry-After', String(q.retryAfterSeconds));
        log({ ...event, outcome: 'DEMO_QUOTA_EXCEEDED', scope: q.scope, status: 429 });
        return _err(res, 429, 'DEMO_QUOTA_EXCEEDED', { scope: q.scope, retryAfterSeconds: q.retryAfterSeconds });
      }

      const request = { method: 'POST', path: config.chatPath, body: { prompt } };
      const signed = await gatewayClient.sign({ key: config.keys[scenario], request, provider: config.provider });
      if (!signed.ok) {
        log({ ...event, outcome: 'DEMO_SIGN_FAILED', upstreamStatus: signed.status, upstreamReason: signed.reason, status: 502, latencyMs: now() - started });
        return _err(res, 502, 'DEMO_SIGN_FAILED');
      }
      log({ ...event, outcome: 'SIGNED', artifactId: signed.artifactId, status: 200, latencyMs: now() - started });
      return res.status(200).json({
        scenario,
        request,
        artifactHeader: Buffer.from(JSON.stringify(signed.artifact), 'utf8').toString('base64'),
        artifactId: signed.artifactId,
        expiresAt: signed.expiresAt,
      });
    });

  app.use((_req, res) => _err(res, 404, 'NOT_FOUND'));
  // Body-parser and any unexpected error: never echo internals.
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    if (err && (err.type === 'entity.too.large')) return _err(res, 413, 'DEMO_REQUEST_TOO_LARGE');
    if (err && (err.type === 'entity.parse.failed' || err.status === 400)) return _err(res, 400, 'DEMO_INVALID_REQUEST');
    log({ event: 'DEMO_SIGNER_ERROR', message: err && err.message ? String(err.message).slice(0, 200) : 'unknown' });
    return _err(res, 500, 'DEMO_INTERNAL_ERROR');
  });

  return app;
}

module.exports = { createDemoSignerApp, validateSignBody };
