'use strict';

/**
 * Administration of the dynamic OpenAI-compatible provider registry.
 *
 *   GET  /v1/admin/providers                 - list                       (READ_PROVIDERS)
 *   GET  /v1/admin/providers/:id             - one                        (READ_PROVIDERS)
 *   POST /v1/admin/providers                 - register  { id, baseUrl, apiKeyEnv?, models?, defaultModel?, timeoutMs?, maxTokens?, failoverProvider?, enabled? }  (MANAGE_PROVIDERS)
 *   PUT  /v1/admin/providers/:id             - change any of those except id  (MANAGE_PROVIDERS)
 *   POST /v1/admin/providers/:id/disable     - stop routing to it         (MANAGE_PROVIDERS)
 *   POST /v1/admin/providers/:id/enable      - resume                     (MANAGE_PROVIDERS)
 *
 * There is no DELETE: a provider is disabled, never removed (the name and its history stay reserved). Mounted behind the admin stack (operator authentication, RBAC,
 * admin-plane gates) and the operator MFA step-up (src/middleware/mfaStepUp.js) in src/app.js - registering a destination the gateway will send prompts to is a privileged change.
 * The response never carries a key: `apiKeyEnv` is only the NAME of the environment variable, and `keyConfigured` says whether it is set on THIS replica.
 */

const { Router } = require('express');
const registry = require('../../../core/providers/compatRegistry');
const { isControlPlaneError } = require('../../../core/controlPlane');
const { resolveOperatorActor } = require('../../../core/audit/actorAttribution');
const { success, failure } = require('../../response');
const { permissionGuard } = require('../permissionGuard');

function createProvidersAdminRouter({ requirePermission, getPolicies } = {}) {
  const router = Router();
  const _canRead = permissionGuard(requirePermission, 'READ_PROVIDERS', 'providersAdmin');
  const _canManage = permissionGuard(requirePermission, 'MANAGE_PROVIDERS', 'providersAdmin');

  function _handle(res, fn) {
    return Promise.resolve().then(fn).catch((err) => {
      if (err && err.name === 'CompatRegistryError') return failure(res, err.code, err.message, err.status);
      if (isControlPlaneError(err)) return failure(res, err.code, err.message, err.status);
      return failure(res, 'PROVIDER_REGISTRY_FAILED', 'The provider registry could not be changed.', 500);
    });
  }
  const idOf = (req) => String(req.params.id || '');

  router.get('/', _canRead, (req, res) => _handle(res, () => success(res, { providers: registry.list() })));
  // POST /compare - estimated cost, recent latency / failure rate / load and a weighted score for the enabled providers, for a request of the given size
  router.post('/compare', _canRead, (req, res) => _handle(res, () => {
    const b = req.body || {};
    const int = (v) => Number.isInteger(v) && v >= 0 && v <= 10_000_000;
    if (!int(b.inputTokens) || !int(b.outputTokens)) return failure(res, 'INVALID_COMPARE', 'inputTokens and outputTokens are integers between 0 and 10,000,000', 400);
    if (b.providers !== undefined && !(Array.isArray(b.providers) && b.providers.length <= 64 && b.providers.every((p) => typeof p === 'string'))) return failure(res, 'INVALID_COMPARE', 'providers is a list of provider names', 400);
    let policies = [];
    try { policies = typeof getPolicies === 'function' ? getPolicies() : []; } catch { policies = []; }
    try {
      return success(res, require('../../../core/providers/costAccounting').compare({ policies, providers: b.providers, inputTokens: b.inputTokens, outputTokens: b.outputTokens, weights: b.weights || {},
        names: require('../../../../services/providers/router').listEnabledProviders() }));
    } catch (e) { if (e instanceof RangeError) return failure(res, 'INVALID_COMPARE', e.message, 400); throw e; }
  }));
  router.get('/:id', _canRead, (req, res) => _handle(res, () => {
    const p = registry.get(idOf(req));
    if (!p) return failure(res, 'PROVIDER_NOT_FOUND', 'no such provider', 404);
    return success(res, { provider: p });
  }));
  router.post('/', _canManage, (req, res) => _handle(res, async () => success(res, { provider: await registry.register(req.body, resolveOperatorActor(req)) }, 201)));
  router.put('/:id', _canManage, (req, res) => _handle(res, async () => success(res, { provider: await registry.update(idOf(req), req.body || {}, resolveOperatorActor(req)) })));
  router.post('/:id/disable', _canManage, (req, res) => _handle(res, async () => success(res, { provider: await registry.setEnabled(idOf(req), false, resolveOperatorActor(req)) })));
  router.post('/:id/enable', _canManage, (req, res) => _handle(res, async () => success(res, { provider: await registry.setEnabled(idOf(req), true, resolveOperatorActor(req)) })));

  return router;
}

module.exports = { createProvidersAdminRouter };
