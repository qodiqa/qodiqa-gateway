'use strict';

/**
 * Policy Visual Builder API — Component #41
 *
 * All routes are ops-level authenticated (mounted behind _opsIpAllow + _opsAuth
 * + _opsGate in server.js), consistent with the adjacent policySimulate router.
 *
 * Routes (all under /v1/policy):
 *   POST /visual/graph      — build graph model from one policy
 *   POST /visual/tree       — build tree model from one policy
 *   POST /visual/deps       — build dependency graph from N policies
 *   POST /visual/stats      — generate statistics for one policy
 *   POST /visual/highlight  — build graph + apply risk highlighting
 *   GET  /visual/flow       — QODIQA decision flow stages
 *   POST /visual/export     — export graph as SVG, PNG, or JSON
 *
 * All routes are read-only: no audit, nonce, or rate-limit state is mutated.
 */

const { Router } = require('express');

const pv = require('../../visual/policyBuilder');
const { success, failure, internalError } = require('../response');
const { emit: _emit } = require('../../../services/logger');

// only the policy builder's own validation messages ("<function>: <reason>",
// src/visual/policyBuilder) are returned to the caller; any other exception (an unexpected runtime error) is logged
// and answered with a fixed message, so internal error text never reaches the client.
function _visualError(res, code, err, req) {
  const msg = err && typeof err.message === 'string' ? err.message : '';
  if (/^[a-z][A-Za-z]+: \S/.test(msg)) return failure(res, code, msg, 400); // lowerCamel builder function — never an errno like "ENOENT: …"
  _emit('ERROR', 'POLICY_VISUAL_UNEXPECTED_ERROR', { code, requestId: req && req.requestId ? req.requestId : null, error: msg });
  return failure(res, code, 'The policy could not be processed', 400);
}

// ── Input helpers ─────────────────────────────────────────────────────────────

function _parseBody(req) {
  return req.body || {};
}

function _requirePolicy(body, res) {
  const { policy } = body;
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    failure(res, 'MISSING_POLICY', 'body.policy must be a plain object', 400);
    return null;
  }
  return policy;
}

// ── Router factory ────────────────────────────────────────────────────────────

/**
 * @param {function(): ReadonlyArray} [getLivePolicies]  — optional; used by /visual/deps when no policies body supplied
 * @returns {Router}
 */
function createPolicyVisualRouter(getLivePolicies) {
  const router = Router();

  // ── POST /visual/graph ────────────────────────────────────────────────────
  router.post('/visual/graph', (req, res) => {
    const reqId  = req.requestId ?? null;
    const body   = _parseBody(req);
    const policy = _requirePolicy(body, res);
    if (!policy) return;

    let result;
    try {
      result = pv.buildGraph(policy);
    } catch (err) {
      return _visualError(res, 'BUILD_GRAPH_ERROR', err, req);
    }

    return success(res, result, 200);
  });

  // ── POST /visual/tree ─────────────────────────────────────────────────────
  router.post('/visual/tree', (req, res) => {
    const reqId  = req.requestId ?? null;
    const body   = _parseBody(req);
    const policy = _requirePolicy(body, res);
    if (!policy) return;

    const { format } = body;  // 'json' (default) or 'text'

    let tree;
    try {
      tree = pv.buildTree(policy);
    } catch (err) {
      return _visualError(res, 'BUILD_TREE_ERROR', err, req);
    }

    if (format === 'text') {
      let text;
      try {
        text = pv.renderTreeText(tree);
      } catch (err) {
        return internalError(res, req, err, { label: 'POLICY_VISUAL_RENDER_TREE_ERROR', code: 'RENDER_TREE_ERROR' });
      }
      return success(res, { tree, text }, 200);
    }

    return success(res, { tree }, 200);
  });

  // ── POST /visual/deps ─────────────────────────────────────────────────────
  router.post('/visual/deps', (req, res) => {
    const reqId = req.requestId ?? null;
    const body  = _parseBody(req);
    let   { policies } = body;

    // Fall back to live policy set if available
    if (!Array.isArray(policies)) {
      if (typeof getLivePolicies === 'function') {
        policies = getLivePolicies();
      } else {
        return failure(res, 'MISSING_POLICIES', 'body.policies must be an array', 400);
      }
    }

    if (!Array.isArray(policies)) {
      return failure(res, 'MISSING_POLICIES', 'body.policies must be an array', 400);
    }

    let result;
    try {
      result = pv.buildDependencyGraph(policies);
    } catch (err) {
      return _visualError(res, 'BUILD_DEPS_ERROR', err, req);
    }

    return success(res, result, 200);
  });

  // ── POST /visual/stats ────────────────────────────────────────────────────
  router.post('/visual/stats', (req, res) => {
    const reqId  = req.requestId ?? null;
    const body   = _parseBody(req);
    const policy = _requirePolicy(body, res);
    if (!policy) return;

    let stats;
    try {
      stats = pv.generateStatistics(policy);
    } catch (err) {
      return _visualError(res, 'STATS_ERROR', err, req);
    }

    return success(res, stats, 200);
  });

  // ── POST /visual/highlight ────────────────────────────────────────────────
  router.post('/visual/highlight', (req, res) => {
    const reqId  = req.requestId ?? null;
    const body   = _parseBody(req);
    const policy = _requirePolicy(body, res);
    if (!policy) return;

    let graph, result;
    try {
      graph  = pv.buildGraph(policy);
      result = pv.highlightRisks(graph);
    } catch (err) {
      return _visualError(res, 'HIGHLIGHT_ERROR', err, req);
    }

    return success(res, result, 200);
  });

  // ── GET /visual/flow ──────────────────────────────────────────────────────
  router.get('/visual/flow', (req, res) => {
    const flow   = pv.getDecisionFlow();
    const text   = pv.renderDecisionFlowText();
    return success(res, { stages: flow, text }, 200);
  });

  // ── POST /visual/export ───────────────────────────────────────────────────
  router.post('/visual/export', (req, res) => {
    const reqId  = req.requestId ?? null;
    const body   = _parseBody(req);
    const policy = _requirePolicy(body, res);
    if (!policy) return;

    const { format, layoutOptions, title } = body;
    const validFormats = new Set(['svg', 'png', 'json']);

    if (format && !validFormats.has(format)) {
      return failure(res, 'INVALID_FORMAT', `format must be one of: ${[...validFormats].join(', ')}`, 400);
    }

    const fmt = format || 'svg';

    let graph, laid;
    try {
      graph = pv.buildGraph(policy);
      const highlighted = pv.highlightRisks(graph);
      laid  = pv.applyLayout(highlighted, layoutOptions || {});
    } catch (err) {
      return _visualError(res, 'BUILD_ERROR', err, req);
    }

    // The three branches below export a graph as a binary/text artifact
    // (SVG, PNG, or a standalone JSON blob) — a different resource entirely
    // from this API's JSON envelope, so they intentionally stay outside the
    // success()/failure() convention used everywhere else in this file.
    if (fmt === 'svg') {
      let svg;
      try {
        svg = pv.exportSvg(laid, { title: title || policy.policyId });
      } catch (err) {
        return internalError(res, req, err, { label: 'POLICY_VISUAL_EXPORT_SVG_ERROR', code: 'EXPORT_SVG_ERROR' });
      }
      res.set('Content-Type', 'image/svg+xml');
      return res.status(200).send(svg);
    }

    if (fmt === 'png') {
      let png;
      try {
        png = pv.exportPng(laid);
      } catch (err) {
        return internalError(res, req, err, { label: 'POLICY_VISUAL_EXPORT_PNG_ERROR', code: 'EXPORT_PNG_ERROR' });
      }
      res.set('Content-Type', 'image/png');
      return res.status(200).send(png);
    }

    // fmt === 'json'
    let json;
    try {
      json = pv.exportJson(Object.assign({}, graph, { bounds: laid.bounds }), {
        source: 'policy-visual-builder-api',
        pretty: true,
      });
    } catch (err) {
      return internalError(res, req, err, { label: 'POLICY_VISUAL_EXPORT_JSON_ERROR', code: 'EXPORT_JSON_ERROR' });
    }
    res.set('Content-Type', 'application/json');
    return res.status(200).send(json);
  });

  // ── 405 catch-all — reject unsupported methods/paths under this mount ──────
  router.use((req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405));

  return router;
}

module.exports = { createPolicyVisualRouter };
