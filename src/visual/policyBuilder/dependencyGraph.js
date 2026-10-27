'use strict';

/**
 * Dependency Graph — Component #41
 *
 * Given an array of policies, builds a dependency graph showing:
 *   - Policy inheritance relationships
 *   - Shared capabilities (referenced by multiple policies)
 *   - Shared resources
 *   - Execution dependencies (one policy referencing another)
 *
 * Pure function — returns a frozen graph object; no side-effects.
 */

const { NODE_TYPES, EDGE_TYPES, RISK_LEVELS } = require('./constants');

// ── Helpers ───────────────────────────────────────────────────────────────────

function _policyNodeId(policyId) {
  return `policy:${policyId}`;
}

function _capNodeId(cap) {
  return `cap:${cap}`;
}

function _resNodeId(res) {
  return `res:${res}`;
}

function _edgeKey(from, to, type) {
  return `${from}→${to}:${type}`;
}

function _assessPolicyRisk(policy) {
  if (policy.riskLevel === RISK_LEVELS.CRITICAL) return RISK_LEVELS.CRITICAL;
  if (policy.deprecated && policy.effect === 'allow') return RISK_LEVELS.CRITICAL;
  if (policy.expiresAt) {
    try {
      if (new Date(policy.expiresAt) < new Date()) return RISK_LEVELS.HIGH;
    } catch { /* ignore */ }
  }
  return policy.riskLevel || RISK_LEVELS.LOW;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Build a cross-policy dependency graph.
 *
 * @param {object[]} policies  — array of policy objects
 * @returns {{ nodes: object[], edges: object[], meta: object }}
 */
function buildDependencyGraph(policies) {
  if (!Array.isArray(policies)) {
    throw new TypeError('buildDependencyGraph: policies must be an array');
  }

  const nodes       = [];
  const edges       = [];
  const nodeMap     = new Map();  // id → node
  const edgeSet     = new Set();  // deduplication keys
  const incomingCount = new Map(); // nodeId → count of incoming edges (for shared detection)

  function _upsertNode(node) {
    if (!nodeMap.has(node.id)) {
      nodeMap.set(node.id, node);
      nodes.push(node);
    }
    return nodeMap.get(node.id);
  }

  function _addEdge(from, to, type, label) {
    const key = _edgeKey(from, to, type);
    if (!edgeSet.has(key)) {
      edgeSet.add(key);
      edges.push({ from, to, type, label });
      incomingCount.set(to, (incomingCount.get(to) || 0) + 1);
    }
  }

  // First pass — add all policy nodes so parent references can resolve
  for (const policy of policies) {
    if (!policy || typeof policy !== 'object') continue;
    const { policyId, version, effect } = policy;
    if (typeof policyId !== 'string' || !policyId) continue;

    _upsertNode({
      id:        _policyNodeId(policyId),
      type:      NODE_TYPES.POLICY,
      label:     policyId + (version ? ` v${version}` : ''),
      data: {
        policyId,
        version,
        effect:     effect || 'allow',
        deprecated: !!policy.deprecated,
        expiresAt:  policy.expiresAt || null,
      },
      riskLevel: _assessPolicyRisk(policy),
    });
  }

  // Second pass — build edges
  for (const policy of policies) {
    if (!policy || typeof policy !== 'object') continue;
    const { policyId, rules, inherits, capabilities, resources, dependsOn } = policy;
    if (typeof policyId !== 'string' || !policyId) continue;

    const pNodeId = _policyNodeId(policyId);

    // Inheritance edges
    const parentIds = Array.isArray(inherits) ? inherits : [];
    for (const parentId of parentIds) {
      if (typeof parentId !== 'string' || !parentId) continue;
      const parentNid = _policyNodeId(parentId);
      _upsertNode({
        id:       parentNid,
        type:     NODE_TYPES.POLICY,
        label:    `${parentId} (parent)`,
        data:     { policyId: parentId, isParent: true },
        riskLevel: RISK_LEVELS.LOW,
      });
      _addEdge(pNodeId, parentNid, EDGE_TYPES.INHERITS, 'inherits');
    }

    // Explicit dependency edges
    const deps = Array.isArray(dependsOn) ? dependsOn : [];
    for (const depId of deps) {
      if (typeof depId !== 'string' || !depId) continue;
      const depNid = _policyNodeId(depId);
      _upsertNode({
        id:       depNid,
        type:     NODE_TYPES.POLICY,
        label:    `${depId} (dependency)`,
        data:     { policyId: depId, isDependency: true },
        riskLevel: RISK_LEVELS.LOW,
      });
      _addEdge(pNodeId, depNid, EDGE_TYPES.DEPENDS, 'depends on');
    }

    // Top-level capability list
    const capList = Array.isArray(capabilities) ? capabilities : [];
    for (const cap of capList) {
      if (typeof cap !== 'string' || !cap) continue;
      _upsertNode({
        id:       _capNodeId(cap),
        type:     NODE_TYPES.CAPABILITY,
        label:    cap,
        data:     { capability: cap },
        riskLevel: RISK_LEVELS.LOW,
      });
      _addEdge(pNodeId, _capNodeId(cap), EDGE_TYPES.REQUIRES, 'capability');
    }

    // Top-level resource list
    const resList = Array.isArray(resources) ? resources : [];
    for (const res of resList) {
      if (typeof res !== 'string' || !res) continue;
      _upsertNode({
        id:       _resNodeId(res),
        type:     NODE_TYPES.RESOURCE,
        label:    res,
        data:     { resource: res },
        riskLevel: RISK_LEVELS.LOW,
      });
      _addEdge(pNodeId, _resNodeId(res), EDGE_TYPES.REQUIRES, 'resource');
    }

    // Capabilities and resources declared inline within rules
    const ruleList = Array.isArray(rules) ? rules : [];
    for (const rule of ruleList) {
      if (!rule || typeof rule !== 'object') continue;

      if (typeof rule.capability === 'string' && rule.capability) {
        _upsertNode({
          id:       _capNodeId(rule.capability),
          type:     NODE_TYPES.CAPABILITY,
          label:    rule.capability,
          data:     { capability: rule.capability },
          riskLevel: RISK_LEVELS.LOW,
        });
        _addEdge(pNodeId, _capNodeId(rule.capability), EDGE_TYPES.REQUIRES, 'capability');
      }

      if (typeof rule.resource === 'string' && rule.resource) {
        _upsertNode({
          id:       _resNodeId(rule.resource),
          type:     NODE_TYPES.RESOURCE,
          label:    rule.resource,
          data:     { resource: rule.resource },
          riskLevel: RISK_LEVELS.LOW,
        });
        _addEdge(pNodeId, _resNodeId(rule.resource), EDGE_TYPES.REQUIRES, 'resource');
      }
    }
  }

  // Mark nodes shared by more than one policy
  for (const node of nodes) {
    const ic = incomingCount.get(node.id) || 0;
    if (ic > 1) node.shared = true;
  }

  const policyNodes     = nodes.filter(n => n.type === NODE_TYPES.POLICY);
  const capabilityNodes = nodes.filter(n => n.type === NODE_TYPES.CAPABILITY);
  const resourceNodes   = nodes.filter(n => n.type === NODE_TYPES.RESOURCE);
  const inheritEdges    = edges.filter(e => e.type === EDGE_TYPES.INHERITS);
  const dependEdges     = edges.filter(e => e.type === EDGE_TYPES.DEPENDS);

  return Object.freeze({
    nodes: Object.freeze(nodes),
    edges: Object.freeze(edges),
    meta:  Object.freeze({
      policyCount:      policyNodes.length,
      capabilityCount:  capabilityNodes.length,
      resourceCount:    resourceNodes.length,
      inheritanceCount: inheritEdges.length,
      dependencyCount:  dependEdges.length,
      sharedNodeCount:  nodes.filter(n => n.shared).length,
      nodeCount:        nodes.length,
      edgeCount:        edges.length,
    }),
  });
}

module.exports = { buildDependencyGraph };
