'use strict';

/**
 * Graph Builder — Component #41
 *
 * Converts a QODIQA policy object into a directed graph model suitable for
 * visual rendering, export, and programmatic traversal.
 *
 * The graph is a pure data structure: no rendering, no I/O, no side-effects.
 * All exported functions are deterministic pure functions given the same input.
 */

const {
  NODE_TYPES,
  EDGE_TYPES,
  RISK_LEVELS,
  HIGH_RISK_ACTIONS,
  HIGH_RISK_FIELDS,
  WILDCARD_VALUES,
} = require('./constants');

// ── Internal risk assessment ──────────────────────────────────────────────────

function _isWildcard(value) {
  if (typeof value === 'string' && WILDCARD_VALUES.has(value)) return true;
  if (Array.isArray(value) && value.some(v => WILDCARD_VALUES.has(String(v)))) return true;
  return false;
}

function _assessRuleRisk(rule) {
  if (!rule || typeof rule !== 'object') return RISK_LEVELS.LOW;

  if (rule.riskLevel === RISK_LEVELS.CRITICAL) return RISK_LEVELS.CRITICAL;
  if (rule.riskLevel === RISK_LEVELS.HIGH)     return RISK_LEVELS.HIGH;

  if (_isWildcard(rule.value)) return RISK_LEVELS.HIGH;

  if (typeof rule.field === 'string' && HIGH_RISK_FIELDS.has(rule.field.toLowerCase())) {
    return RISK_LEVELS.HIGH;
  }
  if (typeof rule.action === 'string' && HIGH_RISK_ACTIONS.has(rule.action.toLowerCase())) {
    return RISK_LEVELS.HIGH;
  }
  if (typeof rule.value === 'string' && HIGH_RISK_ACTIONS.has(rule.value.toLowerCase())) {
    return RISK_LEVELS.HIGH;
  }

  if (rule.riskLevel === RISK_LEVELS.MEDIUM) return RISK_LEVELS.MEDIUM;

  return RISK_LEVELS.LOW;
}

function _assessPolicyRisk(policy) {
  if (policy.riskLevel === RISK_LEVELS.CRITICAL) return RISK_LEVELS.CRITICAL;

  if (policy.deprecated && policy.effect === 'allow') return RISK_LEVELS.CRITICAL;

  if (policy.expiresAt) {
    try {
      if (new Date(policy.expiresAt) < new Date()) return RISK_LEVELS.HIGH;
    } catch { /* non-parseable date — ignore */ }
  }

  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  for (const rule of rules) {
    const ruleRisk = _assessRuleRisk(rule);
    if (ruleRisk === RISK_LEVELS.CRITICAL) return RISK_LEVELS.CRITICAL;
    if (ruleRisk === RISK_LEVELS.HIGH)     return RISK_LEVELS.HIGH;
  }

  return policy.riskLevel || RISK_LEVELS.LOW;
}

// ── ID helpers ────────────────────────────────────────────────────────────────

function _nid(...parts) {
  return parts.join(':');
}

// ── Label helpers ─────────────────────────────────────────────────────────────

function _conditionLabel(rule) {
  if (!rule || typeof rule !== 'object') return '(invalid condition)';
  const op  = rule.operator || '?';
  const val = Array.isArray(rule.value)
    ? `[${rule.value.slice(0, 3).join(', ')}${rule.value.length > 3 ? '…' : ''}]`
    : String(rule.value !== undefined ? rule.value : '');
  return `${rule.field || '?'} ${op} ${val}`;
}

// ── Sub-node builders ─────────────────────────────────────────────────────────

/**
 * Build condition, capability, resource, and action sub-nodes for a single rule.
 * Mutates nodes and edges in-place.
 *
 * @param {object}   rule
 * @param {string}   ruleNodeId
 * @param {number}   ruleIndex
 * @param {object[]} nodes
 * @param {object[]} edges
 * @param {Set}      seenNodeIds   — for deduplication
 */
function _expandRule(rule, ruleNodeId, ruleIndex, nodes, edges, seenNodeIds) {
  // Does the rule carry a nested condition group?
  if (rule.group && typeof rule.group === 'object') {
    const logic  = (rule.group.logic || 'AND').toUpperCase();
    const conds  = Array.isArray(rule.group.conditions) ? rule.group.conditions : [];
    const groupId = _nid('group', ruleNodeId);

    if (!seenNodeIds.has(groupId)) {
      seenNodeIds.add(groupId);
      nodes.push({
        id:        groupId,
        type:      NODE_TYPES.GROUP,
        label:     `${logic} (${conds.length})`,
        data:      { logic, conditionCount: conds.length },
        riskLevel: RISK_LEVELS.LOW,
      });
    }
    edges.push({ from: ruleNodeId, to: groupId, type: EDGE_TYPES.CONTAINS, label: 'group' });

    for (let ci = 0; ci < conds.length; ci++) {
      const cond   = conds[ci];
      const condId = _nid('cond', ruleNodeId, 'g', ci);
      if (!seenNodeIds.has(condId)) {
        seenNodeIds.add(condId);
        nodes.push({
          id:        condId,
          type:      NODE_TYPES.CONDITION,
          label:     _conditionLabel(cond),
          data:      { ...cond, _ruleIndex: ruleIndex, _condIndex: ci },
          riskLevel: _assessRuleRisk(cond),
        });
      }
      edges.push({ from: groupId, to: condId, type: EDGE_TYPES.CONTAINS, label: logic });
    }
    return;
  }

  // Simple rule → one condition node
  const condId = _nid('cond', ruleNodeId, 0);
  if (!seenNodeIds.has(condId)) {
    seenNodeIds.add(condId);
    nodes.push({
      id:        condId,
      type:      NODE_TYPES.CONDITION,
      label:     _conditionLabel(rule),
      data:      { field: rule.field, operator: rule.operator, value: rule.value, _ruleIndex: ruleIndex },
      riskLevel: _assessRuleRisk(rule),
    });
  }
  edges.push({ from: ruleNodeId, to: condId, type: EDGE_TYPES.CONTAINS, label: 'condition' });

  // Capability sub-node
  if (typeof rule.capability === 'string' && rule.capability) {
    const capId = _nid('cap', rule.capability);
    if (!seenNodeIds.has(capId)) {
      seenNodeIds.add(capId);
      nodes.push({
        id:        capId,
        type:      NODE_TYPES.CAPABILITY,
        label:     rule.capability,
        data:      { capability: rule.capability },
        riskLevel: RISK_LEVELS.LOW,
      });
    }
    edges.push({ from: condId, to: capId, type: EDGE_TYPES.REQUIRES, label: 'capability' });
  }

  // Resource sub-node
  if (typeof rule.resource === 'string' && rule.resource) {
    const resId = _nid('res', rule.resource);
    if (!seenNodeIds.has(resId)) {
      seenNodeIds.add(resId);
      nodes.push({
        id:        resId,
        type:      NODE_TYPES.RESOURCE,
        label:     rule.resource,
        data:      { resource: rule.resource },
        riskLevel: _assessRuleRisk(rule),
      });
    }
    edges.push({ from: condId, to: resId, type: EDGE_TYPES.REQUIRES, label: 'resource' });
  }

  // Action sub-node
  if (typeof rule.action === 'string' && rule.action) {
    const actId = _nid('act', rule.action);
    if (!seenNodeIds.has(actId)) {
      seenNodeIds.add(actId);
      nodes.push({
        id:        actId,
        type:      NODE_TYPES.ACTION,
        label:     rule.action,
        data:      { action: rule.action },
        riskLevel: HIGH_RISK_ACTIONS.has(rule.action.toLowerCase())
          ? RISK_LEVELS.HIGH
          : RISK_LEVELS.LOW,
      });
    }
    edges.push({ from: condId, to: actId, type: EDGE_TYPES.REQUIRES, label: 'action' });
  }
}

// ── Input validation ──────────────────────────────────────────────────────────

function _assertPolicy(policy, caller) {
  if (policy === null || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new TypeError(`${caller}: policy must be a plain object`);
  }
  if (typeof policy.policyId !== 'string' || policy.policyId.trim() === '') {
    throw new TypeError(`${caller}: policy.policyId must be a non-empty string`);
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Build a directed graph model from a single policy.
 *
 * Returns a frozen object with shape:
 *   { nodes: object[], edges: object[], meta: object }
 *
 * Nodes carry: id, type, label, data, riskLevel
 * Edges carry: from, to, type, label
 *
 * @param {object} policy  — { policyId, version, effect, rules, ... }
 * @returns {{ nodes: object[], edges: object[], meta: object }}
 */
function buildGraph(policy) {
  _assertPolicy(policy, 'buildGraph');

  const { policyId, version, effect, rules } = policy;
  const ver       = version || 1;
  const eff       = effect  || 'allow';
  const nodes     = [];
  const edges     = [];
  const seenIds   = new Set();

  const policyRisk   = _assessPolicyRisk(policy);
  const policyNodeId = _nid('policy', policyId, ver);

  seenIds.add(policyNodeId);
  nodes.push({
    id:        policyNodeId,
    type:      NODE_TYPES.POLICY,
    label:     `${policyId} v${ver}`,
    data: {
      policyId,
      version:     ver,
      effect:      eff,
      deprecated:  !!policy.deprecated,
      expiresAt:   policy.expiresAt   || null,
      description: policy.description || null,
    },
    riskLevel: policyRisk,
  });

  // Rule nodes
  const ruleList = Array.isArray(rules) ? rules : [];
  for (let ri = 0; ri < ruleList.length; ri++) {
    const rule     = ruleList[ri];
    if (!rule || typeof rule !== 'object') continue;

    const ruleNodeId = _nid('rule', policyId, ri);
    const ruleRisk   = _assessRuleRisk(rule);
    const ruleLabel  = rule.label || `Rule ${ri + 1}`;

    seenIds.add(ruleNodeId);
    nodes.push({
      id:        ruleNodeId,
      type:      NODE_TYPES.RULE,
      label:     ruleLabel,
      data:      { ...rule, _index: ri },
      riskLevel: ruleRisk,
    });
    edges.push({ from: policyNodeId, to: ruleNodeId, type: EDGE_TYPES.CONTAINS, label: 'rule' });

    _expandRule(rule, ruleNodeId, ri, nodes, edges, seenIds);
  }

  // Decision node
  const decisionNodeId = _nid('decision', policyId, ver);
  const decisionLabel  = eff === 'deny' ? 'BLOCK' : 'EXECUTE';
  seenIds.add(decisionNodeId);
  nodes.push({
    id:        decisionNodeId,
    type:      NODE_TYPES.DECISION,
    label:     decisionLabel,
    data:      { effect: eff, decision: decisionLabel },
    riskLevel: eff === 'deny' ? RISK_LEVELS.MEDIUM : RISK_LEVELS.LOW,
  });
  edges.push({ from: policyNodeId, to: decisionNodeId, type: EDGE_TYPES.PRODUCES, label: 'produces' });

  // Inheritance reference nodes
  const inherits = Array.isArray(policy.inherits) ? policy.inherits : [];
  for (const parentId of inherits) {
    if (typeof parentId !== 'string' || !parentId) continue;
    const parentNodeId = _nid('policy', parentId, 'ref');
    if (!seenIds.has(parentNodeId)) {
      seenIds.add(parentNodeId);
      nodes.push({
        id:        parentNodeId,
        type:      NODE_TYPES.POLICY,
        label:     `${parentId} (inherited)`,
        data:      { policyId: parentId, inherited: true },
        riskLevel: RISK_LEVELS.LOW,
      });
    }
    edges.push({ from: policyNodeId, to: parentNodeId, type: EDGE_TYPES.INHERITS, label: 'inherits' });
  }

  return Object.freeze({
    nodes: Object.freeze(nodes),
    edges: Object.freeze(edges),
    meta:  Object.freeze({
      policyId,
      version:   ver,
      effect:    eff,
      riskLevel: policyRisk,
      nodeCount: nodes.length,
      edgeCount: edges.length,
    }),
  });
}

module.exports = { buildGraph };
