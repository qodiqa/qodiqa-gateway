'use strict';

/**
 * Risk Highlighter — Component #41
 *
 * Annotates a graph model with risk findings: which nodes are critical,
 * which rules carry high-risk permissions, which policies are expired or
 * deprecated, and which conditions reference broad wildcards.
 *
 * Returns a structured findings array and an annotated node list.
 * Pure function — no state, no I/O.
 */

const {
  NODE_TYPES,
  RISK_LEVELS,
  WILDCARD_VALUES,
  HIGH_RISK_ACTIONS,
  HIGH_RISK_FIELDS,
} = require('./constants');

// ── Finding codes ─────────────────────────────────────────────────────────────

const FINDING_CODES = Object.freeze({
  CRITICAL_RULE:          'CRITICAL_RULE',
  HIGH_RISK_PERMISSION:   'HIGH_RISK_PERMISSION',
  SENSITIVE_RESOURCE:     'SENSITIVE_RESOURCE',
  BROAD_WILDCARD:         'BROAD_WILDCARD',
  EXPIRED_POLICY:         'EXPIRED_POLICY',
  DEPRECATED_CAPABILITY:  'DEPRECATED_CAPABILITY',
  DEPRECATED_POLICY:      'DEPRECATED_POLICY',
  HIGH_RISK_ACTION:       'HIGH_RISK_ACTION',
  DENY_EFFECT:            'DENY_EFFECT',
});

// ── Internal helpers ──────────────────────────────────────────────────────────

function _isWildcard(value) {
  if (typeof value === 'string' && WILDCARD_VALUES.has(value)) return true;
  if (Array.isArray(value) && value.some(v => WILDCARD_VALUES.has(String(v)))) return true;
  return false;
}

function _finding(code, nodeId, message, riskLevel) {
  return Object.freeze({ code, nodeId, message, riskLevel });
}

function _inspectNode(node, findings) {
  const { id, type, data, riskLevel } = node;
  if (!data) return;

  // Explicit critical risk
  if (riskLevel === RISK_LEVELS.CRITICAL) {
    findings.push(_finding(FINDING_CODES.CRITICAL_RULE, id,
      `Node "${node.label}" is marked critical risk`, RISK_LEVELS.CRITICAL));
  }

  if (type === NODE_TYPES.POLICY) {
    // Expired policy
    if (data.expiresAt) {
      try {
        if (new Date(data.expiresAt) < new Date()) {
          findings.push(_finding(FINDING_CODES.EXPIRED_POLICY, id,
            `Policy "${data.policyId}" expired at ${data.expiresAt}`, RISK_LEVELS.HIGH));
        }
      } catch { /* ignore */ }
    }

    // Deprecated policy
    if (data.deprecated) {
      findings.push(_finding(FINDING_CODES.DEPRECATED_POLICY, id,
        `Policy "${data.policyId}" is marked deprecated`, RISK_LEVELS.HIGH));
    }

    // deny effect
    if (data.effect === 'deny') {
      findings.push(_finding(FINDING_CODES.DENY_EFFECT, id,
        `Policy "${data.policyId}" uses deny effect — inverted logic`, RISK_LEVELS.MEDIUM));
    }
  }

  if (type === NODE_TYPES.CONDITION || type === NODE_TYPES.RULE) {
    const value    = data.value;
    const field    = data.field;
    const operator = data.operator;
    const action   = data.action;

    // Broad wildcard in value
    if (_isWildcard(value)) {
      findings.push(_finding(FINDING_CODES.BROAD_WILDCARD, id,
        `Node "${node.label}" uses a broad wildcard value "${value}"`, RISK_LEVELS.HIGH));
    }

    // High-risk field reference
    if (typeof field === 'string' && HIGH_RISK_FIELDS.has(field.toLowerCase())) {
      findings.push(_finding(FINDING_CODES.HIGH_RISK_PERMISSION, id,
        `Rule targets sensitive field "${field}"`, RISK_LEVELS.HIGH));
    }

    // High-risk action
    if (typeof action === 'string' && HIGH_RISK_ACTIONS.has(action.toLowerCase())) {
      findings.push(_finding(FINDING_CODES.HIGH_RISK_ACTION, id,
        `Rule references high-risk action "${action}"`, RISK_LEVELS.HIGH));
    }
    if (typeof value === 'string' && HIGH_RISK_ACTIONS.has(value.toLowerCase())) {
      findings.push(_finding(FINDING_CODES.HIGH_RISK_ACTION, id,
        `Rule value targets high-risk action "${value}"`, RISK_LEVELS.HIGH));
    }

    // notIn with empty value array is suspicious
    if (operator === 'notIn' && Array.isArray(value) && value.length === 0) {
      findings.push(_finding(FINDING_CODES.BROAD_WILDCARD, id,
        `Rule uses "notIn []" which matches everything`, RISK_LEVELS.CRITICAL));
    }
  }

  if (type === NODE_TYPES.CAPABILITY && data.deprecated) {
    findings.push(_finding(FINDING_CODES.DEPRECATED_CAPABILITY, id,
      `Capability "${data.capability}" is deprecated`, RISK_LEVELS.MEDIUM));
  }

  if (type === NODE_TYPES.RESOURCE) {
    // Resources with wildcard-like names
    const resName = (data.resource || '').toString();
    if (WILDCARD_VALUES.has(resName) || resName.includes('*')) {
      findings.push(_finding(FINDING_CODES.SENSITIVE_RESOURCE, id,
        `Resource "${resName}" is a broad wildcard`, RISK_LEVELS.HIGH));
    }
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Annotate a graph with risk findings.
 *
 * @param {{ nodes: object[], edges: object[], meta?: object }} graph
 * @returns {{ nodes: object[], edges: object[], findings: object[], summary: object }}
 */
function highlightRisks(graph) {
  if (!graph || typeof graph !== 'object') {
    throw new TypeError('highlightRisks: graph must be a non-null object');
  }
  if (!Array.isArray(graph.nodes)) {
    throw new TypeError('highlightRisks: graph.nodes must be an array');
  }

  const findings = [];

  // Inspect each node
  for (const node of graph.nodes) {
    _inspectNode(node, findings);
  }

  // Annotate nodes with their findings
  const findingsByNode = new Map();
  for (const f of findings) {
    if (!findingsByNode.has(f.nodeId)) findingsByNode.set(f.nodeId, []);
    findingsByNode.get(f.nodeId).push(f);
  }

  const annotatedNodes = graph.nodes.map(node => {
    const nodeFindings = findingsByNode.get(node.id) || [];
    if (nodeFindings.length === 0) return node;

    // Escalate riskLevel to the highest finding level
    const levelOrder = [RISK_LEVELS.LOW, RISK_LEVELS.MEDIUM, RISK_LEVELS.HIGH, RISK_LEVELS.CRITICAL];
    let highestLevel = node.riskLevel || RISK_LEVELS.LOW;
    for (const f of nodeFindings) {
      if (levelOrder.indexOf(f.riskLevel) > levelOrder.indexOf(highestLevel)) {
        highestLevel = f.riskLevel;
      }
    }

    return Object.assign({}, node, {
      riskLevel: highestLevel,
      findings:  nodeFindings,
    });
  });

  const criticalCount = findings.filter(f => f.riskLevel === RISK_LEVELS.CRITICAL).length;
  const highCount     = findings.filter(f => f.riskLevel === RISK_LEVELS.HIGH).length;
  const mediumCount   = findings.filter(f => f.riskLevel === RISK_LEVELS.MEDIUM).length;

  let overallRisk = RISK_LEVELS.LOW;
  if (criticalCount > 0) overallRisk = RISK_LEVELS.CRITICAL;
  else if (highCount > 0) overallRisk = RISK_LEVELS.HIGH;
  else if (mediumCount > 0) overallRisk = RISK_LEVELS.MEDIUM;

  return {
    nodes:    annotatedNodes,
    edges:    Array.isArray(graph.edges)  ? graph.edges  : [],
    meta:     graph.meta || null,
    findings,
    summary: Object.freeze({
      findingCount:  findings.length,
      criticalCount,
      highCount,
      mediumCount,
      overallRisk,
    }),
  };
}

module.exports = { highlightRisks, FINDING_CODES };
