'use strict';

/**
 * Tree Builder — Component #41
 *
 * Converts a QODIQA policy into a hierarchical tree model and provides
 * ASCII-art rendering for terminal and text-based displays.
 *
 * Pure functions — no state, no I/O.
 */

// ── ASCII characters ──────────────────────────────────────────────────────────

const _BRANCH = '├── '; // ├──
const _LAST   = '└── '; // └──
const _PIPE   = '│    ';           // │
const _SPACE  = '     ';

// ── Label helpers ─────────────────────────────────────────────────────────────

function _ruleLabel(rule, index) {
  if (rule.label) return rule.label;
  if (typeof rule.field === 'string' && rule.field && rule.operator) {
    const val = Array.isArray(rule.value)
      ? `[${rule.value.slice(0, 2).join(', ')}${rule.value.length > 2 ? '…' : ''}]`
      : String(rule.value !== undefined ? rule.value : '');
    return `Rule ${index + 1}: ${rule.field} ${rule.operator} ${val}`;
  }
  return `Rule ${index + 1}`;
}

function _conditionLabel(rule) {
  if (!rule || typeof rule !== 'object') return '(invalid)';
  const op  = rule.operator || '?';
  const val = Array.isArray(rule.value)
    ? `[${rule.value.slice(0, 3).join(', ')}${rule.value.length > 3 ? '…' : ''}]`
    : String(rule.value !== undefined ? rule.value : '');
  return `${rule.field || '?'} ${op} ${val}`;
}

// ── Sub-builders ──────────────────────────────────────────────────────────────

function _buildConditionNode(rule) {
  if (rule.group && typeof rule.group === 'object') {
    const logic = (rule.group.logic || 'AND').toUpperCase();
    const conds = Array.isArray(rule.group.conditions) ? rule.group.conditions : [];
    return {
      type:     'group',
      label:    `${logic} (${conds.length} condition${conds.length !== 1 ? 's' : ''})`,
      data:     { logic, conditionCount: conds.length },
      children: conds.map(c => ({
        type:     'condition',
        label:    _conditionLabel(c),
        data:     c,
        children: [],
      })),
    };
  }

  const extras = [];
  if (rule.capability) extras.push({ type: 'capability', label: `capability: ${rule.capability}`, data: { capability: rule.capability }, children: [] });
  if (rule.resource)   extras.push({ type: 'resource',   label: `resource: ${rule.resource}`,     data: { resource:   rule.resource   }, children: [] });
  if (rule.action)     extras.push({ type: 'action',     label: `action: ${rule.action}`,         data: { action:     rule.action     }, children: [] });

  return {
    type:     'condition',
    label:    _conditionLabel(rule),
    data:     { field: rule.field, operator: rule.operator, value: rule.value },
    children: extras,
  };
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Build a tree model from a policy.
 *
 * Shape:
 *   { type: 'policy', label, data, children: [ rule nodes ] }
 *
 * Each rule node has:
 *   { type: 'rule', label, data, children: [ condition node, result node ] }
 *
 * @param {object} policy
 * @returns {object}
 */
function buildTree(policy) {
  if (policy === null || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new TypeError('buildTree: policy must be a plain object');
  }
  if (typeof policy.policyId !== 'string' || policy.policyId.trim() === '') {
    throw new TypeError('buildTree: policy.policyId must be a non-empty string');
  }

  const { policyId, version, effect, rules } = policy;
  const ver      = version || 1;
  const eff      = effect  || 'allow';
  const ruleList = Array.isArray(rules) ? rules : [];

  const ruleNodes = ruleList.map((rule, ri) => {
    if (!rule || typeof rule !== 'object') {
      return {
        type:     'rule',
        label:    `Rule ${ri + 1}: (invalid)`,
        data:     null,
        children: [],
      };
    }

    const resultLabel = eff === 'deny' ? 'Result → BLOCK' : 'Result → EXECUTE';
    return {
      type:     'rule',
      label:    _ruleLabel(rule, ri),
      data:     { ...rule, _index: ri },
      children: [
        _buildConditionNode(rule),
        { type: 'result', label: resultLabel, data: { effect: eff }, children: [] },
      ],
    };
  });

  const tags = [];
  if (policy.deprecated)  tags.push('DEPRECATED');
  if (policy.expiresAt) {
    try {
      if (new Date(policy.expiresAt) < new Date()) tags.push('EXPIRED');
    } catch { /* ignore */ }
  }
  const tagStr = tags.length ? ` [${tags.join(', ')}]` : '';

  return {
    type:  'policy',
    label: `${policyId} v${ver} [${eff.toUpperCase()}]${tagStr}`,
    data: {
      policyId,
      version:    ver,
      effect:     eff,
      deprecated: !!policy.deprecated,
      expiresAt:  policy.expiresAt || null,
    },
    children: ruleNodes,
  };
}

/**
 * Render a tree node and its children to an ASCII string.
 * (Internal recursive helper — not exported.)
 *
 * @param {object}  node
 * @param {string}  prefix
 * @param {boolean} isLast
 * @returns {string}
 */
function _renderNode(node, prefix, isLast) {
  const connector  = isLast ? _LAST : _BRANCH;
  const childPfx   = prefix + (isLast ? _SPACE : _PIPE);
  const children   = Array.isArray(node.children) ? node.children : [];

  let out = prefix + connector + node.label + '\n';
  for (let i = 0; i < children.length; i++) {
    out += _renderNode(children[i], childPfx, i === children.length - 1);
  }
  return out;
}

/**
 * Render a tree model to an ASCII art string.
 *
 * @param {object} treeNode  — result of buildTree()
 * @returns {string}
 */
function renderTreeText(treeNode) {
  if (!treeNode || typeof treeNode !== 'object') {
    throw new TypeError('renderTreeText: treeNode must be a non-null object');
  }

  const children = Array.isArray(treeNode.children) ? treeNode.children : [];
  let out = treeNode.label + '\n';
  for (let i = 0; i < children.length; i++) {
    out += _renderNode(children[i], '', i === children.length - 1);
  }
  return out;
}

module.exports = { buildTree, renderTreeText };
