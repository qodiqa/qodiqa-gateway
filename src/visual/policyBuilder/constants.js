'use strict';

// ── Node types ────────────────────────────────────────────────────────────────

const NODE_TYPES = Object.freeze({
  POLICY:     'policy',
  RULE:       'rule',
  CONDITION:  'condition',
  GROUP:      'group',
  CAPABILITY: 'capability',
  RESOURCE:   'resource',
  ACTION:     'action',
  DECISION:   'decision',
});

// ── Edge types ────────────────────────────────────────────────────────────────

const EDGE_TYPES = Object.freeze({
  CONTAINS:  'contains',
  REQUIRES:  'requires',
  PRODUCES:  'produces',
  INHERITS:  'inherits',
  DEPENDS:   'depends',
});

// ── Risk levels ───────────────────────────────────────────────────────────────

const RISK_LEVELS = Object.freeze({
  LOW:      'low',
  MEDIUM:   'medium',
  HIGH:     'high',
  CRITICAL: 'critical',
});

// ── Risk signal sets ──────────────────────────────────────────────────────────

const HIGH_RISK_ACTIONS = Object.freeze(new Set([
  'delete', 'drop', 'truncate', 'destroy', 'purge', 'wipe',
  'overwrite', 'remove', 'erase', 'revoke', 'terminate',
]));

const HIGH_RISK_FIELDS = Object.freeze(new Set([
  'admin', 'root', 'superuser', 'system', 'god', 'master',
]));

const WILDCARD_VALUES = Object.freeze(new Set([
  '*', '.*', '**', 'ALL', 'any', 'all',
]));

// ── Decision flow stages (ordered) ────────────────────────────────────────────

const DECISION_FLOW_STAGES = Object.freeze([
  { id: 'request',             label: 'Request',              description: 'Inbound AI execution request received' },
  { id: 'authentication',      label: 'Authentication',       description: 'Ed25519 artifact signature verified' },
  { id: 'consent_validation',  label: 'Consent Validation',   description: 'Consent artifact presence and validity checked' },
  { id: 'capability_check',    label: 'Capability Validation', description: 'Capability tokens evaluated' },
  { id: 'policy_evaluation',   label: 'Policy Evaluation',    description: 'Policy rules evaluated against request context' },
  { id: 'risk_evaluation',     label: 'Risk Evaluation',      description: 'Risk level and anomaly signals assessed' },
  { id: 'decision',            label: 'Decision',             description: 'Final EXECUTE or BLOCK determination made' },
  { id: 'artifact_generation', label: 'Artifact Generation',  description: 'Immutable decision artifact produced and signed' },
]);

// ── Layer ordering for layout ──────────────────────────────────────────────────

const LAYER_ORDER = Object.freeze({
  [NODE_TYPES.POLICY]:     0,
  [NODE_TYPES.RULE]:       1,
  [NODE_TYPES.GROUP]:      2,
  [NODE_TYPES.CONDITION]:  2,
  [NODE_TYPES.CAPABILITY]: 3,
  [NODE_TYPES.RESOURCE]:   3,
  [NODE_TYPES.ACTION]:     3,
  [NODE_TYPES.DECISION]:   4,
});

// ── Node colours (used by SVG exporter) ───────────────────────────────────────

const NODE_COLOURS = Object.freeze({
  [NODE_TYPES.POLICY]:     { fill: '#1e3a5f', stroke: '#5b7cfa', text: '#e2e8f0' },
  [NODE_TYPES.RULE]:       { fill: '#1a2744', stroke: '#3b82f6', text: '#cbd5e1' },
  [NODE_TYPES.CONDITION]:  { fill: '#1e2d40', stroke: '#6366f1', text: '#c7d2fe' },
  [NODE_TYPES.GROUP]:      { fill: '#1a2533', stroke: '#8b5cf6', text: '#ddd6fe' },
  [NODE_TYPES.CAPABILITY]: { fill: '#1e3320', stroke: '#22c55e', text: '#bbf7d0' },
  [NODE_TYPES.RESOURCE]:   { fill: '#1e2f3c', stroke: '#06b6d4', text: '#a5f3fc' },
  [NODE_TYPES.ACTION]:     { fill: '#2d2416', stroke: '#f59e0b', text: '#fde68a' },
  [NODE_TYPES.DECISION]:   { fill: '#1e2d20', stroke: '#4ade80', text: '#dcfce7' },
});

// Risk-level overlay colours for border highlighting
const RISK_COLOURS = Object.freeze({
  [RISK_LEVELS.LOW]:      null,
  [RISK_LEVELS.MEDIUM]:   '#f59e0b',
  [RISK_LEVELS.HIGH]:     '#ef4444',
  [RISK_LEVELS.CRITICAL]: '#dc2626',
});

module.exports = {
  NODE_TYPES,
  EDGE_TYPES,
  RISK_LEVELS,
  HIGH_RISK_ACTIONS,
  HIGH_RISK_FIELDS,
  WILDCARD_VALUES,
  DECISION_FLOW_STAGES,
  LAYER_ORDER,
  NODE_COLOURS,
  RISK_COLOURS,
};
