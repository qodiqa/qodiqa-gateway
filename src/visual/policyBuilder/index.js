'use strict';

/**
 * Policy Visual Builder — Component #41
 *
 * Public entry point.  Aggregates all sub-modules into a single coherent API.
 *
 * Usage:
 *   const pv = require('./src/visual/policyBuilder');
 *   const graph  = pv.buildGraph(policy);
 *   const laid   = pv.applyLayout(graph);
 *   const svg    = pv.exportSvg(laid, { title: policy.policyId });
 *   const png    = pv.exportPng(laid);
 *   const json   = pv.exportJson(graph);
 *   const tree   = pv.buildTree(policy);
 *   const text   = pv.renderTreeText(tree);
 *   const deps   = pv.buildDependencyGraph([policy1, policy2]);
 *   const stats  = pv.generateStatistics(policy);
 *   const highlighted = pv.highlightRisks(graph);
 *   const flow   = pv.getDecisionFlow();
 */

const { buildGraph }            = require('./graphBuilder');
const { buildTree, renderTreeText } = require('./treeBuilder');
const { buildDependencyGraph }  = require('./dependencyGraph');
const { applyLayout }           = require('./layoutEngine');
const { generateStatistics }    = require('./statistics');
const { highlightRisks, FINDING_CODES } = require('./riskHighlighter');
const { exportSvg }             = require('./exporters/svgExporter');
const { exportPng }             = require('./exporters/pngExporter');
const { exportJson, importJson, SCHEMA_VERSION } = require('./exporters/jsonExporter');
const {
  NODE_TYPES,
  EDGE_TYPES,
  RISK_LEVELS,
  DECISION_FLOW_STAGES,
  DEFAULT_OPTIONS: LAYOUT_DEFAULTS,
} = require('./constants');

// ── Decision flow ─────────────────────────────────────────────────────────────

/**
 * Return the ordered QODIQA decision flow stages.
 * Deterministic — always returns the same frozen array.
 *
 * @returns {ReadonlyArray<{ id: string, label: string, description: string }>}
 */
function getDecisionFlow() {
  return DECISION_FLOW_STAGES;
}

/**
 * Render the QODIQA decision flow as an ASCII diagram string.
 *
 * @returns {string}
 */
function renderDecisionFlowText() {
  const lines = [];
  for (let i = 0; i < DECISION_FLOW_STAGES.length; i++) {
    const stage = DECISION_FLOW_STAGES[i];
    lines.push(`  ${stage.label}`);
    if (i < DECISION_FLOW_STAGES.length - 1) lines.push('  ↓');
  }
  return lines.join('\n');
}

// ── Convenience pipeline ──────────────────────────────────────────────────────

/**
 * Full pipeline: policy → laid-out, risk-highlighted graph ready for export.
 *
 * @param {object}  policy
 * @param {object}  [layoutOptions]
 * @returns {{ nodes, edges, bounds, findings, summary, meta }}
 */
function buildVisual(policy, layoutOptions) {
  const graph       = buildGraph(policy);
  const highlighted = highlightRisks(graph);
  const laid        = applyLayout(highlighted, layoutOptions);
  return Object.assign({}, laid, {
    findings: highlighted.findings,
    summary:  highlighted.summary,
    meta:     graph.meta,
  });
}

// ── Module exports ────────────────────────────────────────────────────────────

module.exports = Object.freeze({
  // Core builders
  buildGraph,
  buildTree,
  renderTreeText,
  buildDependencyGraph,

  // Layout
  applyLayout,

  // Statistics
  generateStatistics,

  // Risk
  highlightRisks,
  FINDING_CODES,

  // Exporters
  exportSvg,
  exportPng,
  exportJson,
  importJson,

  // Decision flow
  getDecisionFlow,
  renderDecisionFlowText,

  // Convenience
  buildVisual,

  // Constants
  NODE_TYPES,
  EDGE_TYPES,
  RISK_LEVELS,
  SCHEMA_VERSION,
  LAYOUT_DEFAULTS,
});
