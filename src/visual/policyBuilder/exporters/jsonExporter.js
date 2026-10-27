'use strict';

/**
 * JSON Graph Model Exporter — Component #41
 *
 * Serialises a graph model (or laid-out graph) to a stable, self-describing
 * JSON document suitable for storage, interchange, or re-import.
 *
 * Pure function — no state, no I/O.
 */

// ── Schema version ────────────────────────────────────────────────────────────

const SCHEMA_VERSION = '1.0.0';

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Export a graph model to a JSON string.
 *
 * @param {object} graph         — { nodes, edges, meta?, bounds?, findings? }
 * @param {object} [options]
 * @param {boolean} [options.pretty]   — pretty-print (default true)
 * @param {string}  [options.source]   — source description (e.g. "buildGraph")
 * @returns {string}  JSON document
 */
function exportJson(graph, options) {
  if (!graph || typeof graph !== 'object') {
    throw new TypeError('exportJson: graph must be a non-null object');
  }
  if (!Array.isArray(graph.nodes)) {
    throw new TypeError('exportJson: graph.nodes must be an array');
  }

  const opts   = options || {};
  const pretty = opts.pretty !== false;

  const document = {
    schemaVersion: SCHEMA_VERSION,
    exportedAt:    new Date().toISOString(),
    source:        opts.source || 'qodiqa-policy-visual-builder',
    meta:          graph.meta   || null,
    bounds:        graph.bounds || null,
    nodeCount:     graph.nodes.length,
    edgeCount:     Array.isArray(graph.edges) ? graph.edges.length : 0,
    nodes:         graph.nodes,
    edges:         Array.isArray(graph.edges)  ? graph.edges  : [],
    findings:      Array.isArray(graph.findings) ? graph.findings : [],
  };

  return pretty
    ? JSON.stringify(document, null, 2)
    : JSON.stringify(document);
}

/**
 * Parse a previously exported JSON graph document back to a graph object.
 *
 * @param {string} jsonStr
 * @returns {{ nodes: object[], edges: object[], meta: object|null, bounds: object|null }}
 */
function importJson(jsonStr) {
  if (typeof jsonStr !== 'string' || jsonStr.trim() === '') {
    throw new TypeError('importJson: jsonStr must be a non-empty string');
  }

  let parsed;
  try {
    parsed = JSON.parse(jsonStr);
  } catch (err) {
    throw new Error(`importJson: invalid JSON — ${err.message}`);
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('importJson: document root must be a plain object');
  }
  if (!Array.isArray(parsed.nodes)) {
    throw new Error('importJson: document.nodes must be an array');
  }

  return {
    nodes:    parsed.nodes,
    edges:    Array.isArray(parsed.edges)    ? parsed.edges    : [],
    findings: Array.isArray(parsed.findings) ? parsed.findings : [],
    meta:     parsed.meta   || null,
    bounds:   parsed.bounds || null,
  };
}

module.exports = { exportJson, importJson, SCHEMA_VERSION };
