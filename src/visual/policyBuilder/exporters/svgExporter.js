'use strict';

/**
 * SVG Exporter — Component #41
 *
 * Renders a laid-out graph (output of layoutEngine.applyLayout) to SVG markup.
 * No external dependencies — uses only string construction.
 *
 * Pure function — no state, no I/O.
 */

const { NODE_COLOURS, RISK_COLOURS, NODE_TYPES, RISK_LEVELS } = require('../constants');

// ── SVG helpers ───────────────────────────────────────────────────────────────

function _esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function _truncate(str, max) {
  const s = String(str || '');
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

// ── Node rendering ────────────────────────────────────────────────────────────

function _renderNode(node) {
  const { x, y, width, height, type, label, riskLevel } = node;
  const colours      = NODE_COLOURS[type] || NODE_COLOURS[NODE_TYPES.CONDITION];
  const riskStroke   = RISK_COLOURS[riskLevel];
  const stroke       = riskStroke || colours.stroke;
  const strokeWidth  = riskLevel === RISK_LEVELS.CRITICAL ? 3
                     : riskLevel === RISK_LEVELS.HIGH     ? 2.5
                     : 1.5;

  const radius    = 6;
  const cx        = x + width / 2;
  const cy        = y + height / 2;
  const shortLabel = _truncate(label, 24);

  let svg = '';

  // Shadow
  svg += `<rect x="${x + 2}" y="${y + 2}" width="${width}" height="${height}" rx="${radius}" ry="${radius}" fill="#000000" opacity="0.3"/>`;

  // Body
  svg += `<rect x="${x}" y="${y}" width="${width}" height="${height}" rx="${radius}" ry="${radius}" fill="${colours.fill}" stroke="${stroke}" stroke-width="${strokeWidth}"/>`;

  // Risk indicator bar at top
  if (riskStroke) {
    svg += `<rect x="${x + 1}" y="${y + 1}" width="${width - 2}" height="4" rx="${radius}" ry="${radius}" fill="${riskStroke}" opacity="0.85"/>`;
  }

  // Type badge (small pill in top-left)
  const badgeLabel = (type || '').toUpperCase().slice(0, 4);
  svg += `<rect x="${x + 5}" y="${y + 7}" width="${badgeLabel.length * 5 + 4}" height="10" rx="3" ry="3" fill="${colours.stroke}" opacity="0.25"/>`;
  svg += `<text x="${x + 7}" y="${y + 15.5}" font-size="6" font-family="monospace" fill="${colours.stroke}" opacity="0.9">${_esc(badgeLabel)}</text>`;

  // Label text (centred)
  svg += `<text x="${cx}" y="${cy + 5}" text-anchor="middle" font-size="11" font-family="'Segoe UI',system-ui,sans-serif" fill="${colours.text}" font-weight="500">${_esc(shortLabel)}</text>`;

  return svg;
}

// ── Edge rendering ────────────────────────────────────────────────────────────

/**
 * Find a node by id in the node array (O(n) — layouts are typically small).
 */
function _findNode(nodes, id) {
  return nodes.find(n => n.id === id) || null;
}

function _renderEdge(edge, nodes) {
  const from = _findNode(nodes, edge.from);
  const to   = _findNode(nodes, edge.to);
  if (!from || !to) return '';

  const x1 = from.x + from.width  / 2;
  const y1 = from.y + from.height;
  const x2 = to.x   + to.width    / 2;
  const y2 = to.y;

  // Cubic bezier for a gentle curve
  const cy1 = y1 + (y2 - y1) * 0.4;
  const cy2 = y2 - (y2 - y1) * 0.4;

  const edgeColours = {
    contains:  '#4b5563',
    requires:  '#22c55e',
    produces:  '#5b7cfa',
    inherits:  '#a855f7',
    depends:   '#f59e0b',
  };
  const stroke = edgeColours[edge.type] || '#4b5563';

  let svg = '';
  svg += `<path d="M ${x1} ${y1} C ${x1} ${cy1}, ${x2} ${cy2}, ${x2} ${y2}" stroke="${stroke}" stroke-width="1.5" fill="none" stroke-dasharray="${edge.type === 'inherits' ? '5,3' : 'none'}" opacity="0.7" marker-end="url(#arrowhead)"/>`;

  // Edge label (midpoint)
  if (edge.label) {
    const lx = (x1 + x2) / 2;
    const ly = (y1 + y2) / 2;
    svg += `<rect x="${lx - 18}" y="${ly - 7}" width="36" height="10" rx="3" fill="#0f1117" opacity="0.7"/>`;
    svg += `<text x="${lx}" y="${ly + 1}" text-anchor="middle" font-size="7" font-family="monospace" fill="#94a3b8">${_esc(_truncate(edge.label, 10))}</text>`;
  }

  return svg;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Export a laid-out graph to an SVG string.
 *
 * @param {{ nodes: object[], edges: object[], bounds: { width: number, height: number } }} layoutGraph
 * @param {object} [options]
 * @param {string} [options.title]        — optional title text
 * @param {string} [options.background]   — background fill (default #0f1117)
 * @returns {string}  SVG markup
 */
function exportSvg(layoutGraph, options) {
  if (!layoutGraph || typeof layoutGraph !== 'object') {
    throw new TypeError('exportSvg: layoutGraph must be a non-null object');
  }
  if (!Array.isArray(layoutGraph.nodes)) {
    throw new TypeError('exportSvg: layoutGraph.nodes must be an array');
  }

  const opts   = options || {};
  const nodes  = layoutGraph.nodes;
  const edges  = Array.isArray(layoutGraph.edges)  ? layoutGraph.edges  : [];
  const bounds = layoutGraph.bounds || { width: 800, height: 600 };
  const bg     = opts.background || '#0f1117';
  const title  = opts.title || 'QODIQA Policy Visual';

  const w = Math.max(bounds.width,  400);
  const h = Math.max(bounds.height, 300) + (opts.title ? 32 : 0);

  const titleOffset = opts.title ? 28 : 0;

  let svg = `<?xml version="1.0" encoding="UTF-8"?>\n`;
  svg += `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="${_esc(title)}">\n`;

  // Defs
  svg += `  <defs>\n`;
  svg += `    <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">\n`;
  svg += `      <polygon points="0 0, 8 3, 0 6" fill="#4b5563"/>\n`;
  svg += `    </marker>\n`;
  svg += `  </defs>\n`;

  // Background
  svg += `  <rect width="${w}" height="${h}" fill="${bg}"/>\n`;

  // Title
  if (opts.title) {
    svg += `  <text x="16" y="20" font-size="13" font-family="'Segoe UI',system-ui,sans-serif" fill="#e2e8f0" font-weight="600">${_esc(title)}</text>\n`;
  }

  // Graph group (shifted down if title present)
  svg += `  <g transform="translate(0,${titleOffset})">\n`;

  // Edges (behind nodes)
  for (const edge of edges) {
    svg += '    ' + _renderEdge(edge, nodes) + '\n';
  }

  // Nodes
  for (const node of nodes) {
    svg += '    ' + _renderNode(node) + '\n';
  }

  svg += `  </g>\n`;
  svg += `</svg>\n`;

  return svg;
}

module.exports = { exportSvg };
