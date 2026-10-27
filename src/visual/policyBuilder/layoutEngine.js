'use strict';

/**
 * Layout Engine — Component #41
 *
 * Assigns x, y positions and dimensions to graph nodes using a layered
 * Sugiyama-inspired layout algorithm.  Operates purely on the graph model
 * produced by graphBuilder or dependencyGraph — no rendering, no I/O.
 *
 * Algorithm:
 *   1. Assign each node to a layer based on its type (LAYER_ORDER).
 *   2. Within each layer, order nodes by the position of their first parent.
 *   3. Centre each layer horizontally within the canvas.
 *   4. Return enriched node objects with x, y, width, height, layer.
 */

const { LAYER_ORDER } = require('./constants');

// ── Default options ───────────────────────────────────────────────────────────

const DEFAULT_OPTIONS = Object.freeze({
  nodeWidth:     160,
  nodeHeight:     48,
  horizontalGap:  32,
  verticalGap:    72,
  padding:        48,
});

// ── Internal helpers ──────────────────────────────────────────────────────────

/**
 * Determine the layer index for a node.
 * Nodes with unknown types fall into layer 3 (peer of conditions).
 */
function _nodeLayer(node) {
  const v = LAYER_ORDER[node.type];
  return v !== undefined ? v : 3;
}

/**
 * Order nodes within a layer by the x-position of their first parent.
 * Nodes with no parent come last (stable sort).
 *
 * @param {object[]} layerNodes
 * @param {Map}      parentX     — nodeId → parent x (from prior layer)
 * @returns {object[]}
 */
function _orderByParent(layerNodes, parentX) {
  return layerNodes.slice().sort((a, b) => {
    const ax = parentX.get(a.id) !== undefined ? parentX.get(a.id) : Infinity;
    const bx = parentX.get(b.id) !== undefined ? parentX.get(b.id) : Infinity;
    return ax - bx;
  });
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Apply layout coordinates to a graph's nodes.
 *
 * @param {{ nodes: object[], edges: object[] }} graph
 * @param {object} [options]
 * @returns {{ nodes: object[], edges: object[], bounds: { width: number, height: number } }}
 */
function applyLayout(graph, options) {
  if (!graph || typeof graph !== 'object') {
    throw new TypeError('applyLayout: graph must be a non-null object');
  }
  if (!Array.isArray(graph.nodes)) {
    throw new TypeError('applyLayout: graph.nodes must be an array');
  }

  const opts = Object.assign({}, DEFAULT_OPTIONS, options || {});
  const { nodes, edges } = graph;

  // Group nodes by layer
  const layerMap = new Map();
  for (const node of nodes) {
    const layer = _nodeLayer(node);
    if (!layerMap.has(layer)) layerMap.set(layer, []);
    layerMap.get(layer).push(node);
  }

  // Sort layer indices
  const layerIndices = [...layerMap.keys()].sort((a, b) => a - b);

  // Build parent-edge lookup: child id → [parent id]
  const parentEdges = new Map();
  for (const edge of (Array.isArray(edges) ? edges : [])) {
    if (!parentEdges.has(edge.to)) parentEdges.set(edge.to, []);
    parentEdges.get(edge.to).push(edge.from);
  }

  // Compute positions layer by layer, tracking parent x for ordering
  const positionMap = new Map(); // nodeId → { x, y }
  const layoutNodes = [];

  let maxLayerWidth = 0;

  // First pass: compute max canvas width from the widest layer
  for (const li of layerIndices) {
    const layerNodes = layerMap.get(li);
    const w = layerNodes.length * opts.nodeWidth
            + (layerNodes.length - 1) * opts.horizontalGap;
    if (w > maxLayerWidth) maxLayerWidth = w;
  }

  const canvasWidth = maxLayerWidth + opts.padding * 2;

  // Second pass: position each layer
  for (let li = 0; li < layerIndices.length; li++) {
    const layerIndex = layerIndices[li];
    const rawNodes   = layerMap.get(layerIndex);

    // Build parent-x map for ordering within this layer
    const parentXMap = new Map();
    for (const node of rawNodes) {
      const parents = parentEdges.get(node.id) || [];
      for (const pid of parents) {
        const pos = positionMap.get(pid);
        if (pos !== undefined) {
          // Use average parent x
          const prev = parentXMap.get(node.id);
          parentXMap.set(node.id, prev !== undefined ? (prev + pos.x) / 2 : pos.x);
        }
      }
    }

    const ordered = _orderByParent(rawNodes, parentXMap);
    const layerW  = ordered.length * opts.nodeWidth
                  + (ordered.length - 1) * opts.horizontalGap;
    const startX  = opts.padding + (maxLayerWidth - layerW) / 2;
    const y       = opts.padding + li * (opts.nodeHeight + opts.verticalGap);

    for (let ni = 0; ni < ordered.length; ni++) {
      const node = ordered[ni];
      const x    = startX + ni * (opts.nodeWidth + opts.horizontalGap);
      const pos  = { x: Math.round(x), y: Math.round(y) };
      positionMap.set(node.id, pos);

      layoutNodes.push(Object.assign({}, node, {
        x:      pos.x,
        y:      pos.y,
        width:  opts.nodeWidth,
        height: opts.nodeHeight,
        layer:  layerIndex,
      }));
    }
  }

  const canvasHeight = opts.padding
    + layerIndices.length * (opts.nodeHeight + opts.verticalGap)
    + opts.padding;

  return {
    nodes:  layoutNodes,
    edges:  Array.isArray(edges) ? edges : [],
    bounds: { width: Math.round(canvasWidth), height: Math.round(canvasHeight) },
  };
}

module.exports = { applyLayout, DEFAULT_OPTIONS };
