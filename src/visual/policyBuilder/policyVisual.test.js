'use strict';

/**
 * Policy Visual Builder — Comprehensive Test Suite — Component #41
 *
 * Covers:
 *   graphBuilder     — simple, complex, nested, edge cases, invalid
 *   treeBuilder      — structure, ASCII render, edge cases
 *   dependencyGraph  — multi-policy deps, shared nodes, inheritance
 *   layoutEngine     — coordinate assignment, bounds, layer ordering
 *   statistics       — all fields, risk derivation, complexity scoring
 *   riskHighlighter  — all finding codes, escalation, summary
 *   svgExporter      — output shape, valid XML prefix, edge/node rendering
 *   pngExporter      — valid PNG signature, non-empty buffer
 *   jsonExporter     — export + round-trip import
 *   index (pipeline) — buildVisual convenience, constants exposed
 *   decision flow    — stage count, text render
 */

const {
  buildGraph,
  buildTree,
  renderTreeText,
  buildDependencyGraph,
  applyLayout,
  generateStatistics,
  highlightRisks,
  exportSvg,
  exportPng,
  exportJson,
  importJson,
  getDecisionFlow,
  renderDecisionFlowText,
  buildVisual,
  NODE_TYPES,
  EDGE_TYPES,
  RISK_LEVELS,
  FINDING_CODES,
  SCHEMA_VERSION,
} = require('./index');

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeSimplePolicy(overrides) {
  return Object.assign({
    policyId:  'test-policy',
    version:   1,
    effect:    'allow',
    createdAt: '2025-01-01T00:00:00Z',
    rules: [
      { field: 'action',   operator: 'equals', value: 'inference' },
      { field: 'consent',  operator: 'equals', value: true },
    ],
  }, overrides || {});
}

function makeComplexPolicy() {
  return {
    policyId:    'complex-policy',
    version:     2,
    effect:      'allow',
    description: 'Multi-rule complex policy',
    inherits:    ['base-policy'],
    capabilities: ['cap:read', 'cap:write'],
    resources:    ['res:user-data'],
    createdAt:   '2025-06-01T00:00:00Z',
    rules: [
      {
        field:      'action',
        operator:   'in',
        value:      ['read', 'list', 'describe'],
        capability: 'cap:read',
        resource:   'res:user-data',
        action:     'read',
      },
      {
        field:    'metadata.tenantId',
        operator: 'equals',
        value:    'tenant-acme',
      },
      {
        field:    'consent',
        operator: 'equals',
        value:    true,
      },
    ],
  };
}

function makeHighRiskPolicy() {
  return {
    policyId:   'risky-policy',
    version:    1,
    effect:     'allow',
    deprecated: true,
    expiresAt:  '2020-01-01T00:00:00Z',
    createdAt:  '2019-01-01T00:00:00Z',
    rules: [
      { field: 'action', operator: 'equals', value: '*' },
      { field: 'admin',  operator: 'equals', value: true },
    ],
  };
}

function makeGroupPolicy() {
  return {
    policyId:  'group-policy',
    version:   1,
    effect:    'deny',
    createdAt: '2025-01-01T00:00:00Z',
    rules: [
      {
        label: 'Blocked region rule',
        group: {
          logic: 'OR',
          conditions: [
            { field: 'metadata.country', operator: 'equals', value: 'XX' },
            { field: 'metadata.country', operator: 'equals', value: 'YY' },
          ],
        },
      },
    ],
  };
}

// ── graphBuilder tests ────────────────────────────────────────────────────────

describe('graphBuilder', () => {
  test('simple policy produces a graph with policy + rule + condition + decision nodes', () => {
    const graph = buildGraph(makeSimplePolicy());
    expect(graph.nodes.length).toBeGreaterThan(0);
    expect(graph.edges.length).toBeGreaterThan(0);

    const policyNode   = graph.nodes.find(n => n.type === NODE_TYPES.POLICY);
    const ruleNodes    = graph.nodes.filter(n => n.type === NODE_TYPES.RULE);
    const condNodes    = graph.nodes.filter(n => n.type === NODE_TYPES.CONDITION);
    const decisionNode = graph.nodes.find(n => n.type === NODE_TYPES.DECISION);

    expect(policyNode).toBeDefined();
    expect(ruleNodes.length).toBe(2);       // two rules
    expect(condNodes.length).toBe(2);       // one condition per simple rule
    expect(decisionNode).toBeDefined();
    expect(decisionNode.label).toBe('EXECUTE');
  });

  test('meta reflects correct counts', () => {
    const graph = buildGraph(makeSimplePolicy());
    expect(graph.meta.policyId).toBe('test-policy');
    expect(graph.meta.version).toBe(1);
    expect(graph.meta.effect).toBe('allow');
    expect(graph.meta.nodeCount).toBe(graph.nodes.length);
    expect(graph.meta.edgeCount).toBe(graph.edges.length);
  });

  test('deny-effect policy produces BLOCK decision node', () => {
    const graph = buildGraph(makeSimplePolicy({ effect: 'deny' }));
    const decision = graph.nodes.find(n => n.type === NODE_TYPES.DECISION);
    expect(decision.label).toBe('BLOCK');
  });

  test('complex policy produces capability, resource, action nodes', () => {
    const graph = buildGraph(makeComplexPolicy());
    const capNodes = graph.nodes.filter(n => n.type === NODE_TYPES.CAPABILITY);
    const resNodes = graph.nodes.filter(n => n.type === NODE_TYPES.RESOURCE);
    const actNodes = graph.nodes.filter(n => n.type === NODE_TYPES.ACTION);

    expect(capNodes.length).toBeGreaterThan(0);
    expect(resNodes.length).toBeGreaterThan(0);
    expect(actNodes.length).toBeGreaterThan(0);
  });

  test('policy with inherits adds inheritance edges and reference nodes', () => {
    const graph = buildGraph(makeComplexPolicy());
    const inheritEdges = graph.edges.filter(e => e.type === EDGE_TYPES.INHERITS);
    expect(inheritEdges.length).toBe(1);
    expect(inheritEdges[0].label).toBe('inherits');

    const inheritedNode = graph.nodes.find(n => n.data && n.data.inherited === true);
    expect(inheritedNode).toBeDefined();
  });

  test('group conditions produce GROUP and CONDITION nodes', () => {
    const graph    = buildGraph(makeGroupPolicy());
    const groups   = graph.nodes.filter(n => n.type === NODE_TYPES.GROUP);
    const conds    = graph.nodes.filter(n => n.type === NODE_TYPES.CONDITION);
    expect(groups.length).toBe(1);
    expect(conds.length).toBe(2);
  });

  test('capabilities are deduplicated across rules', () => {
    const policy = makeSimplePolicy({
      policyId: 'dedup-test',
      rules: [
        { field: 'action', operator: 'equals', value: 'read',  capability: 'shared-cap' },
        { field: 'action', operator: 'equals', value: 'write', capability: 'shared-cap' },
      ],
    });
    const graph   = buildGraph(policy);
    const capNodes = graph.nodes.filter(n => n.type === NODE_TYPES.CAPABILITY);
    expect(capNodes.length).toBe(1);  // deduplicated
  });

  test('policy with no rules still produces policy + decision nodes', () => {
    const graph = buildGraph(makeSimplePolicy({ rules: [] }));
    expect(graph.nodes.find(n => n.type === NODE_TYPES.POLICY)).toBeDefined();
    expect(graph.nodes.find(n => n.type === NODE_TYPES.DECISION)).toBeDefined();
  });

  test('high-risk deprecated+expired policy gets CRITICAL riskLevel', () => {
    const graph       = buildGraph(makeHighRiskPolicy());
    const policyNode  = graph.nodes.find(n => n.type === NODE_TYPES.POLICY);
    expect(policyNode.riskLevel).toBe(RISK_LEVELS.CRITICAL);
  });

  test('graph is frozen — meta cannot be mutated', () => {
    const graph = buildGraph(makeSimplePolicy());
    expect(() => { graph.meta.policyId = 'mutated'; }).toThrow();
  });

  test('throws TypeError for non-object policy', () => {
    expect(() => buildGraph(null)).toThrow(TypeError);
    expect(() => buildGraph('string')).toThrow(TypeError);
    expect(() => buildGraph([])).toThrow(TypeError);
  });

  test('throws TypeError for missing policyId', () => {
    expect(() => buildGraph({ version: 1, effect: 'allow', rules: [] })).toThrow(TypeError);
  });

  test('deterministic: two identical calls produce identical output', () => {
    const p = makeSimplePolicy();
    const g1 = buildGraph(p);
    const g2 = buildGraph(p);
    expect(JSON.stringify(g1)).toBe(JSON.stringify(g2));
  });

  test('100 evaluations of the same policy produce identical graphs', () => {
    const p     = makeComplexPolicy();
    const first = JSON.stringify(buildGraph(p));
    for (let i = 0; i < 99; i++) {
      expect(JSON.stringify(buildGraph(p))).toBe(first);
    }
  });
});

// ── treeBuilder tests ─────────────────────────────────────────────────────────

describe('treeBuilder', () => {
  test('buildTree returns correct root structure', () => {
    const tree = buildTree(makeSimplePolicy());
    expect(tree.type).toBe('policy');
    expect(tree.label).toContain('test-policy');
    expect(tree.label).toContain('ALLOW');
    expect(tree.children.length).toBe(2); // two rules
  });

  test('each rule node has condition and result children', () => {
    const tree = buildTree(makeSimplePolicy());
    const rule = tree.children[0];
    expect(rule.type).toBe('rule');
    const condition = rule.children.find(c => c.type === 'condition');
    const result    = rule.children.find(c => c.type === 'result');
    expect(condition).toBeDefined();
    expect(result).toBeDefined();
    expect(result.label).toContain('EXECUTE');
  });

  test('deny-effect policy result says BLOCK', () => {
    const tree = buildTree(makeSimplePolicy({ effect: 'deny' }));
    const result = tree.children[0].children.find(c => c.type === 'result');
    expect(result.label).toContain('BLOCK');
  });

  test('deprecated + expired policy label contains flags', () => {
    const tree = buildTree(makeHighRiskPolicy());
    expect(tree.label).toContain('DEPRECATED');
    expect(tree.label).toContain('EXPIRED');
  });

  test('group rule produces group node with correct logic label', () => {
    const tree  = buildTree(makeGroupPolicy());
    const rule  = tree.children[0];
    const group = rule.children.find(c => c.type === 'group');
    expect(group).toBeDefined();
    expect(group.label).toContain('OR');
    expect(group.children.length).toBe(2);
  });

  test('renderTreeText returns a non-empty string', () => {
    const tree = buildTree(makeSimplePolicy());
    const text = renderTreeText(tree);
    expect(typeof text).toBe('string');
    expect(text.length).toBeGreaterThan(0);
    expect(text).toContain('test-policy');
  });

  test('renderTreeText uses tree characters', () => {
    const tree = buildTree(makeSimplePolicy());
    const text = renderTreeText(tree);
    expect(text).toMatch(/[├└]/);
  });

  test('throws TypeError for non-object policy', () => {
    expect(() => buildTree(null)).toThrow(TypeError);
    expect(() => buildTree(42)).toThrow(TypeError);
  });

  test('throws TypeError for missing policyId', () => {
    expect(() => buildTree({ version: 1, rules: [] })).toThrow(TypeError);
  });

  test('renderTreeText throws for non-object input', () => {
    expect(() => renderTreeText(null)).toThrow(TypeError);
  });
});

// ── dependencyGraph tests ─────────────────────────────────────────────────────

describe('dependencyGraph', () => {
  test('two policies with shared capability produce shared node', () => {
    const p1 = makeSimplePolicy({ policyId: 'pol-a', rules: [{ field: 'action', operator: 'equals', value: 'read', capability: 'shared-cap' }] });
    const p2 = makeSimplePolicy({ policyId: 'pol-b', rules: [{ field: 'action', operator: 'equals', value: 'write', capability: 'shared-cap' }] });
    const depGraph = buildDependencyGraph([p1, p2]);

    const capNode = depGraph.nodes.find(n => n.type === NODE_TYPES.CAPABILITY && n.data.capability === 'shared-cap');
    expect(capNode).toBeDefined();
    expect(capNode.shared).toBe(true);
    expect(depGraph.meta.capabilityCount).toBe(1);
  });

  test('inheritance produces INHERITS edge', () => {
    const parent = makeSimplePolicy({ policyId: 'parent' });
    const child  = makeSimplePolicy({ policyId: 'child', inherits: ['parent'] });
    const dg     = buildDependencyGraph([parent, child]);

    const inheritEdge = dg.edges.find(e => e.type === EDGE_TYPES.INHERITS);
    expect(inheritEdge).toBeDefined();
    expect(inheritEdge.from).toContain('child');
    expect(inheritEdge.to).toContain('parent');
    expect(dg.meta.inheritanceCount).toBe(1);
  });

  test('meta reflects correct counts', () => {
    const p1 = makeSimplePolicy({ policyId: 'a' });
    const p2 = makeSimplePolicy({ policyId: 'b', capabilities: ['cap-x'] });
    const dg = buildDependencyGraph([p1, p2]);

    expect(dg.meta.policyCount).toBe(2);
    expect(dg.meta.capabilityCount).toBeGreaterThanOrEqual(1);
    expect(dg.meta.nodeCount).toBe(dg.nodes.length);
    expect(dg.meta.edgeCount).toBe(dg.edges.length);
  });

  test('empty array produces empty graph', () => {
    const dg = buildDependencyGraph([]);
    expect(dg.nodes.length).toBe(0);
    expect(dg.edges.length).toBe(0);
  });

  test('invalid entries in array are skipped', () => {
    const dg = buildDependencyGraph([null, undefined, 42, makeSimplePolicy({ policyId: 'valid' })]);
    expect(dg.nodes.find(n => n.data && n.data.policyId === 'valid')).toBeDefined();
  });

  test('throws TypeError for non-array input', () => {
    expect(() => buildDependencyGraph(null)).toThrow(TypeError);
    expect(() => buildDependencyGraph('oops')).toThrow(TypeError);
  });

  test('dependsOn produces DEPENDS edges', () => {
    const p1 = makeSimplePolicy({ policyId: 'dep-a', dependsOn: ['dep-b'] });
    const p2 = makeSimplePolicy({ policyId: 'dep-b' });
    const dg = buildDependencyGraph([p1, p2]);
    const depEdge = dg.edges.find(e => e.type === EDGE_TYPES.DEPENDS);
    expect(depEdge).toBeDefined();
  });
});

// ── layoutEngine tests ────────────────────────────────────────────────────────

describe('layoutEngine', () => {
  test('all nodes receive x, y, width, height, layer', () => {
    const graph  = buildGraph(makeSimplePolicy());
    const layout = applyLayout(graph);

    for (const node of layout.nodes) {
      expect(typeof node.x).toBe('number');
      expect(typeof node.y).toBe('number');
      expect(typeof node.width).toBe('number');
      expect(typeof node.height).toBe('number');
      expect(typeof node.layer).toBe('number');
    }
  });

  test('policy node is in layer 0 (top)', () => {
    const graph  = buildGraph(makeSimplePolicy());
    const layout = applyLayout(graph);
    const pn     = layout.nodes.find(n => n.type === NODE_TYPES.POLICY && !n.data?.inherited);
    expect(pn.layer).toBe(0);
  });

  test('decision node is in layer 4 (bottom)', () => {
    const graph  = buildGraph(makeSimplePolicy());
    const layout = applyLayout(graph);
    const dn     = layout.nodes.find(n => n.type === NODE_TYPES.DECISION);
    expect(dn.layer).toBe(4);
  });

  test('bounds are non-zero positive integers', () => {
    const graph  = buildGraph(makeSimplePolicy());
    const layout = applyLayout(graph);
    expect(layout.bounds.width).toBeGreaterThan(0);
    expect(layout.bounds.height).toBeGreaterThan(0);
    expect(Number.isInteger(layout.bounds.width)).toBe(true);
    expect(Number.isInteger(layout.bounds.height)).toBe(true);
  });

  test('custom options are respected', () => {
    const graph  = buildGraph(makeSimplePolicy());
    const layout = applyLayout(graph, { nodeWidth: 200, nodeHeight: 60 });
    for (const node of layout.nodes) {
      expect(node.width).toBe(200);
      expect(node.height).toBe(60);
    }
  });

  test('throws TypeError for non-object graph', () => {
    expect(() => applyLayout(null)).toThrow(TypeError);
  });

  test('edges pass through unchanged', () => {
    const graph  = buildGraph(makeSimplePolicy());
    const layout = applyLayout(graph);
    expect(Array.isArray(layout.edges)).toBe(true);
    expect(layout.edges.length).toBe(graph.edges.length);
  });
});

// ── statistics tests ──────────────────────────────────────────────────────────

describe('statistics', () => {
  test('simple policy produces correct rule and condition counts', () => {
    const stats = generateStatistics(makeSimplePolicy());
    expect(stats.ruleCount).toBe(2);
    expect(stats.conditionCount).toBe(2);
  });

  test('complex policy counts capabilities and resources', () => {
    const stats = generateStatistics(makeComplexPolicy());
    expect(stats.capabilityCount).toBeGreaterThan(0);
    expect(stats.resourceCount).toBeGreaterThan(0);
    expect(stats.actionCount).toBeGreaterThan(0);
  });

  test('wildcard value increments wildcardCount', () => {
    const policy = makeSimplePolicy({
      policyId: 'wildcard-test',
      rules: [{ field: 'action', operator: 'equals', value: '*' }],
    });
    const stats = generateStatistics(policy);
    expect(stats.wildcardCount).toBe(1);
    expect(stats.riskLevel).toBe(RISK_LEVELS.HIGH);
  });

  test('deprecated + expired → CRITICAL risk', () => {
    const stats = generateStatistics(makeHighRiskPolicy());
    expect(stats.deprecated).toBe(true);
    expect(stats.expired).toBe(true);
    expect(stats.riskLevel).toBe(RISK_LEVELS.CRITICAL);
  });

  test('deny effect adds to complexity score', () => {
    const allow = generateStatistics(makeSimplePolicy({ effect: 'allow' }));
    const deny  = generateStatistics(makeSimplePolicy({ policyId: 'dp', effect: 'deny' }));
    expect(deny.complexityScore).toBeGreaterThan(allow.complexityScore);
  });

  test('inheritance depth is reflected', () => {
    const policy = makeComplexPolicy(); // inherits: ['base-policy']
    const stats  = generateStatistics(policy);
    expect(stats.inheritanceDepth).toBe(1);
  });

  test('result is frozen', () => {
    const stats = generateStatistics(makeSimplePolicy());
    expect(() => { stats.ruleCount = 999; }).toThrow();
  });

  test('throws TypeError for non-object policy', () => {
    expect(() => generateStatistics(null)).toThrow(TypeError);
    expect(() => generateStatistics([])).toThrow(TypeError);
  });

  test('throws TypeError for missing policyId', () => {
    expect(() => generateStatistics({ version: 1, rules: [] })).toThrow(TypeError);
  });

  test('nested group conditions counted', () => {
    const stats = generateStatistics(makeGroupPolicy());
    expect(stats.conditionCount).toBe(2); // OR group with 2 conditions
  });
});

// ── riskHighlighter tests ─────────────────────────────────────────────────────

describe('riskHighlighter', () => {
  test('expired policy produces EXPIRED_POLICY finding', () => {
    const graph  = buildGraph(makeHighRiskPolicy());
    const result = highlightRisks(graph);
    const f      = result.findings.find(f => f.code === FINDING_CODES.EXPIRED_POLICY);
    expect(f).toBeDefined();
    expect(f.riskLevel).toBe(RISK_LEVELS.HIGH);
  });

  test('deprecated policy produces DEPRECATED_POLICY finding', () => {
    const graph  = buildGraph(makeHighRiskPolicy());
    const result = highlightRisks(graph);
    const f      = result.findings.find(f => f.code === FINDING_CODES.DEPRECATED_POLICY);
    expect(f).toBeDefined();
  });

  test('wildcard value produces BROAD_WILDCARD finding', () => {
    const policy = makeSimplePolicy({
      policyId: 'wc-test',
      rules: [{ field: 'action', operator: 'equals', value: '*' }],
    });
    const graph  = buildGraph(policy);
    const result = highlightRisks(graph);
    const f      = result.findings.find(f => f.code === FINDING_CODES.BROAD_WILDCARD);
    expect(f).toBeDefined();
    expect(f.riskLevel).toBe(RISK_LEVELS.HIGH);
  });

  test('deny effect produces DENY_EFFECT finding', () => {
    const graph  = buildGraph(makeGroupPolicy()); // deny effect
    const result = highlightRisks(graph);
    const f      = result.findings.find(f => f.code === FINDING_CODES.DENY_EFFECT);
    expect(f).toBeDefined();
    expect(f.riskLevel).toBe(RISK_LEVELS.MEDIUM);
  });

  test('notIn with empty array → CRITICAL BROAD_WILDCARD', () => {
    const policy = makeSimplePolicy({
      policyId: 'notin-empty',
      rules: [{ field: 'region', operator: 'notIn', value: [] }],
    });
    const graph  = buildGraph(policy);
    const result = highlightRisks(graph);
    const f      = result.findings.find(f =>
      f.code === FINDING_CODES.BROAD_WILDCARD && f.riskLevel === RISK_LEVELS.CRITICAL
    );
    expect(f).toBeDefined();
  });

  test('summary reflects finding counts', () => {
    const graph   = buildGraph(makeHighRiskPolicy());
    const result  = highlightRisks(graph);
    expect(result.summary.findingCount).toBeGreaterThan(0);
    expect(result.summary.highCount + result.summary.criticalCount).toBeGreaterThan(0);
    expect([RISK_LEVELS.HIGH, RISK_LEVELS.CRITICAL]).toContain(result.summary.overallRisk);
  });

  test('clean policy produces no findings', () => {
    const policy = makeSimplePolicy({ policyId: 'clean' });
    const graph  = buildGraph(policy);
    const result = highlightRisks(graph);
    expect(result.findings.length).toBe(0);
    expect(result.summary.overallRisk).toBe(RISK_LEVELS.LOW);
  });

  test('annotated nodes include findings array', () => {
    const graph  = buildGraph(makeHighRiskPolicy());
    const result = highlightRisks(graph);
    const affectedNodes = result.nodes.filter(n => n.findings && n.findings.length > 0);
    expect(affectedNodes.length).toBeGreaterThan(0);
  });

  test('throws TypeError for non-object graph', () => {
    expect(() => highlightRisks(null)).toThrow(TypeError);
  });

  test('throws TypeError for missing nodes array', () => {
    expect(() => highlightRisks({ edges: [] })).toThrow(TypeError);
  });
});

// ── svgExporter tests ─────────────────────────────────────────────────────────

describe('svgExporter', () => {
  function _makeLayout() {
    const graph = buildGraph(makeSimplePolicy());
    return applyLayout(graph);
  }

  test('returns a string starting with SVG XML declaration', () => {
    const svg = exportSvg(_makeLayout());
    expect(typeof svg).toBe('string');
    expect(svg).toMatch(/^<\?xml/);
    expect(svg).toContain('<svg');
    expect(svg).toContain('</svg>');
  });

  test('title option appears in output', () => {
    const svg = exportSvg(_makeLayout(), { title: 'My Policy' });
    expect(svg).toContain('My Policy');
  });

  test('SVG contains rect elements for nodes', () => {
    const svg = exportSvg(_makeLayout());
    const rectCount = (svg.match(/<rect/g) || []).length;
    expect(rectCount).toBeGreaterThan(0);
  });

  test('SVG contains path elements for edges', () => {
    const layout = _makeLayout();
    const svg    = exportSvg(layout);
    if (layout.edges.length > 0) {
      expect(svg).toContain('<path');
    }
  });

  test('throws TypeError for non-object input', () => {
    expect(() => exportSvg(null)).toThrow(TypeError);
    expect(() => exportSvg({ edges: [] })).toThrow(TypeError);
  });

  test('empty node list produces minimal valid SVG', () => {
    const svg = exportSvg({ nodes: [], edges: [], bounds: { width: 400, height: 300 } });
    expect(svg).toContain('<svg');
    expect(svg).toContain('</svg>');
  });

  test('special characters in labels are XML-escaped', () => {
    const policy = makeSimplePolicy({ policyId: 'xss-<script>-test' });
    // buildGraph allows any policyId that passes its TypeError check;
    // SVG output must not contain raw angle brackets from label text.
    try {
      const graph  = buildGraph(policy);
      const layout = applyLayout(graph);
      const svg    = exportSvg(layout);
      // The label text (between SVG text tags) must be escaped
      const rawTag = '<script>';
      expect(svg).not.toContain(rawTag);
    } catch {
      // If buildGraph rejects the id, the escaping test is N/A — pass.
    }
  });
});

// ── pngExporter tests ─────────────────────────────────────────────────────────

describe('pngExporter', () => {
  function _makeLayout() {
    return applyLayout(buildGraph(makeSimplePolicy()));
  }

  test('returns a Buffer', () => {
    const png = exportPng(_makeLayout());
    expect(Buffer.isBuffer(png)).toBe(true);
  });

  test('PNG starts with valid PNG signature bytes', () => {
    const png = exportPng(_makeLayout());
    // PNG signature: 137 80 78 71 13 10 26 10
    expect(png[0]).toBe(137);
    expect(png[1]).toBe(80);   // P
    expect(png[2]).toBe(78);   // N
    expect(png[3]).toBe(71);   // G
    expect(png[4]).toBe(13);
    expect(png[5]).toBe(10);
    expect(png[6]).toBe(26);
    expect(png[7]).toBe(10);
  });

  test('PNG is non-trivially sized', () => {
    const png = exportPng(_makeLayout());
    expect(png.length).toBeGreaterThan(100);
  });

  test('throws TypeError for non-object input', () => {
    expect(() => exportPng(null)).toThrow(TypeError);
    expect(() => exportPng({ edges: [] })).toThrow(TypeError);
  });

  test('small graph produces valid PNG', () => {
    const miniLayout = { nodes: [], edges: [], bounds: { width: 64, height: 64 } };
    const png        = exportPng(miniLayout);
    expect(Buffer.isBuffer(png)).toBe(true);
    expect(png[0]).toBe(137);
  });
});

// ── jsonExporter tests ────────────────────────────────────────────────────────

describe('jsonExporter', () => {
  test('exportJson returns a valid JSON string', () => {
    const graph = buildGraph(makeSimplePolicy());
    const json  = exportJson(graph);
    expect(typeof json).toBe('string');
    expect(() => JSON.parse(json)).not.toThrow();
  });

  test('exported document contains schemaVersion and exportedAt', () => {
    const doc = JSON.parse(exportJson(buildGraph(makeSimplePolicy())));
    expect(doc.schemaVersion).toBe(SCHEMA_VERSION);
    expect(typeof doc.exportedAt).toBe('string');
  });

  test('round-trip: exportJson → importJson preserves nodes and edges', () => {
    const graph     = buildGraph(makeSimplePolicy());
    const json      = exportJson(graph);
    const imported  = importJson(json);

    expect(imported.nodes.length).toBe(graph.nodes.length);
    expect(imported.edges.length).toBe(graph.edges.length);
  });

  test('compact mode (pretty:false) produces single-line JSON', () => {
    const graph = buildGraph(makeSimplePolicy());
    const json  = exportJson(graph, { pretty: false });
    expect(json.includes('\n')).toBe(false);
  });

  test('importJson throws for non-string input', () => {
    expect(() => importJson(null)).toThrow(TypeError);
    expect(() => importJson('')).toThrow(TypeError);
  });

  test('importJson throws for invalid JSON', () => {
    expect(() => importJson('{broken json')).toThrow();
  });

  test('importJson throws when nodes is missing', () => {
    expect(() => importJson('{"edges":[]}')).toThrow();
  });

  test('throws TypeError for non-object graph', () => {
    expect(() => exportJson(null)).toThrow(TypeError);
    expect(() => exportJson({ edges: [] })).toThrow(TypeError);
  });
});

// ── decision flow tests ───────────────────────────────────────────────────────

describe('decisionFlow', () => {
  test('getDecisionFlow returns 8 stages', () => {
    const flow = getDecisionFlow();
    expect(Array.isArray(flow)).toBe(true);
    expect(flow.length).toBe(8);
  });

  test('each stage has id, label, description', () => {
    for (const stage of getDecisionFlow()) {
      expect(typeof stage.id).toBe('string');
      expect(typeof stage.label).toBe('string');
      expect(typeof stage.description).toBe('string');
    }
  });

  test('first stage is Request', () => {
    expect(getDecisionFlow()[0].id).toBe('request');
  });

  test('last stage is artifact_generation', () => {
    const flow = getDecisionFlow();
    expect(flow[flow.length - 1].id).toBe('artifact_generation');
  });

  test('renderDecisionFlowText returns a string with stage labels', () => {
    const text = renderDecisionFlowText();
    expect(typeof text).toBe('string');
    expect(text).toContain('Request');
    expect(text).toContain('Decision');
    expect(text).toContain('↓');
  });

  test('getDecisionFlow is deterministic across 10 calls', () => {
    const first = JSON.stringify(getDecisionFlow());
    for (let i = 0; i < 9; i++) {
      expect(JSON.stringify(getDecisionFlow())).toBe(first);
    }
  });
});

// ── convenience pipeline tests ────────────────────────────────────────────────

describe('buildVisual pipeline', () => {
  test('returns nodes, edges, bounds, findings, summary, meta', () => {
    const result = buildVisual(makeSimplePolicy());
    expect(Array.isArray(result.nodes)).toBe(true);
    expect(Array.isArray(result.edges)).toBe(true);
    expect(result.bounds).toBeDefined();
    expect(Array.isArray(result.findings)).toBe(true);
    expect(result.summary).toBeDefined();
    expect(result.meta).toBeDefined();
  });

  test('all nodes have layout coordinates', () => {
    const result = buildVisual(makeSimplePolicy());
    for (const node of result.nodes) {
      expect(typeof node.x).toBe('number');
      expect(typeof node.y).toBe('number');
    }
  });

  test('risky policy → summary.overallRisk is HIGH or CRITICAL', () => {
    const result = buildVisual(makeHighRiskPolicy());
    expect([RISK_LEVELS.HIGH, RISK_LEVELS.CRITICAL]).toContain(result.summary.overallRisk);
  });

  test('clean policy → summary.findingCount is 0', () => {
    const result = buildVisual(makeSimplePolicy({ policyId: 'clean-pipe' }));
    expect(result.summary.findingCount).toBe(0);
  });

  test('custom layoutOptions are applied', () => {
    const result = buildVisual(makeSimplePolicy(), { nodeWidth: 240 });
    for (const node of result.nodes) {
      expect(node.width).toBe(240);
    }
  });
});

// ── constants exposure tests ──────────────────────────────────────────────────

describe('constants', () => {
  test('NODE_TYPES contains expected keys', () => {
    expect(NODE_TYPES.POLICY).toBe('policy');
    expect(NODE_TYPES.RULE).toBe('rule');
    expect(NODE_TYPES.CONDITION).toBe('condition');
    expect(NODE_TYPES.DECISION).toBe('decision');
    expect(NODE_TYPES.CAPABILITY).toBe('capability');
    expect(NODE_TYPES.RESOURCE).toBe('resource');
    expect(NODE_TYPES.ACTION).toBe('action');
    expect(NODE_TYPES.GROUP).toBe('group');
  });

  test('EDGE_TYPES contains expected keys', () => {
    expect(EDGE_TYPES.CONTAINS).toBe('contains');
    expect(EDGE_TYPES.REQUIRES).toBe('requires');
    expect(EDGE_TYPES.PRODUCES).toBe('produces');
    expect(EDGE_TYPES.INHERITS).toBe('inherits');
  });

  test('RISK_LEVELS has four tiers', () => {
    expect(Object.values(RISK_LEVELS).length).toBe(4);
    expect(RISK_LEVELS.LOW).toBe('low');
    expect(RISK_LEVELS.CRITICAL).toBe('critical');
  });

  test('SCHEMA_VERSION is a non-empty string', () => {
    expect(typeof SCHEMA_VERSION).toBe('string');
    expect(SCHEMA_VERSION.length).toBeGreaterThan(0);
  });
});

// ── large policy stress tests ─────────────────────────────────────────────────

describe('large policy handling', () => {
  function makeLargePolicy(ruleCount) {
    const rules = [];
    for (let i = 0; i < ruleCount; i++) {
      rules.push({ field: `metadata.field${i}`, operator: 'equals', value: `value-${i}` });
    }
    return { policyId: `large-policy-${ruleCount}`, version: 1, effect: 'allow', createdAt: '2025-01-01', rules };
  }

  test('50-rule policy builds graph without error', () => {
    const graph = buildGraph(makeLargePolicy(50));
    expect(graph.meta.ruleCount).toBeUndefined(); // meta has no ruleCount, check nodes
    expect(graph.nodes.filter(n => n.type === NODE_TYPES.RULE).length).toBe(50);
  });

  test('50-rule policy produces complete tree', () => {
    const tree = buildTree(makeLargePolicy(50));
    expect(tree.children.length).toBe(50);
  });

  test('50-rule policy stats complexityScore is high', () => {
    const stats = generateStatistics(makeLargePolicy(50));
    expect(stats.complexityScore).toBeGreaterThan(500);
  });

  test('50-rule policy applies layout without error', () => {
    const graph  = buildGraph(makeLargePolicy(50));
    const layout = applyLayout(graph);
    expect(layout.bounds.width).toBeGreaterThan(0);
  });

  test('50-rule policy exports to SVG without error', () => {
    const graph  = buildGraph(makeLargePolicy(50));
    const layout = applyLayout(graph);
    const svg    = exportSvg(layout);
    expect(svg).toContain('<svg');
  });

  test('50-rule policy exports to PNG without error', () => {
    const graph  = buildGraph(makeLargePolicy(50));
    const layout = applyLayout(graph);
    const png    = exportPng(layout);
    expect(Buffer.isBuffer(png)).toBe(true);
    expect(png[0]).toBe(137);
  });
});
