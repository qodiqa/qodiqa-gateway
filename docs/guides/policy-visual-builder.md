# Policy Visual Builder — Component #41

QODIQA Component #41. Provides deterministic visual representations of QODIQA authorization policies as graph models, tree views, dependency maps, and exportable diagrams.

Policies remain defined as JSON internally. The visual builder is an additional read-only representation layer — it never mutates policy state.

---

## Architecture

```
src/visual/policyBuilder/
├── constants.js          Node types, edge types, risk levels, colour palette
├── graphBuilder.js       Policy → directed graph model
├── treeBuilder.js        Policy → hierarchical tree model + ASCII render
├── dependencyGraph.js    [Policy] → cross-policy dependency graph
├── layoutEngine.js       Graph → graph with x/y coordinates
├── statistics.js         Policy → statistical summary
├── riskHighlighter.js    Graph → annotated graph with risk findings
├── index.js              Public API entry point
└── exporters/
    ├── svgExporter.js    Laid-out graph → SVG string
    ├── pngExporter.js    Laid-out graph → PNG Buffer (pure Node.js, no deps)
    └── jsonExporter.js   Graph → JSON document + import
```

API routes: `src/api/routes/policyVisual.js`
Test suite: `src/visual/policyBuilder/policyVisual.test.js`

---

## Graph Model

Every graph produced by this module follows this shape:

```typescript
{
  nodes: Node[],
  edges: Edge[],
  meta:  Meta
}

Node {
  id:        string          // unique within the graph
  type:      NodeType        // see Node Types below
  label:     string          // human-readable
  data:      object          // type-specific payload
  riskLevel: RiskLevel       // 'low' | 'medium' | 'high' | 'critical'
  // After layoutEngine:
  x:         number
  y:         number
  width:     number
  height:    number
  layer:     number
  // After riskHighlighter:
  findings?: Finding[]
}

Edge {
  from:  string   // source node id
  to:    string   // target node id
  type:  EdgeType
  label: string
}

Meta {
  policyId:  string
  version:   number
  effect:    'allow' | 'deny'
  riskLevel: RiskLevel
  nodeCount: number
  edgeCount: number
}
```

### Node Types

| Type         | Description                                    |
|--------------|------------------------------------------------|
| `policy`     | Top-level policy node                          |
| `rule`       | Individual rule within a policy                |
| `condition`  | Field/operator/value condition from a rule     |
| `group`      | AND/OR/NOT logical group of conditions         |
| `capability` | Named capability token referenced by a rule    |
| `resource`   | Protected resource referenced by a rule        |
| `action`     | Permitted action                               |
| `decision`   | Final EXECUTE or BLOCK outcome                 |

### Edge Types

| Type       | Meaning                                     |
|------------|---------------------------------------------|
| `contains` | Parent contains child (policy→rule, etc.)   |
| `requires` | Node requires a capability/resource/action  |
| `produces` | Policy produces a decision                  |
| `inherits` | Policy inherits rules from another policy   |
| `depends`  | Explicit execution dependency               |

### Risk Levels

`low` → `medium` → `high` → `critical`

Risk is derived from:
- Explicit `riskLevel` field on the policy or rule
- Wildcard values (`*`, `**`, `ALL`, `any`)
- High-risk actions (`delete`, `drop`, `truncate`, `destroy`, …)
- High-risk fields (`admin`, `root`, `superuser`, …)
- `deprecated: true` on an allow-effect policy → CRITICAL
- Expired `expiresAt` date → HIGH

---

## Rendering Pipeline

```
Policy (JSON)
    │
    ├─ buildGraph()       → Graph model
    │       │
    │       ├─ highlightRisks()  → Annotated graph (risk findings)
    │       │       │
    │       │       └─ applyLayout()   → Graph with x,y coordinates
    │       │               │
    │       │               ├─ exportSvg()  → SVG string
    │       │               ├─ exportPng()  → PNG Buffer
    │       │               └─ exportJson() → JSON document
    │
    ├─ buildTree()        → Tree model
    │       └─ renderTreeText()  → ASCII art string
    │
    └─ generateStatistics()  → Statistics object
```

---

## Supported Policy Structures

The visual builder works with QODIQA policy objects as produced by the Policy Engine. All fields beyond the base schema are optional and provide richer visualisations when present.

### Minimum required fields

```json
{
  "policyId": "my-policy",
  "version":  1,
  "effect":   "allow",
  "rules":    []
}
```

### Full extended schema

```json
{
  "policyId":    "my-policy",
  "version":     1,
  "effect":      "allow",
  "description": "Human-readable description",
  "deprecated":  false,
  "expiresAt":   "2026-12-31T00:00:00Z",
  "riskLevel":   "low",
  "inherits":    ["base-policy"],
  "dependsOn":   ["prerequisite-policy"],
  "capabilities": ["cap:read"],
  "resources":    ["res:user-data"],
  "rules": [
    {
      "label":      "Optional rule label",
      "field":      "action",
      "operator":   "equals",
      "value":      "inference",
      "capability": "cap:read",
      "resource":   "res:user-data",
      "action":     "inference",
      "riskLevel":  "low",
      "group": {
        "logic": "OR",
        "conditions": [
          { "field": "metadata.region", "operator": "equals", "value": "us-east-1" },
          { "field": "metadata.region", "operator": "equals", "value": "eu-west-1" }
        ]
      }
    }
  ]
}
```

The `group` field on a rule replaces the direct `field/operator/value` and represents a logical group of conditions (AND, OR, NOT) supporting unlimited nesting depth.

---

## Decision Flow

The QODIQA decision flow is a fixed ordered sequence of 8 stages:

```
  Request
  ↓
  Authentication
  ↓
  Consent Validation
  ↓
  Capability Validation
  ↓
  Policy Evaluation
  ↓
  Risk Evaluation
  ↓
  Decision
  ↓
  Artifact Generation
```

Retrieve programmatically: `pv.getDecisionFlow()` returns an array of `{ id, label, description }` objects.

---

## Statistics

`generateStatistics(policy)` returns a frozen object:

| Field                | Type     | Description                                       |
|----------------------|----------|---------------------------------------------------|
| `ruleCount`          | number   | Total number of rules                             |
| `conditionCount`     | number   | Total conditions (including nested group conds)   |
| `capabilityCount`    | number   | Distinct capabilities referenced                  |
| `resourceCount`      | number   | Distinct resources referenced                     |
| `actionCount`        | number   | Distinct actions referenced                       |
| `fieldCount`         | number   | Distinct field paths used                         |
| `operatorCount`      | number   | Distinct operators used                           |
| `wildcardCount`      | number   | Rules using wildcard values                       |
| `highRiskActionCount`| number   | Rules referencing high-risk actions               |
| `complexityScore`    | number   | Computed complexity metric (higher = more complex)|
| `riskLevel`          | string   | Derived aggregate risk level                      |
| `deprecated`         | boolean  | Whether policy is deprecated                      |
| `expired`            | boolean  | Whether policy has passed its `expiresAt` date    |
| `inheritanceDepth`   | number   | Number of parent policies listed in `inherits`    |
| `capabilities`       | string[] | Capability names                                  |
| `resources`          | string[] | Resource names                                    |
| `actions`            | string[] | Action names                                      |
| `fields`             | string[] | Field path names                                  |
| `operators`          | string[] | Operator names                                    |

### Complexity Score

Complexity is a heuristic numeric score:

- Each rule: **+10 points**
- Each nested group condition: **+5 points**
- Each wildcard value: **+15 points**
- Large `in`/`notIn` arrays: **+2 per 3 values**
- `deny` effect: **+20 points**
- Each inherited parent policy: **+8 points**
- Rule count > 10: **+20 flat**
- Rule count > 20: **+30 flat additional**

---

## Risk Findings

`highlightRisks(graph)` annotates a graph with risk findings and returns:

```typescript
{
  nodes:    Node[],           // annotated with riskLevel and findings[]
  edges:    Edge[],
  findings: Finding[],
  summary: {
    findingCount:  number,
    criticalCount: number,
    highCount:     number,
    mediumCount:   number,
    overallRisk:   RiskLevel
  }
}
```

### Finding Codes

| Code                   | Trigger                                               |
|------------------------|-------------------------------------------------------|
| `CRITICAL_RULE`        | Node has explicit CRITICAL riskLevel                  |
| `HIGH_RISK_PERMISSION` | Rule targets a sensitive field (admin, root, etc.)    |
| `SENSITIVE_RESOURCE`   | Resource name is a wildcard                           |
| `BROAD_WILDCARD`       | Rule value is a wildcard (`*`, `ALL`, etc.)           |
| `EXPIRED_POLICY`       | Policy `expiresAt` is in the past                     |
| `DEPRECATED_POLICY`    | Policy has `deprecated: true`                         |
| `DEPRECATED_CAPABILITY`| Capability has `deprecated: true`                     |
| `HIGH_RISK_ACTION`     | Rule references a high-risk action (delete, drop, …)  |
| `DENY_EFFECT`          | Policy uses deny effect (inverted logic warning)      |

---

## Export Formats

### SVG

```javascript
const svg = pv.exportSvg(layoutGraph, { title: 'My Policy', background: '#0f1117' });
// Returns string — valid SVG XML
```

- Pure string construction, no external dependencies.
- Dark background with colour-coded node types.
- Risk level highlighted with border colour and top indicator bar.
- Curved bezier edges labelled with edge type.
- Suitable for embedding in HTML, saving as `.svg`, or rendering in browsers.

### PNG

```javascript
const png = pv.exportPng(layoutGraph, { background: '#0f1117' });
// Returns Buffer — valid PNG binary
```

- Pure Node.js implementation using built-in `zlib` for DEFLATE compression.
- No external npm dependencies.
- RGB truecolour (24-bit), no alpha channel.
- Renders: filled node rectangles, coloured borders, risk indicator bars, Bresenham line edges.
- Text is not rasterised — use SVG for text-bearing output.

### JSON

```javascript
const json = pv.exportJson(graph, { pretty: true, source: 'my-system' });
// Returns string — JSON document

const graph = pv.importJson(json);
// Returns { nodes, edges, findings, meta, bounds }
```

Document schema:

```json
{
  "schemaVersion": "1.0.0",
  "exportedAt":    "ISO-8601 timestamp",
  "source":        "qodiqa-policy-visual-builder",
  "meta":          { ... },
  "bounds":        { "width": 800, "height": 600 },
  "nodeCount":     12,
  "edgeCount":     11,
  "nodes":         [ ... ],
  "edges":         [ ... ],
  "findings":      [ ... ]
}
```

---

## API Endpoints

All endpoints require ops-level authentication (mounted at `/v1/policy`).

### POST /v1/policy/visual/graph

Build a graph model from a policy.

**Request:**
```json
{ "policy": { "policyId": "...", "version": 1, "effect": "allow", "rules": [] } }
```

**Response:** `{ "status": "success", "data": { nodes, edges, meta } }`

---

### POST /v1/policy/visual/tree

Build a tree model. Optional `"format": "text"` returns ASCII art.

**Request:**
```json
{ "policy": { ... }, "format": "text" }
```

**Response:** `{ "data": { "tree": { ... }, "text": "Policy ...\n├── ..." } }`

---

### POST /v1/policy/visual/deps

Build a dependency graph from multiple policies.

**Request:**
```json
{ "policies": [ { ... }, { ... } ] }
```

If `policies` is omitted, the live policy set is used.

---

### POST /v1/policy/visual/stats

Generate statistics for a policy.

**Request:**
```json
{ "policy": { ... } }
```

---

### POST /v1/policy/visual/highlight

Build a graph and annotate it with risk findings.

**Request:**
```json
{ "policy": { ... } }
```

---

### GET /v1/policy/visual/flow

Returns the QODIQA decision flow stages and ASCII text representation.

---

### POST /v1/policy/visual/export

Export a policy graph as SVG, PNG, or JSON.

**Request:**
```json
{
  "policy":        { ... },
  "format":        "svg",
  "title":         "My Policy",
  "layoutOptions": { "nodeWidth": 160, "nodeHeight": 48 }
}
```

`format` must be one of: `svg` (default), `png`, `json`.

- SVG: `Content-Type: image/svg+xml`
- PNG: `Content-Type: image/png`
- JSON: `Content-Type: application/json`

---

## Extension Points

### Adding a new node type

1. Add the type to `NODE_TYPES` in `constants.js`.
2. Add a colour entry to `NODE_COLOURS` in `constants.js`.
3. Add a layer index to `LAYER_ORDER` in `constants.js`.
4. Emit nodes of the new type in `graphBuilder.js`.
5. Add rendering logic in `svgExporter.js` and `pngExporter.js` if needed.

### Adding a new edge type

1. Add to `EDGE_TYPES` in `constants.js`.
2. Add a colour entry in `svgExporter.js` (`edgeColours` map) and `pngExporter.js`.

### Adding a new risk finding

1. Add a finding code to `FINDING_CODES` in `riskHighlighter.js`.
2. Add inspection logic in `_inspectNode()`.

### Adding a new export format

1. Create `src/visual/policyBuilder/exporters/<format>Exporter.js`.
2. Export a function `export<Format>(layoutGraph, options)`.
3. Re-export from `index.js`.
4. Add a case to the `POST /visual/export` route in `policyVisual.js`.

---

## Examples

### Build and export an SVG

```javascript
const pv = require('./src/visual/policyBuilder');

const policy = {
  policyId: 'my-api-policy',
  version:  1,
  effect:   'allow',
  rules: [
    { field: 'action',  operator: 'equals', value: 'inference' },
    { field: 'consent', operator: 'equals', value: true },
  ],
};

const graph  = pv.buildGraph(policy);
const layout = pv.applyLayout(graph);
const svg    = pv.exportSvg(layout, { title: 'My API Policy' });
// fs.writeFileSync('policy.svg', svg);
```

### Full pipeline with risk highlighting

```javascript
const result = pv.buildVisual(policy);
console.log('Risk:', result.summary.overallRisk);
console.log('Findings:', result.summary.findingCount);
const svg = pv.exportSvg(result, { title: policy.policyId });
```

### ASCII tree

```javascript
const tree = pv.buildTree(policy);
const text = pv.renderTreeText(tree);
console.log(text);
// my-api-policy v1 [ALLOW]
// ├── Rule 1: action equals inference
// │    ├── action equals inference
// │    └── Result → EXECUTE
// └── Rule 2: consent equals true
//      ├── consent equals true
//      └── Result → EXECUTE
```

### Multi-policy dependency graph

```javascript
const deps = pv.buildDependencyGraph([policyA, policyB, policyC]);
console.log('Shared nodes:', deps.meta.sharedNodeCount);
```

### Decision flow

```javascript
console.log(pv.renderDecisionFlowText());
//   Request
//   ↓
//   Authentication
//   ↓
//   ...
//   Artifact Generation
```
