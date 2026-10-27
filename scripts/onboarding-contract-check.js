#!/usr/bin/env node
'use strict';

/**
 * Onboarding Contract Drift Check — item 14 (Program 4).
 *
 * Extends the documentation-drift guard (see scripts/doc-drift-check.js) to
 * cover the one area it explicitly does not: the request/response JSON
 * bodies docs/guides/quickstart.md shows for `POST /sign` and `POST /ai/chat` (the
 * "onboarding contract"). This has drifted from the live code twice already
 * (`payload.provider` omission; the `meta.callerId`/`callerContext`/
 * `transparency` gaps fixed alongside this check) without anything catching
 * it, because routeParity.test.js (API-3) only checks route path/method
 * existence, never body shape.
 *
 * Ground truth, never hand-duplicated:
 *   - Request shape: introspected directly from the live Zod schemas
 *     (src/validation/schemas/sign.schema.js, aiChat.schema.js) via
 *     `.shape` — the same `.strict()`/`.passthrough()` schemas the routes
 *     themselves validate against (post item-9 audit).
 *   - Response shape: statically parsed from the literal response object(s)
 *     each route handler actually returns (src/api/routes/sign.js,
 *     aiChat.js, src/validation/signArtifact.js) at check-run time. There is
 *     deliberately no OpenAPI/hand-maintained duplicate consulted here —
 *     src/openapi/componentsBuilder.js's SignResponse component was found to
 *     have independently drifted from this same code (missing `artifactId`/
 *     `meta`, wrongly flattening `keyId`/`expiresAt` to the top level) during
 *     this item's investigation, which is exactly the failure mode a
 *     hand-maintained duplicate produces and this check exists to avoid.
 *     (That OpenAPI drift is out of this item's scope — see
 *     ITEM-14-REMEDIATION-REPORT.md.)
 *
 * Comparison is bidirectional (requirement 3):
 *   - documented field absent from the live shape entirely -> FAIL
 *   - live-required field not documented -> FAIL
 * Nested objects (artifact, artifact.payload, meta) are compared
 * recursively, not just at the top level.
 *
 * A handful of fields cannot be resolved by pure static analysis and are
 * declared explicitly below, the same way scripts/doc-drift-map.js declares
 * *where* to look (not *what* the answer is):
 *   - aiChatBodySchema's `prompt` is structurally `.optional()` in Zod
 *     (item 9: business-required-ness is enforced by a superRefine, not the
 *     schema shape) — this check can only compare declared shape, not
 *     runtime-required-ness, so a doc that dropped `prompt` entirely would
 *     not be caught here. It is documented today, so this is not a live gap.
 * Still correct against the
 *     current schema: `zodTree()` below derives `required` purely from
 *     `fieldSchema.isOptional()` (see `unwrapToZodObject()`, which unwraps
 *     past the ZodEffects wrapper `.superRefine()` adds but never inspects
 *     the refine function itself) — so the check genuinely still cannot see
 *     superRefine-enforced business-requiredness, confirming the exception's
 *     own claim rather than just inheriting it. Live-confirmed against a
 *     running server (`POST /ai/chat`, no Postgres needed — the body guard
 *     runs before artifact/consent) that `prompt` is still business-required
 *     in practice: missing entirely, empty string, and whitespace-only all
 *     correctly `BLOCK` with `MISSING_PROMPT`. docs/guides/quickstart.md still documents
 *     `prompt` in every `/ai/chat` example (8 occurrences, request and SDK
 *     forms alike), so the known blind spot remains unexercised — running
 *     this check right now against current code and current docs: PASS,
 *     zero drift. (Incidental, harmless observation made during this
 *     re-verification, not a doc/check defect: the superRefine's own
 *     `p === null` branch is dead code today — Zod's field-level type check
 *     on `z.string().optional()` rejects a literal `null` before superRefine
 *     ever runs, live-confirmed via `POST /ai/chat` returning
 *     `INVALID_REQUEST_BODY` for `{"prompt":null}` rather than the
 *     superRefine's own `MISSING_PROMPT`. Doesn't affect this check's own
 *     correctness or docs/guides/quickstart.md's accuracy — not fixed here, out of this
 *     item's scope.)
 *   - `/sign` response's `artifact.payload.provider` is only spread in when
 *     the bound request targets `/ai/chat` (sign.js: `isAiChatRequest`) —
 *     declared here as a known, optional field rather than mis-parsed from
 *     the conditional spread expression.
 *
 *`buildAiChatLiveTrees()`'s EXECUTE-response extraction
 * was itself the source of a standing false-positive drift report, not
 * docs/guides/quickstart.md. `aiChat.js` has several literal `res.status(200).json(`
 * call sites — `_enforceAndStream()`'s pre-stream BLOCK responses and the
 * router's own artifact-decode BLOCK responses (`MISSING_ARTIFACT` etc.)
 * all use a literal `200` and appear earlier in the file than the actual
 * EXECUTE response. `propsAt()`'s plain first-match `.exec()` silently
 * picked up the wrong one (a BLOCK shape: `decision`/`reason`/`details`/
 * `requestId`), which is why this check reported docs/guides/quickstart.md's real,
 * correct EXECUTE fields (`response`/`artifactId`/`keyId`/`transparency`)
 * as absent from the live response, and BLOCK's `details` field as
 * present-but-undocumented — docs/guides/quickstart.md's example already matched the
 * true EXECUTE response byte-for-byte throughout. Fixed by
 * `propsAtMatching()`, which walks every match of the anchor and returns
 * the one object literal that itself declares `decision: 'EXECUTE'`,
 * instead of trusting the first textual match to be unique.
 *
 * Usage: node scripts/onboarding-contract-check.js
 * Exit codes: 0 = pass, 1 = drift detected.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

// ── Generic source parsing helpers ──────────────────────────────────────────
// Same "parse the real source, don't hand-copy it" approach already used in
// this repo by src/openapi/routeParity.test.js (regex route extraction) and
// — extended here to pull
// object-literal key sets out of specific, anchored source locations.

function findMatchingBrace(src, openIdx) {
  let i = openIdx;
  let depth = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      const quote = ch;
      i++;
      while (i < src.length && src[i] !== quote) {
        if (src[i] === '\\') i++;
        i++;
      }
      i++;
      continue;
    }
    if (ch === '/' && src[i + 1] === '/') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (ch === '/' && src[i + 1] === '*') {
      i += 2;
      while (i < src.length - 1 && !(src[i] === '*' && src[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    if (ch === '{') depth++;
    else if (ch === '}') { depth--; if (depth === 0) return i; }
    i++;
  }
  throw new Error(`unbalanced braces starting at index ${openIdx}`);
}

// Returns [{ key, kind: 'value'|'object'|'identifier'|'spread'|'unknown' }]
// for the top-level properties of the object literal opening at openBraceIdx.
// `kind: 'object'` means the value is itself an inline `{ ... }` literal —
// the caller can locate it via `valueStart` and recurse.
function parseTopLevelProps(src, openBraceIdx) {
  const closeIdx = findMatchingBrace(src, openBraceIdx);
  let i = openBraceIdx + 1;
  const props = [];

  function skipTrivia() {
    while (i < closeIdx) {
      const ch = src[i];
      if (/\s/.test(ch)) { i++; continue; }
      if (ch === '/' && src[i + 1] === '/') { while (i < closeIdx && src[i] !== '\n') i++; continue; }
      if (ch === '/' && src[i + 1] === '*') {
        i += 2;
        while (i < closeIdx - 1 && !(src[i] === '*' && src[i + 1] === '/')) i++;
        i += 2;
        continue;
      }
      break;
    }
  }

  function readSegment() {
    const start = i;
    let depth = 0;
    while (i < closeIdx) {
      const ch = src[i];
      if (ch === '"' || ch === "'" || ch === '`') {
        const quote = ch;
        i++;
        while (i < closeIdx && src[i] !== quote) { if (src[i] === '\\') i++; i++; }
        i++;
        continue;
      }
      if (ch === '/' && src[i + 1] === '/') { while (i < closeIdx && src[i] !== '\n') i++; continue; }
      if (ch === '/' && src[i + 1] === '*') {
        i += 2;
        while (i < closeIdx - 1 && !(src[i] === '*' && src[i + 1] === '/')) i++;
        i += 2;
        continue;
      }
      if ('{[('.includes(ch)) { depth++; i++; continue; }
      if ('}])'.includes(ch)) { depth--; i++; continue; }
      if (ch === ',' && depth === 0) return [start, i];
      i++;
    }
    return [start, closeIdx];
  }

  while (true) {
    skipTrivia();
    if (i >= closeIdx) break;
    const [segStart, segEnd] = readSegment();
    const seg = src.slice(segStart, segEnd);
    const trimmed = seg.trim();
    if (i < closeIdx) i++; // skip the comma
    if (!trimmed) continue;
    if (trimmed.startsWith('...')) { props.push({ key: null, kind: 'spread', raw: trimmed }); continue; }
    const m = trimmed.match(/^(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"|([A-Za-z_$][\w$]*))\s*:\s*([\s\S]+)$/);
    if (m) {
      const key = m[1] ?? m[2] ?? m[3];
      const leadingWs = seg.length - seg.trimStart().length;
      const colonRel = trimmed.indexOf(':');
      const absColon = segStart + leadingWs + colonRel;
      let valueStart = absColon + 1;
      while (/\s/.test(src[valueStart])) valueStart++;
      const valueText = m[4].trim();
      props.push({ key, kind: valueText.startsWith('{') ? 'object' : 'value', valueText, valueStart });
    } else if (/^[A-Za-z_$][\w$]*$/.test(trimmed)) {
      props.push({ key: trimmed, kind: 'identifier', valueText: trimmed });
    } else {
      props.push({ key: null, kind: 'unknown', raw: trimmed });
    }
  }
  return props;
}

function propsAt(src, anchorRegex) {
  const m = anchorRegex.exec(src);
  if (!m) throw new Error(`onboarding-contract-check: anchor not found: ${anchorRegex}`);
  const braceIdx = src.indexOf('{', m.index + m[0].length);
  if (braceIdx === -1) throw new Error(`onboarding-contract-check: no '{' after anchor: ${anchorRegex}`);
  return parseTopLevelProps(src, braceIdx);
}

// Like propsAt(), but for an anchor that matches MULTIPLE call sites in the
// source (e.g. a route handler with several `return res.status(200).json(`
// branches, one per outcome) — walks every match and returns the props for
// the first object literal whose own `predicateKey` property has the literal
// string value `predicateValue`. Needed because `propsAt()`'s plain
// `.exec()` always returns the FIRST match textually, which is only correct
// when the anchor is unique in the file (`aiChat.js` has multiple
// literal `res.status(200).json(` call sites — `_enforceAndStream()`'s
// pre-stream BLOCK responses and the router's own artifact-decode BLOCK
// responses both use a literal 200 and appear earlier in the file than the
// actual EXECUTE response this check needs).
function propsAtMatching(src, anchorRegex, predicateKey, predicateValue) {
  const re = new RegExp(anchorRegex.source, 'g');
  let m;
  const tried = [];
  while ((m = re.exec(src)) !== null) {
    const braceIdx = src.indexOf('{', m.index + m[0].length);
    if (braceIdx === -1) continue;
    const props = parseTopLevelProps(src, braceIdx);
    tried.push(m.index);
    const hit = props.find(
      (p) => p.key === predicateKey && p.kind === 'value' && p.valueText.replace(/^['"]|['"]$/g, '') === predicateValue
    );
    if (hit) return props;
  }
  throw new Error(
    `onboarding-contract-check: no object with ${predicateKey}: '${predicateValue}' found for anchor ` +
    `${anchorRegex} (checked ${tried.length} match(es) at offsets [${tried.join(', ')}])`
  );
}

function propsAtValue(src, prop) {
  const braceIdx = src.indexOf('{', prop.valueStart);
  return parseTopLevelProps(src, braceIdx);
}

// Converts an extracted prop list into a shape tree: { key: { required, children } }.
// `spread`/`unknown` entries are dropped (their contents are opaque/caller-supplied
// and cannot be enumerated statically); `extra` declares fields that a conditional
// spread injects (see file header) with an explicit required flag.
function treeFromProps(props, extra = {}) {
  const tree = {};
  for (const p of props) {
    if (p.kind === 'spread' || p.kind === 'unknown') continue;
    tree[p.key] = { required: true, children: null };
  }
  for (const [key, opts] of Object.entries(extra)) {
    tree[key] = { required: false, children: null, ...opts };
  }
  return tree;
}

// ── Zod introspection (request shapes) ──────────────────────────────────────

function unwrapToZodObject(schema) {
  let s = schema;
  let guard = 0;
  while (s && guard++ < 10) {
    // zod 4: refinements are checks on the schema itself, so there is no ZodEffects wrapper.
    const def = s._zod && s._zod.def;
    if (def && def.type === 'object') return s;
    if (def && def.type === 'pipe') { s = def.in; continue; }
    if (def && def.innerType) { s = def.innerType; continue; } // optional / nullable / default
    break;
  }
  return null;
}

function zodTree(schema) {
  const obj = unwrapToZodObject(schema);
  if (!obj) return null;
  const tree = {};
  for (const [key, fieldSchema] of Object.entries(obj.shape)) {
    const nestedObj = unwrapToZodObject(fieldSchema);
    tree[key] = { required: !fieldSchema.isOptional(), children: nestedObj ? zodTree(fieldSchema) : null };
  }
  return tree;
}

// ── docs/guides/quickstart.md extraction ────────────────────────────────────────────────

function extractSection(md, headingRegex, nextHeadingRegex) {
  const m = headingRegex.exec(md);
  if (!m) throw new Error(`onboarding-contract-check: heading not found in docs/guides/quickstart.md: ${headingRegex}`);
  const rest = md.slice(m.index + m[0].length);
  const nm = nextHeadingRegex.exec(rest);
  return nm ? rest.slice(0, nm.index) : rest;
}

function extractJsonAfter(text, markerIndex, label) {
  const braceIdx = text.indexOf('{', markerIndex);
  if (braceIdx === -1) throw new Error(`onboarding-contract-check: no JSON object found for ${label}`);
  const closeIdx = findMatchingBrace(text, braceIdx);
  const raw = text.slice(braceIdx, closeIdx + 1);
  try {
    return JSON.parse(raw);
  } catch (err) {
    throw new Error(`onboarding-contract-check: failed to parse documented JSON for ${label}: ${err.message}`);
  }
}

// Recursively converts a parsed JSON value into a doc-tree: plain nested
// objects for objects, the sentinel 'LEAF' for anything else (string,
// number, boolean, null, array).
function docTreeFromJson(value) {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const node = {};
    for (const [k, v] of Object.entries(value)) node[k] = docTreeFromJson(v);
    return node;
  }
  return 'LEAF';
}

// ── Bidirectional diff ──────────────────────────────────────────────────────

function diffTrees(liveTree, docNode, pathPrefix, out) {
  const docKeys = docNode && typeof docNode === 'object' ? Object.keys(docNode) : [];
  for (const key of docKeys) {
    if (!(key in liveTree)) out.documentedNotInLive.push(pathPrefix + key);
  }
  for (const [key, spec] of Object.entries(liveTree)) {
    if (spec.required && !docKeys.includes(key)) out.requiredNotDocumented.push(pathPrefix + key);
    if (spec.children && docKeys.includes(key)) {
      const docChild = docNode[key];
      if (docChild && typeof docChild === 'object') {
        diffTrees(spec.children, docChild, `${pathPrefix}${key}.`, out);
      }
    }
  }
}

function report(label, liveTree, docJson, out) {
  const diff = { documentedNotInLive: [], requiredNotDocumented: [] };
  diffTrees(liveTree, docTreeFromJson(docJson), '', diff);
  const failed = diff.documentedNotInLive.length > 0 || diff.requiredNotDocumented.length > 0;
  out.push({ label, failed, diff });
  return failed;
}

// ── Live shape assembly ─────────────────────────────────────────────────────

function buildSignLiveTrees() {
  const signSrc = fs.readFileSync(path.join(ROOT, 'src/api/routes/sign.js'), 'utf8');
  const artifactSrc = fs.readFileSync(path.join(ROOT, 'src/validation/signArtifact.js'), 'utf8');
  const { signBodySchema } = require(path.join(ROOT, 'src/validation/schemas/sign.schema'));

  const requestTree = zodTree(signBodySchema);

  const innerPayloadProps = propsAt(signSrc, /(?:const|let) innerPayload = /);
  const callerContextProps = propsAt(signSrc, /const callerContext = Object\.freeze\(/);
  const innerPayloadTree = treeFromProps(innerPayloadProps, {
    // Only spread in when the bound request targets /ai/chat (isAiChatRequest) —
    // see file header. Declared explicitly, not parsed from the conditional spread.
    provider: { required: false },
  });
  innerPayloadTree.callerContext.children = treeFromProps(callerContextProps);

  const envelopeProps = propsAt(artifactSrc, /return Object\.freeze\(/);
  const envelopeTree = treeFromProps(envelopeProps);
  envelopeTree.payload.children = innerPayloadTree;

  const responseProps = propsAt(signSrc, /return res\.status\(200\)\.json\(/);
  const responseTree = treeFromProps(responseProps);
  responseTree.artifact.children = envelopeTree;
  const metaProp = responseProps.find((p) => p.key === 'meta');
  responseTree.meta.children = treeFromProps(propsAtValue(signSrc, metaProp));

  return { requestTree, responseTree };
}

function buildAiChatLiveTrees() {
  const aiChatSrc = fs.readFileSync(path.join(ROOT, 'src/api/routes/aiChat.js'), 'utf8');
  const { aiChatBodySchema } = require(path.join(ROOT, 'src/validation/schemas/aiChat.schema'));

  const requestTree = zodTree(aiChatBodySchema);
  // aiChat.js has several literal `res.status(200).json(` call sites —
  // _enforceAndStream()'s pre-stream BLOCK responses and the router's own
  // artifact-decode BLOCK responses all use a literal 200 and appear earlier
  // in the file than the actual EXECUTE response below. propsAt()'s plain
  // first-match .exec() picked up the wrong one (a BLOCK shape:
  // decision/reason/details/requestId), which is why this check previously
  // reported docs/guides/quickstart.md's real, correct EXECUTE fields (response/
  // artifactId/keyId/transparency) as "not present in the live response" and
  // BLOCK's `details` field as "present but not documented" — a checker
  // defect, not a documentation drift (docs/guides/quickstart.md's example already
  // matched the true EXECUTE response byte-for-byte). Disambiguated by
  // requiring the match whose own object literal declares `decision: 'EXECUTE'`.
  const responseProps = propsAtMatching(aiChatSrc, /return res\.status\(200\)\.json\(/, 'decision', 'EXECUTE');
  const responseTree = treeFromProps(responseProps);

  return { requestTree, responseTree };
}

// ── Documented shape assembly ───────────────────────────────────────────────

function buildDocJson() {
  const md = fs.readFileSync(path.join(ROOT, 'docs/guides/quickstart.md'), 'utf8');

  const genArtifact = extractSection(md, /^## Generate Artifact$/m, /^## /m);
  const signRequestJson = extractJsonAfter(genArtifact, genArtifact.indexOf("-d '"), 'POST /sign request');
  const signResponseJson = extractJsonAfter(genArtifact, genArtifact.indexOf('```json'), 'POST /sign response');

  const execSection = extractSection(md, /^## Execute First Authorized Request$/m, /^## /m);
  const curlIdx = execSection.indexOf('### Using curl (two steps)');
  if (curlIdx === -1) throw new Error('onboarding-contract-check: "Using curl (two steps)" subsection not found');
  const curlSection = execSection.slice(curlIdx);
  const step3Idx = curlSection.indexOf('# Step 3');
  if (step3Idx === -1) throw new Error('onboarding-contract-check: "# Step 3" marker not found in curl walkthrough');
  const step3 = curlSection.slice(step3Idx);
  const chatRequestJson = extractJsonAfter(step3, step3.indexOf("-d '"), 'POST /ai/chat request');
  const chatResponseJson = extractJsonAfter(curlSection, curlSection.indexOf('```json'), 'POST /ai/chat response (EXECUTE)');

  return { signRequestJson, signResponseJson, chatRequestJson, chatResponseJson };
}

// ── Main ─────────────────────────────────────────────────────────────────────

function main() {
  console.log('onboarding-contract-check: validating docs/guides/quickstart.md against live schemas/handlers...\n');

  const sign = buildSignLiveTrees();
  const aiChat = buildAiChatLiveTrees();
  const docs = buildDocJson();

  const results = [];
  report('POST /sign — request body', sign.requestTree, docs.signRequestJson, results);
  report('POST /sign — response body', sign.responseTree, docs.signResponseJson, results);
  report('POST /ai/chat — request body', aiChat.requestTree, docs.chatRequestJson, results);
  report('POST /ai/chat — response body (EXECUTE)', aiChat.responseTree, docs.chatResponseJson, results);

  let anyFailed = false;
  for (const r of results) {
    if (r.failed) {
      anyFailed = true;
      console.error(`FAIL: ${r.label}`);
      for (const field of r.diff.documentedNotInLive) {
        console.error(`  - documented but not present in the live schema/response: ${field}`);
      }
      for (const field of r.diff.requiredNotDocumented) {
        console.error(`  - present in the live schema/response but not documented: ${field}`);
      }
    } else {
      console.log(`PASS: ${r.label}`);
    }
  }

  if (anyFailed) {
    console.error(
      '\nOnboarding contract drift check FAILED.\n' +
      'Update docs/guides/quickstart.md\'s examples to match the live request/response shape, or if the ' +
      'field genuinely no longer exists, remove it from docs/guides/quickstart.md. This check derives the ' +
      'live shape directly from src/validation/schemas/{sign,aiChat}.schema.js and the actual ' +
      'route handlers — it is never hand-maintained, so a failure here means real drift, not a ' +
      'stale expectation.\n'
    );
    process.exitCode = 1;
    return;
  }

  console.log('\nPASS: no onboarding-contract drift detected.');
}

if (require.main === module) main();

module.exports = {
  findMatchingBrace,
  parseTopLevelProps,
  propsAt,
  propsAtMatching,
  propsAtValue,
  treeFromProps,
  unwrapToZodObject,
  zodTree,
  docTreeFromJson,
  diffTrees,
  buildSignLiveTrees,
  buildAiChatLiveTrees,
  buildDocJson,
};
