#!/usr/bin/env node
'use strict';

/**
 * keeps the GENERATED sections of docs/protocol/QODIQA-PROTOCOL.md equal to the implementation.
 *
 * Each section between `<!-- BEGIN GENERATED:<name> -->` and `<!-- END GENERATED:<name> -->` is rendered here from the
 * code's own constants (module exports where they exist, otherwise the exact source line, cited): the domain-tag
 * registry, the verification limits, the artifact wire schema, the audit-schema field sets per version and the
 * schema/version constants. The prose around them is reviewed by hand; the numbers inside them cannot drift.
 *
 *   node scripts/protocol/spec-check.js           exit 1 if any generated section differs from the code (CI)
 *   node scripts/protocol/spec-check.js --write   rewrite the generated sections from the code
 */

const fs = require('fs');
const path = require('path');

const REPO = path.join(__dirname, '..', '..');
const SPEC = path.join(REPO, 'docs', 'protocol', 'QODIQA-PROTOCOL.md');
const req = (p) => require(path.join(REPO, p));

/** The exact source line of a `const NAME = …` definition (for constants a module does not export). */
function sourceConst(file, name) {
  const lines = fs.readFileSync(path.join(REPO, file), 'utf8').split(/\r?\n/);
  const i = lines.findIndex((l) => new RegExp(`\\bconst\\s+${name}\\s*=`).test(l));
  if (i < 0) throw new Error(`${file}: const ${name} not found`);
  return { line: i + 1, text: lines[i].trim() };
}

function sections() {
  const timeCheck = req('src/validation/timeCheck');
  const { DEPRECATED_WINDOW_MS } = req('src/validation/keyLifecycle');
  const signSchema = req('src/validation/schemas/sign.schema');
  const eb = req('src/core/audit/entryBuilder');
  const chain = req('src/core/evidence/chain');
  const { DEFAULT_THRESHOLDS } = req('src/validation/checkAnomaly');
  const { buildNonceKey } = req('src/validation/nonceStore');
  const { registry } = require('./domainRegistry');
  const hdr = sourceConst('src/api/routes/aiChat.js', 'MAX_ARTIFACT_HDR_BYTES');
  const sigRe = sourceConst('src/validation/validateArtifact.js', 'CANONICAL_SIG_RE');
  const schema = sourceConst('src/validation/validateArtifact.js', 'ARTIFACT_SCHEMA');

  const out = {};
  out['domain-tags'] = [
    '| tag | `ARTIFACT_DOMAINS` constant | defined at |',
    '|---|---|---|',
    ...registry().map((t) => `| \`${t.tag}\` | ${t.constant ? `\`${t.constant}\`` : '—'} | ${t.locations.map((l) => `\`${l}\``).join(', ')} |`),
  ].join('\n');
  out.limits = [
    '| constant | value | source |',
    '|---|---|---|',
    `| future-timestamp tolerance (\`FUTURE_SKEW_MS\`) | ${timeCheck.FUTURE_SKEW_MS} ms | \`src/validation/timeCheck.js\` |`,
    `| maximum artifact age (\`MAX_SKEW_MS\` = \`MAX_ARTIFACT_AGE_MS\`) | ${timeCheck.MAX_SKEW_MS} ms | \`src/validation/timeCheck.js\` |`,
    `| deprecated-key verification window (\`DEPRECATED_WINDOW_MS\`) | ${DEPRECATED_WINDOW_MS} ms | \`src/validation/keyLifecycle.js\` |`,
    `| /sign requested-TTL bounds (\`MIN_TTL_MS\` … \`MAX_TTL_MS\`; then clamped to the maximum artifact age) | ${signSchema.MIN_TTL_MS} … ${signSchema.MAX_TTL_MS} ms | \`src/validation/schemas/sign.schema.js\` |`,
    `| /sign HTTP methods | ${[...signSchema.VALID_HTTP_METHODS].join(', ')} | \`src/validation/schemas/sign.schema.js\` |`,
    `| \`x-qodiqa-artifact\` header cap | \`${hdr.text}\` | \`src/api/routes/aiChat.js:${hdr.line}\` |`,
    `| canonical signature encoding | \`${sigRe.text}\` | \`src/validation/validateArtifact.js:${sigRe.line}\` |`,
    `| artifact wire keys | \`${schema.text}\` | \`src/validation/validateArtifact.js:${schema.line}\` |`,
    `| nonce key layout (\`buildNonceKey('<requestId>', '<tenantId>')\`) | \`${buildNonceKey('<requestId>', '<tenantId>')}\` | \`src/validation/nonceStore.js\` |`,
    `| anomaly defaults (\`DEFAULT_THRESHOLDS\`) | \`${JSON.stringify(DEFAULT_THRESHOLDS)}\` | \`src/validation/checkAnomaly.js\` |`,
  ].join('\n');
  const versions = eb.SUPPORTED_SCHEMA_VERSIONS;
  out['audit-schema'] = [
    `- \`CURRENT_SCHEMA_VERSION\` = **${eb.CURRENT_SCHEMA_VERSION}** (written by \`buildEntry\`); \`SUPPORTED_SCHEMA_VERSIONS\` = \`[${versions.join(', ')}]\` (any other version is refused).`,
    `- \`EVIDENCE_SCHEMA_CURRENT\` (evidence-chain records, a separate schema) = **${chain.EVIDENCE_SCHEMA_CURRENT}**.`,
    '',
    '| version | hashed fields (exactly these, canonicalized and domain-hashed) | added |',
    '|---|---|---|',
    ...versions.map((v, i) => {
      const f = eb[`CORE_HASH_FIELDS_V${v}`]; const prev = i ? eb[`CORE_HASH_FIELDS_V${versions[i - 1]}`] : [];
      const added = f.filter((x) => !prev.includes(x));
      return `| ${v} | ${f.length} fields | ${added.map((x) => `\`${x}\``).join(', ')} |`;
    }),
  ].join('\n');
  return out;
}

function apply(text, secs) {
  let out = text; const missing = [];
  for (const [name, body] of Object.entries(secs)) {
    const re = new RegExp(`(<!-- BEGIN GENERATED:${name} -->)[\\s\\S]*?(<!-- END GENERATED:${name} -->)`);
    if (!re.test(out)) { missing.push(name); continue; }
    out = out.replace(re, `$1\n${body}\n$2`);
  }
  return { out, missing };
}

function check() {
  const text = fs.readFileSync(SPEC, 'utf8').replace(/\r\n/g, '\n');
  const { out, missing } = apply(text, sections());
  const diff = [];
  for (const name of Object.keys(sections())) {
    const re = new RegExp(`<!-- BEGIN GENERATED:${name} -->([\\s\\S]*?)<!-- END GENERATED:${name} -->`);
    const a = (text.match(re) || [])[1]; const b = (out.match(re) || [])[1];
    if (a !== b) diff.push(name);
  }
  return { ok: missing.length === 0 && diff.length === 0, missing, drifted: diff };
}

if (require.main === module) {
  if (process.argv.includes('--write')) {
    const text = fs.readFileSync(SPEC, 'utf8').replace(/\r\n/g, '\n');
    const { out, missing } = apply(text, sections());
    if (missing.length) { process.stderr.write(`missing generated markers: ${missing.join(', ')}\n`); process.exit(1); }
    fs.writeFileSync(SPEC, out);
    process.stdout.write('{"wrote":"docs/protocol/QODIQA-PROTOCOL.md (generated sections)"}\n');
  } else {
    const r = check();
    process.stdout.write(`${JSON.stringify(r)}\n`);
    if (!r.ok) process.stderr.write('[protocol-spec] DRIFT: a generated section of docs/protocol/QODIQA-PROTOCOL.md no longer matches the code. Run `node scripts/protocol/spec-check.js --write`, review, and update the surrounding prose.\n');
    process.exit(r.ok ? 0 : 1);
  }
}
module.exports = { check, sections };
