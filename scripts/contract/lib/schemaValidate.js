'use strict';

/**
 * minimal JSON Schema validator for exactly the keyword subset the OpenAPI generator emits
 * (type, properties, required, items, enum, oneOf, additionalProperties, local $ref to #/components/schemas/*; format is
 * informational and not enforced). Inventory of keywords in docs/api/openapi.json:
 * An unknown keyword is reported as an error rather than ignored, so a future generator change cannot silently weaken
 * the response-contract check.
 *
 *   validate(schema, value, doc) → [] | ['<json pointer>: <message>', ...]
 */

const KNOWN = new Set(['type', 'properties', 'required', 'items', 'enum', 'oneOf', 'additionalProperties', '$ref', 'format',
  'description', 'example', 'examples', 'title', 'default', 'minimum', 'maximum', 'minLength', 'maxLength', 'pattern', 'minItems', 'maxItems', 'readOnly', 'deprecated']);

function typeOf(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (Number.isInteger(v)) return 'integer';
  return typeof v;
}
function typeOk(t, v) {
  const a = typeOf(v);
  if (t === 'number') return a === 'number' || a === 'integer';
  return t === a;
}

function resolve(schema, doc) {
  let s = schema; let guard = 0;
  while (s && s.$ref) {
    if (!s.$ref.startsWith('#/')) throw new Error(`non-local $ref ${s.$ref}`);
    s = s.$ref.slice(2).split('/').reduce((o, k) => (o ? o[k.replace(/~1/g, '/').replace(/~0/g, '~')] : undefined), doc);
    if (++guard > 50) throw new Error('ref loop');
  }
  return s;
}

function validate(schema, value, doc, ptr = '', out = []) {
  const s = resolve(schema, doc);
  if (!s || typeof s !== 'object') { out.push(`${ptr || '/'}: unresolvable schema`); return out; }
  for (const k of Object.keys(s)) if (!KNOWN.has(k)) out.push(`${ptr || '/'}: unsupported schema keyword "${k}"`);
  if (s.oneOf) {
    const matches = s.oneOf.filter((alt) => validate(alt, value, doc, ptr, []).length === 0).length;
    if (matches !== 1) out.push(`${ptr || '/'}: matches ${matches} of ${s.oneOf.length} oneOf alternatives (exactly 1 required)`);
    return out;
  }
  if (s.type !== undefined) {
    const types = Array.isArray(s.type) ? s.type : [s.type];
    if (!types.some((t) => typeOk(t, value))) { out.push(`${ptr || '/'}: expected ${types.join('|')}, got ${typeOf(value)}`); return out; }
  }
  if (s.enum && !s.enum.some((e) => JSON.stringify(e) === JSON.stringify(value))) out.push(`${ptr || '/'}: ${JSON.stringify(value)} not in enum`);
  if (typeOf(value) === 'object') {
    const props = s.properties || {};
    for (const r of s.required || []) if (!(r in value)) out.push(`${ptr}/${r}: required property missing`);
    for (const [k, v] of Object.entries(value)) {
      if (props[k]) validate(props[k], v, doc, `${ptr}/${k}`, out);
      else if (s.additionalProperties === false) out.push(`${ptr}/${k}: additional property not allowed`);
      else if (s.additionalProperties && typeof s.additionalProperties === 'object') validate(s.additionalProperties, v, doc, `${ptr}/${k}`, out);
    }
  }
  if (typeOf(value) === 'array' && s.items) value.forEach((v, i) => validate(s.items, v, doc, `${ptr}/${i}`, out));
  return out;
}

/** Find the OpenAPI operation for a concrete (method, path): exact template match, path params as single segments. */
function findOperation(doc, method, urlPath) {
  const p = urlPath.split('?')[0];
  const cands = [];
  for (const [tpl, item] of Object.entries(doc.paths)) {
    if (!item[method]) continue;
    const re = new RegExp(`^${tpl.replace(/[.*+?^${}()|[\]\\]/g, (c) => (c === '{' || c === '}' ? c : `\\${c}`)).replace(/\{[^}]+\}/g, '[^/]+')}$`);
    if (re.test(p)) cands.push({ tpl, op: item[method], literal: tpl.replace(/\{[^}]+\}/g, '').length });
  }
  cands.sort((a, b) => b.literal - a.literal);   // most specific template wins (/root before /{id})
  return cands[0] || null;
}

module.exports = { validate, resolve, findOperation, typeOf };
