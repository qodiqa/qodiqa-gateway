'use strict';

/**
 * `contract:check` only proves that the committed OpenAPI file equals the generator's output —
 * the generator is a hand-written registry, so a request body could document `APPROVE` while the Zod schema that really validates it
 * accepts `APPROVED` (nine such drifts were found). This suite compares, for the request bodies and component enums that had drifted,
 * what the COMMITTED spec says against the Zod schema the route actually runs: property names, `required`, enum values, numeric bounds.
 * Add a row to CASES when a new route gets a Zod schema; the helper does the comparison.
 */

const spec = require('../../docs/api/openapi.json');
const dsr = require('../validation/schemas/dsr.schema');
const gov = require('../validation/schemas/policyGovernance.schema');
const si = require('../validation/schemas/signingIdentity.schema');
const audit = require('../validation/schemas/auditStore.schema');
const consent = require('../validation/schemas/consent.schema');

// ── Zod introspection (zod 4.x; dependency upgrade — same extraction the zod 3.x version did) ─────────────────────
// zod 4 keeps refinements as checks on the schema itself (no ZodEffects wrapper); `.check(integer())` is QODIQA's
// zod-3-compatible `.int()` (src/validation/zod.js), flagged on its def.
function unwrap(t) {
  let cur = t; let optional = false; let nullable = false;
  for (let i = 0; i < 12; i++) {
    const n = cur._zod.def.type;
    if (n === 'optional') { optional = true; cur = cur._zod.def.innerType; }
    else if (n === 'nullable') { nullable = true; cur = cur._zod.def.innerType; }
    else if (n === 'default' || n === 'prefault') { optional = true; cur = cur._zod.def.innerType; }
    else if (n === 'pipe') { cur = cur._zod.def.in; }
    else if (n === 'catch' || n === 'readonly') { cur = cur._zod.def.innerType; }
    else break;
  }
  return { type: cur, optional, nullable };
}
function shapeOf(schema) { const u = unwrap(schema).type; return u._zod.def.type === 'object' ? u._zod.def.shape : null; }
function describeProp(t) {
  const { type, optional } = unwrap(t);
  const name = type._zod.def.type;
  const out = { optional, kind: name };
  if (name === 'enum') out.enum = [...type.options];
  if (name === 'number') {
    for (const c of type._zod.def.checks || []) {
      const d = c._zod.def;
      if (d.check === 'greater_than') out.min = d.value;
      if (d.check === 'less_than') out.max = d.value;
      if (d.check === 'number_format' || d.qodiqaZod3Integer) out.int = true;
    }
  }
  return out;
}

function requestBodySchema(path, method) {
  return spec.paths[path][method].requestBody.content['application/json'].schema;
}
function resolve(s) {
  if (s && s.$ref) return s.$ref.split('/').slice(1).reduce((a, k) => a[k], spec);
  return s;
}
const nonNull = (s) => { const r = resolve(s); return r && r.oneOf ? resolve(r.oneOf.find((x) => x.type !== 'null')) : r; };

/** Compares one spec object schema to one Zod object schema. */
function compare(specSchema, zodSchema, { skipRequired = [] } = {}) {
  const s = resolve(specSchema);
  const shape = shapeOf(zodSchema);
  const problems = [];
  const specProps = Object.keys(s.properties || {});
  for (const p of specProps) if (!(p in shape)) problems.push(`spec documents "${p}" which the Zod schema does not accept`);
  const zodRequired = Object.keys(shape).filter((k) => !describeProp(shape[k]).optional).sort();
  const specRequired = [...(s.required || [])].sort();
  for (const k of zodRequired) if (!specRequired.includes(k) && !skipRequired.includes(k)) problems.push(`Zod requires "${k}" but the spec does not`);
  for (const k of specRequired) if (!zodRequired.includes(k)) problems.push(`spec requires "${k}" but Zod does not`);
  for (const p of specProps) {
    if (!(p in shape)) continue;
    const z = describeProp(shape[p]);
    const sp = nonNull(s.properties[p]) || {};
    if (z.enum && sp.enum && JSON.stringify([...z.enum].sort()) !== JSON.stringify([...sp.enum].sort())) problems.push(`"${p}" enum: spec ${JSON.stringify(sp.enum)} vs Zod ${JSON.stringify(z.enum)}`);
    if (z.enum && !sp.enum) problems.push(`"${p}" is an enum in Zod (${z.enum.join('|')}) but not in the spec`);
    if (z.min !== undefined && sp.minimum !== undefined && sp.minimum !== z.min) problems.push(`"${p}" minimum: spec ${sp.minimum} vs Zod ${z.min}`);
    if (z.max !== undefined && sp.maximum !== undefined && sp.maximum !== z.max) problems.push(`"${p}" maximum: spec ${sp.maximum} vs Zod ${z.max}`);
  }
  return problems;
}

const CASES = [
  ['POST /v1/policy/governance/draft', () => requestBodySchema('/v1/policy/governance/draft', 'post'), gov.draftSchema],
  ['POST /v1/policy/governance/{id}/review', () => requestBodySchema('/v1/policy/governance/{id}/review', 'post'), gov.reviewDecisionSchema],
  ['POST /v1/policy/governance/emergency/activate', () => requestBodySchema('/v1/policy/governance/emergency/activate', 'post'), gov.emergencyActivateSchema],
  ['POST /v1/admin/dsr/{id}/export', () => requestBodySchema('/v1/admin/dsr/{id}/export', 'post'), dsr.dsrExportSchema],
  ['POST /v1/admin/dsr/{id}/verify-identity', () => requestBodySchema('/v1/admin/dsr/{id}/verify-identity', 'post'), dsr.dsrVerifyIdentitySchema],
  ['POST /signing-identities', () => requestBodySchema('/signing-identities', 'post'), si.createSigningIdentitySchema],
  ['POST /audit-store/retention/policies', () => requestBodySchema('/audit-store/retention/policies', 'post'), audit.retentionPolicyBodySchema],
];

describe('OpenAPI request bodies agree with the Zod schemas that validate them', () => {
  test.each(CASES)('%s', (_name, getSpec, zodSchema) => {
    expect(zodSchema).toBeDefined();
    expect(compare(getSpec(), zodSchema)).toEqual([]);
  });
});

describe('OpenAPI component enums agree with the code', () => {
  test('DsrRequest.status = DSR_STATUSES; request_type = DSR_REQUEST_TYPES', () => {
    const c = spec.components.schemas.DsrRequest.properties;
    expect([...nonNull(c.status).enum].sort()).toEqual([...dsr.DSR_STATUSES].sort());
    expect([...nonNull(c.request_type).enum].sort()).toEqual([...dsr.DSR_REQUEST_TYPES].sort());
  });
  test('PolicyChangeRequest.requestType = REQUEST_TYPES; status = STATUSES', () => {
    const c = spec.components.schemas.PolicyChangeRequest.properties;
    expect([...nonNull(c.requestType).enum].sort()).toEqual([...gov.REQUEST_TYPES].sort());
    expect([...nonNull(c.status).enum].sort()).toEqual([...gov.STATUSES].sort());
  });
  test('GET /consent pageSize maximum = the Zod cap, not the shared 500', () => {
    const params = spec.paths['/consent'].get.parameters.map(resolve);
    const ps = params.find((p) => p.name === 'pageSize');
    const zod = describeProp(consent.consentListQuerySchema.shape.pageSize);
    expect(ps.schema.maximum).toBe(zod.max);
  });
});

describe('the comparison helper itself catches drift (guards the guard)', () => {
  test('a spec that says APPROVE where Zod says APPROVED is reported', () => {
    const bad = { type: 'object', properties: { decision: { type: 'string', enum: ['APPROVE', 'REJECT'] } }, required: ['decision'] };
    expect(compare(bad, gov.reviewDecisionSchema).join(' ')).toMatch(/decision.*enum/);
  });
  test('a spec that requires a field Zod does not, or omits one Zod requires, is reported', () => {
    const bad = { type: 'object', properties: { policyId: { type: 'string' }, requestType: { type: 'string' }, payload: { type: 'object' } }, required: ['policyId', 'requestType', 'payload'] };
    const p = compare(bad, gov.draftSchema).join(' | ');
    expect(p).toMatch(/Zod requires "changeReason"/);
    expect(p).toMatch(/spec requires "payload" but Zod does not/);
  });
});
