'use strict';

/**
 * Ready-made ABAC rules for the controls the plan names. Each function returns a complete policy object (`{ id, type: 'ABAC', priority, enabled, config }`) that validates
 * with the ABAC evaluator, so an operator can paste it into the tenant's policy set and publish it through the normal governance. They are conveniences over the one rule type, not
 * separate engines: every one is plain ABAC and is read, hashed and simulated as such.
 *
 *   userAllowList(ids)                 only these signing keys / callers            (REQUIRE subject.userId in ids)
 *   userDenyList(ids)                  never these                                  (DENY)
 *   modelAllowList(models)             only these models                            (REQUIRE request.model in models)
 *   modelDenyList(models)
 *   purposeRequired(purposes)          the request must DECLARE one of these purposes (REQUIRE; a missing declaration refuses)
 *   dataClassLimit(max, { providers }) refuse data classified above `max` (optionally only toward some providers)
 *   dataCategoryDeny(categories)       refuse a request carrying any of these DLP categories (CARD, IBAN, ...), unless redacted first by an earlier DLP rule is NOT considered:
 *                                      the rule sees the request as received
 *   dataRegionAllow(regions)           the request must declare a data region from the list
 *   toolAllowList(tools)               tool scope: only these server/name pairs may be authorised
 *   toolClassDeny(classes)             tool scope: never these action classes (e.g. command, financial)
 *   toolIrreversibleRequiresRegion?    (not provided: use ABAC directly)
 *   operationalDeny(modes, { when })   refuse while the platform is in one of these operational modes (maintenance, incident, degraded)
 */

const LEVELS = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'];
const policy = (id, priority, config) => ({ id, type: 'ABAC', priority, enabled: true, config: { abacFormat: 1, ...config } });
const leaf = (attr, op, value) => (value === undefined ? { attr, op } : { attr, op, value });

const userAllowList = (ids, { id = 'ABAC_USER_ALLOW', priority = 30 } = {}) => policy(id, priority, { effect: 'REQUIRE', reason: 'USER_NOT_ALLOWED', when: leaf('subject.userId', 'in', ids) });
const userDenyList = (ids, { id = 'ABAC_USER_DENY', priority = 30 } = {}) => policy(id, priority, { effect: 'DENY', reason: 'USER_DENIED', when: leaf('subject.userId', 'in', ids) });
const modelAllowList = (models, { id = 'ABAC_MODEL_ALLOW', priority = 31 } = {}) => policy(id, priority, { effect: 'REQUIRE', reason: 'MODEL_NOT_ALLOWED', when: leaf('request.model', 'in', models) });
const modelDenyList = (models, { id = 'ABAC_MODEL_DENY', priority = 31 } = {}) => policy(id, priority, { effect: 'DENY', reason: 'MODEL_DENIED', when: leaf('request.model', 'in', models) });
const purposeRequired = (purposes, { id = 'ABAC_PURPOSE', priority = 32 } = {}) => policy(id, priority, { effect: 'REQUIRE', reason: 'PURPOSE_NOT_DECLARED', when: leaf('request.purpose', 'in', purposes) });
const dataRegionAllow = (regions, { id = 'ABAC_DATA_REGION', priority = 32 } = {}) => policy(id, priority, { effect: 'REQUIRE', reason: 'DATA_REGION_NOT_ALLOWED', when: leaf('request.dataRegion', 'in', regions) });

function dataClassLimit(max, { providers, id = 'ABAC_DATA_CLASS', priority = 33 } = {}) {
  const i = LEVELS.indexOf(max); if (i < 0 || i === LEVELS.length - 1) throw new Error('dataClassLimit: max is PUBLIC, INTERNAL or CONFIDENTIAL');
  const above = leaf('resource.classification', 'in', LEVELS.slice(i + 1));
  const when = providers && providers.length ? { all: [leaf('request.provider', 'in', providers), above] } : above;
  return policy(id, priority, { effect: 'DENY', reason: 'DATA_CLASS_TOO_HIGH', when });
}
const dataCategoryDeny = (categories, { id = 'ABAC_DATA_CATEGORY', priority = 33 } = {}) => policy(id, priority, { effect: 'DENY', reason: 'DATA_CATEGORY_DENIED', when: leaf('resource.categories', 'hasAny', categories) });

const toolAllowList = (tools, { id = 'ABAC_TOOL_ALLOW', priority = 40 } = {}) => policy(id, priority, {
  effect: 'REQUIRE', reason: 'TOOL_NOT_ALLOWED', appliesTo: 'tool',
  when: { any: tools.map((t) => ({ all: [leaf('tool.server', 'eq', t.server), leaf('tool.name', 'eq', t.name)] })) },
});
const toolClassDeny = (classes, { id = 'ABAC_TOOL_CLASS', priority = 41 } = {}) => policy(id, priority, { effect: 'DENY', reason: 'TOOL_CLASS_DENIED', appliesTo: 'tool', when: leaf('tool.class', 'in', classes) });

function operationalDeny(modes, { id = 'ABAC_OPS_MODE', priority = 20, reason = 'OPERATIONAL_MODE' } = {}) {
  return policy(id, priority, { effect: 'DENY', reason, when: leaf('ops.mode', 'in', modes) });
}

module.exports = { userAllowList, userDenyList, modelAllowList, modelDenyList, purposeRequired, dataRegionAllow, dataClassLimit, dataCategoryDeny, toolAllowList, toolClassDeny, operationalDeny, LEVELS };
