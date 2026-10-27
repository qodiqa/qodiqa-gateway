'use strict';

/**
 * / audit 2026-10-20: the "not provisioned by the author" check, shared by EVERY stage that grants a decision
 * (reviewer, approver, publisher, rollback approver). It used to live privately in PolicyGovernanceService and was applied only to
 * review and approve, so publish() and the rollback approval skipped it: an identity the author had created or keyed could publish.
 */

const rules     = require('./makerCheckerRules');
const rbacStore = require('../../rbac/store');

function assertIndependentOfAuthor(request, actor, stage) {
  let record = null;
  // (verification): a failing store read is not "no record" — it must not silently skip the independence check.
  try { record = actor && actor.id ? rbacStore.getUser(actor.id) : null; } catch (err) {
    throw new rules.MakerCheckerViolationError(`The ${String(stage).toLowerCase()}'s identity could not be read to prove independence of the author`, `${stage}_INDEPENDENCE_UNVERIFIABLE`);
  }
  // transitive — every ancestor in the provisioning lineage is checked, not just the direct parents.
  rules.assertActorNotProvisionedByAuthor({ id: request.author_id, username: request.author_username }, record, stage,
    (id) => rbacStore.getUser(id));
}

module.exports = { assertIndependentOfAuthor };
