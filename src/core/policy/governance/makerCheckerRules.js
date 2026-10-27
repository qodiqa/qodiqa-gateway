'use strict';

/**
 * makerCheckerRules — server-side maker-checker (four-eyes) identity
 * separation assertions for the policy governance workflow.
 *
 * Every function compares INDIVIDUAL actor identity (id, not role) — two
 * accounts sharing the same RBAC role may legitimately occupy different
 * stages of the same change request; the same account may never occupy
 * two incompatible stages. Callers must always pass identity that was
 * attached to the request by upstream RBAC middleware (req.rbacUser.id) —
 * never a client-supplied "I am a different person" claim from the request
 * body, which is client-side validation and therefore insufficient.
 *
 * Each assertion throws MakerCheckerViolationError rather than returning a
 * boolean, so a forgotten call site fails loudly instead of silently
 * allowing a self-approval.
 */

class MakerCheckerViolationError extends Error {
  constructor(message, rule) {
    super(message);
    this.name = 'MakerCheckerViolationError';
    this.code = 'MAKER_CHECKER_VIOLATION';
    this.rule = rule;
  }
}

function _sameActor(a, b) {
  return !!a && !!b && a === b;
}

/** Author == Reviewer must be impossible. */
function assertReviewerNotAuthor(authorId, reviewerId) {
  if (_sameActor(authorId, reviewerId)) {
    throw new MakerCheckerViolationError(
      'The reviewer must be a different individual than the author',
      'AUTHOR_EQ_REVIEWER',
    );
  }
}

/** Author == Approver must be impossible. */
function assertApproverNotAuthor(authorId, approverId) {
  if (_sameActor(authorId, approverId)) {
    throw new MakerCheckerViolationError(
      'The approver must be a different individual than the author',
      'AUTHOR_EQ_APPROVER',
    );
  }
}

/**
 * Reviewer == Approver must be impossible, but only when strict
 * ("enterprise") mode is active —'s own "(if enterprise mode
 * requires)" qualifier. In relaxed mode this is a no-op by design.
 */
function assertApproverNotReviewer(reviewerId, approverId, { strict = true } = {}) {
  if (!strict) return;
  if (_sameActor(reviewerId, approverId)) {
    throw new MakerCheckerViolationError(
      'In strict mode, the approver must be a different individual than the reviewer',
      'REVIEWER_EQ_APPROVER',
    );
  }
}

/** Author == Publisher must be impossible. */
function assertPublisherNotAuthor(authorId, publisherId) {
  if (_sameActor(authorId, publisherId)) {
    throw new MakerCheckerViolationError(
      'The publisher must be a different individual than the author',
      'AUTHOR_EQ_PUBLISHER',
    );
  }
}

/** Author == Rollback Approver must be impossible. */
function assertRollbackApproverNotAuthor(authorId, rollbackApproverId) {
  if (_sameActor(authorId, rollbackApproverId)) {
    throw new MakerCheckerViolationError(
      'The rollback approver must be a different individual than the rollback requester',
      'AUTHOR_EQ_ROLLBACK_APPROVER',
    );
  }
}

/** Approver == Emergency Rollback Operator must be impossible. */
function assertRollbackApproverNotOriginalPublisher(originalPublisherId, rollbackApproverId) {
  if (_sameActor(originalPublisherId, rollbackApproverId)) {
    throw new MakerCheckerViolationError(
      'The rollback approver must be a different individual than whoever activated the version being rolled back',
      'PUBLISHER_EQ_ROLLBACK_APPROVER',
    );
  }
}

/** Emergency activator must never retrospectively approve their own emergency change. */
function assertEmergencyRetroApproverNotActivator(activatorId, retroApproverId) {
  if (_sameActor(activatorId, retroApproverId)) {
    throw new MakerCheckerViolationError(
      'The emergency retrospective approver must be a different individual than whoever activated the emergency change',
      'ACTIVATOR_EQ_RETRO_APPROVER',
    );
  }
}

/**
 *the reviewer / approver must not be an identity the AUTHOR provisioned —
 * created by the author, or holding an API key the author issued (the author has seen that key's plaintext). Without
 * this, one admin could create a second identity, mint its key and approve their own change: maker-checker would
 * compare two account ids belonging to one person. `actorRecord` is the actor's stored RBAC user record
 * (createdById / createdBy / apiKeyIssuedById, src/core/rbac/store.js); legacy records without ids are compared by
 * the recorded username.
 */
// provisioning lineage is TRANSITIVE. Author A creates and keys B (allowed: B is strictly subordinate),
// then — holding B's key — has B create and key approver C. A direct-parent check sees only B and passes, yet A controls
// A, B and C. The walk follows both edges (createdById, apiKeyIssuedById) up to MAX_LINEAGE_DEPTH ancestors.
const MAX_LINEAGE_DEPTH = 16;

/**
 * @param {{id?: string, username?: string}} author
 * @param {object|null} actorRecord          the reviewer/approver's RBAC record
 * @param {string} [stage]
 * @param {(id: string) => object|null} [lookup]  resolves an ancestor's RBAC record (rbacStore.getUser); without it only
 *                                                the direct parents are checked
 */
function assertActorNotProvisionedByAuthor(author, actorRecord, stage = 'APPROVER', lookup = null) {
  if (!author || !actorRecord) return;
  const isAuthor = (id, name) => (!!author.id && !!id && id === author.id) || (!!author.username && !!name && name === author.username);
  const violation = (how, depth) => new MakerCheckerViolationError(
    `The ${stage.toLowerCase()} must be independent of the author: this identity was ${how} ${depth === 0 ? 'by the author' : `by an identity the author provisioned (${depth} level${depth > 1 ? 's' : ''} up)`}`,
    `${stage}_PROVISIONED_BY_AUTHOR`,
  );
  const seen = new Set();
  let frontier = [actorRecord];
  for (let depth = 0; depth <= MAX_LINEAGE_DEPTH && frontier.length; depth++) {
    const next = [];
    for (const rec of frontier) {
      if (!rec || seen.has(rec.id)) continue;
      seen.add(rec.id);
      if (isAuthor(rec.createdById, rec.createdBy)) throw violation('created', depth);
      if (isAuthor(rec.apiKeyIssuedById, rec.apiKeyIssuedById ? rec.apiKeyIssuedBy : null)) throw violation('given its API key', depth);
      if (typeof lookup !== 'function') continue;
      for (const parentId of [rec.createdById, rec.apiKeyIssuedById]) {
        if (!parentId || seen.has(parentId)) continue;
        let parent = null;
        let lookupFailed = false;
        try { parent = lookup(parentId); } catch { lookupFailed = true; }
        // (verification): an ancestor that cannot be resolved (hard-deleted by the author, or a store error) breaks the lineage
        // walk; treating it as "no ancestor" let A create B, B create C, A delete B, and C approve A's change. Fail closed instead.
        if (!parent || lookupFailed) {
          throw new MakerCheckerViolationError(
            `The ${stage.toLowerCase()} cannot be shown to be independent of the author: a provisioning ancestor (${parentId}) can no longer be resolved`,
            `${stage}_LINEAGE_UNVERIFIABLE`,
          );
        }
        next.push(parent);
      }
    }
    frontier = next;
  }
}

module.exports = {
  MakerCheckerViolationError,
  assertActorNotProvisionedByAuthor,
  assertReviewerNotAuthor,
  assertApproverNotAuthor,
  assertApproverNotReviewer,
  assertPublisherNotAuthor,
  assertRollbackApproverNotAuthor,
  assertRollbackApproverNotOriginalPublisher,
  assertEmergencyRetroApproverNotActivator,
};
