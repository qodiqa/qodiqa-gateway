'use strict';

const rules = require('../makerCheckerRules');
const { MakerCheckerViolationError } = rules;

describe('makerCheckerRules', () => {
  describe('assertReviewerNotAuthor', () => {
    test('throws when reviewer === author', () => {
      expect(() => rules.assertReviewerNotAuthor('user-1', 'user-1')).toThrow(MakerCheckerViolationError);
    });
    test('passes for different individuals', () => {
      expect(() => rules.assertReviewerNotAuthor('user-1', 'user-2')).not.toThrow();
    });
    test('throws error carries a stable rule code', () => {
      try {
        rules.assertReviewerNotAuthor('user-1', 'user-1');
        throw new Error('should have thrown');
      } catch (err) {
        expect(err.code).toBe('MAKER_CHECKER_VIOLATION');
        expect(err.rule).toBe('AUTHOR_EQ_REVIEWER');
      }
    });
  });

  describe('assertApproverNotAuthor', () => {
    test('throws when approver === author', () => {
      expect(() => rules.assertApproverNotAuthor('user-1', 'user-1')).toThrow(MakerCheckerViolationError);
    });
    test('passes for different individuals', () => {
      expect(() => rules.assertApproverNotAuthor('user-1', 'user-2')).not.toThrow();
    });
  });

  describe('assertApproverNotReviewer', () => {
    test('strict mode (default): throws when approver === reviewer', () => {
      expect(() => rules.assertApproverNotReviewer('user-1', 'user-1')).toThrow(MakerCheckerViolationError);
      expect(() => rules.assertApproverNotReviewer('user-1', 'user-1', { strict: true })).toThrow(MakerCheckerViolationError);
    });
    test('relaxed mode: same individual as reviewer and approver is explicitly permitted', () => {
      expect(() => rules.assertApproverNotReviewer('user-1', 'user-1', { strict: false })).not.toThrow();
    });
    test('different individuals always pass, either mode', () => {
      expect(() => rules.assertApproverNotReviewer('user-1', 'user-2', { strict: true })).not.toThrow();
      expect(() => rules.assertApproverNotReviewer('user-1', 'user-2', { strict: false })).not.toThrow();
    });
    test('no reviewer yet (null) never triggers a violation', () => {
      expect(() => rules.assertApproverNotReviewer(null, 'user-2')).not.toThrow();
    });
  });

  describe('assertPublisherNotAuthor', () => {
    test('throws when publisher === author', () => {
      expect(() => rules.assertPublisherNotAuthor('user-1', 'user-1')).toThrow(MakerCheckerViolationError);
    });
    test('passes for different individuals', () => {
      expect(() => rules.assertPublisherNotAuthor('user-1', 'user-2')).not.toThrow();
    });
  });

  describe('assertRollbackApproverNotAuthor', () => {
    test('throws when the rollback approver requested their own rollback', () => {
      expect(() => rules.assertRollbackApproverNotAuthor('user-1', 'user-1')).toThrow(MakerCheckerViolationError);
    });
  });

  describe('assertRollbackApproverNotOriginalPublisher', () => {
    test('throws when the rollback approver activated the version being rolled back', () => {
      expect(() => rules.assertRollbackApproverNotOriginalPublisher('user-1', 'user-1')).toThrow(MakerCheckerViolationError);
    });
    test('passes when the rollback approver is neither the requester nor the original publisher', () => {
      expect(() => rules.assertRollbackApproverNotOriginalPublisher('user-1', 'user-2')).not.toThrow();
    });
  });

  describe('assertEmergencyRetroApproverNotActivator', () => {
    test('throws when the retrospective approver activated the emergency change', () => {
      expect(() => rules.assertEmergencyRetroApproverNotActivator('user-1', 'user-1')).toThrow(MakerCheckerViolationError);
    });
    test('passes for a different individual', () => {
      expect(() => rules.assertEmergencyRetroApproverNotActivator('user-1', 'user-2')).not.toThrow();
    });
  });

  describe('null/undefined identity handling', () => {
    test('never throws a false positive when either identity is missing', () => {
      expect(() => rules.assertReviewerNotAuthor(null, null)).not.toThrow();
      expect(() => rules.assertApproverNotAuthor(undefined, 'user-1')).not.toThrow();
      expect(() => rules.assertPublisherNotAuthor('user-1', undefined)).not.toThrow();
    });
  });
});

// an identity the author provisioned is not an independent second person.
describe('assertActorNotProvisionedByAuthor', () => {
  const author = { id: 'author-1', username: 'alice' };
  test('refuses an approver the author created (by id, or by username on legacy records)', () => {
    expect(() => rules.assertActorNotProvisionedByAuthor(author, { createdById: 'author-1', createdBy: 'alice' }, 'APPROVER'))
      .toThrow(expect.objectContaining({ code: 'MAKER_CHECKER_VIOLATION', rule: 'APPROVER_PROVISIONED_BY_AUTHOR' }));
    expect(() => rules.assertActorNotProvisionedByAuthor(author, { createdBy: 'alice' }, 'REVIEWER'))
      .toThrow(expect.objectContaining({ rule: 'REVIEWER_PROVISIONED_BY_AUTHOR' }));
  });
  test('refuses an approver whose current API key the author issued', () => {
    expect(() => rules.assertActorNotProvisionedByAuthor(author, { createdBy: 'BOOTSTRAP', apiKeyIssuedById: 'author-1', apiKeyIssuedBy: 'alice' }))
      .toThrow(expect.objectContaining({ rule: 'APPROVER_PROVISIONED_BY_AUTHOR' }));
  });
  // (PROBE-SEC01-A): lineage is transitive — author A provisions B, B provisions approver C.
  test('refuses an approver provisioned by an identity the author provisioned (transitive), via the lookup', () => {
    const recs = {
      'b-1': { id: 'b-1', createdById: 'author-1', createdBy: 'alice', apiKeyIssuedById: 'author-1', apiKeyIssuedBy: 'alice' },
      'c-1': { id: 'c-1', createdById: 'b-1', createdBy: 'bob', apiKeyIssuedById: 'b-1', apiKeyIssuedBy: 'bob' },
    };
    const lookup = (id) => recs[id] || null;
    expect(() => rules.assertActorNotProvisionedByAuthor(author, recs['c-1'], 'APPROVER', lookup))
      .toThrow(expect.objectContaining({ rule: 'APPROVER_PROVISIONED_BY_AUTHOR', message: expect.stringMatching(/1 level up/) }));
    // a deeper chain, and a cycle in the records, still terminate
    recs['d-1'] = { id: 'd-1', createdById: 'c-1', apiKeyIssuedById: null };
    recs['b-1'].apiKeyIssuedById = 'd-1';
    expect(() => rules.assertActorNotProvisionedByAuthor(author, recs['d-1'], 'REVIEWER', lookup))
      .toThrow(expect.objectContaining({ rule: 'REVIEWER_PROVISIONED_BY_AUTHOR' }));
    // an independent lineage passes
    const indep = { 'x-1': { id: 'x-1', createdById: 'root-0', apiKeyIssuedById: null }, 'root-0': { id: 'root-0', createdById: null } };
    expect(() => rules.assertActorNotProvisionedByAuthor(author, indep['x-1'], 'APPROVER', (id) => indep[id] || null)).not.toThrow();
  });

  test('allows an independently provisioned approver; a self-issued key is not "issued by the author"', () => {
    expect(() => rules.assertActorNotProvisionedByAuthor(author, { createdById: 'admin-9', createdBy: 'carol', apiKeyIssuedById: null, apiKeyIssuedBy: 'bob' })).not.toThrow();
    expect(() => rules.assertActorNotProvisionedByAuthor(author, null)).not.toThrow();
  });
});

describe('verification — lineage walk fails closed', () => {
  const rules = require('../makerCheckerRules');
  const author = { id: 'A', username: 'alice' };

  test('F1-MC-01 a deleted ancestor (A created B, B created C, A deleted B) does not make C independent', () => {
    const C = { id: 'C', createdById: 'B', createdBy: 'bob' };
    expect(() => rules.assertActorNotProvisionedByAuthor(author, C, 'APPROVER', () => null))
      .toThrow(/cannot be shown to be independent/);
  });

  test('F1-MC-02 a lookup that throws is a refusal, not "no ancestor"', () => {
    const C = { id: 'C', createdById: 'B', createdBy: 'bob' };
    expect(() => rules.assertActorNotProvisionedByAuthor(author, C, 'APPROVER', () => { throw new Error('store down'); }))
      .toThrow(/cannot be shown to be independent/);
  });

  test('F1-MC-03 a resolvable lineage that never reaches the author still passes', () => {
    const C = { id: 'C', createdById: 'B', createdBy: 'bob' };
    const B = { id: 'B', createdById: 'ROOT', createdBy: 'root' };
    const ROOT = { id: 'ROOT', createdBy: 'BOOTSTRAP' };
    const lookup = (id) => ({ B, ROOT }[id] || null);
    expect(() => rules.assertActorNotProvisionedByAuthor(author, C, 'APPROVER', lookup)).not.toThrow();
  });
});
