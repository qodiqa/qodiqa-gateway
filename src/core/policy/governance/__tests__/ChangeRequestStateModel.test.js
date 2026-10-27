'use strict';

const {
  STATE, isValidTransition, isTerminal, isValid,
} = require('../ChangeRequestStateModel');

describe('ChangeRequestStateModel', () => {
  describe('STATE constants', () => {
    test('exports all ten states', () => {
      expect(Object.keys(STATE)).toHaveLength(10);
      for (const s of ['DRAFT', 'SUBMITTED', 'IN_REVIEW', 'REVIEWED', 'APPROVED',
        'SCHEDULED', 'PUBLISHED', 'REJECTED', 'WITHDRAWN', 'EXPIRED']) {
        expect(STATE[s]).toBe(s);
      }
    });
  });

  describe('isValidTransition() — strict mode (default)', () => {
    test('DRAFT -> SUBMITTED is valid',       () => expect(isValidTransition('DRAFT', 'SUBMITTED')).toBe(true));
    test('SUBMITTED -> IN_REVIEW is valid',   () => expect(isValidTransition('SUBMITTED', 'IN_REVIEW')).toBe(true));
    test('IN_REVIEW -> REVIEWED is valid',    () => expect(isValidTransition('IN_REVIEW', 'REVIEWED')).toBe(true));
    test('IN_REVIEW -> DRAFT is valid (changes requested)', () => expect(isValidTransition('IN_REVIEW', 'DRAFT')).toBe(true));
    test('REVIEWED -> APPROVED is valid',     () => expect(isValidTransition('REVIEWED', 'APPROVED')).toBe(true));
    test('REVIEWED -> REJECTED is valid',     () => expect(isValidTransition('REVIEWED', 'REJECTED')).toBe(true));
    test('APPROVED -> SCHEDULED is valid',    () => expect(isValidTransition('APPROVED', 'SCHEDULED')).toBe(true));
    test('APPROVED -> PUBLISHED is valid',    () => expect(isValidTransition('APPROVED', 'PUBLISHED')).toBe(true));
    test('SCHEDULED -> PUBLISHED is valid',   () => expect(isValidTransition('SCHEDULED', 'PUBLISHED')).toBe(true));

    test('DRAFT -> PUBLISHED is NEVER valid', () => {
      expect(isValidTransition('DRAFT', 'PUBLISHED')).toBe(false);
      expect(isValidTransition('DRAFT', 'PUBLISHED', true)).toBe(false);
      expect(isValidTransition('DRAFT', 'PUBLISHED', false)).toBe(false);
    });

    test('SUBMITTED -> APPROVED is invalid in strict mode (review is mandatory)', () => {
      expect(isValidTransition('SUBMITTED', 'APPROVED', true)).toBe(false);
    });

    test('SUBMITTED -> PUBLISHED is invalid', () => expect(isValidTransition('SUBMITTED', 'PUBLISHED')).toBe(false));
    test('unknown state returns false', () => expect(isValidTransition('BOGUS', 'DRAFT')).toBe(false));
    test('terminal states have no outgoing transitions', () => {
      for (const s of ['PUBLISHED', 'REJECTED', 'WITHDRAWN', 'EXPIRED']) {
        expect(isValidTransition(s, 'DRAFT')).toBe(false);
        expect(isValidTransition(s, 'SUBMITTED')).toBe(false);
      }
    });
  });

  describe('isValidTransition() — relaxed mode', () => {
    test('SUBMITTED -> APPROVED is valid (merges reviewer into approver)', () => {
      expect(isValidTransition('SUBMITTED', 'APPROVED', false)).toBe(true);
    });
    test('DRAFT -> PUBLISHED is still never valid, even relaxed', () => {
      expect(isValidTransition('DRAFT', 'PUBLISHED', false)).toBe(false);
    });
    test('every other edge is identical to strict mode', () => {
      expect(isValidTransition('REVIEWED', 'APPROVED', false)).toBe(true);
      expect(isValidTransition('APPROVED', 'PUBLISHED', false)).toBe(true);
    });
  });

  describe('isTerminal()', () => {
    test('PUBLISHED/REJECTED/WITHDRAWN/EXPIRED are terminal', () => {
      for (const s of ['PUBLISHED', 'REJECTED', 'WITHDRAWN', 'EXPIRED']) expect(isTerminal(s)).toBe(true);
    });
    test('DRAFT/SUBMITTED/IN_REVIEW/REVIEWED/APPROVED/SCHEDULED are not terminal', () => {
      for (const s of ['DRAFT', 'SUBMITTED', 'IN_REVIEW', 'REVIEWED', 'APPROVED', 'SCHEDULED']) {
        expect(isTerminal(s)).toBe(false);
      }
    });
  });

  describe('isValid()', () => {
    test('recognises all ten states', () => {
      for (const s of Object.values(STATE)) expect(isValid(s)).toBe(true);
    });
    test('rejects unknown state', () => expect(isValid('BOGUS')).toBe(false));
  });
});
