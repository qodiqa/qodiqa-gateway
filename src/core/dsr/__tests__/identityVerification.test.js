'use strict';

/**
 * identityVerification — test suite (mocked DSRStore)
 *
 * Covers: verifyIdentity() method/result validation, assertVerified(),
 * assertApproved() gates.
 */

describe('identityVerification', () => {
  let iv;
  let mockUpdateStatus;

  beforeEach(() => {
    jest.resetModules();
    mockUpdateStatus = jest.fn();
    jest.doMock('../DSRStore', () => ({ updateStatus: mockUpdateStatus }));
    iv = require('../identityVerification');
  });

  afterEach(() => jest.resetModules());

  describe('VERIFICATION_METHODS / isValidMethod()', () => {
    test('exposes a fixed enum of methods', () => {
      expect(iv.VERIFICATION_METHODS).toEqual([
        'OPERATOR_ATTESTATION', 'PRIOR_ACCOUNT_VERIFICATION', 'LEGAL_REQUEST',
      ]);
    });
    test('accepts a listed method', () => expect(iv.isValidMethod('OPERATOR_ATTESTATION')).toBe(true));
    test('rejects an unlisted method', () => expect(iv.isValidMethod('MADE_UP')).toBe(false));
  });

  describe('verifyIdentity()', () => {
    test('VERIFIED result transitions status to IDENTITY_VERIFIED', async () => {
      mockUpdateStatus.mockResolvedValue({ id: 'req-1', status: 'IDENTITY_VERIFIED' });

      await iv.verifyIdentity({
        requestId: 'req-1', method: 'OPERATOR_ATTESTATION', result: 'VERIFIED', verifiedBy: 'ops-1',
      });

      expect(mockUpdateStatus).toHaveBeenCalledWith(expect.objectContaining({
        id: 'req-1', status: 'IDENTITY_VERIFIED', eventType: 'DSR_IDENTITY_VERIFIED',
      }));
    });

    test('FAILED result transitions status to REJECTED and records an error', async () => {
      mockUpdateStatus.mockResolvedValue({ id: 'req-1', status: 'REJECTED' });

      await iv.verifyIdentity({
        requestId: 'req-1', method: 'LEGAL_REQUEST', result: 'FAILED', verifiedBy: 'ops-1',
      });

      const call = mockUpdateStatus.mock.calls[0][0];
      expect(call.status).toBe('REJECTED');
      expect(call.patch.error).toBeTruthy();
      expect(call.eventType).toBe('DSR_IDENTITY_VERIFICATION_FAILED');
    });

    test('rejects an invalid method', async () => {
      await expect(iv.verifyIdentity({
        requestId: 'req-1', method: 'MADE_UP', result: 'VERIFIED', verifiedBy: 'ops-1',
      })).rejects.toThrow('method must be one of');
    });

    test('rejects an invalid result', async () => {
      await expect(iv.verifyIdentity({
        requestId: 'req-1', method: 'LEGAL_REQUEST', result: 'MAYBE', verifiedBy: 'ops-1',
      })).rejects.toThrow("result must be 'VERIFIED' or 'FAILED'");
    });

    test('requires verifiedBy', async () => {
      await expect(iv.verifyIdentity({
        requestId: 'req-1', method: 'LEGAL_REQUEST', result: 'VERIFIED',
      })).rejects.toThrow('verifiedBy is required');
    });
  });

  describe('assertVerified()', () => {
    test('passes for a VERIFIED request', () => {
      expect(() => iv.assertVerified({ id: 'req-1', identity_verification_result: 'VERIFIED' })).not.toThrow();
    });
    test('throws for an unverified request', () => {
      expect(() => iv.assertVerified({ id: 'req-1', identity_verification_result: null }))
        .toThrow('has not passed identity verification');
    });
    test('throws for a null request', () => {
      expect(() => iv.assertVerified(null)).toThrow();
    });
  });

  describe('assertApproved()', () => {
    test('passes for an APPROVED request', () => {
      expect(() => iv.assertApproved({ id: 'req-1', status: 'APPROVED' })).not.toThrow();
    });
    test('throws for a merely IDENTITY_VERIFIED (not yet approved) request', () => {
      expect(() => iv.assertApproved({ id: 'req-1', status: 'IDENTITY_VERIFIED' }))
        .toThrow('is not approved for execution');
    });
  });
});
