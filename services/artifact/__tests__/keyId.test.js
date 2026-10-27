'use strict';

const { parseKeyId, InvalidKeyIdError, KEY_ID_PATTERN } = require('../keyId');

describe('parseKeyId', () => {
  describe('valid IDs', () => {
    test.each([
      ['default:key_v1', { tenantId: 'default', keyVersion: 1 }],
      ['isolation-tenant-a:key_v1', { tenantId: 'isolation-tenant-a', keyVersion: 1 }],
      ['tenant_with_underscores:key_v42', { tenantId: 'tenant_with_underscores', keyVersion: 42 }],
      ['A1b2-C3d4:key_v0', { tenantId: 'A1b2-C3d4', keyVersion: 0 }],
      [`${'a'.repeat(64)}:key_v1`, { tenantId: 'a'.repeat(64), keyVersion: 1 }],
    ])('parses %s', (keyId, expected) => {
      const result = parseKeyId(keyId);
      expect(result.tenantId).toBe(expected.tenantId);
      expect(result.keyVersion).toBe(expected.keyVersion);
    });

    test('returns a frozen object', () => {
      const result = parseKeyId('default:key_v1');
      expect(Object.isFrozen(result)).toBe(true);
    });
  });

  describe('malformed IDs', () => {
    test.each([
      ['no colon at all', 'defaultkey_v1'],
      ['wrong version prefix', 'default:v1'],
      ['wrong separator', 'default;key_v1'],
      ['trailing garbage', 'default:key_v1x'],
      ['tenant id with invalid characters', 'def ault:key_v1'],
      ['tenant id with a colon in it', 'def:ault:key_v1'],
      ['tenant id too long (65 chars)', `${'a'.repeat(65)}:key_v1`],
      ['double colon', 'default::key_v1'],
      ['whitespace only', '   '],
    ])('rejects %s (%p)', (_label, keyId) => {
      expect(() => parseKeyId(keyId)).toThrow(InvalidKeyIdError);
    });
  });

  describe('missing version', () => {
    test.each([
      'default:key_v',
      'default:key_',
      'default:',
      'default',
    ])('rejects %p', (keyId) => {
      expect(() => parseKeyId(keyId)).toThrow(InvalidKeyIdError);
    });
  });

  describe('invalid / non-string input', () => {
    test.each([
      [null],
      [undefined],
      [123],
      [{}],
      [[]],
      [''],
    ])('rejects %p', (keyId) => {
      expect(() => parseKeyId(keyId)).toThrow(InvalidKeyIdError);
    });

    test('non-string input is tagged NOT_A_STRING', () => {
      try {
        parseKeyId(null);
        throw new Error('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(InvalidKeyIdError);
        expect(err.reason).toBe('NOT_A_STRING');
      }
    });

    test('empty string is tagged NOT_A_STRING', () => {
      try {
        parseKeyId('');
        throw new Error('should have thrown');
      } catch (err) {
        expect(err.reason).toBe('NOT_A_STRING');
      }
    });
  });

  describe('typed error propagation', () => {
    test('malformed ID is tagged MALFORMED and carries the offending keyId', () => {
      try {
        parseKeyId('not-a-valid-key-id');
        throw new Error('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(InvalidKeyIdError);
        expect(err).toBeInstanceOf(Error);
        expect(err.name).toBe('InvalidKeyIdError');
        expect(err.code).toBe('INVALID_KEY_ID');
        expect(err.reason).toBe('MALFORMED');
        expect(err.keyId).toBe('not-a-valid-key-id');
      }
    });

    test('error message is descriptive and attributable', () => {
      try {
        parseKeyId('bad-id');
      } catch (err) {
        expect(err.message).toContain('bad-id');
        expect(err.message).toContain('MALFORMED');
      }
    });
  });

  test('KEY_ID_PATTERN is exported and usable directly for boolean checks', () => {
    expect(KEY_ID_PATTERN.test('default:key_v1')).toBe(true);
    expect(KEY_ID_PATTERN.test('default')).toBe(false);
  });
});
