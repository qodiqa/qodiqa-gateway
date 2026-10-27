'use strict';

const { validateIdempotencyKey, IDEMPOTENCY_KEY_MAX_LENGTH, IDEMPOTENCY_HEADER_MAX_BYTES } = require('../idempotencyKey');

describe('validateIdempotencyKey', () => {
  test('accepts a typical UUID-shaped key', () => {
    const result = validateIdempotencyKey('550e8400-e29b-41d4-a716-446655440000');
    expect(result).toEqual({ valid: true, key: '550e8400-e29b-41d4-a716-446655440000' });
  });

  test('preserves the original value unmodified (no trim/re-case)', () => {
    const result = validateIdempotencyKey('MixedCase_Key.123:abc');
    expect(result.valid).toBe(true);
    expect(result.key).toBe('MixedCase_Key.123:abc');
  });

  test('rejects an empty string', () => {
    expect(validateIdempotencyKey('')).toEqual({ valid: false, reason: 'IDEMPOTENCY_KEY_INVALID' });
  });

  test('rejects a non-string value', () => {
    expect(validateIdempotencyKey(123).valid).toBe(false);
    expect(validateIdempotencyKey(null).valid).toBe(false);
    expect(validateIdempotencyKey(undefined).valid).toBe(false);
  });

  test('rejects an array (repeated header)', () => {
    expect(validateIdempotencyKey(['a', 'b'])).toEqual({ valid: false, reason: 'IDEMPOTENCY_KEY_INVALID' });
  });

  test('rejects a key exceeding IDEMPOTENCY_KEY_MAX_LENGTH', () => {
    const tooLong = 'a'.repeat(IDEMPOTENCY_KEY_MAX_LENGTH + 1);
    expect(validateIdempotencyKey(tooLong)).toEqual({ valid: false, reason: 'IDEMPOTENCY_KEY_TOO_LARGE' });
  });

  test('accepts a key at exactly IDEMPOTENCY_KEY_MAX_LENGTH', () => {
    const maxLen = 'a'.repeat(IDEMPOTENCY_KEY_MAX_LENGTH);
    expect(validateIdempotencyKey(maxLen).valid).toBe(true);
  });

  test('rejects a raw value exceeding IDEMPOTENCY_HEADER_MAX_BYTES even if under length limit', () => {
    // multi-byte UTF-8 characters inflate byte length faster than char length
    const wide = '\u{1F600}'.repeat(Math.ceil(IDEMPOTENCY_HEADER_MAX_BYTES / 4) + 10);
    const result = validateIdempotencyKey(wide);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('IDEMPOTENCY_KEY_TOO_LARGE');
  });

  test('rejects whitespace', () => {
    expect(validateIdempotencyKey('has a space').valid).toBe(false);
    expect(validateIdempotencyKey('trailing' + String.fromCharCode(9)).valid).toBe(false);
    expect(validateIdempotencyKey('newline' + String.fromCharCode(10)).valid).toBe(false);
  });

  test('rejects control characters', () => {
    expect(validateIdempotencyKey('key' + String.fromCharCode(0) + 'withnull').valid).toBe(false);
    expect(validateIdempotencyKey('key' + String.fromCharCode(27) + 'withescape').valid).toBe(false);
  });

  test('accepts common opaque-token charsets', () => {
    expect(validateIdempotencyKey('req_2f8b3c9d1a').valid).toBe(true);
    expect(validateIdempotencyKey('01HXYZ0123456789ABCDEFGHJK').valid).toBe(true); // ULID-shaped
    expect(validateIdempotencyKey('dGVzdC1iYXNlNjQ=').valid).toBe(true); // base64-shaped
  });
});
