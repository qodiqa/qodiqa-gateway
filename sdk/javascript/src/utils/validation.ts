import { ValidationError } from '../errors.js';

/**
 * Returns true if `url` is a syntactically valid http or https URL.
 */
export function isValidUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Returns true if `key` matches the ops API key format: `ok_` followed by
 * exactly 64 lowercase hexadecimal characters (total length 67).
 */
export function isValidApiKey(key: string): boolean {
  return /^ok_[0-9a-f]{64}$/.test(key);
}

/**
 * Throws `ValidationError` if `value` is an empty string or contains only
 * whitespace.
 */
export function assertNonEmpty(value: string, name: string): void {
  if (!value || value.trim() === '') {
    throw new ValidationError(`"${name}" must be a non-empty string.`);
  }
}

/**
 * Throws `ValidationError` if `value` is not a positive integer (> 0).
 */
export function assertPositiveInt(value: number, name: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new ValidationError(`"${name}" must be a positive integer, got: ${value}.`);
  }
}
