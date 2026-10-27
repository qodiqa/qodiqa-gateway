'use strict';

/**
 * Local KEK Provider
 *
 * Reads the 256-bit Key Encryption Key from QODIQA_KEY_ENCRYPTION_KEY.
 * This is the current production provider and the fallback for all deployments
 * that have not yet migrated to an external KMS.
 *
 * Zero external dependencies; fully synchronous; backward compatible.
 */

const { KekProvider } = require('./base');

const KEK_BYTE_LENGTH = 32;

class LocalKekProvider extends KekProvider {
  constructor() {
    super();
    this._kek = null;
  }

  get name() {
    return 'local:env:QODIQA_KEY_ENCRYPTION_KEY';
  }

  async initialize() {
    const raw = process.env.QODIQA_KEY_ENCRYPTION_KEY;
    if (!raw) {
      throw new Error(
        'LocalKekProvider: QODIQA_KEY_ENCRYPTION_KEY is not set. ' +
        'A 256-bit KEK (64 hex characters) is required.',
      );
    }
    if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
      throw new Error(
        `LocalKekProvider: QODIQA_KEY_ENCRYPTION_KEY must be exactly 64 hex characters. ` +
        `Got ${raw.length} character(s).`,
      );
    }
    const kek = Buffer.from(raw, 'hex');
    if (kek.length !== KEK_BYTE_LENGTH) {
      throw new Error(
        `LocalKekProvider: decoded KEK is ${kek.length} bytes; expected ${KEK_BYTE_LENGTH}.`,
      );
    }
    this._kek = kek;
  }

  async getWrappingKey() {
    if (!this._kek) {
      throw new Error('LocalKekProvider: not initialized — call initialize() first');
    }
    return this._kek;
  }

  // Local provider delegates wrapping-key rotation to the operator (env var replacement).
  async rotateWrappingKey() {
    return { version: 'env:manual' };
  }

  async healthCheck() {
    const healthy = this._kek !== null;
    return {
      healthy,
      detail: healthy
        ? 'KEK loaded from QODIQA_KEY_ENCRYPTION_KEY'
        : 'KEK not loaded — initialize() has not been called',
    };
  }
}

module.exports = { LocalKekProvider };
