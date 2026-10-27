import { ValidationError } from './errors.js';
import { isValidUrl, isValidApiKey } from './utils/validation.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface QodiqaClientConfig {
  /** Ops API key — must start with `ok_` followed by 64 hex characters */
  apiKey?: string;
  /**
   * Per-identity signing API key (prefix `sk_`), sent as `Authorization:
   * Bearer <signToken>` when calling POST /sign. Issued via
   * POST /signing-identities/:id/api-key or
   * `scripts/provision-signing-identity.js` — never a shared secret.
   */
  signToken?: string;
  /** Base URL for the QODIQA server. Default: `http://localhost:3000` */
  baseUrl?: string;
  /** Request timeout in milliseconds. Default: 30 000 */
  timeout?: number;
  /** Maximum retry attempts for retryable errors. Default: 2 */
  maxRetries?: number;
  /** Extra headers merged into every request */
  defaultHeaders?: Record<string, string>;
  /** Override the `User-Agent` header */
  userAgent?: string;
  /**
   * Operator MFA step-up. Called only when the server answers 401 `MFA_REQUIRED` to a mutation
   * (the step-up refuses BEFORE the handler runs, so nothing was changed); the SDK then resends that one request once
   * with `X-QODIQA-OTP: <code>`. Return a FRESH code each call — the server accepts a TOTP code at most once per
   * 30-second step. Unset: `MfaRequiredError` is thrown.
   */
  otpProvider?: () => string | Promise<string>;
}

export interface ResolvedConfig {
  apiKey: string | undefined;
  signToken: string | undefined;
  baseUrl: string;
  timeout: number;
  maxRetries: number;
  defaultHeaders: Record<string, string>;
  userAgent: string;
  otpProvider: (() => string | Promise<string>) | undefined;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_BASE_URL = 'http://localhost:3000';
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RETRIES = 2;
const DEFAULT_USER_AGENT = '@qodiqa/sdk/1.0.0 node/' + process.version;

// ---------------------------------------------------------------------------
// resolveConfig
// ---------------------------------------------------------------------------

export function resolveConfig(config: QodiqaClientConfig): ResolvedConfig {
  return {
    apiKey: config.apiKey,
    signToken: config.signToken,
    baseUrl: config.baseUrl ?? DEFAULT_BASE_URL,
    timeout: config.timeout ?? DEFAULT_TIMEOUT_MS,
    maxRetries: config.maxRetries ?? DEFAULT_MAX_RETRIES,
    defaultHeaders: config.defaultHeaders ?? {},
    userAgent: config.userAgent ?? DEFAULT_USER_AGENT,
    otpProvider: config.otpProvider,
  };
}

// ---------------------------------------------------------------------------
// validateConfig
// ---------------------------------------------------------------------------

export function validateConfig(config: ResolvedConfig): void {
  if (!isValidUrl(config.baseUrl)) {
    throw new ValidationError(
      `Invalid baseUrl: "${config.baseUrl}" — must be a valid http or https URL.`,
    );
  }

  if (config.apiKey !== undefined && !isValidApiKey(config.apiKey)) {
    throw new ValidationError(
      'Invalid apiKey: must start with "ok_" followed by exactly 64 hexadecimal characters (total 67 chars).',
    );
  }

  if (config.timeout <= 0) {
    throw new ValidationError('timeout must be a positive integer (milliseconds).');
  }

  if (config.maxRetries < 0 || !Number.isInteger(config.maxRetries)) {
    throw new ValidationError('maxRetries must be a non-negative integer.');
  }
}
