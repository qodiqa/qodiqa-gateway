import { AuthenticationError } from './errors.js';
import type { ResolvedConfig } from './config.js';

export class AuthProvider {
  constructor(private readonly config: ResolvedConfig) {}

  /**
   * Returns the `Authorization: Bearer ok_<hex>` header required for all
   * ops-protected endpoints.  Throws `AuthenticationError` if no apiKey is
   * configured.
   */
  getAuthHeader(): Record<string, string> {
    if (!this.config.apiKey) {
      throw new AuthenticationError(
        'An ops API key (apiKey) is required for this endpoint. ' +
          'Provide it when constructing QodiqaClient: new QodiqaClient({ apiKey: "ok_..." }).',
      );
    }
    return { Authorization: `Bearer ${this.config.apiKey}` };
  }

  /**
   * Returns the `x-qodiqa-artifact: <base64>` header used by the /ai/chat
   * endpoint (see `src/api/routes/aiChat.js`, which decodes this header to
   * obtain the artifact).
   *
   * /verify and /verify/v2 do NOT read this header — both routes take the
   * artifact only from the request body (see `src/api/routes/verify.js`),
   * so `VerifyResource` never calls this method (it previously did,
   * sending a header the server silently ignored).
   */
  getArtifactHeader(artifact: string): Record<string, string> {
    if (!artifact || artifact.trim() === '') {
      throw new AuthenticationError(
        'A base64-encoded artifact string is required for this endpoint.',
      );
    }
    return { 'x-qodiqa-artifact': artifact };
  }

  /**
   * Returns the `Authorization: Bearer <token>` header used by POST /sign.
   *
   * As of the TRUST-1 remediation, POST /sign no longer accepts a single
   * shared secret via `x-qodiqa-sign-token` — every caller authenticates
   * with its own individually-issued, individually-revocable signing API
   * key (prefix `sk_`), provisioned via POST /signing-identities or
   * `scripts/provision-signing-identity.js`. The `signToken` config field
   * name is unchanged for backward compatibility; its value is now a
   * per-identity signing key rather than a shared token.
   *
   * remediation (follow-on to TRUST-1): the server now embeds this
   * key's authenticated identity (`callerContext` — see `ArtifactPayload`
   * in types.ts) directly into every artifact it signs, so the returned
   * artifact durably proves not just which shared tenant key signed it, but
   * which specific `sk_...` credential requested the signature. Nothing to
   * change on the client side — this happens automatically server-side from
   * the credential presented here.
   *
   * Throws `AuthenticationError` if no signToken is configured.
   */
  getSignTokenHeader(): Record<string, string> {
    if (!this.config.signToken) {
      throw new AuthenticationError(
        'A signing API key (signToken) is required to call POST /sign. ' +
          'Provide it when constructing QodiqaClient: new QodiqaClient({ signToken: "sk_..." }).',
      );
    }
    return { Authorization: `Bearer ${this.config.signToken}` };
  }
}
