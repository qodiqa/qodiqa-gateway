import { BaseResource } from './base.js';
import type { VerifyRequest, VerifyResponse } from '../types.js';
import { assertNonEmpty } from '../utils/validation.js';

export class VerifyResource extends BaseResource {
  /**
   * Verify a request against the enforcement pipeline (rate-limited under
   * the public `verify_public` bucket).
   *
   * `POST /verify`
   *
   * The artifact travels only in `request.artifact` — the server route
   * reads the artifact from the body and does not inspect any header, so
   * no `x-qodiqa-artifact` header is sent (a previously-sent header
   * here had no server-side effect). The `artifact` parameter is retained
   * for backward compatibility with existing call sites and is still
   * validated as non-empty.
   *
   * @param artifact  Base64-encoded artifact string (validated, not transmitted).
   * @param request   The request descriptor to verify — must include a populated `artifact` field.
   */
  async verify(
    artifact: string,
    request: VerifyRequest,
  ): Promise<VerifyResponse> {
    assertNonEmpty(artifact, 'artifact');

    return this.http.post<VerifyResponse>('/verify', request);
  }

  /**
   * Verify a request against the enforcement pipeline under the higher
   * `verify_v2` rate-limit bucket. Runs the identical validation pipeline
   * as `verify()`/`dryRun()` (same server-side handler; see
   * `src/api/routes/verify.js`) — the only difference is the endpoint's
   * rate-limit configuration.
   *
   * `POST /verify/v2`
   *
   * @param request  The verify request including a populated `artifact` field.
   */
  async verifyV2(request: VerifyRequest): Promise<VerifyResponse> {
    return this.http.post<VerifyResponse>('/verify/v2', request);
  }

  /**
   * Dry-run verification — artifact is included in the request body only,
   * no header is set.
   *
   * `POST /verify`
   *
   * @param request  The verify request including a populated `artifact` field.
   */
  async dryRun(request: VerifyRequest): Promise<VerifyResponse> {
    return this.http.post<VerifyResponse>('/verify', request);
  }
}
