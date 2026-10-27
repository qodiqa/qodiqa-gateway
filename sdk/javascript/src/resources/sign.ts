import { BaseResource } from './base.js';
import type { SignRequest, SignResponse } from '../types.js';
import { assertNonEmpty } from '../utils/validation.js';

export class SignResource extends BaseResource {
  /**
   * Issue a signed artifact via `POST /sign`.
   *
   * Requires a `signToken` to be configured on the client.  Optionally
   * accepts an already-issued artifact string (base64) in `artifactHeader`
   * to attach an existing artifact instead of minting a fresh one.
   *
   * @param request       The signing request body.
   * @param artifactHeader  Optional pre-existing artifact (base64) attached
   *                        as `x-qodiqa-artifact`.
   */
  async sign(
    request: SignRequest,
    artifactHeader?: string,
  ): Promise<SignResponse> {
    assertNonEmpty(request.request.method, 'request.request.method');
    assertNonEmpty(request.request.path, 'request.request.path');

    const headers: Record<string, string> = {
      ...this.auth.getSignTokenHeader(),
    };

    if (artifactHeader !== undefined) {
      Object.assign(headers, this.auth.getArtifactHeader(artifactHeader));
    }

    return this.http.post<SignResponse>('/sign', request, { headers });
  }
}
