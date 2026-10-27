import { BaseResource } from './base.js';
import type { ApiResponse } from '../types.js';
import { assertNonEmpty } from '../utils/validation.js';

export class EvidenceResource extends BaseResource {
  /**
   * Retrieve the evidence package associated with an artifact.
   *
   * `GET /v1/attestation/:artifactId/evidence`
   *
   * Requires ops API key.
   */
  async getPackage(attestationId: string): Promise<ApiResponse<unknown>> {
    // `GET /v1/attestation/:attestationId/evidence` is keyed by the ATTESTATION id (a UUID returned by
    // attestation.verify), not by an artifact id.
    assertNonEmpty(attestationId, 'attestationId');
    const headers = this.auth.getAuthHeader();
    return this.http.get<ApiResponse<unknown>>(
      `/v1/attestation/${encodeURIComponent(attestationId)}/evidence`,
      { headers },
    );
  }
}
