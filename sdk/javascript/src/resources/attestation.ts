import { BaseResource } from './base.js';
import type {
  ApiResponse,
  AttestationVerifyRequest,
  AttestationRecord,
  AttestationListResponse,
  PaginationParams,
} from '../types.js';
import { assertNonEmpty } from '../utils/validation.js';

export class AttestationResource extends BaseResource {
  // ---------------------------------------------------------------------------
  // Public endpoints
  // ---------------------------------------------------------------------------

  /**
   * Generate an attestation from an artifact. `POST /v1/attestation/verify`
   */
  async verify(
    request: AttestationVerifyRequest,
  ): Promise<ApiResponse<AttestationRecord>> {
    return this.http.post<ApiResponse<AttestationRecord>>(
      '/v1/attestation/verify',
      request,
    );
  }

  /**
   * Verify an evidence package (e.g. one previously obtained from
   * `getEvidence()`/`evidence.getPackage()`). `POST /v1/attestation/evidence/verify`
   *
   * Takes an evidence package, NOT a signed artifact — the server checks
   * `evidencePackage.packageType === 'QODIQA::PORTAL_EVIDENCE::V1'` and
   * rejects anything else (including a raw artifact) with
   * `valid: false, failureReason: "Unsupported package type: undefined"`.
   */
  async verifyEvidence(request: {
    evidencePackage: Record<string, unknown>;
  }): Promise<ApiResponse<unknown>> {
    return this.http.post<ApiResponse<unknown>>(
      '/v1/attestation/evidence/verify',
      request,
    );
  }

  /**
   * Verify a full attestation chain by evidence ID range. `POST /v1/attestation/chain/verify`
   *
   * Takes `evidenceIds` and/or a `range`, NOT a signed artifact — the
   * server's schema is `.strict()` and rejects any other key (including
   * `artifact`) with a 400.
   */
  async verifyChain(request: {
    evidenceIds?: string[];
    range?: Record<string, unknown>;
  }): Promise<ApiResponse<unknown>> {
    // admin router + MANAGE_ATTESTATIONS server-side — requires ops API key.
    const headers = this.auth.getAuthHeader();
    return this.http.post<ApiResponse<unknown>>(
      '/v1/attestation/chain/verify',
      request,
      { headers },
    );
  }

  /**
   * Fetch a single attestation record by ID. `GET /v1/attestation/:id`
   */
  async get(id: string): Promise<ApiResponse<AttestationRecord>> {
    assertNonEmpty(id, 'id');
    return this.http.get<ApiResponse<AttestationRecord>>(
      `/v1/attestation/${encodeURIComponent(id)}`,
    );
  }

  // ---------------------------------------------------------------------------
  // Ops-protected endpoints
  // ---------------------------------------------------------------------------

  /**
   * Export an attestation record for audit/regulatory review.
   * `GET /v1/attestation/:id/export`
   *
   * Requires ops API key with the `EXPORT_ATTESTATIONS` permission.
   *
   * This method covers the server's default (JSON) export only — the
   * server also supports `?format=pdf`, streaming a rendered PDF instead of
   * JSON, which this method does not expose (the SDK's `HttpClient` only
   * parses JSON/text bodies, not binary responses). Callers who need the
   * PDF export should call the endpoint directly.
   */
  async export(id: string): Promise<ApiResponse<AttestationRecord>> {
    assertNonEmpty(id, 'id');
    const headers = this.auth.getAuthHeader();
    return this.http.get<ApiResponse<AttestationRecord>>(
      `/v1/attestation/${encodeURIComponent(id)}/export`,
      { headers },
    );
  }

  /**
   * Retrieve the evidence package for an attestation. `GET /v1/attestation/:id/evidence`
   *
   * Requires ops API key.
   */
  async getEvidence(id: string): Promise<ApiResponse<unknown>> {
    assertNonEmpty(id, 'id');
    const headers = this.auth.getAuthHeader();
    return this.http.get<ApiResponse<unknown>>(
      `/v1/attestation/${encodeURIComponent(id)}/evidence`,
      { headers },
    );
  }

  /**
   * Retrieve a summary for an attestation record. `GET /v1/attestation/:id/summary`
   *
   * Requires ops API key.
   */
  async getSummary(id: string): Promise<ApiResponse<unknown>> {
    assertNonEmpty(id, 'id');
    const headers = this.auth.getAuthHeader();
    return this.http.get<ApiResponse<unknown>>(
      `/v1/attestation/${encodeURIComponent(id)}/summary`,
      { headers },
    );
  }

  /**
   * List attestation history (admin). `GET /v1/attestation/admin/history`
   *
   * Requires ops API key.
   */
  async list(
    params?: PaginationParams,
  ): Promise<ApiResponse<AttestationListResponse>> {
    const headers = this.auth.getAuthHeader();
    const query = this.buildPaginationQuery(params);
    return this.http.get<ApiResponse<AttestationListResponse>>(
      '/v1/attestation/admin/history',
      { headers, query },
    );
  }

  /**
   * Retrieve attestation admin statistics. `GET /v1/attestation/admin/stats`
   *
   * Requires ops API key.
   */
  async stats(): Promise<ApiResponse<unknown>> {
    const headers = this.auth.getAuthHeader();
    return this.http.get<ApiResponse<unknown>>('/v1/attestation/admin/stats', {
      headers,
    });
  }
}
