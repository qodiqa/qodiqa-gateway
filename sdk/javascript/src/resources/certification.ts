import { BaseResource } from './base.js';
import type {
  ApiResponse,
  CertificationEvaluateRequest,
  CertificationRecord,
  BatchSubmitRequest,
  BatchRecord,
  CertificationListResponse,
  PaginationParams,
} from '../types.js';
import { assertNonEmpty } from '../utils/validation.js';

export class CertificationResource extends BaseResource {
  // ---------------------------------------------------------------------------
  // Public endpoints
  // ---------------------------------------------------------------------------

  /**
   * Run a certification evaluation. `POST /v1/certification/evaluate`
   *
   * Requires ops API key.
   */
  async evaluate(
    request: CertificationEvaluateRequest,
  ): Promise<ApiResponse<CertificationRecord>> {
    const headers = this.auth.getAuthHeader();
    return this.http.post<ApiResponse<CertificationRecord>>(
      '/v1/certification/evaluate',
      request,
      { headers },
    );
  }

  /**
   * Retrieve a certification record by ID. `GET /v1/certification/:id`
   */
  async get(id: string): Promise<ApiResponse<CertificationRecord>> {
    assertNonEmpty(id, 'id');
    return this.http.get<ApiResponse<CertificationRecord>>(
      `/v1/certification/${encodeURIComponent(id)}`,
    );
  }

  /**
   * Retrieve a summary for a certification record. `GET /v1/certification/:id/summary`
   */
  async getSummary(id: string): Promise<ApiResponse<unknown>> {
    assertNonEmpty(id, 'id');
    return this.http.get<ApiResponse<unknown>>(
      `/v1/certification/${encodeURIComponent(id)}/summary`,
    );
  }

  // ---------------------------------------------------------------------------
  // Ops-protected endpoints
  // ---------------------------------------------------------------------------

  /**
   * Submit a batch of certification requests. `POST /v1/certifications/batch`
   *
   * Requires ops API key.
   */
  async submitBatch(
    request: BatchSubmitRequest,
  ): Promise<ApiResponse<BatchRecord>> {
    const headers = this.auth.getAuthHeader();
    return this.http.post<ApiResponse<BatchRecord>>(
      '/v1/certifications/batch',
      request,
      { headers },
    );
  }

  /**
   * Get the status of a certification batch. `GET /v1/certifications/batch/:batchId`
   *
   * Requires ops API key.
   */
  async getBatch(batchId: string): Promise<ApiResponse<BatchRecord>> {
    assertNonEmpty(batchId, 'batchId');
    const headers = this.auth.getAuthHeader();
    return this.http.get<ApiResponse<BatchRecord>>(
      `/v1/certifications/batch/${encodeURIComponent(batchId)}`,
      { headers },
    );
  }

  /**
   * Get the results for a completed certification batch.
   * `GET /v1/certifications/batch/:batchId/results`
   *
   * Requires ops API key.
   */
  async getBatchResults(batchId: string): Promise<ApiResponse<unknown>> {
    assertNonEmpty(batchId, 'batchId');
    const headers = this.auth.getAuthHeader();
    return this.http.get<ApiResponse<unknown>>(
      `/v1/certifications/batch/${encodeURIComponent(batchId)}/results`,
      { headers },
    );
  }

  /**
   * Cancel a pending or processing certification batch.
   * `POST /v1/certifications/batch/:batchId/cancel`
   *
   * Requires ops API key.
   */
  async cancelBatch(batchId: string): Promise<ApiResponse<unknown>> {
    assertNonEmpty(batchId, 'batchId');
    const headers = this.auth.getAuthHeader();
    return this.http.post<ApiResponse<unknown>>(
      `/v1/certifications/batch/${encodeURIComponent(batchId)}/cancel`,
      {},
      { headers },
    );
  }

  /**
   * List certification history (admin). `GET /v1/certification/admin/history`
   *
   * Requires ops API key. Note the singular `/v1/certification` mount —
   * distinct from the plural `/v1/certifications/batch/*` routes above.
   */
  async list(
    params?: PaginationParams,
  ): Promise<ApiResponse<CertificationListResponse>> {
    const headers = this.auth.getAuthHeader();
    const query = this.buildPaginationQuery(params);
    return this.http.get<ApiResponse<CertificationListResponse>>(
      '/v1/certification/admin/history',
      { headers, query },
    );
  }

  /**
   * Retrieve certification admin statistics. `GET /v1/certification/admin/stats`
   *
   * Requires ops API key. Note the singular `/v1/certification` mount.
   */
  async stats(): Promise<ApiResponse<unknown>> {
    const headers = this.auth.getAuthHeader();
    return this.http.get<ApiResponse<unknown>>('/v1/certification/admin/stats', {
      headers,
    });
  }
}
