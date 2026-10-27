import { BaseResource } from './base.js';
import type {
  ApiResponse,
  WebhookCreateRequest,
  WebhookRecord,
  WebhookCreateResult,
  WebhookUpdateRequest,
  WebhookListResponse,
  PaginationParams,
} from '../types.js';
import { assertNonEmpty } from '../utils/validation.js';
import { ValidationError } from '../errors.js';

export class WebhooksResource extends BaseResource {
  /**
   * Create a new webhook. `POST /v1/webhooks`
   *
   * Requires ops API key.
   */
  async create(
    request: WebhookCreateRequest,
  ): Promise<ApiResponse<WebhookCreateResult>> {
    assertNonEmpty(request.tenantId, 'request.tenantId');
    assertNonEmpty(request.url, 'request.url');
    if (!Array.isArray(request.eventTypes) || request.eventTypes.length === 0) {
      throw new ValidationError('"request.eventTypes" must be a non-empty array of event type strings.');
    }
    const headers = this.auth.getAuthHeader();
    return this.http.post<ApiResponse<WebhookCreateResult>>('/v1/webhooks', request, {
      headers,
    });
  }

  /**
   * List webhooks. `GET /v1/webhooks`
   *
   * Requires ops API key. `tenantId` is required server-side
   * (`src/api/routes/webhooks.js`) — there is no cross-tenant list.
   */
  async list(
    tenantId: string,
    params?: PaginationParams,
  ): Promise<ApiResponse<WebhookListResponse>> {
    assertNonEmpty(tenantId, 'tenantId');
    const headers = this.auth.getAuthHeader();
    const query = { ...this.buildPaginationQuery(params), tenantId };
    return this.http.get<ApiResponse<WebhookListResponse>>(
      '/v1/webhooks',
      { headers, query },
    );
  }

  /**
   * Retrieve a single webhook by ID. `GET /v1/webhooks/:id?tenantId=`
   *
   * Requires ops API key. `tenantId` is required server-side (400 without it — / API-15: before this
   * argument existed, the call could never succeed against a real gateway).
   */
  async get(id: string, tenantId: string): Promise<ApiResponse<WebhookRecord>> {
    assertNonEmpty(id, 'id');
    assertNonEmpty(tenantId, 'tenantId');
    const headers = this.auth.getAuthHeader();
    return this.http.get<ApiResponse<WebhookRecord>>(
      `/v1/webhooks/${encodeURIComponent(id)}`,
      { headers, query: { tenantId } },
    );
  }

  /**
   * Update a webhook. `PATCH /v1/webhooks/:id?tenantId=`
   *
   * Requires ops API key. `tenantId` is required server-side (400 without it — / API-15: before this
   * argument existed, the call could never succeed against a real gateway).
   */
  async update(
    id: string,
    request: WebhookUpdateRequest,
    tenantId: string,
  ): Promise<ApiResponse<WebhookRecord>> {
    assertNonEmpty(id, 'id');
    assertNonEmpty(tenantId, 'tenantId');
    const headers = this.auth.getAuthHeader();
    return this.http.patch<ApiResponse<WebhookRecord>>(
      `/v1/webhooks/${encodeURIComponent(id)}`,
      request,
      { headers, query: { tenantId } },
    );
  }

  /**
   * Delete a webhook. `DELETE /v1/webhooks/:id?tenantId=`
   *
   * Requires ops API key. `tenantId` is required server-side (400 without it — / API-15: before this
   * argument existed, the call could never succeed against a real gateway).
   */
  async delete(id: string, tenantId: string): Promise<ApiResponse<void>> {
    assertNonEmpty(id, 'id');
    assertNonEmpty(tenantId, 'tenantId');
    const headers = this.auth.getAuthHeader();
    return this.http.delete<ApiResponse<void>>(
      `/v1/webhooks/${encodeURIComponent(id)}`,
      { headers, query: { tenantId } },
    );
  }

  /**
   * Send a test event to a webhook. `POST /v1/webhooks/:id/test?tenantId=`
   *
   * Requires ops API key. `tenantId` is required server-side (400 without it — / API-15: before this
   * argument existed, the call could never succeed against a real gateway).
   */
  async test(id: string, tenantId: string): Promise<ApiResponse<unknown>> {
    assertNonEmpty(id, 'id');
    assertNonEmpty(tenantId, 'tenantId');
    const headers = this.auth.getAuthHeader();
    return this.http.post<ApiResponse<unknown>>(
      `/v1/webhooks/${encodeURIComponent(id)}/test`,
      {},
      { headers, query: { tenantId } },
    );
  }

  /**
   * Get delivery log for a webhook. `GET /v1/webhooks/:id/deliveries?tenantId=`
   *
   * Requires ops API key. `tenantId` is required server-side (400 without it — / API-15: before this
   * argument existed, the call could never succeed against a real gateway).
   */
  async getDeliveries(id: string, tenantId: string): Promise<ApiResponse<unknown>> {
    assertNonEmpty(id, 'id');
    assertNonEmpty(tenantId, 'tenantId');
    const headers = this.auth.getAuthHeader();
    return this.http.get<ApiResponse<unknown>>(
      `/v1/webhooks/${encodeURIComponent(id)}/deliveries`,
      { headers, query: { tenantId } },
    );
  }

  /**
   * Get webhook delivery metrics. `GET /v1/webhooks/metrics`
   *
   * Requires ops API key.
   */
  async metrics(): Promise<ApiResponse<unknown>> {
    const headers = this.auth.getAuthHeader();
    return this.http.get<ApiResponse<unknown>>('/v1/webhooks/metrics', {
      headers,
    });
  }
}
