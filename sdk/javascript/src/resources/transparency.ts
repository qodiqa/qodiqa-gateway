import { BaseResource } from './base.js';
import type {
  ApiResponse,
  TransparencyEntry,
  TransparencyEntryEnvelope,
  TransparencyRegisterResult,
  TransparencyLatestRoot,
  TransparencyRootList,
  TransparencyRootGenerated,
  TransparencyChainValidation,
  TransparencyVerifyResult,
  InclusionProof,
  PaginationParams,
  PaginatedResponse,
  Receipt,
} from '../types.js';
import { assertNonEmpty } from '../utils/validation.js';

export class TransparencyResource extends BaseResource {
  // ---------------------------------------------------------------------------
  // Public endpoints
  // ---------------------------------------------------------------------------

  /**
   * Fetch a single transparency log entry. `GET /v1/transparency/entry/:id`
   */
  async getEntry(id: string): Promise<ApiResponse<TransparencyEntryEnvelope>> {
    assertNonEmpty(id, 'id');
    return this.http.get<ApiResponse<TransparencyEntryEnvelope>>(
      `/v1/transparency/entry/${encodeURIComponent(id)}`,
    );
  }

  /**
   * List transparency log entries. `GET /v1/transparency/entries`
   */
  async listEntries(
    params?: PaginationParams,
  ): Promise<ApiResponse<PaginatedResponse<TransparencyEntry>>> {
    const query = this.buildPaginationQuery(params);
    return this.http.get<ApiResponse<PaginatedResponse<TransparencyEntry>>>(
      '/v1/transparency/entries',
      { query },
    );
  }

  /**
   * Get the latest signed root, or the root named by `rootId`. `GET /v1/transparency/root[?rootId=]`
   * `data.root` is null (with `data.message`) before the first root exists.
   */
  async getRoot(rootId?: string): Promise<ApiResponse<TransparencyLatestRoot>> {
    return this.http.get<ApiResponse<TransparencyLatestRoot>>(
      '/v1/transparency/root',
      rootId !== undefined ? { query: { rootId } } : undefined,
    );
  }

  /**
   * List signed roots, newest first. `GET /v1/transparency/roots` (previously called the
   * latest-root endpoint, which ignores pagination).
   */
  async listRoots(
    params?: PaginationParams,
  ): Promise<ApiResponse<TransparencyRootList>> {
    const query = this.buildPaginationQuery(params);
    return this.http.get<ApiResponse<TransparencyRootList>>(
      '/v1/transparency/roots',
      { query },
    );
  }

  /**
   * Verify a single transparency entry by ID. `GET /v1/transparency/verify/:id`
   */
  async verifyEntry(
    id: string,
  ): Promise<ApiResponse<TransparencyVerifyResult>> {
    assertNonEmpty(id, 'id');
    return this.http.get<ApiResponse<TransparencyVerifyResult>>(
      `/v1/transparency/verify/${encodeURIComponent(id)}`,
    );
  }

  /**
   * Get an inclusion proof for a transparency entry. `GET /v1/transparency/proof/:id`
   */
  async getProof(id: string): Promise<ApiResponse<InclusionProof>> {
    assertNonEmpty(id, 'id');
    return this.http.get<ApiResponse<InclusionProof>>(
      `/v1/transparency/proof/${encodeURIComponent(id)}`,
    );
  }

  /**
   * The signed receipt of a request's decision (V2-FREEZE section 6). `GET /v1/transparency/receipt/:requestId` — no credentials: knowing the
   * `requestId` (the artifact's `payload.requestId`) is the authorization. Receipts are kept for a bounded window (default one hour); after it the
   * server answers 404 (`NotFoundError`). Verify the result with `verifyReceipt()`.
   */
  async getReceipt(requestId: string): Promise<ApiResponse<{ receipt: Receipt }>> {
    assertNonEmpty(requestId, 'requestId');
    return this.http.get<ApiResponse<{ receipt: Receipt }>>(
      `/v1/transparency/receipt/${encodeURIComponent(requestId)}`,
    );
  }

  // ---------------------------------------------------------------------------
  // Ops-protected endpoints
  // ---------------------------------------------------------------------------

  /**
   * Register a new transparency log entry. `POST /v1/transparency/register`
   *
   * Requires ops API key. Real (server-`.strict()`-validated) body shape:
   * `{ entryType: 'ARTIFACT'|'EVIDENCE'|'VERIFICATION'|'POLICY'|'AUDIT'|'SYSTEM',
   *    artifactId?, evidenceChainId?, verificationId?, payload?, tenantId? }`
   * — NOT `{ type, ref }`.
   */
  async register(
    data: {
      entryType: 'ARTIFACT' | 'EVIDENCE' | 'VERIFICATION' | 'POLICY' | 'AUDIT' | 'SYSTEM';
      artifactId?: string;
      evidenceChainId?: string;
      verificationId?: string;
      payload?: Record<string, unknown>;
      tenantId?: string;
    },
  ): Promise<ApiResponse<TransparencyRegisterResult>> {
    const headers = this.auth.getAuthHeader();
    return this.http.post<ApiResponse<TransparencyRegisterResult>>(
      '/v1/transparency/register',
      data,
      { headers },
    );
  }

  /**
   * Generate a new transparency root covering all entries not yet included
   * in a prior root. `POST /v1/transparency/admin/roots/generate`
   *
   * Requires ops API key. Required before `getProof()` can return a
   * populated `proof` array for entries registered since the last root.
   */
  async generateRoot(): Promise<ApiResponse<TransparencyRootGenerated>> {
    const headers = this.auth.getAuthHeader();
    return this.http.post<ApiResponse<TransparencyRootGenerated>>(
      '/v1/transparency/admin/roots/generate',
      {},
      { headers },
    );
  }

  /**
   * Get transparency log admin statistics. `GET /v1/transparency/admin/stats`
   *
   * Requires ops API key.
   */
  async stats(): Promise<ApiResponse<unknown>> {
    const headers = this.auth.getAuthHeader();
    return this.http.get<ApiResponse<unknown>>('/v1/transparency/admin/stats', {
      headers,
    });
  }

  /**
   * Validate the transparency log hash chain. `GET /v1/transparency/admin/chain/validate`
   * (previously called `/audit/chain/integrity`, which is the audit chain, not the transparency log.)
   *
   * Requires ops API key (READ_TRANSPARENCY_LOG).
   */
  async validateChain(params?: { startId?: string; endId?: string; limit?: number }): Promise<ApiResponse<TransparencyChainValidation>> {
    const headers = this.auth.getAuthHeader();
    const query: Record<string, string> = {};
    if (params?.startId !== undefined) query.startId = params.startId;
    if (params?.endId !== undefined) query.endId = params.endId;
    if (params?.limit !== undefined) query.limit = String(params.limit);
    return this.http.get<ApiResponse<TransparencyChainValidation>>('/v1/transparency/admin/chain/validate', {
      headers,
      query,
    });
  }
}
