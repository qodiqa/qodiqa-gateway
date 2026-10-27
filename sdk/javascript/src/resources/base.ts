import type { HttpClient } from '../http.js';
import type { AuthProvider } from '../auth.js';
import type { PaginationParams } from '../types.js';

export abstract class BaseResource {
  constructor(
    protected readonly http: HttpClient,
    protected readonly auth: AuthProvider,
  ) {}

  /**
   * Converts a `PaginationParams` object into a flat query-parameter map
   * suitable for use with `HttpClient.get()`.
   */
  protected buildPaginationQuery(
    params?: PaginationParams,
  ): Record<string, string | number | undefined> {
    if (!params) return {};
    const q: Record<string, string | number | undefined> = {};
    if (params.page !== undefined) q['page'] = params.page;
    if (params.pageSize !== undefined) q['pageSize'] = params.pageSize;
    if (params.sortOrder !== undefined) q['sortOrder'] = params.sortOrder;
    return q;
  }
}
