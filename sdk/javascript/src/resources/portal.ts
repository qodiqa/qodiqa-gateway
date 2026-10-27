import { BaseResource } from './base.js';
import type {
  Artifact,
  ApiResponse,
  PortalVerifyResult,
  PortalVerificationRecord,
} from '../types.js';
import { assertNonEmpty } from '../utils/validation.js';

export class PortalResource extends BaseResource {
  /**
   * Submit an artifact for immediate verification via `POST /v1/portal/verify`.
   *
   * Synchronous — no authentication required (rate-limited only), and no
   * pending/in-progress state: the full check suite runs and a complete
   * report is returned in this one call.
   *
   * @param artifact  The raw QODIQA artifact object (the request body IS
   *                  the artifact — not wrapped in `{artifact, request}`).
   */
  async verify(artifact: Artifact): Promise<ApiResponse<PortalVerifyResult>> {
    return this.http.post<ApiResponse<PortalVerifyResult>>('/v1/portal/verify', artifact);
  }

  /**
   * Retrieve a previously-run verification by the `verificationId` a prior
   * `verify()` call returned, via `GET /v1/portal/result/:id`.
   *
   * Requires PostgreSQL to be enabled server-side — the verification
   * portal's history store is Postgres-only. This 404s if PostgreSQL was
   * disabled at `verify()` time (nothing was ever persisted) or is disabled
   * now, even for a `verificationId` `verify()` itself just returned.
   */
  async getResult(
    verificationId: string,
  ): Promise<ApiResponse<{ verification: PortalVerificationRecord }>> {
    assertNonEmpty(verificationId, 'verificationId');
    return this.http.get<ApiResponse<{ verification: PortalVerificationRecord }>>(
      `/v1/portal/result/${encodeURIComponent(verificationId)}`,
    );
  }
}
