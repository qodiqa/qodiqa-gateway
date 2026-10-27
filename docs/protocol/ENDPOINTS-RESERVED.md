# Reserved endpoints (not implemented)

> **Status:** DRAFT 5 for the freeze. Paths, methods, request/response shape and error codes are fixed here so that SDK and
> documentation work can proceed before the implementation exists. **Nothing on this page is available in the product yet**; each endpoint
> answers `404` until its wave lands, and the OpenAPI document does not list it until then. All endpoints are tenant-scoped, authenticated like
> the existing management API (operator key or signing identity, as stated; **the single exception is the receipt endpoint**, see its row), use the existing envelopes (V1 document, section 8) and honor the
> kill switch (`KILL_SWITCH_ACTIVE`).

| endpoint | caller | wave | request → response (summary) | errors |
|---|---|---|---|---|
| `POST /v1/actions/authorize` | agent runtime (signing identity) | | `{ sessionId, seq, tool: {server, name}, args, parentRequestHash? }` → `{ decision, actionArtifact?, approvalId?, reason }`. `ALLOW` returns an `ActionArtifact` (V2-FREEZE section 5); `APPROVAL_REQUIRED` returns HTTP `202` with the management envelope `{ status: "pending", data: { approvalId } }` (not a protocol decision, V2-FREEZE 7.5) | `ACTION_ORDER_VIOLATION`, `TOOL_NOT_ALLOWED`, `TOOL_SCHEMA_CHANGED`, `TOOL_ARGUMENTS_INVALID`, `SESSION_EXPIRED`, `SESSION_LIMIT_EXCEEDED`, `DLP_BLOCKED` |
| `POST /v1/tools/call` | agent runtime | | `{ actionArtifact, args }` → `{ result, receipt }` (the receipt is that of the `ACTION_COMMIT` entry, V2-FREEZE 6; the proxy verifies the artifact, validates args, calls the registered MCP server over HTTP, screens the result) | `ACTION_MISMATCH`, `ACTION_REPLAY`, `TOOL_NOT_ALLOWED`, `DLP_BLOCKED` |
| `GET /v1/approvals`, `GET /v1/approvals/{id}` | approvers (operator) | | **built**: list / read approval requests of the tenant | — |
| `POST /v1/approvals/{id}/decision` | approver (not the requester; MFA step-up) | | `{ decision: "APPROVE" or "DENY", notBefore?, notes? }` → signed approval statement (`QODIQA::APPROVAL::V1`) bound to `actionHash` | `APPROVAL_INVALID`, `APPROVAL_EXPIRED` |
| `POST /v1/approvals/{id}/cancel` | requester | | → status `CANCELLED` | — |
| `GET /v1/actions/approvals/{id}`, `POST /v1/actions/approvals/{id}/cancel` | requester (signing identity) | | **built**: the requester's side - its own request, withdrawal; the reserved `/v1/approvals/{id}/cancel` is replaced by this (the requester is a signing identity, not an operator) | `APPROVAL_NOT_CANCELLABLE` |
| `POST /v1/kill-switch`, `DELETE /v1/kill-switch` | operator (MFA step-up) | | activate / release the global stop → signed state (`QODIQA::KILL_SWITCH::V1`), propagated within 5 s | — |
| `POST /v1/artifacts/{artifactId}/revoke` | operator | | revoke one artifact for its remaining lifetime; `artifactId` is the 32-hex artifact id | — |
| `GET /v1/transparency/receipt/{requestId}` | **unauthenticated by design** — the capability is knowledge of the UUID v4 `requestId` (122 bits) | | → the receipt document only (V2-FREEZE section 6); rate limited like `/verify` | 404 until persisted |
| `POST /v1/agents`, `GET /v1/agents`, `GET /v1/agents/{id}`, `POST /v1/agents/{id}/disable` | operator | | agent identity lifecycle | — |
| `POST /v1/sessions`, `GET /v1/sessions/{id}`, `POST /v1/sessions/{id}/terminate` | agent / operator | | session with TTL, action budget and cost budget; terminate also cancels in-flight work | `SESSION_EXPIRED` |
| `POST /v1/delegations`, `GET /v1/delegations/{id}`, `POST /v1/delegations/{id}/revoke`, `POST /v1/delegations/verify` | signing identity (agent issuer) | | **built**: issue a narrower token; revoke (cascades); verify a chain - `docs/protocol/DELEGATION.md` | `DELEGATION_*` |
| `GET /v1/mcp/servers`, `POST /v1/mcp/servers`, `GET\|PUT\|DELETE /v1/mcp/servers/{id}`, `POST /v1/mcp/servers/{id}/tools/refresh` | operator | | register servers (URL allowlist, pinned identity), list and refresh tool schemas (a `schemaHash` change needs re-approval) | `TOOL_SCHEMA_CHANGED` |
| `POST /v1/mcp/servers`, `GET /v1/mcp/servers`, `GET /v1/mcp/servers/{id}`, `POST /v1/mcp/servers/{id}/disable\|enable\|identity`, `POST /v1/mcp/servers/{id}/tools/refresh`, `POST /v1/tools/call` | operator (servers) / signing identity (call) | | **built** - the shapes differ from the reservation above (disable / enable / pin rotation instead of PUT / DELETE; servers are never deleted): see `docs/security/TOOL_GATEWAY.md` | `MCP_*`, `TOOL_*`, `ACTION_POLICY_*` |
| `GET /v1/tools`, `POST /v1/tools`, `PUT /v1/tools/{id}`, `POST /v1/tools/{id}/revoke` | operator | | tool registry and per-tool policy; revoke takes effect within 5 s | — |
| `POST /v1/actions/authorize`, `POST /v1/actions/plans`, `/v1/tool-registry` (`POST /`, `GET /`, `GET /entry`, `POST /approve\|disable\|policy`) | signing identity (actions) / operator (registry) | | **built**: per-action authorisation, execution plan, versioned tool registry; the registry lives under `/v1/tool-registry` (tool names contain `/`); `/v1/tools` stays reserved for the tool gateway | `ACTION_*`, `TOOL_*` |
| `GET /v1/dlp/rules`, `POST /v1/dlp/rules`, `PUT\|DELETE /v1/dlp/rules/{id}`, `POST /v1/dlp/test` | operator | | rule management and a dry run on a sample | — |
| `GET /v1/providers`, `POST /v1/providers`, `PUT\|DELETE /v1/providers/{id}`, `GET /v1/routing`, `PUT /v1/routing` | operator | | dynamic provider registry and routing rules | — |
| `GET /v1/proofs/{requestId}` | auditor | | downloadable proof bundle (`format: "qodiqa-proof/1"`, `VECTORS-FORMAT.md`) | 404 |

Conventions: identifiers are UUID v4 (or a 32-hex hash where stated); there is **no unprefixed alias** of any path above (only `/v1/...`); list endpoints use the existing `page` / `pageSize`; every mutation writes an audit entry
(`AUDIT-V8-FREEZE.md`); no endpoint accepts a filesystem path or an arbitrary URL, except MCP server registration, which passes the same SSRF
guard as providers.
