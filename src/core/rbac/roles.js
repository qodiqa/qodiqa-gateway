'use strict';

/**
 * RBAC Role Definitions and Permission Matrix
 *
 * This is the single source of truth for the five canonical, built-in
 * roles (admin/auditor/compliance/operator/viewer) and the fixed
 * permission matrix they're evaluated against. The permission matrix is
 * append-only at runtime — no mutation after load. To add a permission:
 * add a key to PERMISSIONS and list the allowed built-in roles.
 *
 * This module has no knowledge of, and no dependency on, custom roles
 * — those are a separate, additive concept defined in
 * `./customRoleStore.js` and composed with this module's canonical matrix
 * by `./authorize.js`, which is what `src/middleware/rbac.js` actually
 * calls. Nothing in this file needs to change, and nothing here changes,
 * when a custom role is created, updated, or deleted — that is the whole
 * point of keeping the two concerns in separate modules: this file's
 * `isPermitted`/`isValidRole`/`permissionsForRole` describe ONLY the five
 * built-in roles, by design, and remain fully backward compatible for any
 * existing caller that only ever deals with those five roles.
 */

// ── Canonical role identifiers ────────────────────────────────────────────────

const ROLES = Object.freeze({
  ADMIN:      'admin',
  AUDITOR:    'auditor',
  COMPLIANCE: 'compliance',
  OPERATOR:   'operator',
  VIEWER:     'viewer',
  // the tenant self-service portal's ONLY role. Deliberately not part
  // of the console-operator privilege ladder above (admin/auditor/
  // compliance/operator/viewer all describe platform-operations trust
  // levels for human console operators authenticated via a per-operator
  // ok_ API key — see src/middleware/opsAuth.js). A tenant-portal user is a
  // different identity CLASS entirely: scoped to exactly one tenant,
  // authenticated via OIDC SSO (src/core/portal/), never granted any
  // platform-wide capability. Mirrors the same reasoning
  // signingIdentityStore.js's header comment already gives for keeping
  // machine signing identities out of this same role enum.
  TENANT:     'tenant',
});

const ROLE_SET = Object.freeze(new Set(Object.values(ROLES)));

// ── Role display metadata (for UI and audit reports) ─────────────────────────

const ROLE_META = Object.freeze({
  [ROLES.ADMIN]: Object.freeze({
    label:       'Administrator',
    description: 'Full platform control: user management, policy management, key management, audit access',
    level:       5,
  }),
  [ROLES.AUDITOR]: Object.freeze({
    label:       'Auditor',
    description: 'Read-only audit role: audit logs, evidence packages, verification outputs',
    level:       4,
  }),
  [ROLES.COMPLIANCE]: Object.freeze({
    label:       'Compliance Officer',
    description: 'Compliance and governance: evidence packages, policy review, audit review',
    level:       3,
  }),
  [ROLES.OPERATOR]: Object.freeze({
    label:       'Operator',
    description: 'Operational execution: runtime monitoring, verification, dashboards, evidence generation',
    level:       2,
  }),
  [ROLES.VIEWER]: Object.freeze({
    label:       'Viewer',
    description: 'Lowest privilege: read-only platform views only',
    level:       1,
  }),
  [ROLES.TENANT]: Object.freeze({
    label:       'Tenant User',
    description: 'Self-service read-only access to the caller\'s own tenant identity, key metadata, and consent state — not a console-operator privilege level (see ROLES.TENANT comment above); level 0 places it below every operator tier for display purposes only.',
    level:       0,
  }),
});

// ── Permission matrix ─────────────────────────────────────────────────────────
//
// Each key is a permission identifier; the value is the frozen set of roles
// that are allowed to perform that action.  Absence from the set means DENY.
//
// To extend: add a new key. Do not remove or rename existing keys without a
// migration plan — existing authorization calls reference these strings.

const PERMISSIONS = Object.freeze({
  // ── Audit ──────────────────────────────────────────────────────────────────
  READ_AUDIT:          Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE]),

  // ── Alerts ──────────────────────────────────────────────────────
  // Acknowledge / resolve / suppress / mark false-positive / create / test a
  // channel. these needed only READ_AUDIT, so the read-only auditor
  // role could silence alerts. The /alerts mount still requires READ_AUDIT, so
  // the effective set is the roles holding both.
  MANAGE_ALERTS:       Object.freeze([ROLES.ADMIN, ROLES.COMPLIANCE]),

  // ── Evidence ───────────────────────────────────────────────────────────────
  GENERATE_EVIDENCE:   Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE, ROLES.OPERATOR]),

  // ── Dashboard ──────────────────────────────────────────────────────────────
  VIEW_DASHBOARD:      Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE, ROLES.OPERATOR, ROLES.VIEWER]),

  // ── Policy management ──────────────────────────────────────────────────────
  READ_POLICIES:       Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE, ROLES.OPERATOR]),
  MANAGE_POLICIES:     Object.freeze([ROLES.ADMIN]),

  // ── Global kill switch ──────────────────────────────────────────────
  // Raising or lowering the switch stops / resumes ALL signing and execution: admin only (every route is also behind the
  // operator MFA step-up). Reading the state is harmless and useful to anyone who watches the platform.
  MANAGE_KILL_SWITCH:  Object.freeze([ROLES.ADMIN]),
  READ_KILL_SWITCH:    Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE, ROLES.OPERATOR]),

  // ── Dynamic provider registry ─────────────────────────────────────
  // Registering or changing a destination the gateway sends prompts to: admin only (and behind the operator MFA step-up). Reading it is harmless.
  MANAGE_PROVIDERS:    Object.freeze([ROLES.ADMIN]),
  READ_PROVIDERS:      Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE, ROLES.OPERATOR]),

  // ── Per-artifact revocation ─────────────────────────────────────────
  // Withdrawing one signed artifact (and looking one up). Admin only; every change is behind the operator MFA step-up.
  MANAGE_ARTIFACT_REVOCATIONS: Object.freeze([ROLES.ADMIN]),

  // ── Downloadable proof of one request ──────────────────────────────
  READ_AUDIT_PROOFS:   Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE]),
  // The same proof WITH the contiguous platform chain (raw entries of every tenant between the request and the checkpoint): platform operators only.
  READ_AUDIT_PROOFS_FULL_CHAIN: Object.freeze([ROLES.ADMIN]),

  // ── Agent identities and sessions ────────────────────────────────────
  MANAGE_AGENTS:          Object.freeze([ROLES.ADMIN]),
  READ_AGENTS:            Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE, ROLES.OPERATOR]),
  MANAGE_AGENT_SESSIONS:  Object.freeze([ROLES.ADMIN, ROLES.OPERATOR]),

  // ── Tool registry ──────────────────────────────────────────────────
  MANAGE_TOOLS:           Object.freeze([ROLES.ADMIN]),
  READ_TOOLS:             Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE, ROLES.OPERATOR]),

  // ── MCP servers ────────────────────────────────────────────────────
  MANAGE_MCP_SERVERS:     Object.freeze([ROLES.ADMIN]),
  READ_MCP_SERVERS:       Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE, ROLES.OPERATOR]),

  // ── Human approval of agent actions ──────────────────────────────────
  // Deciding is the maker-checker half: the approver is never the requester (src/core/approvals/approvalStore.js). Reading is wider than deciding.
  DECIDE_APPROVALS:       Object.freeze([ROLES.ADMIN, ROLES.COMPLIANCE]),
  READ_APPROVALS:         Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE, ROLES.OPERATOR]),

  // ── Key management ─────────────────────────────────────────────────────────
  MANAGE_KEYS:         Object.freeze([ROLES.ADMIN]),

  // ── Signing identities (TRUST-1 remediation) ──────────────────────────────
  // Provisioning a signing identity/API key grants a machine caller the
  // ability to mint production signing authority for its scoped tenant —
  // the same trust level as MANAGE_KEYS. Admin-only, no exceptions.
  MANAGE_SIGNING_IDENTITIES: Object.freeze([ROLES.ADMIN]),
  // Read-only visibility (scope, enabled/revoked state, last-used) without
  // the ability to mint or revoke keys — useful for auditors reviewing
  // caller attribution without granting them provisioning power.
  READ_SIGNING_IDENTITIES:   Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE]),

  // ── User / RBAC administration ─────────────────────────────────────────────
  MANAGE_USERS:        Object.freeze([ROLES.ADMIN]),
  READ_USERS:          Object.freeze([ROLES.ADMIN]),

  // ── Centralized audit store ────────────────────────────────────────────────
  // MANAGE_RETENTION covers legal holds, retention policy enforcement, and
  // retention policy creation.  Compliance officers need this for hold placement.
  MANAGE_RETENTION:    Object.freeze([ROLES.ADMIN, ROLES.COMPLIANCE]),

  // ── Compliance reporting ───────────────────────────────────────────────────
  READ_COMPLIANCE:     Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE]),
  GENERATE_REPORT:     Object.freeze([ROLES.ADMIN, ROLES.COMPLIANCE]),

  // ── Consent management ─────────────────────────────────────────────────────
  // MANAGE_CONSENT: full lifecycle management of consent records — grant,
  // revoke, suspend, resume, and audit.  Restricted to admins only because
  // consent records directly govern what actions actors are permitted to take.
  MANAGE_CONSENT:      Object.freeze([ROLES.ADMIN]),

  // ── Policy provenance (Component #20) ─────────────────────────────────────
  // READ_POLICY_PROVENANCE: query version history, diffs, timelines, reports.
  // Granted to auditors and compliance officers in addition to admins.
  READ_POLICY_PROVENANCE:   Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE]),
  // INVESTIGATE_POLICIES: run integrity checks, access investigator views,
  // export full provenance records including policy_content snapshots.
  INVESTIGATE_POLICIES:     Object.freeze([ROLES.ADMIN, ROLES.AUDITOR]),

  // ── Immutable Evidence Chain (Component #21) ───────────────────────────────
  // READ_EVIDENCE_CHAIN: query evidence records, chain segments, verification
  // history, reports, and dashboard stats.
  READ_EVIDENCE_CHAIN:      Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE]),
  // VERIFY_EVIDENCE_CHAIN: trigger on-demand 7-step verification runs and
  // chain continuity checks.  Requires auditor-level trust.
  VERIFY_EVIDENCE_CHAIN:    Object.freeze([ROLES.ADMIN, ROLES.AUDITOR]),

  // ── Transparency Log (Component #22) ──────────────────────────────────────
  // READ_TRANSPARENCY_LOG: query entries, roots, verification history, stats.
  // Granted to auditors and compliance officers in addition to admins.
  READ_TRANSPARENCY_LOG:    Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE]),
  // MANAGE_TRANSPARENCY_LOG: register entries and generate root digests.
  // Restricted to admins only — root generation is a privileged operation.
  MANAGE_TRANSPARENCY_LOG:  Object.freeze([ROLES.ADMIN]),

  // ── Public Verification Portal (Component #23) ─────────────────────────────
  // READ_VERIFICATION_PORTAL: query verification history and aggregate stats.
  // Granted to auditors and compliance officers in addition to admins.
  READ_VERIFICATION_PORTAL:   Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE]),
  // MANAGE_VERIFICATION_PORTAL: reserved for future portal administration.
  // Restricted to admins only.
  MANAGE_VERIFICATION_PORTAL: Object.freeze([ROLES.ADMIN]),

  // ── Attestation API (Component #24) ───────────────────────────────────────
  // READ_ATTESTATIONS: query attestation history and aggregate statistics.
  // Granted to auditors and compliance officers for regulatory review.
  READ_ATTESTATIONS:          Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE]),
  // EXPORT_ATTESTATIONS: export attestation records and evidence packages
  // in JSON or PDF format for audit and regulatory submission.
  EXPORT_ATTESTATIONS:        Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE]),
  // MANAGE_ATTESTATIONS: reserved for future attestation administration.
  // Restricted to admins only.
  MANAGE_ATTESTATIONS:        Object.freeze([ROLES.ADMIN]),

  // ── Certification Runtime (Component #25) ─────────────────────────────────
  // READ_CERTIFICATIONS: query certification history, batch status, and
  // aggregate statistics.  Operators are included so they can monitor the
  // batches they submitted via SUBMIT_BATCH_CERTIFICATION.
  READ_CERTIFICATIONS:        Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE, ROLES.OPERATOR]),
  // EXPORT_CERTIFICATIONS: export certification records and evidence packages
  // in JSON or PDF format for regulatory submission and external audits.
  EXPORT_CERTIFICATIONS:      Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE]),
  // MANAGE_CERTIFICATIONS: reserved for certification administration.
  // Restricted to admins only.
  MANAGE_CERTIFICATIONS:      Object.freeze([ROLES.ADMIN]),
  // SUBMIT_BATCH_CERTIFICATION: submit asynchronous batch certification
  // requests.  Granted to operators who run certification pipelines.
  SUBMIT_BATCH_CERTIFICATION: Object.freeze([ROLES.ADMIN, ROLES.OPERATOR]),
  // CANCEL_BATCH_CERTIFICATION: cancel an in-progress batch certification run.
  // Granted to operators who manage certification pipelines.
  CANCEL_BATCH_CERTIFICATION: Object.freeze([ROLES.ADMIN, ROLES.OPERATOR]),

  // ── Webhooks (Component #28) ───────────────────────────────────────────────
  // READ_WEBHOOKS: list endpoints and query delivery history.
  // Granted to auditors for observability and operational review.
  READ_WEBHOOKS:              Object.freeze([ROLES.ADMIN, ROLES.AUDITOR]),
  // MANAGE_WEBHOOKS: create, update, delete webhook endpoints, trigger test events.
  // Restricted to admins only — webhook registration controls external data flow.
  MANAGE_WEBHOOKS:            Object.freeze([ROLES.ADMIN]),

  // ── Persistence Recovery DLQ (Component #32) ──────────────────────────────
  // READ_RECOVERY_QUEUE: inspect DLQ contents, queue stats, item detail.
  // Granted to auditors for operational visibility into failed persistence jobs.
  READ_RECOVERY_QUEUE:        Object.freeze([ROLES.ADMIN, ROLES.AUDITOR]),
  // MANAGE_RECOVERY_QUEUE: replay and archive DLQ items.
  // Restricted to admins only — replaying jobs triggers real persistence writes.
  MANAGE_RECOVERY_QUEUE:      Object.freeze([ROLES.ADMIN]),

  // ── Data Subject Rights / GDPR DSR ────────────────────────────────
  // READ_DSR: list/inspect DSR requests and their lifecycle event trail.
  // Granted to auditors for regulatory review, same as READ_AUDIT.
  READ_DSR:                   Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE]),
  // MANAGE_DSR: create requests, verify identity, approve, and execute
  // rectification/erasure/restriction/portability. Follows the
  // MANAGE_RETENTION precedent (admin + compliance) rather than
  // MANAGE_CONSENT (admin-only) — DSR execution is a compliance function,
  // not routine consent administration.
  MANAGE_DSR:                 Object.freeze([ROLES.ADMIN, ROLES.COMPLIANCE]),

  // ── Policy Governance / Maker-Checker ────────────────────────────
  // These permissions gate CAPABILITY (who may take which workflow action).
  // The actual maker-checker guarantee — "the same identity must never
  // perform incompatible stages" — is enforced separately, server-side, by
  // comparing individual actor identity at each transition (see
  // src/core/policy/governance/makerCheckerRules.js), not by role
  // membership. Two different admins may legitimately author and approve
  // the same change; the same admin may never do both.
  READ_POLICY_GOVERNANCE:     Object.freeze([ROLES.ADMIN, ROLES.AUDITOR, ROLES.COMPLIANCE, ROLES.OPERATOR]),
  // PROPOSE_POLICY_CHANGE: create/submit drafts. Broad "maker" pool.
  PROPOSE_POLICY_CHANGE:      Object.freeze([ROLES.ADMIN, ROLES.OPERATOR, ROLES.COMPLIANCE]),
  // REVIEW_POLICY_CHANGE: give non-binding technical/compliance sign-off
  // before formal approval.
  REVIEW_POLICY_CHANGE:       Object.freeze([ROLES.ADMIN, ROLES.COMPLIANCE, ROLES.AUDITOR]),
  // APPROVE_POLICY_CHANGE: the formal checker.
  APPROVE_POLICY_CHANGE:      Object.freeze([ROLES.ADMIN, ROLES.COMPLIANCE]),
  // PUBLISH_POLICY_CHANGE: the only step that touches the live enforcement
  // store — admin-only, matching MANAGE_POLICIES' existing scope.
  PUBLISH_POLICY_CHANGE:      Object.freeze([ROLES.ADMIN]),
  // REQUEST_POLICY_ROLLBACK / APPROVE_POLICY_ROLLBACK: same maker/checker
  // split as change proposals, applied to rollback specifically.
  REQUEST_POLICY_ROLLBACK:    Object.freeze([ROLES.ADMIN, ROLES.COMPLIANCE, ROLES.OPERATOR]),
  APPROVE_POLICY_ROLLBACK:    Object.freeze([ROLES.ADMIN, ROLES.COMPLIANCE]),
  // EMERGENCY_POLICY_OVERRIDE: the one deliberate bypass of the normal
  // gate — restricted to admins only, compensated for by mandatory
  // justification, TTL, and retrospective approval (EmergencyPolicyService).
  EMERGENCY_POLICY_OVERRIDE:  Object.freeze([ROLES.ADMIN]),
  // APPROVE_EMERGENCY_POLICY: retrospective approval of an emergency
  // activation — must be a different individual than the activator.
  APPROVE_EMERGENCY_POLICY:   Object.freeze([ROLES.ADMIN, ROLES.COMPLIANCE]),

  // ── Tenant self-service portal ──────────────────────────────────────
  // ROLES.TENANT is the intended caller; ROLES.ADMIN is included too, but
  // ONLY because admin already has a strictly BROADER existing permission
  // covering the same data cross-tenant (MANAGE_KEYS for READ_TENANT_KEYS,
  // MANAGE_CONSENT for READ_TENANT_CONSENT, READ_USERS for
  // READ_TENANT_IDENTITY) — this grants admin no capability it did not
  // already have, keeps INV-06 ("admin is permitted every defined
  // permission", rbac.invariants.test.js) intact, and costs nothing since
  // an admin's ok_ operator session never carries a req.tenantContext to
  // exercise it through the portal routes in practice (see
  // src/middleware/portalAuth.js). No OTHER operator role (auditor/
  // compliance/operator/viewer) is included — those do NOT already have an
  // equivalent broader permission, so adding them would be a genuine
  // least-privilege expansion, not a no-op. Tenant SCOPE (which tenant's
  // rows) is enforced separately, server-side, from req.tenantContext —
  // never by this permission matrix, which only answers "is this role
  // class allowed to call this kind of route at all." See
  //.
  READ_TENANT_IDENTITY:       Object.freeze([ROLES.TENANT, ROLES.ADMIN]),
  READ_TENANT_KEYS:           Object.freeze([ROLES.TENANT, ROLES.ADMIN]),
  READ_TENANT_CONSENT:        Object.freeze([ROLES.TENANT, ROLES.ADMIN]),
  // usage-metering API + CSV export
  // (src/api/routes/tenantPortal.js GET /api/usage, /api/usage/export).
  // ROLES.ADMIN included per INV-06 (admin is permitted every defined
  // permission) — no pre-existing broader admin permission covers usage
  // metering specifically, unlike KEYS/CONSENT/IDENTITY above, so this is a
  // small, deliberate least-privilege expansion for admin, not a no-op.
  READ_TENANT_USAGE:          Object.freeze([ROLES.TENANT, ROLES.ADMIN]),
});

// ── Permission set for fast lookup ───────────────────────────────────────────

const PERMISSION_SET = Object.freeze(new Set(Object.keys(PERMISSIONS)));

// ── Public helpers ────────────────────────────────────────────────────────────

function isValidRole(role) {
  return typeof role === 'string' && ROLE_SET.has(role);
}

function isValidPermission(permission) {
  return typeof permission === 'string' && PERMISSION_SET.has(permission);
}

/**
 * Deterministic, fail-closed permission check.
 * Returns true only when role is valid AND permission exists AND role is in
 * the allowed set.  Any missing or invalid input returns false.
 */
function isPermitted(role, permission) {
  if (!role || !permission) return false;
  if (!isValidRole(role)) return false;
  const allowed = PERMISSIONS[permission];
  if (!allowed) return false;
  return allowed.includes(role);
}

/**
 * Returns every permission granted to a given role (for introspection).
 */
function permissionsForRole(role) {
  if (!isValidRole(role)) return [];
  return Object.entries(PERMISSIONS)
    .filter(([, roles]) => roles.includes(role))
    .map(([perm]) => perm);
}

module.exports = {
  ROLES,
  ROLE_SET,
  ROLE_META,
  PERMISSIONS,
  PERMISSION_SET,
  isValidRole,
  isValidPermission,
  isPermitted,
  permissionsForRole,
};
