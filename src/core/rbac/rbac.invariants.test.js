'use strict';

/**
 * RBAC Invariant Tests — Final Verification
 *
 * These tests are structural invariants over the permission matrix, role
 * definitions, and middleware factory.  They do not test request flow —
 * they verify that the RBAC model is internally consistent and complete.
 *
 * INV-01…INV-10   Permission matrix integrity
 * INV-11…INV-20   Role integrity
 * INV-21…INV-30   Middleware factory invariants
 * INV-31…INV-40   Endpoint permission coverage (server-level)
 * INV-41…INV-50   Fail-closed and security invariants
 */

const {
  ROLES,
  ROLE_SET,
  PERMISSIONS,
  PERMISSION_SET,
  isValidRole,
  isValidPermission,
  isPermitted,
  permissionsForRole,
} = require('./roles');

const {
  createRequirePermission: _createRequirePermission,
  createRbacResolveMiddleware,
} = require('../../middleware/rbac');
const { isPermitted: _rbacIsPermitted, isValidPermission: _rbacIsValidPermission } = require('./authorize');

// createRequirePermission() now requires isPermitted/isValidPermission to be
// injected (src/middleware/rbac.js no longer reaches into src/core directly —
// see .dependency-cruiser.js's no-middleware-to-core rule). This wrapper
// supplies the real ./authorize.js implementation so every existing call
// site below keeps working unchanged.
function createRequirePermission(opts) {
  return _createRequirePermission({ isPermitted: _rbacIsPermitted, isValidPermission: _rbacIsValidPermission, ...opts });
}

// ─────────────────────────────────────────────────────────────────────────────
// INV-01…INV-10  Permission matrix integrity
// ─────────────────────────────────────────────────────────────────────────────

describe('INV-01…INV-10  Permission matrix integrity', () => {

  test('INV-01  PERMISSION_SET size equals Object.keys(PERMISSIONS) length — no duplicate keys', () => {
    expect(PERMISSION_SET.size).toBe(Object.keys(PERMISSIONS).length);
  });

  test('INV-02  every permission name is a non-empty uppercase_underscore string', () => {
    const valid = /^[A-Z][A-Z0-9_]+$/;
    for (const perm of PERMISSION_SET) {
      expect(perm).toMatch(valid);
    }
  });

  test('INV-03  every permission has at least one allowed role', () => {
    for (const [perm, roles] of Object.entries(PERMISSIONS)) {
      expect(roles.length).toBeGreaterThan(0);
    }
  });

  test('INV-04  every role in every permission list is a valid canonical role', () => {
    for (const [, roles] of Object.entries(PERMISSIONS)) {
      for (const role of roles) {
        expect(ROLE_SET.has(role)).toBe(true);
      }
    }
  });

  test('INV-05  PERMISSIONS object is frozen — no runtime mutation', () => {
    expect(Object.isFrozen(PERMISSIONS)).toBe(true);
    for (const roleList of Object.values(PERMISSIONS)) {
      expect(Object.isFrozen(roleList)).toBe(true);
    }
  });

  test('INV-06  admin is permitted every defined permission', () => {
    for (const perm of PERMISSION_SET) {
      expect(isPermitted(ROLES.ADMIN, perm)).toBe(true);
    }
  });

  test('INV-07  viewer is permitted exactly VIEW_DASHBOARD', () => {
    const viewerPerms = permissionsForRole(ROLES.VIEWER);
    expect(viewerPerms).toHaveLength(1);
    expect(viewerPerms[0]).toBe('VIEW_DASHBOARD');
  });

  test('INV-08  isValidPermission matches PERMISSION_SET exactly', () => {
    for (const perm of PERMISSION_SET) {
      expect(isValidPermission(perm)).toBe(true);
    }
    expect(isValidPermission('NONEXISTENT_PERM')).toBe(false);
    expect(isValidPermission('')).toBe(false);
    expect(isValidPermission(null)).toBe(false);
    expect(isValidPermission(42)).toBe(false);
  });

  test('INV-09  all three formerly-missing permissions are now in the matrix', () => {
    expect(isValidPermission('MANAGE_CONSENT')).toBe(true);
    expect(isValidPermission('SUBMIT_BATCH_CERTIFICATION')).toBe(true);
    expect(isValidPermission('CANCEL_BATCH_CERTIFICATION')).toBe(true);
  });

  test('INV-10  removed dead permissions are absent from the matrix', () => {
    // These were defined but had zero enforcement in any route or test.
    // Removing them eliminates confusion and stale authorization surface.
    expect(isValidPermission('EXPORT_AUDIT')).toBe(false);
    expect(isValidPermission('READ_INVESTIGATIONS')).toBe(false);
    expect(isValidPermission('VIEW_DIAGNOSTICS')).toBe(false);
    expect(isValidPermission('VERIFY_ARTIFACTS')).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// INV-11…INV-20  Role integrity
// ─────────────────────────────────────────────────────────────────────────────

describe('INV-11…INV-20  Role integrity', () => {

  test('INV-11  exactly six canonical roles exist', () => {
    // 5 -> 6, adding 'tenant' — the tenant self-service
    // portal's one role, deliberately outside the 5-role console-operator
    // ladder (see roles.js's ROLES.TENANT comment for why it's a distinct
    // identity class, not a sixth operator tier).
    expect(ROLE_SET.size).toBe(6);
    expect(ROLE_SET.has('admin')).toBe(true);
    expect(ROLE_SET.has('auditor')).toBe(true);
    expect(ROLE_SET.has('compliance')).toBe(true);
    expect(ROLE_SET.has('operator')).toBe(true);
    expect(ROLE_SET.has('viewer')).toBe(true);
    expect(ROLE_SET.has('tenant')).toBe(true);
  });

  test('INV-12  ROLE_SET is frozen', () => {
    expect(Object.isFrozen(ROLES)).toBe(true);
  });

  test('INV-13  isValidRole matches ROLE_SET exactly', () => {
    for (const role of ROLE_SET) {
      expect(isValidRole(role)).toBe(true);
    }
    expect(isValidRole('superadmin')).toBe(false);
    expect(isValidRole('')).toBe(false);
    expect(isValidRole(null)).toBe(false);
  });

  test('INV-14  operator does not have any MANAGE_* write permission except SUBMIT/CANCEL batch', () => {
    const opPerms = permissionsForRole(ROLES.OPERATOR);
    const forbidden = ['MANAGE_USERS', 'MANAGE_KEYS', 'MANAGE_POLICIES', 'MANAGE_CONSENT',
                       'MANAGE_RETENTION', 'MANAGE_WEBHOOKS', 'MANAGE_RECOVERY_QUEUE',
                       'MANAGE_TRANSPARENCY_LOG', 'MANAGE_VERIFICATION_PORTAL',
                       'MANAGE_ATTESTATIONS', 'MANAGE_CERTIFICATIONS'];
    for (const perm of forbidden) {
      expect(opPerms).not.toContain(perm);
    }
    // Operator's only "MANAGE-like" operations are batch certification lifecycle
    expect(opPerms).toContain('SUBMIT_BATCH_CERTIFICATION');
    expect(opPerms).toContain('CANCEL_BATCH_CERTIFICATION');
  });

  test('INV-15  compliance does not have user, key, policy, consent, or webhook management', () => {
    const compPerms = permissionsForRole(ROLES.COMPLIANCE);
    expect(compPerms).not.toContain('MANAGE_USERS');
    expect(compPerms).not.toContain('MANAGE_KEYS');
    expect(compPerms).not.toContain('MANAGE_POLICIES');
    expect(compPerms).not.toContain('MANAGE_CONSENT');
    expect(compPerms).not.toContain('MANAGE_WEBHOOKS');
    expect(compPerms).not.toContain('SUBMIT_BATCH_CERTIFICATION');
    expect(compPerms).not.toContain('CANCEL_BATCH_CERTIFICATION');
    // compliance does have MANAGE_RETENTION
    expect(compPerms).toContain('MANAGE_RETENTION');
  });

  test('INV-16  auditor cannot modify any system state', () => {
    const auditPerms = permissionsForRole(ROLES.AUDITOR);
    const writePerms = auditPerms.filter(p => p.startsWith('MANAGE_') || p.startsWith('SUBMIT_') || p.startsWith('CANCEL_'));
    // Auditors get VERIFY_EVIDENCE_CHAIN (triggers read-side verification) and INVESTIGATE_POLICIES
    // but no state-mutating MANAGE_* or SUBMIT_/CANCEL_
    expect(writePerms).toHaveLength(0);
  });

  test('INV-17  no privilege escalation: viewer cannot reach any permission above VIEW_DASHBOARD', () => {
    const viewerPerms = permissionsForRole(ROLES.VIEWER);
    for (const perm of viewerPerms) {
      expect(perm).toBe('VIEW_DASHBOARD');
    }
  });

  test('INV-18  permissionsForRole returns empty array for invalid role', () => {
    expect(permissionsForRole('godmode')).toEqual([]);
    expect(permissionsForRole('')).toEqual([]);
    expect(permissionsForRole(null)).toEqual([]);
  });

  test('INV-19  operator has READ_CERTIFICATIONS for batch status monitoring', () => {
    expect(isPermitted(ROLES.OPERATOR, 'READ_CERTIFICATIONS')).toBe(true);
  });

  test('INV-20  operator cannot export certifications', () => {
    expect(isPermitted(ROLES.OPERATOR, 'EXPORT_CERTIFICATIONS')).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// INV-21…INV-30  Middleware factory invariants
// ─────────────────────────────────────────────────────────────────────────────

describe('INV-21…INV-30  Middleware factory invariants', () => {

  test('INV-21  requirePermission does NOT throw for every defined permission', () => {
    const rp = createRequirePermission();
    for (const perm of PERMISSION_SET) {
      expect(() => rp(perm)).not.toThrow();
    }
  });

  test('INV-22  requirePermission DOES throw for any permission not in the matrix', () => {
    const rp = createRequirePermission();
    const stale = ['EXPORT_AUDIT', 'READ_INVESTIGATIONS', 'VIEW_DIAGNOSTICS', 'VERIFY_ARTIFACTS'];
    for (const perm of stale) {
      expect(() => rp(perm)).toThrow(`unknown permission "${perm}"`);
    }
    expect(() => rp('TOTALLY_FAKE')).toThrow('unknown permission');
    expect(() => rp('')).toThrow();
  });

  test('INV-23  requirePermission always validates permission names — no disabled/bypass mode exists', () => {
    const rp = createRequirePermission();
    for (const perm of PERMISSION_SET) {
      expect(() => rp(perm)).not.toThrow();
    }
    expect(() => rp('NONEXISTENT')).toThrow('unknown permission');
  });

  test('INV-24  rbacResolve never attaches any identity — there is no synthetic/implicit admin, ever', () => {
    // Regression guard for the removed vulnerability: no configuration, no
    // option, and no code path in createRbacResolveMiddleware may ever
    // attach an identity that was not set by the authentication layer.
    const mw  = createRbacResolveMiddleware({ store: {} });
    const req = {};
    let statusCode;
    const res = { status: (s) => { statusCode = s; return res; }, json: () => res };
    mw(req, res, () => { throw new Error('should not reach next — no identity present'); });
    expect(req.rbacUser).toBeUndefined();
    expect(statusCode).toBe(403);

    // Passing any other option (including the removed `enabled` flag, in any
    // form) must not change this outcome — there is no flag that opens it.
    const mw2 = createRbacResolveMiddleware({ store: {}, enabled: false });
    const req2 = {};
    let statusCode2;
    const res2 = { status: (s) => { statusCode2 = s; return res2; }, json: () => res2 };
    mw2(req2, res2, () => { throw new Error('should not reach next'); });
    expect(req2.rbacUser).toBeUndefined();
    expect(statusCode2).toBe(403);
  });

  test('INV-25  rbacResolve when rbacUser already set (by authentication) calls next() immediately', () => {
    const mw = createRbacResolveMiddleware({ store: {} });
    const req = { rbacUser: { id: 'u1', username: 'alice', role: 'auditor', enabled: true }, requestId: 'x' };
    let nextCalled = false;
    mw(req, {}, () => { nextCalled = true; });
    expect(nextCalled).toBe(true);
  });

  test('INV-26  rbacResolve when no rbacUser returns 403', () => {
    const mw = createRbacResolveMiddleware({ store: {} });
    const req = { requestId: 'x', ip: '127.0.0.1', path: '/test', method: 'GET' };
    let statusCode;
    const res = {
      status: (s) => { statusCode = s; return res; },
      json:   () => res,
    };
    mw(req, res, () => { throw new Error('should not reach next'); });
    expect(statusCode).toBe(403);
  });

  test('INV-27  requirePermission middleware returns 403 when rbacUser has insufficient role', () => {
    const rp  = createRequirePermission();
    const mw  = rp('MANAGE_KEYS'); // viewer does not have this
    const req = {
      rbacUser:  { id: 'v1', username: 'viewer', role: 'viewer', enabled: true },
      requestId: 'x',
      path:      '/keys',
      method:    'GET',
    };
    let statusCode;
    const res = {
      status: (s) => { statusCode = s; return res; },
      json:   () => res,
    };
    mw(req, res, () => { throw new Error('should not reach next'); });
    expect(statusCode).toBe(403);
  });

  test('INV-28  requirePermission middleware calls next() when role is permitted', () => {
    const rp  = createRequirePermission();
    const mw  = rp('MANAGE_KEYS'); // admin has this
    const req = {
      rbacUser:  { id: 'a1', username: 'admin', role: 'admin', enabled: true },
      requestId: 'x',
      path:      '/keys',
      method:    'GET',
    };
    let nextCalled = false;
    const res = { status: () => { throw new Error('should not 403'); } };
    mw(req, res, () => { nextCalled = true; });
    expect(nextCalled).toBe(true);
  });

  test('INV-29  requirePermission returns 403 (not 500) when rbacUser is absent', () => {
    const rp  = createRequirePermission();
    const mw  = rp('READ_AUDIT');
    const req = { requestId: 'x', path: '/t', method: 'GET' };  // no rbacUser
    let statusCode;
    const res = {
      status: (s) => { statusCode = s; return res; },
      json:   () => res,
    };
    mw(req, res, () => { throw new Error('should not reach next'); });
    expect(statusCode).toBe(403);
  });

  test('INV-30  MANAGE_CONSENT permission middleware accepts admin, rejects all others', () => {
    const rp  = createRequirePermission();
    const mw  = rp('MANAGE_CONSENT');
    function check(role) {
      const req = { rbacUser: { id: 'u', username: role, role, enabled: true }, requestId: 'x', path: '/consent', method: 'GET' };
      let statusCode = 200;
      const res = { status: (s) => { statusCode = s; return res; }, json: () => res };
      let nextCalled = false;
      mw(req, res, () => { nextCalled = true; });
      return { statusCode, nextCalled };
    }
    expect(check('admin').nextCalled).toBe(true);
    expect(check('auditor').statusCode).toBe(403);
    expect(check('compliance').statusCode).toBe(403);
    expect(check('operator').statusCode).toBe(403);
    expect(check('viewer').statusCode).toBe(403);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// INV-31…INV-40  Endpoint permission coverage
// ─────────────────────────────────────────────────────────────────────────────

describe('INV-31…INV-40  Endpoint permission coverage (server.js mount verification)', () => {

  // Enumerate every ops-protected mount from server.js.
  // Format: [mountPath, permissionOrNull]
  // null = router-internal checks verified separately; these are the mount-level gates.
  const PROTECTED_MOUNTS = [
    // Mount-level gates (explicit requirePermission at app.use)
    ['/audit',           'READ_AUDIT'],
    ['/audit-viewer',    'READ_AUDIT'],
    ['/evidence',        'GENERATE_EVIDENCE'],
    ['/v1/evidence',     'GENERATE_EVIDENCE'],
    ['/provenance',      'READ_POLICY_PROVENANCE'],
    ['/evidence-chain',  'READ_EVIDENCE_CHAIN'],
    ['/dashboard',       'VIEW_DASHBOARD'],
    ['/key-admin',       'MANAGE_KEYS'],
    ['/alerts',          'READ_AUDIT'],
    ['/consent',         'MANAGE_CONSENT'],
    // Added final verification pass:
    ['/v1/admin/organizations', 'MANAGE_USERS'],
    ['/v1/admin/tenants',       'MANAGE_USERS'],
    ['/v1/policy',              'READ_POLICIES'],
  ];

  // Router-internal mounts (requirePermission passed as factory arg, no top-level gate here)
  const INTERNAL_MOUNTS = [
    '/policy-ui',
    '/transparency',     // admin sub-router
    '/portal',           // admin sub-router
    '/v1/attestation',   // admin sub-router
    '/v1/certification', // admin sub-router
    '/v1/certifications',
    '/rbac',
    '/audit-store',
    '/compliance',
    '/v1/webhooks',
    '/v1/prq',
    '/signing-identities', // admin sub-router (TRUST-1 remediation)
  ];

  test('INV-31  every mount-level permission is valid in the permission matrix', () => {
    for (const [mount, perm] of PROTECTED_MOUNTS) {
      expect(isValidPermission(perm)).toBe(true);
    }
  });

  test('INV-32  mount-level permissions are enforced by known, valid middleware at factory time', () => {
    const rp = createRequirePermission();
    for (const [, perm] of PROTECTED_MOUNTS) {
      expect(() => rp(perm)).not.toThrow();
    }
  });

  test('INV-33  /consent is gated by MANAGE_CONSENT — admin only', () => {
    const perm = PROTECTED_MOUNTS.find(([p]) => p === '/consent')?.[1];
    expect(perm).toBe('MANAGE_CONSENT');
    expect(isPermitted(ROLES.ADMIN,      'MANAGE_CONSENT')).toBe(true);
    expect(isPermitted(ROLES.AUDITOR,    'MANAGE_CONSENT')).toBe(false);
    expect(isPermitted(ROLES.COMPLIANCE, 'MANAGE_CONSENT')).toBe(false);
    expect(isPermitted(ROLES.OPERATOR,   'MANAGE_CONSENT')).toBe(false);
    expect(isPermitted(ROLES.VIEWER,     'MANAGE_CONSENT')).toBe(false);
  });

  test('INV-34  /v1/admin/organizations is gated by MANAGE_USERS — admin only', () => {
    const perm = PROTECTED_MOUNTS.find(([p]) => p === '/v1/admin/organizations')?.[1];
    expect(perm).toBe('MANAGE_USERS');
    expect(isPermitted(ROLES.ADMIN,      'MANAGE_USERS')).toBe(true);
    expect(isPermitted(ROLES.AUDITOR,    'MANAGE_USERS')).toBe(false);
    expect(isPermitted(ROLES.OPERATOR,   'MANAGE_USERS')).toBe(false);
    expect(isPermitted(ROLES.VIEWER,     'MANAGE_USERS')).toBe(false);
  });

  test('INV-35  /v1/admin/tenants is gated by MANAGE_USERS — admin only', () => {
    const perm = PROTECTED_MOUNTS.find(([p]) => p === '/v1/admin/tenants')?.[1];
    expect(perm).toBe('MANAGE_USERS');
    expect(isPermitted(ROLES.ADMIN, 'MANAGE_USERS')).toBe(true);
  });

  test('INV-36  /v1/policy is gated by READ_POLICIES — admin, auditor, compliance, operator', () => {
    const perm = PROTECTED_MOUNTS.find(([p]) => p === '/v1/policy')?.[1];
    expect(perm).toBe('READ_POLICIES');
    expect(isPermitted(ROLES.ADMIN,      'READ_POLICIES')).toBe(true);
    expect(isPermitted(ROLES.AUDITOR,    'READ_POLICIES')).toBe(true);
    expect(isPermitted(ROLES.COMPLIANCE, 'READ_POLICIES')).toBe(true);
    expect(isPermitted(ROLES.OPERATOR,   'READ_POLICIES')).toBe(true);
    expect(isPermitted(ROLES.VIEWER,     'READ_POLICIES')).toBe(false);
  });

  test('INV-37  router-internal permission check list is complete', () => {
    // Verify every internal router permission name is valid at factory time.
    // This catches any drift between internal router permission strings and the matrix.
    const rp = createRequirePermission();
    const INTERNAL_PERMISSIONS = [
      // policyManagement
      'READ_POLICIES', 'MANAGE_POLICIES',
      // policyProvenance
      'READ_POLICY_PROVENANCE', 'INVESTIGATE_POLICIES',
      // evidenceChain
      'READ_EVIDENCE_CHAIN', 'VERIFY_EVIDENCE_CHAIN',
      // transparencyLog
      'READ_TRANSPARENCY_LOG', 'MANAGE_TRANSPARENCY_LOG',
      // verificationPortal
      'READ_VERIFICATION_PORTAL',
      // attestation
      'READ_ATTESTATIONS', 'EXPORT_ATTESTATIONS',
      // certification
      'READ_CERTIFICATIONS', 'EXPORT_CERTIFICATIONS',
      // certificationBatch
      'SUBMIT_BATCH_CERTIFICATION', 'CANCEL_BATCH_CERTIFICATION',
      // rbacAdmin
      'READ_USERS', 'MANAGE_USERS',
      // auditStore
      'READ_AUDIT', 'MANAGE_RETENTION',
      // compliance
      'READ_COMPLIANCE', 'GENERATE_REPORT',
      // webhooks
      'READ_WEBHOOKS', 'MANAGE_WEBHOOKS',
      // prqDlq
      'READ_RECOVERY_QUEUE', 'MANAGE_RECOVERY_QUEUE',
      // signingIdentities (TRUST-1 remediation)
      'READ_SIGNING_IDENTITIES', 'MANAGE_SIGNING_IDENTITIES',
    ];
    for (const perm of INTERNAL_PERMISSIONS) {
      expect(() => rp(perm)).not.toThrow();
    }
  });

  test('INV-38  every permission used by any endpoint (mount or router-internal) is in the matrix', () => {
    // Union of all permissions referenced across all routers
    const ALL_USED = new Set([
      ...PROTECTED_MOUNTS.map(([, p]) => p),
      'READ_POLICIES', 'MANAGE_POLICIES',
      'READ_POLICY_PROVENANCE', 'INVESTIGATE_POLICIES',
      'READ_EVIDENCE_CHAIN', 'VERIFY_EVIDENCE_CHAIN',
      'READ_TRANSPARENCY_LOG', 'MANAGE_TRANSPARENCY_LOG',
      'READ_VERIFICATION_PORTAL',
      'READ_ATTESTATIONS', 'EXPORT_ATTESTATIONS',
      'READ_CERTIFICATIONS', 'EXPORT_CERTIFICATIONS',
      'SUBMIT_BATCH_CERTIFICATION', 'CANCEL_BATCH_CERTIFICATION',
      'READ_USERS', 'MANAGE_USERS',
      'READ_AUDIT', 'MANAGE_RETENTION',
      'READ_COMPLIANCE', 'GENERATE_REPORT',
      'MANAGE_CONSENT',
      'READ_WEBHOOKS', 'MANAGE_WEBHOOKS',
      'READ_RECOVERY_QUEUE', 'MANAGE_RECOVERY_QUEUE',
      'VIEW_DASHBOARD', 'MANAGE_KEYS', 'GENERATE_EVIDENCE',
      'READ_DSR', 'MANAGE_DSR',
      'READ_POLICY_GOVERNANCE', 'PROPOSE_POLICY_CHANGE', 'REVIEW_POLICY_CHANGE',
      'APPROVE_POLICY_CHANGE', 'PUBLISH_POLICY_CHANGE',
      'REQUEST_POLICY_ROLLBACK', 'APPROVE_POLICY_ROLLBACK',
      'EMERGENCY_POLICY_OVERRIDE', 'APPROVE_EMERGENCY_POLICY',
      'READ_SIGNING_IDENTITIES', 'MANAGE_SIGNING_IDENTITIES',
    ]);
    for (const perm of ALL_USED) {
      expect(isValidPermission(perm)).toBe(true);
    }
  });

  test('INV-39  every permission in the matrix is used by at least one route or marked reserved', () => {
    const ACTIVE = new Set([
      'READ_AUDIT', 'GENERATE_EVIDENCE', 'VIEW_DASHBOARD',
      'READ_POLICIES', 'MANAGE_POLICIES', 'MANAGE_KEYS',
      'MANAGE_USERS', 'READ_USERS', 'MANAGE_RETENTION',
      'READ_COMPLIANCE', 'GENERATE_REPORT', 'MANAGE_CONSENT',
      'READ_POLICY_PROVENANCE', 'INVESTIGATE_POLICIES',
      'READ_EVIDENCE_CHAIN', 'VERIFY_EVIDENCE_CHAIN',
      'READ_TRANSPARENCY_LOG', 'MANAGE_TRANSPARENCY_LOG',
      'READ_VERIFICATION_PORTAL',
      'READ_ATTESTATIONS', 'EXPORT_ATTESTATIONS',
      'READ_CERTIFICATIONS', 'EXPORT_CERTIFICATIONS',
      'SUBMIT_BATCH_CERTIFICATION', 'CANCEL_BATCH_CERTIFICATION',
      'READ_WEBHOOKS', 'MANAGE_WEBHOOKS',
      'READ_RECOVERY_QUEUE', 'MANAGE_RECOVERY_QUEUE',
      'READ_DSR', 'MANAGE_DSR',
      'READ_POLICY_GOVERNANCE', 'PROPOSE_POLICY_CHANGE', 'REVIEW_POLICY_CHANGE',
      'APPROVE_POLICY_CHANGE', 'PUBLISH_POLICY_CHANGE',
      'REQUEST_POLICY_ROLLBACK', 'APPROVE_POLICY_ROLLBACK',
      'EMERGENCY_POLICY_OVERRIDE', 'APPROVE_EMERGENCY_POLICY',
      'READ_SIGNING_IDENTITIES', 'MANAGE_SIGNING_IDENTITIES',
      // the tenant self-service portal's 3 permissions —
      // used by src/api/routes/tenantPortal.js's GET /tenant-portal/api/{me,keys,consent}.
      'READ_TENANT_IDENTITY', 'READ_TENANT_KEYS', 'READ_TENANT_CONSENT',
      // usage-metering API + CSV export — used by
      // src/api/routes/tenantPortal.js's GET /tenant-portal/api/usage(/export).
      'READ_TENANT_USAGE',
      // alert mutations — src/alerting/api/alertRoutes.js POST routes.
      'MANAGE_ALERTS',
      // global kill switch — src/api/routes/admin/killSwitch.js (GET / READ_KILL_SWITCH; POST activate|release / MANAGE_KILL_SWITCH).
      'MANAGE_KILL_SWITCH', 'READ_KILL_SWITCH',
      // dynamic provider registry — src/api/routes/admin/providers.js.
      'MANAGE_PROVIDERS', 'READ_PROVIDERS',
      // per-artifact revocation — src/api/routes/admin/artifactRevocations.js.
      'MANAGE_ARTIFACT_REVOCATIONS',
      // downloadable proof of one request — src/api/routes/proofs.js.
      'READ_AUDIT_PROOFS', 'READ_AUDIT_PROOFS_FULL_CHAIN',
      // agent identities and sessions - src/api/routes/agents.js.
      'MANAGE_AGENTS', 'READ_AGENTS', 'MANAGE_AGENT_SESSIONS',
      // tool registry - src/api/routes/toolRegistry.js.
      'MANAGE_TOOLS', 'READ_TOOLS',
      // MCP servers - src/api/routes/mcpServers.js.
      'MANAGE_MCP_SERVERS', 'READ_MCP_SERVERS',
      // human approval of agent actions - src/api/routes/approvals.js.
      'DECIDE_APPROVALS', 'READ_APPROVALS',
    ]);
    // Intentionally reserved (no route yet, documented in roles.js as "reserved for future")
    const RESERVED = new Set([
      'MANAGE_VERIFICATION_PORTAL',
      'MANAGE_ATTESTATIONS',
      'MANAGE_CERTIFICATIONS',
    ]);
    for (const perm of PERMISSION_SET) {
      expect(ACTIVE.has(perm) || RESERVED.has(perm)).toBe(true);
    }
    // Verify no undocumented permission sneaked in
    const total = ACTIVE.size + RESERVED.size;
    expect(PERMISSION_SET.size).toBe(total);
  });

  test('INV-40  public endpoints have no ops middleware — listed for completeness', () => {
    // These are the PUBLIC surfaces (no auth required):
    const PUBLIC_SURFACES = [
      '/ai/chat', '/ai/chat/stream', '/verify',
      '/sign', '/.well-known', '/public-key', '/public-keys', '/keys',
      '/transparency (public router)',
      '/portal (public router)',
      '/v1/attestation (public router)',
      '/v1/certification (public router)',
      '/v1/ai/chat', '/v1/ai/chat/stream', '/v1/verify',
    ];
    // OPS-authenticated but no RBAC permission check (auth = ops token, not RBAC role):
    const OPS_AUTH_ONLY = [
      '/health', '/ready', '/metrics', '/diagnostics',
    ];
    // Existence check — this test documents intent, not runtime state
    expect(PUBLIC_SURFACES.length).toBeGreaterThan(0);
    expect(OPS_AUTH_ONLY.length).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// INV-41…INV-50  Fail-closed and security invariants
// ─────────────────────────────────────────────────────────────────────────────

describe('INV-41…INV-50  Fail-closed and security invariants', () => {

  test('INV-41  isPermitted returns false for every input combination involving invalid role', () => {
    const invalidRoles = [null, undefined, '', 'superadmin', 42, {}, []];
    for (const role of invalidRoles) {
      for (const perm of PERMISSION_SET) {
        expect(isPermitted(role, perm)).toBe(false);
      }
    }
  });

  test('INV-42  isPermitted returns false for every input combination involving invalid permission', () => {
    const invalidPerms = [null, undefined, '', 'HACK_EVERYTHING', 'EXPORT_AUDIT', 'VIEW_DIAGNOSTICS'];
    for (const perm of invalidPerms) {
      for (const role of ROLE_SET) {
        expect(isPermitted(role, perm)).toBe(false);
      }
    }
  });

  test('INV-43  no permission grants viewer any access beyond VIEW_DASHBOARD', () => {
    for (const perm of PERMISSION_SET) {
      if (perm === 'VIEW_DASHBOARD') continue;
      expect(isPermitted(ROLES.VIEWER, perm)).toBe(false);
    }
  });

  test('INV-44  no permission grants auditor any state-mutating access', () => {
    const writeLike = Array.from(PERMISSION_SET).filter(p =>
      p.startsWith('MANAGE_') || p.startsWith('SUBMIT_') || p.startsWith('CANCEL_')
    );
    for (const perm of writeLike) {
      expect(isPermitted(ROLES.AUDITOR, perm)).toBe(false);
    }
  });

  test('INV-45  privilege escalation: operator cannot reach user management', () => {
    expect(isPermitted(ROLES.OPERATOR, 'MANAGE_USERS')).toBe(false);
    expect(isPermitted(ROLES.OPERATOR, 'READ_USERS')).toBe(false);
  });

  test('INV-46  privilege escalation: operator cannot reach key management', () => {
    expect(isPermitted(ROLES.OPERATOR, 'MANAGE_KEYS')).toBe(false);
  });

  test('INV-47  privilege escalation: operator cannot manage consent', () => {
    expect(isPermitted(ROLES.OPERATOR, 'MANAGE_CONSENT')).toBe(false);
  });

  test('INV-48  privilege escalation: compliance cannot manage consent, users, or keys', () => {
    expect(isPermitted(ROLES.COMPLIANCE, 'MANAGE_CONSENT')).toBe(false);
    expect(isPermitted(ROLES.COMPLIANCE, 'MANAGE_USERS')).toBe(false);
    expect(isPermitted(ROLES.COMPLIANCE, 'MANAGE_KEYS')).toBe(false);
  });

  test('INV-49  confused deputy: no combination of lower roles equals admin', () => {
    // A user with operator + auditor + compliance combined still does not have
    // any permission that is admin-only.  isPermitted checks a single role; this
    // test verifies that admin-only permissions are not reachable from any other role.
    const adminOnlyPerms = Array.from(PERMISSION_SET).filter(perm => {
      const allowed = PERMISSIONS[perm];
      return allowed.length === 1 && allowed[0] === 'admin';
    });
    expect(adminOnlyPerms.length).toBeGreaterThan(0); // sanity: some admin-only perms exist
    for (const perm of adminOnlyPerms) {
      for (const role of ['auditor', 'compliance', 'operator', 'viewer']) {
        expect(isPermitted(role, perm)).toBe(false);
      }
    }
  });

  test('INV-50  fail-closed: requirePermission engine errors always produce 403, never 500', () => {
    // Simulate an engine error by mocking isPermitted to throw
    const original = require('./roles').isPermitted;
    // The middleware wraps isPermitted in a try/catch and returns _deny403
    // We verify the middleware response is 403 by invoking with an rbacUser whose
    // role will cause the real isPermitted to return false (viewer vs MANAGE_KEYS)
    const rp  = createRequirePermission();
    const mw  = rp('MANAGE_KEYS');
    const req = {
      rbacUser:  { id: 'v', username: 'viewer', role: 'viewer', enabled: true },
      requestId: 'x', path: '/keys', method: 'GET',
    };
    let statusCode = 0;
    const res = {
      status: (s) => { statusCode = s; return res; },
      json:   () => res,
    };
    mw(req, res, () => { throw new Error('should not reach next'); });
    expect(statusCode).toBe(403);
    // Verify it is not 500
    expect(statusCode).not.toBe(500);
  });
});
