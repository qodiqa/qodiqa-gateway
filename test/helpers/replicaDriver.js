'use strict';

// one "replica" of the control plane — a separate Node process with
// its own module state, driven over IPC by test/integration/replicaRevocation.integration.test.js.
// Step 1 ran it against shared JSON files;
// since step 3 it runs against the PostgreSQL control plane (QODIQA_CONTROL_PLANE_BACKEND=pg
// in the parent's env), exactly as a production replica would.

const cp      = require('../../src/core/controlPlane');
const signing = require('../../src/core/signing/signingIdentityStore');
const rbac    = require('../../src/core/rbac/store');
const tenants = require('../../src/core/tenancy/tenantRegistry');
const killSwitch = require('../../src/core/killSwitch');   // the global kill switch (test/integration/killSwitchPropagation.integration.test.js)

const OPS = {
  'signing.create':  (a) => signing.createSigningIdentity(a),
  'signing.issue':   (id) => signing.issueSigningKey(id),
  'signing.revoke':  (id) => signing.revokeSigningKey(id, { revokedBy: 'w6-test' }),
  'signing.update':  ({ id, patch }) => signing.updateSigningIdentity(id, patch),
  'signing.resolve': (key) => { const i = signing.resolveSigningIdentity(key); return i ? { id: i.id, revoked: i.revoked } : null; },
  'signing.touch':   (id) => signing.touchLastUsed(id),
  'rbac.create':     (a) => rbac.createUser(a),
  'rbac.issue':      (id) => rbac.issueApiKey(id),
  'rbac.revoke':     (id) => rbac.revokeApiKey(id, { revokedBy: 'w6-test' }),
  'rbac.update':     ({ id, patch }) => rbac.updateUser(id, patch),
  'rbac.delete':     (id) => rbac.deleteUser(id, { deletedBy: 'w6-test' }),
  'rbac.resolve':    (key) => { const u = rbac.resolveOperatorKey(key); return u ? { id: u.id } : null; },
  'rbac.get':        (id) => rbac.getUser(id),
  'tenant.register': (id) => tenants.registerTenant(id),
  'tenant.suspend':  (id) => tenants.updateTenant(id, { status: 'suspended' }),
  'tenant.update':   ({ id, patch }) => tenants.updateTenant(id, patch),
  'tenant.assert':   (id) => tenants.assertActiveTenant(id),
  // kill switch: state() throws CONTROL_PLANE_STALE when this replica cannot confirm the state (the gate then refuses)
  'ks.activate':     (reason) => killSwitch.activate({ operatorId: 'ks-test', reason: reason || 'test' }).then((o) => ({ changed: o.changed, active: o.state.active })),
  'ks.release':      () => killSwitch.release({ operatorId: 'ks-test' }).then((o) => ({ changed: o.changed, active: o.state.active })),
  'ks.state':        () => { const st = killSwitch.state(); return { active: st.active, tampered: st.tampered, seq: st.record ? st.record.seq : 0 }; },
  // replica controls
  'cp.pause':        () => cp.stop(),                 // stop pulling: this replica goes stale
  'cp.sync':         () => cp.syncNow(),
  'cp.status':       () => { const s = cp.status(); return { backend: s.backend, ageMs: s.ageMs, syncCount: s.syncCount, notifier: s.notifier }; },
};

process.on('message', async ({ seq, op, arg }) => {
  try {
    const fn = OPS[op];
    if (!fn) throw new Error(`unknown op ${op}`);
    const value = await fn(arg);
    process.send({ seq, ok: true, value: value === undefined ? null : value });
  } catch (err) {
    process.send({ seq, ok: false, error: err.message, code: err.code || null });
  }
});

(async () => {
  try {
    await cp.start({ notifier: process.env.W6_NOTIFIER !== 'off' });
    process.send({ ready: true, backend: cp.backend() });
  } catch (err) {
    process.send({ ready: false, error: err.message });
  }
})();
