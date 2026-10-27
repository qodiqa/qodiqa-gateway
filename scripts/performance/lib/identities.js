'use strict';

/**
 * Item 24 amendment 2 — per-level synthetic identity pool.
 *
 * RATE_LIMIT policies (POL-004/POL-NEW) bucket by `userId`, which
 * checkPolicy.js resolves to the artifact's signing publicKeyId
 * (src/validation/checkPolicy.js: `userId: publicKeyId ?? null`) — not any
 * request-body field. So "N identities" means N distinct signing keys, each
 * needing its own real-consent grant attempt, not N different userId values
 * in the JSON body.
 *
 * Provisioning reuses the exact call scripts/lib/keyStoreProvisioning.js's
 * ensureActiveKey() already uses for the harness's single 'default'
 * identity: rotateKey(clientId) with no opts. For a brand-new clientId this
 * goes straight through keyStore.js's _provisionFirstKey() branch, which
 * never calls _resolveRotationMode() — so it does NOT require opts.mode
 * (only rotating an EXISTING active key does). Confirmed by reading
 * services/artifact/keyStore.js's rotateKey().
 */

const { rotateKey, getActiveKey } = require('../../../services/artifact/keyStore');
const consent = require('../../../src/core/consent');

const CLIENT_ID_PREFIX = 'qodiqaperfid';

/**
 * Mirrors harness.js's original single-identity consent probe exactly
 * (moved here, not duplicated) — attempts a real Postgres grant+verify,
 * returns whether it actually passed. Does not itself mutate global state;
 * callers decide whether/how to fall back.
 */
async function tryRealConsent(actorKeyId, action, tenantId) {
  try {
    await consent.grant({
      actor_id: actorKeyId,
      action,
      tenant_id: tenantId,
      granted_by: 'perf-harness',
      scope: null,
    });
    const check = await consent.verify({ actor_id: actorKeyId, action, tenant_id: tenantId });
    return !!check.pass;
  } catch (err) {
    // Item 24 — this catch used to swallow failures completely, which is
    // exactly how the missing pool.initialize() bug (harness.js) stayed
    // invisible across items 16/17/24's own runs. A stub fallback must
    // never again be silent.
    console.warn(`[identities] real-consent attempt failed for actor="${actorKeyId}" — falling back to stub: ${err.message}`);
    return false;
  }
}

/**
 * Provision `n` synthetic signing identities (clientId qodiqaperfid0..n-1),
 * each with its own key and its own real-consent grant attempt.
 *
 * Once any identity's real-consent attempt fails, consent.verify is
 * globally monkey-patched to the same always-pass stub the original
 * single-identity harness path uses on fallback (module-export mutation —
 * consent.verify is looked up fresh via _registry().verify at each call,
 * per requireConsent.js). From that point on, calling verify() again for
 * later identities would spuriously report "real" consent (the stub always
 * passes) — so once activated, later identities are marked consentOk:false
 * directly, without an unreliable extra call, for an honest aggregate.
 *
 * @param {number} n
 * @param {string} action — artifact.payload.provider / consent action value
 * @returns {Promise<{
 *   identities: Array<{KEY:object, clientId:string, tenantId:string, consentOk:boolean}>,
 *   consentMode: 'real-postgres'|'stubbed-fast-path'|'mixed',
 *   stubbedCount: number, total: number,
 * }>}
 */
async function provisionIdentityPool(n, action) {
  const identities = [];
  let stubActivated = false;

  for (let i = 0; i < n; i++) {
    const clientId = `${CLIENT_ID_PREFIX}${i}`;
    rotateKey(clientId);
    const KEY = getActiveKey(clientId);

    let consentOk;
    if (stubActivated) {
      consentOk = false;
    } else {
      consentOk = await tryRealConsent(KEY.keyId, action, clientId);
      if (!consentOk) {
        consent.verify = async () => ({ pass: true, reason: 'ACTIVE' });
        stubActivated = true;
      }
    }
    identities.push({ KEY, clientId, tenantId: clientId, consentOk });
  }

  const stubbedCount = identities.filter((id) => !id.consentOk).length;
  const consentMode =
    stubbedCount === 0 ? 'real-postgres' :
    stubbedCount === identities.length ? 'stubbed-fast-path' : 'mixed';

  return { identities, consentMode, stubbedCount, total: identities.length };
}

module.exports = { tryRealConsent, provisionIdentityPool, CLIENT_ID_PREFIX };
