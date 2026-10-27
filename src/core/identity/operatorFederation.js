'use strict';

/**
 * The single-sign-on sources the operator admin API accepts, combined for src/middleware/opsAuth.js:
 *   - an OIDC bearer token linked to an RBAC user (oidcService.operatorFederation),
 *   - an operator session token minted after a SAML or LDAP login (operatorSession).
 * Returns null when neither is configured, so a deployment without federation behaves exactly as before.
 *
 * A session token names an RBAC user; on every request the user must still exist, still be enabled and still be linked to the same (issuer, subject) the session was minted for.
 */

const oidcService = require('./oidcService');
const samlService = require('./samlService');
const ldapService = require('./ldapService');
const operatorSession = require('./operatorSession');
const { emit } = require('../../../services/logger');

function create(rbacStore) {
  const oidc = oidcService.operatorFederation(rbacStore);
  const sessions = samlService.isEnabled() || ldapService.isEnabled();
  if (!oidc && !sessions) return null;
  return {
    accepts: (token) => (sessions && operatorSession.looksLikeSession(token)) || (oidc !== null && oidc.accepts(token)),
    async resolve(token) {
      if (sessions && operatorSession.looksLikeSession(token)) {
        const v = operatorSession.verify(token);
        if (!v.ok) { emit('WARN', 'OPERATOR_SESSION_REFUSED', { reason: v.reason }); return { ok: false, reason: v.reason, unavailable: v.unavailable === true }; }
        let user;
        try { user = rbacStore.getUser(v.payload.sub); } catch (e) { return { ok: false, reason: 'IDENTITY_STORE_ERROR', unavailable: true }; }
        if (!user || !user.externalIdentity) return { ok: false, reason: 'SESSION_USER_GONE' };
        if (operatorSession.linkHash(user.externalIdentity.issuer, user.externalIdentity.subject) !== v.payload.lk) return { ok: false, reason: 'SESSION_LINK_CHANGED' };
        return { ok: true, operator: user, via: 'session', providerId: v.payload.prov, assured: v.payload.as === true && !(typeof v.payload.au === 'number' && Math.floor(Date.now() / 1000) >= v.payload.au), expiresAt: v.payload.exp };
      }
      return oidc.resolve(token);
    },
  };
}

module.exports = { create };
