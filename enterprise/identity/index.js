'use strict';

/**
 * QODIQA enterprise identity: federated authentication building blocks. Separable directory (design decision L1): nothing here imports the core; the core reaches it only through
 * src/core/identity/extensionPoint.js and injects what it needs (network access, storage). See docs/guides/IDENTITY.md.
 */

module.exports = {
  jwt: require('./jwt'),
  jwks: require('./jwks'),
  oidc: require('./oidc'),
  saml: require('./saml'),
  ldap: require('./ldap'),
};
