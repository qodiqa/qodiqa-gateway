'use strict';

/**
 * LDAP / Active Directory sign-in for operators: a directory user proves who they are by a bind with their own password, and the verified (issuer, subject) is then mapped to a
 * linked RBAC user exactly like an OIDC or SAML login (the mapping and the session are the core's job; this module only answers "who is this, proven by the directory").
 *
 *   validateConfig(cfg)                       -> throws on a bad provider description
 *   createLdapProvider(cfg, { env, clientFactory })
 *       .authenticate(username, password)     -> { ok: true, issuer, subject, username, groups, assured: false }
 *                                                | { ok: false, reason, unavailable? }
 *       .ldapEscape(value)                    -> RFC 4515 filter-value escaping (exported for tests and for the verifier)
 *
 * Provider description (JSON, one per directory):
 *   id, url (ldaps://host:636, or ldap:// with startTls: true), baseDn, bindDn, bindPasswordEnv (NAME of an environment variable that holds the service-account password - never the
 *   password itself), userFilter (default "(&(objectClass=person)(uid={username}))"; Active Directory: "(&(objectClass=user)(sAMAccountName={username}))"; {username} is the ONLY placeholder
 *   and is always escaped), subjectAttribute (default "entryUUID"; Active Directory "objectGUID" with binarySubject: true), groupAttribute (default "memberOf"), requiredGroups (optional list of
 *   group DNs, ANY one admits), tlsCa (PEM, optional), timeoutMs (default 5000), allowInsecure (tests only: ldap:// without TLS, refused unless the host is loopback).
 *
 * What is refused before any network call: an empty password (many servers treat a bind with a DN and an empty password as an UNAUTHENTICATED bind that succeeds), a username with control
 * characters or longer than 256, a filter template without {username} or with any other brace. A search that does not match EXACTLY one entry is a failed login (the answer never says whether the
 * user exists). Every refusal carries the same shape; the reason is for the log only.
 */

const MAX_USERNAME = 256;
const MAX_PASSWORD = 1024;
const ID_RE = /^[a-z][a-z0-9-]{0,30}$/;
const ATTR_RE = /^[A-Za-z][A-Za-z0-9-]{0,63}$/;

/** RFC 4515: escape the characters that change the meaning of a filter value; non-ASCII becomes the \XX escapes of its UTF-8 bytes. */
function ldapEscape(value) {
  const bytes = Buffer.from(String(value), 'utf8');
  let out = '';
  for (const b of bytes) {
    if (b === 0x5c || b === 0x2a || b === 0x28 || b === 0x29 || b === 0x00 || b > 0x7f) out += `\\${b.toString(16).padStart(2, '0')}`;
    else out += String.fromCharCode(b);
  }
  return out;
}

function validateConfig(cfg) {
  const bad = (m) => { throw new Error(`ldap ${cfg && cfg.id}: ${m}`); };
  if (!cfg || typeof cfg !== 'object') throw new Error('ldap: a provider is an object');
  const allowed = new Set(['id', 'url', 'baseDn', 'bindDn', 'bindPasswordEnv', 'userFilter', 'subjectAttribute', 'binarySubject', 'groupAttribute', 'requiredGroups', 'tlsCa', 'timeoutMs', 'startTls', 'allowInsecure', 'sessionTtlSec']);
  for (const k of Object.keys(cfg)) if (!allowed.has(k)) bad(`unknown member ${k}`);
  if (typeof cfg.id !== 'string' || !ID_RE.test(cfg.id)) bad('id is lowercase letters, digits and hyphens');
  let u; try { u = new URL(cfg.url); } catch { bad('url is not a URL'); }
  if (!['ldap:', 'ldaps:'].includes(u.protocol)) bad('url is ldap:// or ldaps://');
  if (u.username || u.password) bad('url carries no credentials');
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (u.protocol === 'ldap:' && cfg.startTls !== true && !(cfg.allowInsecure === true && loopback)) bad('ldap:// needs startTls: true (a password must never cross the network in clear)');
  for (const k of ['baseDn', 'bindDn']) if (typeof cfg[k] !== 'string' || cfg[k].length < 3 || cfg[k].length > 1024 || /[\u0000-\u001f]/.test(cfg[k])) bad(`${k} is a distinguished name`);
  if (typeof cfg.bindPasswordEnv !== 'string' || !/^[A-Z][A-Z0-9_]{2,63}$/.test(cfg.bindPasswordEnv)) bad('bindPasswordEnv names an environment variable');
  const f = cfg.userFilter === undefined ? '(&(objectClass=person)(uid={username}))' : cfg.userFilter;
  if (typeof f !== 'string' || f.length > 512 || /[\u0000-\u001f]/.test(f)) bad('userFilter is a filter');
  if ((f.match(/\{username\}/g) || []).length !== 1) bad('userFilter contains {username} exactly once');
  if (/[{}]/.test(f.replace('{username}', ''))) bad('userFilter has no placeholder other than {username}');
  if (!f.startsWith('(') || !f.endsWith(')')) bad('userFilter is parenthesised');
  for (const k of ['subjectAttribute', 'groupAttribute']) if (cfg[k] !== undefined && (typeof cfg[k] !== 'string' || !ATTR_RE.test(cfg[k]))) bad(`${k} is an attribute name`);
  if (cfg.requiredGroups !== undefined && (!Array.isArray(cfg.requiredGroups) || cfg.requiredGroups.length > 64 || cfg.requiredGroups.some((g) => typeof g !== 'string' || g.length < 3 || g.length > 1024))) bad('requiredGroups is a list of at most 64 group DNs');
  if (cfg.timeoutMs !== undefined && !(Number.isInteger(cfg.timeoutMs) && cfg.timeoutMs >= 500 && cfg.timeoutMs <= 30000)) bad('timeoutMs is 500..30000');
  if (cfg.tlsCa !== undefined && (typeof cfg.tlsCa !== 'string' || !/BEGIN CERTIFICATE/.test(cfg.tlsCa))) bad('tlsCa is a PEM certificate');
}

const norm = (dn) => String(dn).replace(/\s*,\s*/g, ',').toLowerCase();

function defaultClientFactory(cfg) {
  const { Client } = require('ldapts');   // optionalDependency: only loaded when an LDAP provider is configured
  const tlsOptions = { minVersion: 'TLSv1.2', rejectUnauthorized: true, ...(cfg.tlsCa ? { ca: cfg.tlsCa } : {}) };
  // ldapts opens TLS at connect time whenever tlsOptions is present, so they are passed ONLY for ldaps:// (StartTLS gets its options in withClient)
  return new Client({ url: cfg.url, timeout: cfg.timeoutMs || 5000, connectTimeout: cfg.timeoutMs || 5000, ...(cfg.url.startsWith('ldaps:') ? { tlsOptions } : {}) });
}

function createLdapProvider(cfg, { env = process.env, clientFactory = defaultClientFactory } = {}) {
  validateConfig(cfg);
  const filterTemplate = cfg.userFilter === undefined ? '(&(objectClass=person)(uid={username}))' : cfg.userFilter;
  const subjectAttribute = cfg.subjectAttribute || 'entryUUID';
  const groupAttribute = cfg.groupAttribute || 'memberOf';
  const issuer = `ldap:${cfg.id}`;
  const required = (cfg.requiredGroups || []).map(norm);

  async function withClient(fn) {
    const client = clientFactory(cfg);
    try {
      if (cfg.startTls === true && typeof client.startTLS === 'function') await client.startTLS({ rejectUnauthorized: true, ...(cfg.tlsCa ? { ca: cfg.tlsCa } : {}) });
      return await fn(client);
    } finally { try { await client.unbind(); } catch { /* the connection is gone already */ } }
  }

  async function authenticate(username, password) {
    if (typeof username !== 'string' || username.length === 0 || username.length > MAX_USERNAME || /[\u0000-\u001f\u007f]/.test(username) || username !== username.trim()) return { ok: false, reason: 'LDAP_BAD_USERNAME' };   // a directory may ignore insignificant spaces when it matches a name: a name with leading or trailing space is refused (F10V-01)
    if (typeof password !== 'string' || password.length === 0) return { ok: false, reason: 'LDAP_EMPTY_PASSWORD' };   // never an unauthenticated bind
    if (password.length > MAX_PASSWORD || password.includes('\u0000')) return { ok: false, reason: 'LDAP_BAD_PASSWORD' };
    const servicePassword = env[cfg.bindPasswordEnv];
    if (!servicePassword) return { ok: false, reason: 'LDAP_SERVICE_ACCOUNT_UNSET', unavailable: true };
    const filter = filterTemplate.replace('{username}', ldapEscape(username));
    let entry;
    try {
      entry = await withClient(async (c) => {
        await c.bind(cfg.bindDn, servicePassword);
        const { searchEntries } = await c.search(cfg.baseDn, {
          scope: 'sub', filter, sizeLimit: 2, timeLimit: Math.ceil((cfg.timeoutMs || 5000) / 1000),
          attributes: [subjectAttribute, groupAttribute], ...(cfg.binarySubject === true ? { explicitBufferAttributes: [subjectAttribute] } : {}),
        });
        return searchEntries.length === 1 ? searchEntries[0] : (searchEntries.length === 0 ? null : 'AMBIGUOUS');
      });
    } catch (e) { return { ok: false, reason: 'LDAP_DIRECTORY_UNAVAILABLE', unavailable: true, detail: e && e.name }; }
    if (entry === null) {
      // the same number of directory round trips as a wrong password, so that the time does not tell a name that exists from one that does not (F10V-07)
      try { await withClient((c) => c.bind(`uid=qodiqa-no-such-user,${cfg.baseDn}`, password)); } catch { /* expected: this entry does not exist */ }
      return { ok: false, reason: 'LDAP_NO_SUCH_USER' };
    }
    if (entry === 'AMBIGUOUS') return { ok: false, reason: 'LDAP_AMBIGUOUS_USER' };
    const rawSubject = Array.isArray(entry[subjectAttribute]) ? entry[subjectAttribute][0] : entry[subjectAttribute];
    const subject = Buffer.isBuffer(rawSubject) ? rawSubject.toString('hex') : (typeof rawSubject === 'string' ? rawSubject : '');
    if (!subject || subject.length > 256) return { ok: false, reason: 'LDAP_NO_SUBJECT_ATTRIBUTE' };
    if (typeof entry.dn !== 'string' || !entry.dn) return { ok: false, reason: 'LDAP_NO_DN' };
    try {
      await withClient((c) => c.bind(entry.dn, password));   // the user proves the password to the directory itself
    } catch (e) {
      const invalid = e && (e.name === 'InvalidCredentialsError' || e.code === 49);
      return invalid ? { ok: false, reason: 'LDAP_INVALID_CREDENTIALS' } : { ok: false, reason: 'LDAP_DIRECTORY_UNAVAILABLE', unavailable: true, detail: e && e.name };
    }
    const groupsRaw = entry[groupAttribute];
    const groups = (Array.isArray(groupsRaw) ? groupsRaw : groupsRaw ? [groupsRaw] : []).filter((g) => typeof g === 'string').slice(0, 512);
    if (required.length > 0 && !groups.some((g) => required.includes(norm(g)))) return { ok: false, reason: 'LDAP_NOT_IN_REQUIRED_GROUP' };
    return { ok: true, issuer, subject, username, groups, assured: false };
  }

  return { authenticate, issuer, ldapEscape };
}

module.exports = { validateConfig, createLdapProvider, ldapEscape, MAX_USERNAME };
