#!/usr/bin/env node
'use strict';

/**
 * operator tool: migration-created PostgreSQL LOGIN roles vs. their published placeholders.
 *
 *   node scripts/db/role-credentials.js --check
 *       Probe every migration-created role with its published placeholder password
 *       (src/infra/postgres/roleCredentials.js). Read-only: it only attempts logins.
 *       Exit 0 = proven safe · 1 = a role ACCEPTED its placeholder · 2 = no violation, but
 *       some roles could not be probed from this host (pg_hba / connectivity).
 *
 *   node scripts/db/role-credentials.js --harden-unused --confirm
 *       ALTER ROLE … NOLOGIN for roles with no runtime consumer (qodiqa_read). Needs an
 *       administrative connection (QODIQA_PG_ADMIN_USER / QODIQA_PG_ADMIN_PASSWORD, a role
 *       with CREATEROLE/ADMIN on the target role). Re-enable a role deliberately with
 *       ALTER ROLE <role> LOGIN PASSWORD '<secret>'.
 *
 *   node scripts/db/role-credentials.js --rotate <role> --password-env <VAR> --confirm
 *       ALTER ROLE <role> PASSWORD <value of $VAR>. The secret is read from the environment
 *       and never printed. Then update the consumer's secret store (see the runbook).
 *
 * Connection target: QODIQA_PG_HOST / _PORT / _DATABASE / QODIQA_PG_URL / TLS as for the gateway.
 * Roles are CLUSTER-wide objects: --harden-unused / --rotate affect every database on the cluster.
 * This tool is never run automatically. docs/operations/database-role-management.md.
 */

const { Client } = require('pg');
const rc = require('../../src/infra/postgres/roleCredentials');

const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
const val = (f) => { const i = argv.indexOf(f); return i >= 0 ? argv[i + 1] : undefined; };
const UNUSED = ['qodiqa_read'];

/** RFC 5802 / RFC 7677 SCRAM-SHA-256 verifier in PostgreSQL's stored format. */
function scramVerifier(password, { iterations = 4096, salt = require('crypto').randomBytes(16) } = {}) {
  const crypto = require('crypto');
  const salted = crypto.pbkdf2Sync(password.normalize('NFKC'), salt, iterations, 32, 'sha256');
  const hmac = (k, m) => crypto.createHmac('sha256', k).update(m).digest();
  const storedKey = crypto.createHash('sha256').update(hmac(salted, 'Client Key')).digest();
  const serverKey = hmac(salted, 'Server Key');
  return `SCRAM-SHA-256$${iterations}:${salt.toString('base64')}$${storedKey.toString('base64')}:${serverKey.toString('base64')}`;
}

async function adminClient() {
  const user = process.env.QODIQA_PG_ADMIN_USER; const password = process.env.QODIQA_PG_ADMIN_PASSWORD;
  if (!user || !password) { console.error('QODIQA_PG_ADMIN_USER and QODIQA_PG_ADMIN_PASSWORD are required for this action.'); process.exit(64); }
  const t = rc.targetFromEnv();
  const c = new Client({ host: t.host, port: t.port, database: t.database, ssl: t.ssl, user, password, application_name: 'qodiqa-role-credentials-tool' });
  c.on('error', () => {});
  await c.connect();
  return c;
}

async function main() {
  if (has('--check') || argv.length === 0) {
    const probe = await rc.probeMigrationRoles();
    for (const r of probe.results) console.log(`${r.result.padEnd(13)} ${r.role.padEnd(18)} migration ${r.migration}`);
    if (!probe.ok) { console.log(`\nVIOLATION: ${probe.violations.map((v) => v.role).join(', ')} accept the published placeholder password.`); process.exit(1); }
    if (!probe.proven) { console.log('\nNo violation, but some roles could not be probed from here — re-run from a host that can reach them.'); process.exit(2); }
    console.log('\nPROVEN: no migration-created role accepts its published placeholder.');
    return;
  }
  if (!has('--confirm')) { console.error('Refusing a mutating action without --confirm (roles are cluster-wide).'); process.exit(64); }
  if (has('--harden-unused')) {
    const c = await adminClient();
    try {
      for (const role of UNUSED) {
        const exists = (await c.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [role])).rowCount === 1;
        if (!exists) { console.log(`skip ${role} (absent)`); continue; }
        await c.query(`ALTER ROLE ${c.escapeIdentifier(role)} NOLOGIN`);
        console.log(`NOLOGIN ${role}`);
      }
    } finally { await c.end(); }
    return;
  }
  const role = val('--rotate');
  if (role) {
    if (!rc.MIGRATION_LOGIN_ROLES.some((r) => r.role === role)) { console.error(`${role} is not a migration-created role.`); process.exit(64); }
    const envName = val('--password-env');
    const secret = envName ? process.env[envName] : undefined;
    if (!secret) { console.error('--password-env <VAR> must name an environment variable holding the new password.'); process.exit(64); }
    const { secretProblems } = require('../../src/infra/config/credentialRules');
    const probs = secretProblems(secret, { minLength: 24 });
    if (probs.length) { console.error(`Refusing: the new password fails ${probs.join(', ')} (minimum 24 characters, not a placeholder).`); process.exit(65); }
    // Send a SCRAM-SHA-256 verifier, never the plaintext: a plaintext ALTER ROLE … PASSWORD can
    // land in the server log under log_statement=ddl/all (same approach as psql's \password).
    const c = await adminClient();
    try { await c.query(`ALTER ROLE ${c.escapeIdentifier(role)} PASSWORD ${c.escapeLiteral(scramVerifier(secret))}`); } finally { await c.end(); }
    console.log(`rotated ${role} (password not shown)`);
    return;
  }
  console.error('Unknown action. Use --check, --harden-unused --confirm, or --rotate <role> --password-env <VAR> --confirm.');
  process.exit(64);
}

if (require.main === module) main().catch((e) => { console.error(`role-credentials: ${e.code || ''} ${e.message}`); process.exit(70); });
module.exports = { scramVerifier };
