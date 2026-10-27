'use strict';

/**
 * File-based persistent component registry — single source of truth.
 *
 * backup.js, restore.js, and the DR test suite all resolve component paths
 * through this module so the list of what gets backed up can never drift
 * between the two directions of the DR cycle.
 *
 * Each component's path resolution matches EXACTLY the env var + default the
 * owning module itself uses (audit-log.js, keyStore.js, policyStore.js,
 * organizationRegistry.js, tenantRegistry.js) — verified against those files
 * directly, not guessed.
 */

const path = require('path');

const ROOT = path.join(__dirname, '..', '..');

function _resolve(envVar, defaultRelPath) {
  return process.env[envVar] || path.join(ROOT, defaultRelPath);
}

// `critical: true` means restore MUST fail closed if this component is
// missing from an otherwise-present backup. Organizations/tenants are
// best-effort caches (the owning modules keep in-memory state authoritative
// and treat the file as optional — see organizationRegistry.js's own
// "persistence is best-effort; in-memory state is authoritative" comment),
// so their absence is not fatal.
// `restorePath` is the FIXED, canonical location each component is written
// to under a restore target — independent of wherever the live source was
// actually found via its env var override. This matters because in any real
// deployment (see docs/operations/backup-runbook.md) these env vars commonly
// point OUTSIDE any project root entirely (e.g. QODIQA_AUDIT_LOG=/opt/qodiqa/
// logs/audit.log) — computing a restore path "relative to the source" would
// either escape the restore target (via ../.. segments) or reproduce an
// unrelated absolute path structure that means nothing on the restore host.
// A restored deployment is expected to set its own env vars pointing INTO
// the fresh restore target using this same canonical layout.
//
// — ARRAY ORDER IS THE COPY ORDER of a hot backup, and it is load-bearing. backup.js exports
// the PostgreSQL snapshot BEFORE the first file is read, then copies in this order, each later file being a superset
// of what the earlier ones reference (all are append-only or atomically replaced):
//   anchor export → witness log → witness position claims → PRQ journal → audit-log sidecars (checkpoints, base, .wal,
//   .sum) → audit log (prefix up to its last complete line) → key stores → legacy seed files.
// So: every anchor record's cosignature is in the witness log; every held/exported checkpoint is in the checkpoint
// sidecar; .sum describes a prefix of the copied log; every key that signed something copied earlier is in the copied
// key store; and the PostgreSQL mirror (taken first) lags the file — the normal dual-write state boot recovery
// already handles. `appendOnlyLines` files are copied as the prefix up to the last '\n' at the size seen when their
// copy starts (an in-flight append is not yet acknowledged). `kind: 'dir'` components are bundled (one archive).
//
// `critical` may be a function of the backup context ({ controlPlaneBackend }). In production the control
// plane is PostgreSQL (src/core/controlPlane/index.js resolveBackend): RBAC, signing identities, portal users,
// tenants, organizations and policies live in control_plane_records and come back with the database; their JSON files
// are one-time legacy seed inputs that a PostgreSQL-backed deployment never has.
//
// Deliberately NOT here (derived — rebuilt or re-derived, never restored as data):
//   <audit.log>.anchor-index.json byte-offset index, rebuilt at boot after a passing anchor check
//   <audit.log>.verify.json        verifier watermark; a missing one only widens re-verification (verifierState.js)
// Also NOT here, by design: the witness private key and the witness public-key trust set (QODIQA_WITNESS_KEY_PATH,
// QODIQA_WITNESS_PUBLIC_KEYS). They are deployment configuration provisioned outside the gateway — ideally by another
// party — and are restored from the secret store like the KEK and the TLS material (docs/operations/restore-runbook.md).
const memoryControlPlaneOnly = (ctx) => !!ctx && ctx.controlPlaneBackend === 'memory';

const FILE_COMPONENTS = [
  {
    // the anchor export (append-only JSONL of witnessed checkpoints). Without it a restored gateway cannot pass
    // the anchor boot check (ANCHOR_EXPORT_TRUNCATED) without a bootstrap. Configured only when anchoring is on.
    name: 'anchorExport',
    critical: false,
    appendOnlyLines: true,
    description: 'Audit anchor export — witnessed checkpoint records (QODIQA_ANCHOR_EXPORT_PATH)',
    resolve: () => process.env.QODIQA_ANCHOR_EXPORT_PATH || null,
    restorePath: path.join('anchors', 'anchors.jsonl'),
    companions: [],
  },
  {
    // the local witness's own log of everything it co-signed (rollback/equivocation memory).
    name: 'witnessLog',
    critical: false,
    appendOnlyLines: true,
    description: 'Local witness log — every statement it co-signed (QODIQA_WITNESS_LOG_PATH, local witness mode)',
    resolve: () => process.env.QODIQA_WITNESS_LOG_PATH || null,
    restorePath: path.join('anchors', 'witness-log.jsonl'),
    companions: [],
  },
  {
    // the witness's per-position claims (<log>.positions/<chainLength>), its atomic anti-equivocation record.
    name: 'witnessPositions',
    kind: 'dir',
    critical: false,
    description: 'Local witness position claims (<witness log>.positions/)',
    resolve: () => (process.env.QODIQA_WITNESS_LOG_PATH ? `${process.env.QODIQA_WITNESS_LOG_PATH}.positions` : null),
    restorePath: path.join('anchors', 'witness-log.jsonl.positions'),
    companions: [],
  },
  {
    // pending PostgreSQL writes journalled by the persistence-recovery queue; replayed at boot (idempotent).
    name: 'prqJournal',
    kind: 'dir',
    critical: false,
    description: 'Persistence-recovery journal — writes awaiting PostgreSQL (QODIQA_PRQ_JOURNAL_DIR)',
    resolve: () => _resolve('QODIQA_PRQ_JOURNAL_DIR', path.join('data', 'prq-journal')),
    restorePath: path.join('data', 'prq-journal'),
    companions: [],
  },
  {
    // NOT unconditionally critical here — auditLog is the
    // authoritative audit-chain source only in single-node/file-authoritative
    // mode. In distributed mode (QODIQA_DEPLOYMENT_MODE=distributed), the
    // authoritative chain lives in PostgreSQL's audit_chain table (the exact
    // table qodiqa_audit_chain_full_read()/loadChainFromPg() read — NOT the
    // differently-named platform_audit_events table, a separate table this
    // remediation initially and incorrectly targeted before being corrected)
    // (src/core/audit/audit-log.js's own ORDERING_MODE dispatch), and this
    // local file correctly never exists — a genuinely fresh distributed-mode
    // deployment has none, and backup.js correctly records it as
    // present:false, not an error. Making this component unconditionally
    // critical made restore.js structurally unable to ever complete for
    // distributed-mode backups.
    // Enforcement that audit evidence exists and is valid FROM THE MODE'S
    // OWN AUTHORITATIVE SOURCE now happens in restore.js's mode-aware
    // _verifyAuditEvidence() gate, driven by manifest.auditOrderingMode
    // (recorded at backup time by backup.js via
    // src/infra/config/deploymentMode.js's getResolvedDeploymentConfig() —
    // the exact same resolution server/startup.js's own boot log uses, not
    // re-derived or guessed here) — not by this generic per-file flag, which
    // now only means "if this file exists in the backup, checksum-validate
    // it on restore", same as every other non-critical file component.
    name: 'auditLog',
    critical: false,
    appendOnlyLines: true,
    description: 'Audit Chain — authoritative NDJSON hash chain in single-node mode (QODIQA-PROTOCOL-SPEC.md §11); superseded by PostgreSQL audit_chain table in distributed mode',
    resolve: () => _resolve('QODIQA_AUDIT_LOG', 'audit.log'),
    restorePath: 'audit.log',
    // companions are copied BEFORE the log itself, in this order (see the copy-order note above).
    companions: [
      { suffix: '.checkpoints.jsonl', name: 'auditLogCheckpoints', critical: false, appendOnlyLines: true, description: 'Audit Chain signed checkpoints', restorePath: 'audit.log.checkpoints.jsonl' },
      // step 6: after a retention prune the log starts at a signed checkpoint recorded here — without it
      // a restored log fails closed at boot (AUDIT_BASE_MISSING). dr:verify checks its signature offline.
      { suffix: '.base.json', name: 'auditLogBase', critical: false, description: 'Audit Chain signed base record', restorePath: 'audit.log.base.json' },
      // kept only when its batch continues the backed-up log prefix (backup.js _settleWal; restore.js re-checks)
      { suffix: '.wal', name: 'auditLogWal', critical: false, walOf: 'auditLog', description: 'Audit Chain write-ahead log (crash recovery)', restorePath: 'audit.log.wal' },
      // read whole into memory and required to parse (a non-atomic write fallback can expose an empty/zeroed file)
      { suffix: '.sum', name: 'auditLogSum', critical: false, jsonDocument: true, description: 'Audit Chain anti-deletion checksum', restorePath: 'audit.log.sum' },
    ],
  },
  {
    // step 6: the checkpoint signing key store — its public keys verify the base record and the
    // signed checkpoints (private key AES-256-GCM encrypted under the KEK, like keyStore). Resolved exactly as
    // src/core/audit/checkpoint/checkpointKeyStore.js resolves it.
    name: 'checkpointKeys',
    critical: false,
    description: 'Audit checkpoint signing key store — encrypted; its public keys verify the signed base record',
    resolve: () => process.env.QODIQA_CHECKPOINT_KEYS_PATH
      || (process.env.QODIQA_TRANSPARENCY_KEYS_PATH ? path.join(path.dirname(path.resolve(process.env.QODIQA_TRANSPARENCY_KEYS_PATH)), 'checkpoint-keys.json') : null)
      || path.join(ROOT, 'data', 'checkpoint-keys.json'),
    restorePath: path.join('data', 'checkpoint-keys.json'),
    companions: [],
  },
  {
    name: 'keyStore',
    critical: true,
    description: 'Encrypted signing key store — AES-256-GCM (safe to back up without the KEK)',
    resolve: () => _resolve('QODIQA_KEYS_PATH', path.join('data', 'keys.json')),
    restorePath: path.join('data', 'keys.json'),
    companions: [],
  },
  {
    name: 'keyArchive',
    critical: false,
    description: 'Retired / rotated key archive',
    resolve: () => _resolve('QODIQA_KEYS_ARCHIVE_PATH', path.join('data', 'key-archive.json')),
    restorePath: path.join('data', 'key-archive.json'),
    companions: [],
  },
  {
    // transparency signing key store (signs transparency roots; KEK-encrypted private keys). Also the anchor
    // the checkpoint key store's default path is derived from.
    name: 'transparencyKeys',
    critical: false,
    description: 'Transparency signing key store — encrypted (QODIQA_TRANSPARENCY_KEYS_PATH)',
    resolve: () => _resolve('QODIQA_TRANSPARENCY_KEYS_PATH', path.join('data', 'transparency-keys.json')),
    restorePath: path.join('data', 'transparency-keys.json'),
    companions: [],
  },
  {
    // the key-record MAC keyring that seals the key stores (OA-RC-2). A production boot refuses sealed key
    // stores it cannot authenticate, so a restore without it cannot start. Resolved exactly as macKeyring.js does.
    name: 'macKeys',
    critical: false,
    description: 'Key-record MAC keyring — authenticates the sealed key stores (QODIQA_MAC_KEYS_PATH)',
    resolve: () => process.env.QODIQA_MAC_KEYS_PATH
      || path.join(path.dirname(_resolve('QODIQA_KEYS_PATH', path.join('data', 'keys.json'))), 'mac-keys.json'),
    restorePath: path.join('data', 'mac-keys.json'),
    companions: [],
  },
  {
    name: 'policyStore',
    // required only where the file IS the store (memory control plane). In production the policies live in
    // PostgreSQL (control_plane_records) and this file is a legacy seed that never exists — requiring it made every
    // production backup unrestorable (REQUIRED_COMPONENT_MISSING).
    critical: memoryControlPlaneOnly,
    description: 'Policy Engine version history',
    // INJ-3/#283: this previously read QODIQA_POLICY_STORE_PATH — the env
    // var the now-removed, dead policy/policyStore.js module used. The live
    // policy store (src/core/policy/store.js, actually mounted in the
    // request path) reads QODIQA_POLICY_STORE instead. Both defaulted to the
    // same file (data/policy-store.json), so this only mattered for a
    // deployment that had customized the path via env var — in which case DR
    // backup/restore was silently operating on the wrong file relative to
    // what the live store actually reads/writes.
    resolve: () => _resolve('QODIQA_POLICY_STORE', path.join('data', 'policy-store.json')),
    restorePath: path.join('data', 'policy-store.json'),
    companions: [],
  },
  {
    name: 'organizations',
    critical: false,
    description: 'Organization registry (best-effort cache — in-memory state is authoritative)',
    resolve: () => _resolve('ORG_STORE_PATH', path.join('data', 'organizations.json')),
    restorePath: path.join('data', 'organizations.json'),
    companions: [],
  },
  {
    name: 'tenants',
    critical: false,
    description: 'Tenant registry (best-effort cache — in-memory state is authoritative)',
    resolve: () => _resolve('TENANT_STORE_PATH', path.join('data', 'tenants.json')),
    restorePath: path.join('data', 'tenants.json'),
    companions: [],
  },
];

/** Whether a component is required for this backup context. */
function isRequired(comp, ctx) {
  return typeof comp.critical === 'function' ? !!comp.critical(ctx) : !!comp.critical;
}

module.exports = { FILE_COMPONENTS, ROOT, isRequired };
