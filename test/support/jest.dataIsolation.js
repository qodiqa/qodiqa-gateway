'use strict';

// ── test isolation from the real data/ directory ──────────────────
//
// Two parts, both running before any test file requires application code:
//
// 1. STORE ISOLATION. Every file-backed store whose default path is under the
//    repository's data/ directory is pointed at a per-test-file temp dir,
//    unless the caller (or the test file itself, later) sets its own path.
//    Before this, a plain `npm run test:unit` rewrote the real
//    data/organizations.json and data/tenants.json (their
//    sha256 changed on every run). Store → env var → default it replaces:
//      organizations  ORG_STORE_PATH                      data/organizations.json
//      tenants        TENANT_STORE_PATH                   data/tenants.json
//      RBAC users     QODIQA_RBAC_STORE_PATH              data/rbac-users.json
//      RBAC roles     QODIQA_RBAC_CUSTOM_ROLE_STORE_PATH  data/rbac-custom-roles.json
//      portal users   QODIQA_PORTAL_USER_STORE_PATH       data/tenant-portal-users.json
//      policy store   QODIQA_POLICY_STORE                 data/policy-store.json
//    (Key stores and the audit log are already isolated in test/support/jest.setup.js.)
//    QODIQA_TEST_STORE_ISOLATION=off disables this part only — used once, to
//    enumerate the tests that write to data/.
//
// 2. WRITE GUARD. fs / fs.promises write-type calls whose target resolves
//    inside <repo>/data/ are
//    refused with code EQODIQA_DATA_WRITE and recorded. A refusal alone could
//    be swallowed by code under test, so test/support/jest.dataIsolation.afterEnv.js fails
//    the test (afterEach/afterAll) whenever a refusal was recorded. Reads are
//    never affected. Core modules are shared across test files in a worker, so
//    fs is patched once per worker and only the per-file recorder is swapped.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { fileURLToPath } = require('url');

const REPO = path.resolve(__dirname, '..', '..');
const STORES = {
  ORG_STORE_PATH: 'organizations.json',
  TENANT_STORE_PATH: 'tenants.json',
  QODIQA_RBAC_STORE_PATH: 'rbac-users.json',
  QODIQA_RBAC_CUSTOM_ROLE_STORE_PATH: 'rbac-custom-roles.json',
  QODIQA_PORTAL_USER_STORE_PATH: 'tenant-portal-users.json',
  QODIQA_POLICY_STORE: 'policy-store.json',
};

if (process.env.QODIQA_TEST_STORE_ISOLATION !== 'off') {
  const unset = Object.keys(STORES).filter((k) => !process.env[k]);
  if (unset.length) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-test-stores-'));
    for (const k of unset) process.env[k] = path.join(dir, STORES[k]);
  }
}

// ── write guard ──────────────────────────────────────────────────────────────
const SYM = Symbol.for('qodiqa.w1.dataWriteGuard');
const norm = (p) => { const r = path.resolve(p); return process.platform === 'win32' ? r.toLowerCase() : r; };
const DATA_DIR = norm(path.join(REPO, 'data'));
const PROTECTED_FILES = new Set([norm(path.join(REPO, 'policies.json'))]);

function toPath(arg) {
  if (typeof arg === 'string') return arg;
  if (Buffer.isBuffer(arg)) return arg.toString();
  if (arg instanceof URL) return fileURLToPath(arg);
  return null; // file descriptor or unsupported — not a path write
}
function isProtected(arg) {
  const p = toPath(arg);
  if (p === null) return false;
  const n = norm(p);
  return n === DATA_DIR || n.startsWith(DATA_DIR + path.sep) || PROTECTED_FILES.has(n);
}
const WRITE_FLAGS = /[wa+]/;
function openWrites(flags) {
  if (flags === undefined || flags === null) return false;
  if (typeof flags === 'number') return (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_APPEND | fs.constants.O_TRUNC)) !== 0;
  return WRITE_FLAGS.test(String(flags));
}

if (!fs[SYM]) {
  const state = { sink: [] };
  Object.defineProperty(fs, SYM, { value: state, enumerable: false });
  const refuse = (op, target) => {
    const e = new Error(`data/ write guard: ${op} → ${toPath(target)} refused (tests must not write under data/)`);
    e.code = 'EQODIQA_DATA_WRITE';
    state.sink.push({ op, target: toPath(target) });
    return e;
  };
  // [name, index of the path argument checked, predicate on the args]
  const SINGLE = ['writeFile', 'appendFile', 'truncate', 'mkdir', 'rm', 'rmdir', 'unlink', 'mkdtemp', 'utimes', 'chmod'];
  const DOUBLE = ['rename', 'copyFile', 'cp', 'symlink', 'link']; // destination = 2nd argument
  const origExists = fs.existsSync;
  const targetOf = (name, args) => {
    // mkdir of a directory that already exists changes nothing on disk
    // (recursive mkdir is a no-op there) — not a write.
    if (name === 'mkdir') return isProtected(args[0]) && !origExists(toPath(args[0])) ? args[0] : null;
    if (SINGLE.includes(name)) return isProtected(args[0]) ? args[0] : null;
    if (DOUBLE.includes(name)) return isProtected(args[1]) ? args[1] : null;
    if (name === 'open') return isProtected(args[0]) && openWrites(args[1]) ? args[0] : null;
    if (name === 'createWriteStream') return isProtected(args[0]) ? args[0] : null;
    return null;
  };
  const names = [...SINGLE, ...DOUBLE, 'open'];
  for (const name of names) {
    // callback form
    if (typeof fs[name] === 'function') {
      const orig = fs[name];
      fs[name] = function guarded(...args) {
        const t = targetOf(name, args);
        if (t !== null) {
          const err = refuse(name, t);
          const cb = args.reverse().find((a) => typeof a === 'function');
          if (cb) { process.nextTick(cb, err); return undefined; }
          throw err;
        }
        return orig.apply(this, args);
      };
    }
    // sync form
    const syncName = `${name}Sync`;
    if (typeof fs[syncName] === 'function') {
      const orig = fs[syncName];
      fs[syncName] = function guardedSync(...args) {
        const t = targetOf(name, args);
        if (t !== null) throw refuse(syncName, t);
        return orig.apply(this, args);
      };
    }
    // promise form (fs.promises === require('fs/promises'))
    if (fs.promises && typeof fs.promises[name] === 'function') {
      const orig = fs.promises[name];
      fs.promises[name] = function guardedPromise(...args) {
        const t = targetOf(name, args);
        if (t !== null) return Promise.reject(refuse(`promises.${name}`, t));
        return orig.apply(this, args);
      };
    }
  }
  const origCWS = fs.createWriteStream;
  fs.createWriteStream = function guardedCWS(...args) {
    if (targetOf('createWriteStream', args) !== null) throw refuse('createWriteStream', args[0]);
    return origCWS.apply(this, args);
  };
}
// Fresh recorder for this test file (the patched fs is shared by the worker).
fs[SYM].sink = [];
global.__qodiqaDataWriteGuard = {
  drain: () => fs[SYM].sink.splice(0),
  dataDir: path.join(REPO, 'data'),
};
