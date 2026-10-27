'use strict';

/**
 * QODIQA Ed25519 key store — one reviewed implementation, several independent trust domains.
 *
 * step 6 (design decision M1 = (a), 2026-09-30): the transparency key store's logic, unchanged, behind a builder,
 * so the audit-checkpoint signing key can be a SECOND, fully separate store (own file, own purpose tag, own key ids,
 * same KEK encryption and rotation lifecycle) without duplicating ~650 lines of security-critical code.
 * src/core/transparency/transparencyKeyStore.js is a thin singleton over createEd25519KeyStore() with its exports,
 * file format, event names and error texts unchanged; src/core/audit/checkpoint/checkpointKeyStore.js is the second
 * instance.
 *
 * Each instance:
 *   KEY FORMAT:   <clientId>:key_vN                 (clientId from opts.resolveClientId())
 *   FILE PATH:    opts.dataPath (resolved once, at creation — as the original module did at load)
 *   ENCRYPTION:   AES-256-GCM via QODIQA_KEY_ENCRYPTION_KEY (same KEK, separate file), KEK-fingerprint guard rail
 *   PURPOSE TAG:  every record carries purpose: opts.purpose
 * LIFECYCLE: active → deprecated → revoked; exactly one active key; rotateKey() defaults to 'emergency'
 * BOOTSTRAP: lazy, on first use
 *
 * Instances share NOTHING: separate state, separate file, and a keyId that exists in one store is unknown to the other.
 *
 * — the artifact store's controls, ported:
 *   (i)   PLAINTEXT: a legacy plaintext `privateKeyDer` is loaded ONLY for immediate re-encryption, exactly like
 *         services/artifact/keyStore.js: bootstrap re-saves the file encrypted, re-scans it, and aborts (CRITICAL
 *         <E>_MIGRATION_INCOMPLETE) if any plaintext remains; validateKeyStore() reports any plaintext found on disk
 *         as a PLAINTEXT_<V>_KEY violation (startup treats every violation as FATAL — the artifact store's
 *         validateStartup() step 0). reloadFromDisk() never adopts a plaintext file (it is refused, store kept).
 *   (ii)  MODE: an explicit but unrecognised rotation mode throws (it used to silently mean 'emergency'). An OMITTED
 * mode still means 'emergency' ('s documented default — the fail-safe outcome: the outgoing key is
 *         revoked), and the events now carry modeDefaulted:true so that choice is visible.
 * (iii) ZEROIZATION: the outgoing key's private bytes are zeroed on rotate and revoke.
 *   (iv)  OWNERSHIP: every file entry must be self-consistent — map key === entry.keyId === `${clientId}:key_v${version}`,
 *         and entry.purpose (when present) === this store's purpose — or the load is FATAL.
 * (v) RELOAD: reloadFromDisk() re-reads the file (fail-closed: the live store is kept on any failure) and
 * never un-revokes a key; every mutation first re-loads a file another writer changed.
 * a revoked record carries revokedAt (ISO time of the transition), persisted and reloaded; files written
 *         before this field load with revokedAt: null.
 *
 * K1 — AUTHENTICATED RECORDS (src/infra/crypto/keyRecordSeal.js):
 *   every save writes payload.recordSeal and a per-record recordMac = HMAC(HKDF(KEK), canonical public fields +
 *   trust domain + encrypted-blob digest), and encrypts the active private key with AES-GCM AAD = record identity.
 *   LOAD: a sealed file whose records do not all carry a valid MAC is REFUSED (CRITICAL <E>_RECORD_MAC_REFUSED; FATAL
 *   at bootstrap, store kept at reload). A legacy (unsealed) file is sealed ONCE at bootstrap (trust on first use,
 *   WARN <E>_RECORDS_SEALED) — never at reload once this instance has seen a sealed file, and never when
 *   QODIQA_KEYSTORE_REQUIRE_SEALED=true. validateKeyStore() reports an unsealed or unauthenticated file on disk as a
 *   violation (startup FATAL). Legacy AAD-less ciphertexts still decrypt; a sealed file must carry AAD-bound ones.
 */

const crypto = require('crypto');
const fs     = require('fs');
const { sign: ed25519Sign, verify: ed25519Verify } = require('../../infra/crypto/ed25519');
const { encryptKeyMaterial, decryptKeyMaterial,
        computeKekFingerprint, assertKekFingerprint, deriveKekSubkey } = require('../../../services/artifact/keyEncryption');
const seal = require('../../infra/crypto/keyRecordSeal');
const { emit } = require('../../../services/logger');
const { writeFileAtomicSecure } = require('../../infra/fs/secureWrite');

const FILE_VERSION        = 1;
const ROTATION_DAYS       = 90;
const EXPIRY_DAYS         = 180;
const EXPIRY_WARNING_DAYS = 30;
const KEY_ID_RE = /^[A-Za-z0-9_-]{1,64}:key_v\d+$/;
const VALID_ROTATION_MODES = new Set(['graceful', 'emergency']);
// K1: the operator-run rotation path for these stores — named in expiry findings and errors.
function rotateCommand(store) {
  return `node scripts/keys/rotate-offline.js --store ${store} --mode graceful --operator <id> --reason "<text>" --confirm-offline-recovery`;
}

/**
 * @param {object}   o
 * @param {string}   o.dataPath         key file
 * @param {string}   o.purpose          record purpose tag ('transparency' | 'audit-checkpoint' | …)
 * @param {function} o.resolveClientId  () => clientId for new keys
 * @param {string}   o.storeName        error-message prefix, e.g. 'TransparencyKeyStore'
 * @param {string}   o.noun             lower-case noun in messages, e.g. 'transparency'
 * @param {string}   o.title            capitalised noun, e.g. 'Transparency'
 * @param {string}   o.eventPrefix      event-type prefix, e.g. 'TRANSPARENCY_KEY' (…_CREATED, …_ROTATED, …)
 * @param {string}   o.storeEvent       loaded-event name, e.g. 'TRANSPARENCY_KEYSTORE_LOADED'
 * @param {string}   o.violationNoun    upper-case noun in violation types, e.g. 'TRANSPARENCY'
 * @param {string}   [o.cliStore]       store name used in the rotate CLI command (defaults to o.noun)
 * @param {'emergency'|'graceful'} [o.defaultRotationMode='emergency'] what rotateKey() does when no mode is given. 
 *                                      the TRANSPARENCY store uses 'graceful' — a routine rotation keeps every entry and root signed by
 *                                      the outgoing key verifiable (it stops signing). 'emergency' (revoke) must now be asked for
 *                                      explicitly; it is the compromise response and deliberately distrusts the outgoing key.
 */
function createEd25519KeyStore(o) {
  const DATA_PATH = o.dataPath;
  const KEY_PURPOSE = o.purpose;
  // these stores may have a KEK of their own (QODIQA_TRANSPARENCY_KEY_ENCRYPTION_KEY / QODIQA_CHECKPOINT_KEY_ENCRYPTION_KEY)
  const KEK_SCOPE = (o.purpose === 'transparency' || o.purpose === 'audit-checkpoint') ? o.purpose : null;
  const N = o.noun; const T = o.title; const S = o.storeName; const E = o.eventPrefix; const V = o.violationNoun;
  const ROTATE_CMD = rotateCommand(o.cliStore || N);
  const DEFAULT_MODE = o.defaultRotationMode === 'graceful' ? 'graceful' : 'emergency';

  function _addDays(isoDate, n) { const d = new Date(isoDate); d.setUTCDate(d.getUTCDate() + n); return d.toISOString(); }
  function _computeLifecycle(createdAt) {
    const base = createdAt || new Date().toISOString();
    return { rotationDeadline: _addDays(base, ROTATION_DAYS), expiresAt: _addDays(base, EXPIRY_DAYS) };
  }
  function _isExpired(rec) { if (!rec || !rec.expiresAt) return false; return new Date(rec.expiresAt) <= new Date(); }
  function _sha256(str) { return crypto.createHash('sha256').update(str, 'utf8').digest('hex'); }

  function _selfTest(privDer, pubDer) {
    const probe = crypto.createHash('sha256').update(`qodiqa-${N}-keystore-self-test`, 'utf8').digest();
    const sig = ed25519Sign(probe, privDer);
    if (!ed25519Verify(probe, sig, pubDer)) throw new Error(`FATAL: ${T} Ed25519 key self-test failed`);
  }

  // zero the private bytes of a record leaving 'active'. Object.freeze locks the
  // bindings, not a Buffer's bytes — same pattern as services/artifact/keyStore.js _zeroizePrivateKey().
  function _zeroizePrivateKey(rec) { if (rec && Buffer.isBuffer(rec._privDer)) rec._privDer.fill(0); }

  function _buildActiveRecord(privDer, pubDer, clientId, version, createdAt, lifecycle) {
    _selfTest(privDer, pubDer);
    const ts = createdAt || new Date().toISOString();
    const lc = (lifecycle && lifecycle.rotationDeadline && lifecycle.expiresAt) ? lifecycle : _computeLifecycle(ts);
    return Object.freeze({
      _privDer: privDer, publicKeyDer: pubDer, publicKeyB64: pubDer.toString('base64'), status: 'active', purpose: KEY_PURPOSE,
      createdAt: ts, clientId, keyId: `${clientId}:key_v${version}`, version, algorithm: 'ed25519',
      rotationDeadline: lc.rotationDeadline, expiresAt: lc.expiresAt,
    });
  }
  function _buildDeprecatedRecord(pubDer, clientId, version, createdAt, retiredAt) {
    const buf = Buffer.isBuffer(pubDer) ? pubDer : Buffer.from(pubDer);
    return Object.freeze({
      publicKeyDer: buf, publicKeyB64: buf.toString('base64'), status: 'deprecated', purpose: KEY_PURPOSE,
      createdAt: createdAt || new Date().toISOString(), retiredAt: retiredAt || null, clientId, keyId: `${clientId}:key_v${version}`, version, algorithm: 'ed25519',
    });
  }
  // revokedAt — undefined = "this is the transition, stamp now"; null = unknown (file predates the field).
  function _buildRevokedRecord(pubDer, clientId, version, createdAt, revokedAt) {
    const buf = Buffer.isBuffer(pubDer) ? pubDer : Buffer.from(pubDer);
    return Object.freeze({
      publicKeyDer: buf, publicKeyB64: buf.toString('base64'), status: 'revoked', purpose: KEY_PURPOSE,
      createdAt: createdAt || new Date().toISOString(), clientId, keyId: `${clientId}:key_v${version}`, version, algorithm: 'ed25519',
      revokedAt: revokedAt === undefined ? new Date().toISOString() : revokedAt,
    });
  }
  function _generateRecord(clientId, version) {
    const { privateKey: priv, publicKey: pub } = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' }, privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    });
    const createdAt = new Date().toISOString();
    return _buildActiveRecord(Buffer.from(priv), Buffer.from(pub), clientId, version, createdAt, _computeLifecycle(createdAt));
  }
  function _nextVersion(store) { let max = 0; for (const rec of Object.values(store)) if (rec.version > max) max = rec.version; return max + 1; }

  // ── Persistence (atomic: .tmp then rename) ─────────────────────────────────
  function _macKey() { return deriveKekSubkey(seal.RECORD_MAC_INFO, KEK_SCOPE); }
  function _aadFor(ids) { return { aad: seal.recordAad(KEY_PURPOSE, ids), aadLabel: seal.AAD_LABEL }; }

  function _saveKeys() {
    const payload = { version: FILE_VERSION, kekFingerprint: computeKekFingerprint(KEK_SCOPE), recordSeal: seal.SEAL_DESCRIPTOR, keys: {} };
    const macKey = _macKey();
    for (const [keyId, rec] of Object.entries(_store)) {
      let encryptedEntry = {};
      if (rec.status === 'active' && rec._privDer) {
        // K1: AAD-bound to the record identity.
        encryptedEntry = { encryptedPrivateKeyDer: encryptKeyMaterial(rec._privDer, { keyId: rec.keyId, createdAt: rec.createdAt, scope: KEK_SCOPE,
          ..._aadFor({ keyId: rec.keyId, clientId: rec.clientId, version: rec.version, publicKeyDer: rec.publicKeyDer }) }) };
      }
      /** @type {Record<string, any>} */
      const entry = {
        clientId: rec.clientId, keyId: rec.keyId, version: rec.version, algorithm: rec.algorithm, purpose: KEY_PURPOSE,
        publicKeyDer: rec.publicKeyDer.toString('base64'), status: rec.status, createdAt: rec.createdAt,
        retiredAt: rec.retiredAt || null, rotationDeadline: rec.rotationDeadline || null, expiresAt: rec.expiresAt || null,
        ...(rec.status === 'revoked' ? { revokedAt: rec.revokedAt || null } : {}), //
        ...encryptedEntry,
      };
      entry.recordMac = seal.computeRecordMac(macKey, KEY_PURPOSE, entry, { mapKey: keyId }); // K1
      payload.keys[keyId] = entry;
    }
    ///-15: 0600, fsync, unique temp name, rename.
    const serialized = JSON.stringify(payload, null, 2);
    writeFileAtomicSecure(DATA_PATH, serialized);
    _lastFileHash = _sha256(serialized);
    _sealedSeen = true;
  }

  // K1: refuse an unauthenticated file — CRITICAL event, coded error. Callers decide FATAL (bootstrap) vs keep (reload).
  function _refuseUnauthenticated(kind, detail) {
    emit('CRITICAL', `${E}_RECORD_MAC_REFUSED`, { purpose: KEY_PURPOSE, file: DATA_PATH, kind, ...detail,
      message: `${DATA_PATH}: ${kind === 'unsealed' ? 'unsealed (unauthenticated) key file refused' : 'key record(s) with a missing or invalid MAC refused'} — the file was written without the KEK, or tampered with.` });
    /** @type {any} */ const e = new Error(`${S}: ${DATA_PATH} — ${kind === 'unsealed'
      ? `key file is not sealed (no record MACs) and ${detail.why}`
      : `record MAC ${detail.failures.map((f) => `${f.reason} for "${f.keyId}"`).join(', ')}`} — refusing unauthenticated key metadata`);
    e.code = 'KEYSTORE_RECORD_UNAUTHENTICATED';
    return e;
  }

  // K1: seal state of a parsed file. { sealed, failures } — throws on an unknown marker or a missing KEK.
  function _sealState(data) {
    const sealed = seal.isSealedFile(data);
    if (!sealed) return { sealed: false, failures: [] };
    const records = Object.entries(data.keys).map(([mapKey, entry]) => ({ entry, mapKey }));
    return { sealed: true, failures: seal.checkRecords(_macKey(), KEY_PURPOSE, records) };
  }

  // (i): entries on disk still carrying a plaintext private key — mirrors keyStore._scanFileForPlaintext().
  // [] when the file is absent or unparseable (the loader reports those).
  function _scanFileForPlaintext() {
    if (!fs.existsSync(DATA_PATH)) return [];
    let data;
    try { data = JSON.parse(fs.readFileSync(DATA_PATH, 'utf8')); } catch { return []; }
    const found = [];
    for (const [keyId, entry] of Object.entries((data && data.keys) || {})) {
      if (entry && entry.privateKeyDer) found.push({ keyId });
    }
    return found;
  }

  // opts.allowTofu: whether an unsealed (legacy) file may be accepted for one-time sealing (K1).
  function _tryLoadFromFile(opts = {}) {
    if (!fs.existsSync(DATA_PATH)) return null;
    let raw; let data;
    try { raw = fs.readFileSync(DATA_PATH, 'utf8'); data = JSON.parse(raw); } catch (err) { throw new Error(`${S}: ${DATA_PATH} is corrupted: ${err.message}`); }
    if (!data || typeof data !== 'object' || data.version !== FILE_VERSION) {
      throw new Error(`${S}: ${DATA_PATH} has unsupported format (expected version ${FILE_VERSION})`);
    }
    if (!data.keys || typeof data.keys !== 'object') throw new Error(`${S}: ${DATA_PATH} is missing "keys" field`);
    assertKekFingerprint(data.kekFingerprint, DATA_PATH, KEK_SCOPE);
    const kekFingerprintMigrationNeeded = !data.kekFingerprint;
    // K1: is the file sealed? (KEK-free; an unknown marker throws.) The records are authenticated after the
    // structural checks below and BEFORE anything is returned — nothing from an unauthenticated file is ever adopted.
    const st = { sealed: seal.isSealedFile(data) };
    let plaintextMigrationNeeded = false;
    const store = {};
    for (const [keyId, entry] of Object.entries(data.keys)) {
      if (!KEY_ID_RE.test(keyId)) throw new Error(`${S}: invalid keyId "${keyId}" in ${DATA_PATH}`);
      if (!entry || typeof entry !== 'object') throw new Error(`${S}: invalid entry for key "${keyId}" in ${DATA_PATH}`);
      if (!['active', 'deprecated', 'revoked'].includes(entry.status)) throw new Error(`${S}: invalid status "${entry.status}" for key "${keyId}"`);
      // (iv): ownership / identity — the map key, the recorded keyId and the clientId:key_v<version> the
      // record would be rebuilt under must all agree, and a record of another trust domain is never adopted.
      const derived = `${entry.clientId}:key_v${entry.version}`;
      if (!Number.isInteger(entry.version) || entry.version < 1 || derived !== keyId || (entry.keyId !== undefined && entry.keyId !== keyId)) {
        throw new Error(`${S}: key "${keyId}" in ${DATA_PATH} is not self-consistent (keyId ${JSON.stringify(entry.keyId)}, clientId ${JSON.stringify(entry.clientId)}, version ${JSON.stringify(entry.version)}) — ownership check failed`);
      }
      if (entry.purpose !== undefined && entry.purpose !== KEY_PURPOSE) {
        throw new Error(`${S}: key "${keyId}" in ${DATA_PATH} has purpose "${entry.purpose}", expected "${KEY_PURPOSE}" — refusing a key of another trust domain`);
      }
      if (entry.privateKeyDer) plaintextMigrationNeeded = true; // re-saved encrypted (active) or stripped (other statuses)
      const pubDer = Buffer.from(entry.publicKeyDer, 'base64');
      if (entry.status === 'active') {
        let privDer;
        if (entry.encryptedPrivateKeyDer) {
          // K1: a sealed file only ever carries AAD-bound ciphertexts; a legacy file may carry AAD-less ones.
          if (st.sealed && entry.encryptedPrivateKeyDer.aad !== seal.AAD_LABEL) throw new Error(`${S}: active key "${keyId}" in sealed ${DATA_PATH} has a ciphertext without the record AAD binding`);
          privDer = decryptKeyMaterial(entry.encryptedPrivateKeyDer,
            entry.encryptedPrivateKeyDer.aad !== undefined ? { ..._aadFor({ keyId, clientId: entry.clientId, version: entry.version, publicKeyDer: entry.publicKeyDer }), scope: KEK_SCOPE } : { scope: KEK_SCOPE });
        }
        else if (entry.privateKeyDer) privDer = Buffer.from(entry.privateKeyDer, 'base64'); // legacy plaintext — loaded for immediate re-encryption
        else throw new Error(`${S}: active key "${keyId}" has no private key material`);
        store[keyId] = _buildActiveRecord(privDer, pubDer, entry.clientId, entry.version, entry.createdAt,
          { rotationDeadline: entry.rotationDeadline || null, expiresAt: entry.expiresAt || null });
      } else if (entry.status === 'deprecated') {
        store[keyId] = _buildDeprecatedRecord(pubDer, entry.clientId, entry.version, entry.createdAt, entry.retiredAt || null);
      } else {
        if (entry.revokedAt != null && isNaN(new Date(entry.revokedAt).getTime())) {
          throw new Error(`${S}: key "${keyId}" in ${DATA_PATH} has an unparseable revokedAt`);
        }
        store[keyId] = _buildRevokedRecord(pubDer, entry.clientId, entry.version, entry.createdAt, entry.revokedAt ?? null);
      }
    }
    // K1: record authentication — a sealed file must be authentic record by record; an unsealed (legacy) one
    // is accepted only for the one-time seal migration.
    let sealMigrationNeeded = false;
    if (st.sealed) {
      const failures = _sealState(data).failures;
      if (failures.length > 0) throw _refuseUnauthenticated('mac', { failures });
    } else if (Object.keys(data.keys).length > 0) {
      if (seal.sealRequired()) throw _refuseUnauthenticated('unsealed', { why: 'QODIQA_KEYSTORE_REQUIRE_SEALED=true forbids the one-time seal migration' });
      if (!opts.allowTofu) throw _refuseUnauthenticated('unsealed', { why: 'this instance already holds a sealed store (a sealed file is never downgraded at reload)' });
      sealMigrationNeeded = true;
    }
    return { store, kekFingerprintMigrationNeeded, plaintextMigrationNeeded, sealMigrationNeeded, sealed: st.sealed, fileHash: _sha256(raw) };
  }

  // ── In-memory store ───────────────────────────────
  let _store = {};
  let _bootstrapped = false;
  let _lastFileHash = null; // sha256 of the file bytes this instance last loaded or wrote
  let _sealedSeen = false;  // K1: this instance has loaded or written a sealed file — no unsealed file is accepted after
  function _ensureBootstrapped() {
    if (_bootstrapped) return;
    let loaded = null;
    try { loaded = _tryLoadFromFile({ allowTofu: !_sealedSeen }); } catch (err) { throw new Error(`${S}: FATAL — ${err.message}`); }
    if (loaded) { _store = loaded.store; _lastFileHash = loaded.fileHash; if (loaded.sealed) _sealedSeen = true; }
    if (loaded && loaded.plaintextMigrationNeeded) {
      // (i) — mirrors services/artifact/keyStore.js _ensureBootstrapped(): re-encrypt, re-scan, fail closed.
      emit('INFO', `${E}_MIGRATION_STARTED`, { plaintextKeys: true,
        message: `${DATA_PATH} holds a plaintext ${N} private key — re-encrypting with AES-256-GCM. Startup aborts if this fails.` });
      try { _saveKeys(); } catch (err) {
        emit('CRITICAL', `${E}_MIGRATION_FAILED`, { message: `${T} key migration failed — startup aborted: ${err.message}` });
        throw err;
      }
      const residual = _scanFileForPlaintext();
      if (residual.length > 0) {
        emit('CRITICAL', `${E}_MIGRATION_INCOMPLETE`, { message: `CRITICAL: Unencrypted ${N} private key detected after migration. Startup aborted.`, affectedKeys: residual.map((r) => r.keyId) });
        throw new Error(`CRITICAL: Unencrypted ${N} private key detected after migration attempt. Startup aborted. Keys still plaintext: ${residual.map((r) => r.keyId).join(', ')}`);
      }
      emit('INFO', `${E}_MIGRATION_COMPLETED`, { message: `All ${N} keys are now encrypted at rest.` });
    }
    const active = Object.values(_store).filter((r) => r.status === 'active').length;
    emit('INFO', o.storeEvent, { keys: Object.keys(_store).length, active,
      ...(loaded ? {} : { message: `No ${N} key file found — provision via rotateKey()` }) });
    _bootstrapped = true;
    if (loaded && loaded.kekFingerprintMigrationNeeded && !loaded.plaintextMigrationNeeded) {
      _saveKeys();
      emit('INFO', `${E}_FINGERPRINT_BACKFILLED`, { message: `${DATA_PATH} predated the KEK-fingerprint guard rail — backfilled on load.` });
    }
    if (loaded && loaded.sealMigrationNeeded) {
      // K1: one-time trust-on-first-use seal of a legacy file (skipped when a migration save above already sealed it).
      if (!_sealedSeen) _saveKeys();
      emit('WARN', `${E}_RECORDS_SEALED`, { purpose: KEY_PURPOSE, keys: Object.keys(_store).length, tofu: true,
        message: `${DATA_PATH} predated authenticated key records — sealed once on load (trust on first use). From now on an unsealed or tampered record is refused. Set QODIQA_KEYSTORE_REQUIRE_SEALED=true to forbid this migration.` });
    }
  }

  // ── Cross-instance reload (v; mirrors keyStore.reloadFromDisk()) ──
  // Fail-closed: on any read/parse/decrypt/ownership failure — or a plaintext key on disk — the live store is kept.
  // A key this instance knows to be revoked is never un-revoked (or dropped) by a reload. A store that has never
  // bootstrapped is left alone: its lazy bootstrap will read the current file (and run the migration) itself.
  function reloadFromDisk() {
    if (!_bootstrapped) return { reloaded: false, error: null, skipped: 'not-bootstrapped' };
    let fromFile;
    try {
      fromFile = _tryLoadFromFile({ allowTofu: !_sealedSeen });
      if (fromFile && fromFile.plaintextMigrationNeeded) {
        emit('CRITICAL', `${E}_PLAINTEXT_DETECTED`, { message: `Plaintext ${N} private key found on disk at reload — not adopted; restart to re-run the fail-closed migration.`, affectedKeys: _scanFileForPlaintext().map((r) => r.keyId) });
        throw new Error(`plaintext ${N} private key on disk`);
      }
    } catch (err) {
      emit('ERROR', `${E}STORE_RELOAD_FAILED`, { message: `Reload aborted — existing in-memory ${N} key store retained: ${err.message}`, error: err.message });
      return { reloaded: false, error: err.message };
    }
    if (!fromFile) return { reloaded: false, error: null };
    const prev = _store;
    const regressed = [];
    for (const [kid, p] of Object.entries(prev)) {
      if (!p || p.status !== 'revoked') continue;
      const next = fromFile.store[kid];
      if (next && next.status === 'revoked') continue;
      if (next) _zeroizePrivateKey(next);
      fromFile.store[kid] = _buildRevokedRecord(p.publicKeyDer, p.clientId, p.version, p.createdAt, p.revokedAt ?? null);
      regressed.push({ keyId: kid, onDiskStatus: next ? next.status : 'missing' });
    }
    _store = fromFile.store;
    _lastFileHash = fromFile.fileHash;
    if (fromFile.sealed) _sealedSeen = true;
    if (regressed.length > 0) {
      emit('CRITICAL', `${E}_REVOCATION_REGRESSION_DETECTED`, { keys: regressed, purpose: KEY_PURPOSE,
        message: `${DATA_PATH} no longer showed ${regressed.length} ${N} key(s) this instance knows to be revoked — they stay revoked; the store is re-persisted.` });
      try { _saveKeys(); } catch (err) { emit('ERROR', `${E}_REVOCATION_REGRESSION_REPAIR_FAILED`, { error: err.message }); }
    }
    const newlyRevoked = Object.values(_store).filter((r) => r.status === 'revoked' && prev[r.keyId] && prev[r.keyId].status !== 'revoked').map((r) => r.keyId);
    for (const keyId of newlyRevoked) emit('WARN', `${E}_REVOCATION_PROPAGATED`, { keyId, purpose: KEY_PURPOSE });
    const prevActive = Object.values(prev).find((r) => r.status === 'active') || null;
    const nowActive = Object.values(_store).find((r) => r.status === 'active') || null;
    const activeKeyChanged = !!(nowActive && (!prevActive || prevActive.keyId !== nowActive.keyId));
    if (activeKeyChanged) emit('INFO', `${E}_ACTIVE_KEY_CHANGED`, { keyId: nowActive.keyId, previousKeyId: prevActive ? prevActive.keyId : null, purpose: KEY_PURPOSE });
    const active = Object.values(_store).filter((r) => r.status === 'active').length;
    emit('INFO', `${E}STORE_RELOADED`, { keys: Object.keys(_store).length, active, revoked: newlyRevoked.length, activeKeyChanged });
    return { reloaded: true, keys: Object.keys(_store).length, active, revoked: newlyRevoked.length, activeKeyChanged };
  }

  // Reload-before-mutation: another instance (or an offline CLI) may have changed the file since
  // this instance last read or wrote it; mutating the stale in-memory view would erase that change. Strict: a changed
  // file that cannot be loaded refuses the mutation.
  function _refreshBeforeMutation() {
    let raw;
    try {
      if (!fs.existsSync(DATA_PATH)) return;
      raw = fs.readFileSync(DATA_PATH, 'utf8');
    } catch (err) {
      /** @type {any} */ const e = new Error(`${S}: cannot re-read ${DATA_PATH} before mutation — ${err.message}`); e.code = 'KEYSTORE_RELOAD_FAILED'; throw e;
    }
    if (_lastFileHash !== null && _sha256(raw) === _lastFileHash) return;
    const r = reloadFromDisk();
    if (!r.reloaded && r.error) {
      /** @type {any} */ const e = new Error(`${S}: ${DATA_PATH} changed on disk and could not be reloaded — mutation refused: ${r.error}`); e.code = 'KEYSTORE_RELOAD_FAILED'; throw e;
    }
  }

  // ── Public API ─────────────────────────────────────────────────────────────
  function getActiveKey() {
    _ensureBootstrapped();
    for (const rec of Object.values(_store)) {
      if (rec.status !== 'active') continue;
      if (_isExpired(rec)) {
        emit('WARN', `${E}_SIGNING_BLOCKED`, { keyId: rec.keyId, reason: 'expired', expiresAt: rec.expiresAt });
        throw new Error(`${E}_EXPIRED: key "${rec.keyId}" has expired (expiresAt: ${rec.expiresAt}) — rotate before signing: ${ROTATE_CMD}`);
      }
      return { keyId: rec.keyId, privDer: rec._privDer, pubDer: rec.publicKeyDer, version: rec.version };
    }
    throw new Error(`${S}: no active ${N} signing key — provision via rotateKey()`);
  }

  /**
   * @param {string} keyId
   * @param {{ trustedAt?: string|number|Date }} [o] (timed revocation): a time established by an authority INDEPENDENT of the record
   *   being verified (e.g. an externally anchored checkpoint). Only then may a revoked key with a known revokedAt still be returned,
   *   and only for trustedAt strictly before revokedAt. A record's own created_at is NOT such a time (it is not covered by the
   *   signature). Without trustedAt a revoked key always throws (default behaviour, unchanged).
   */
  function getPublicKey(keyId, o = {}) {
    _ensureBootstrapped();
    const rec = _store[keyId];
    if (!rec) throw new Error(`${S}: unknown ${N} keyId "${keyId}"`);
    if (rec.status === 'revoked') {
      const t = o && o.trustedAt != null ? new Date(o.trustedAt).getTime() : NaN;
      const r = rec.revokedAt ? new Date(rec.revokedAt).getTime() : NaN;
      if (Number.isFinite(t) && Number.isFinite(r) && t < r) {
        return { pubDer: rec.publicKeyDer, status: 'revoked', retiredAt: rec.retiredAt || null, revokedAt: rec.revokedAt, timedValidity: true };
      }
      throw new Error(`${S}: ${N} key "${keyId}" is revoked`);
    }
    return { pubDer: rec.publicKeyDer, status: rec.status, retiredAt: rec.retiredAt || null }; // retiredAt:
  }

  function getKeyStatus(keyId) { _ensureBootstrapped(); return _store[keyId]?.status ?? null; }

  function rotateKey(opts) {
    // (ii): an explicit mode must be a valid one — a typo no longer silently means 'emergency'.
    const requested = opts ? opts.mode : undefined;
    if (requested !== undefined && !VALID_ROTATION_MODES.has(requested)) {
      throw new TypeError(`${S}.rotateKey: opts.mode must be exactly 'graceful' or 'emergency' (or omitted for this store's default rotation mode) — got ${JSON.stringify(requested)}`);
    }
    _ensureBootstrapped();
    _refreshBeforeMutation();
    const clientId = o.resolveClientId();
    const activeEntries = Object.entries(_store).filter(([, rec]) => rec.status === 'active');
    if (activeEntries.length === 0) {
      const nextVersion = _nextVersion(_store) || 1;
      const rec = _generateRecord(clientId, nextVersion);
      _store[rec.keyId] = rec;
      _saveKeys();
      emit('INFO', `${E}_CREATED`, { keyId: rec.keyId, version: rec.version, purpose: KEY_PURPOSE, status: 'active' });
      return { keyId: rec.keyId, version: rec.version, previousKeyId: null, previousKeyStatus: null, mode: null };
    }
    if (activeEntries.length > 1) throw new Error(`${S}: invariant violation — ${activeEntries.length} active ${N} keys`);
    const [activeId, activeRec] = activeEntries[0];
    const nextVersion = activeRec.version + 1;
    const newRec = _generateRecord(clientId, nextVersion);
    const mode = (requested === undefined ? DEFAULT_MODE : requested) === 'graceful' ? 'graceful' : 'emergency';
    const modeDefaulted = requested === undefined;
    if (mode === 'graceful') {
      const retiredAt = new Date().toISOString();
      _store[activeId] = _buildDeprecatedRecord(activeRec.publicKeyDer, activeRec.clientId, activeRec.version, activeRec.createdAt, retiredAt);
      _store[newRec.keyId] = newRec;
      _zeroizePrivateKey(activeRec); //
      _saveKeys();
      emit('INFO', `${E}_RETIRED`, { keyId: activeId, version: activeRec.version, retiredAt, purpose: KEY_PURPOSE, mode });
    } else {
      const revoked = _buildRevokedRecord(activeRec.publicKeyDer, activeRec.clientId, activeRec.version, activeRec.createdAt);
      _store[activeId] = revoked;
      _store[newRec.keyId] = newRec;
      _zeroizePrivateKey(activeRec); //
      _saveKeys();
      emit('INFO', `${E}_REVOKED`, { keyId: activeId, version: activeRec.version, purpose: KEY_PURPOSE, revocationTrigger: 'ROTATION', mode, modeDefaulted, revokedAt: revoked.revokedAt });
    }
    emit('INFO', `${E}_ROTATED`, { keyId: newRec.keyId, version: nextVersion, purpose: KEY_PURPOSE, status: 'active', mode, ...(modeDefaulted ? { modeDefaulted } : {}) });
    return { keyId: newRec.keyId, version: nextVersion, previousKeyId: activeId, previousKeyStatus: mode === 'graceful' ? 'deprecated' : 'revoked', mode };
  }

  function rotateKeyGracefully() { return rotateKey({ mode: 'graceful' }); }

  function revokeKey(keyId) {
    _ensureBootstrapped();
    _refreshBeforeMutation();
    const rec = _store[keyId];
    if (!rec) throw new Error(`${S}: unknown ${N} keyId "${keyId}"`);
    if (rec.status === 'revoked') return;
    const revoked = _buildRevokedRecord(rec.publicKeyDer, rec.clientId, rec.version, rec.createdAt);
    _store[keyId] = revoked;
    _zeroizePrivateKey(rec); //
    _saveKeys();
    emit('INFO', `${E}_REVOKED`, { keyId, version: rec.version, purpose: KEY_PURPOSE, revokedAt: revoked.revokedAt });
  }

  function validateKeyStore() {
    _ensureBootstrapped();
    const expiredKeys = []; const expiringKeys = []; const overdueKeys = []; const violations = [];
    // (i): defence in depth — the artifact store's validateStartup() step 0. Bootstrap already migrated any
    // plaintext; a plaintext key on disk now means the file was changed after that, and startup must fail closed.
    for (const { keyId } of _scanFileForPlaintext()) {
      emit('CRITICAL', `${E}_PLAINTEXT_DETECTED`, { keyId, message: `CRITICAL: Unencrypted ${N} private key detected on disk.` });
      violations.push({ type: `PLAINTEXT_${V}_KEY`, keyId, detail: `${N} private key stored as plaintext in ${DATA_PATH}` });
    }
    // K1: defence in depth — after bootstrap sealed the store, the file on disk must still be sealed and
    // authentic (startup treats every violation as FATAL).
    for (const v of _scanFileSeal()) violations.push(v);
    const activeRecs = Object.values(_store).filter((r) => r.status === 'active');
    const totalActive = activeRecs.length;
    if (activeRecs.length > 1) {
      violations.push({ type: `MULTIPLE_ACTIVE_${V}_KEYS`, detail: `${activeRecs.length} active ${N} keys — expected exactly 1` });
    }
    for (const rec of activeRecs) {
      if (!rec.rotationDeadline || !rec.expiresAt || isNaN(new Date(rec.rotationDeadline).getTime()) || isNaN(new Date(rec.expiresAt).getTime())) {
        violations.push({ type: `INVALID_${V}_KEY_LIFECYCLE`, keyId: rec.keyId, detail: `rotationDeadline or expiresAt is missing or unparseable on active ${N} key` });
        continue;
      }
      if (_isExpired(rec)) {
        expiredKeys.push({ keyId: rec.keyId, createdAt: rec.createdAt, expiresAt: rec.expiresAt, rotateCommand: ROTATE_CMD });
      } else {
        const daysToExpiry = (/** @type {any} */ (new Date(rec.expiresAt)) - Date.now()) / 86_400_000;
        const daysToRotation = (/** @type {any} */ (new Date(rec.rotationDeadline)) - Date.now()) / 86_400_000;
        if (daysToExpiry <= EXPIRY_WARNING_DAYS) expiringKeys.push({ keyId: rec.keyId, daysRemaining: Math.ceil(daysToExpiry) });
        if (daysToRotation <= 0) overdueKeys.push({ keyId: rec.keyId, daysOverdue: Math.ceil(-daysToRotation) });
      }
    }
    return { totalActive, expiredKeys, expiringKeys, overdueKeys, violations };
  }

  // K1: seal violations of the file currently on disk ([] when absent or empty).
  function _scanFileSeal() {
    if (!fs.existsSync(DATA_PATH)) return [];
    let data;
    try { data = JSON.parse(fs.readFileSync(DATA_PATH, 'utf8')); } catch { return []; } // the loader reports corruption
    if (!data || typeof data.keys !== 'object' || data.keys === null || Object.keys(data.keys).length === 0) return [];
    try {
      const st = _sealState(data);
      if (!st.sealed) return [{ type: `UNSEALED_${V}_KEY_STORE`, detail: `${DATA_PATH} carries no record MACs (unauthenticated key metadata)` }];
      return st.failures.map((f) => ({ type: `${V}_KEY_RECORD_MAC_INVALID`, keyId: f.keyId, detail: `record MAC ${f.reason} in ${DATA_PATH}` }));
    } catch (err) {
      return [{ type: `${V}_KEY_SEAL_UNVERIFIABLE`, detail: `${DATA_PATH}: ${err.message}` }];
    }
  }

  function listKeys() {
    _ensureBootstrapped();
    return Object.values(_store).map((rec) => ({
      keyId: rec.keyId, clientId: rec.clientId, version: rec.version, algorithm: rec.algorithm, purpose: KEY_PURPOSE,
      publicKeyB64: rec.publicKeyB64, status: rec.status, createdAt: rec.createdAt, retiredAt: rec.retiredAt || null,
      rotationDeadline: rec.rotationDeadline || null, expiresAt: rec.expiresAt || null,
      revokedAt: rec.status === 'revoked' ? (rec.revokedAt || null) : null, //
    }));
  }

  function _resetStore() { _store = {}; }

  return {
    getActiveKey, getPublicKey, getKeyStatus, rotateKey, rotateKeyGracefully, revokeKey, validateKeyStore, listKeys,
    reloadFromDisk, _scanFileForPlaintext,
    ROTATION_DAYS, EXPIRY_DAYS, EXPIRY_WARNING_DAYS, KEY_PURPOSE, DATA_PATH, ROTATE_COMMAND: ROTATE_CMD,
    _resetStore,
  };
}

module.exports = { createEd25519KeyStore, rotateCommand, ROTATION_DAYS, EXPIRY_DAYS, EXPIRY_WARNING_DAYS };
