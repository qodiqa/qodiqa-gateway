'use strict';

/**
 * QODIQA Disaster Recovery — encryption at rest for the DR JSON backup.
 *
 * SAME MECHANISM AS scripts/pg-backup.sh: every archive file is encrypted exactly like
 *   openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -md sha256 -salt -pass env:QODIQA_BACKUP_ENCRYPTION_KEY
 * ("Salted__" ‖ 8-byte salt ‖ AES-256-CBC ciphertext; key+IV = PBKDF2-HMAC-SHA256(passphrase, salt, 200 000, 48)),
 * so an operator can decrypt any archive with that one openssl command and no QODIQA code. It is then SEALED
 * encrypt-then-MAC like pg-backup.sh: the manifest records the SHA-256 of every ciphertext, and manifest.json.seal is
 * HMAC-SHA256(QODIQA_BACKUP_HMAC_KEY, manifest.json bytes) in pg-backup.sh's hmac_hex format (lowercase hex + "\n",
 * trailing newlines stripped from the key). Restore verifies the seal before trusting ANY checksum in the manifest,
 * then every ciphertext's checksum before decrypting it.
 *
 * Key rules are pg-backup.sh's encryption_preflight(): both keys ≥ 32 characters, no REPLACE_WITH placeholder, and
 * distinct. The plaintext never touches the backup directory when encryption is on.
 *
 * Plaintext policy: a DR backup must be encrypted when
 *   QODIQA_BACKUP_REQUIRE_ENCRYPTION=true   (the shipped qodiqa-backup-config sets it), or
 *   NODE_ENV=production                     (unless QODIQA_BACKUP_ALLOW_PLAINTEXT=true — an explicit, loudly logged
 *                                            override for throwaway targets; it can never lift an explicit
 *                                            QODIQA_BACKUP_REQUIRE_ENCRYPTION=true).
 * Restore / verify refuse a PLAINTEXT backup under the same rule (pg-backup.sh's refuse_plaintext_if_required).
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SCHEME = 'openssl-enc/aes-256-cbc/pbkdf2-hmac-sha256/200000/salted';
const SEAL_SCHEME = 'hmac-sha256(manifest.json)';
const SEAL_FILE = 'manifest.json.seal';
const ITERATIONS = 200000;
const MAGIC = Buffer.from('Salted__', 'ascii');

class BackupCryptoError extends Error {
  constructor(message, code) { super(message); this.name = 'BackupCryptoError'; this.code = code; }
}

const sha256Hex = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

function _deriveKeyIv(passphrase, salt) {
  const dk = crypto.pbkdf2Sync(Buffer.from(passphrase, 'utf8'), salt, ITERATIONS, 48, 'sha256');
  return { key: dk.subarray(0, 32), iv: dk.subarray(32, 48) };
}

/** openssl-enc-compatible encryption; the result is decrypted back with the same derived key and compared (fail closed). */
function encryptBuffer(plain, passphrase) {
  const salt = crypto.randomBytes(8);
  const { key, iv } = _deriveKeyIv(passphrase, salt);
  const c = crypto.createCipheriv('aes-256-cbc', key, iv);
  const out = Buffer.concat([MAGIC, salt, c.update(plain), c.final()]);
  // pg-backup.sh encrypt_in_place(): never accept ciphertext that does not decrypt back to the exact plaintext.
  const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const back = Buffer.concat([d.update(out.subarray(16)), d.final()]);
  if (!back.equals(Buffer.isBuffer(plain) ? plain : Buffer.from(plain))) {
    throw new BackupCryptoError('encrypted archive does not decrypt back to its plaintext', 'BACKUP_ENCRYPTION_FAILED');
  }
  return out;
}

function decryptBuffer(buf, passphrase) {
  if (!Buffer.isBuffer(buf) || buf.length < 32 || !buf.subarray(0, 8).equals(MAGIC)) {
    throw new BackupCryptoError('archive is not an openssl "Salted__" ciphertext', 'BACKUP_DECRYPT_FAILED');
  }
  const { key, iv } = _deriveKeyIv(passphrase, buf.subarray(8, 16));
  try {
    const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([d.update(buf.subarray(16)), d.final()]);
  } catch (e) {
    throw new BackupCryptoError(`archive does not decrypt (wrong key or corrupt): ${e.message}`, 'BACKUP_DECRYPT_FAILED');
  }
}

/** pg-backup.sh hmac_hex(): HMAC-SHA256 lowercase hex, key with trailing newlines stripped. */
function hmacHex(buf, hmacKey) {
  const key = String(hmacKey || '').replace(/\n+$/, '');
  if (!key) throw new BackupCryptoError('empty HMAC key', 'BACKUP_HMAC_KEY_INVALID');
  return crypto.createHmac('sha256', Buffer.from(key, 'utf8')).update(buf).digest('hex');
}

const _badKey = (k) => typeof k !== 'string' || k.includes('REPLACE_WITH') || k.length < 32;

/** Whether policy forbids a plaintext DR backup (backup, verify and restore all use this one rule). */
function plaintextPolicy(env = process.env) {
  const explicit = env.QODIQA_BACKUP_REQUIRE_ENCRYPTION === 'true';
  const production = env.NODE_ENV === 'production';
  const override = env.QODIQA_BACKUP_ALLOW_PLAINTEXT === 'true';
  const required = explicit || (production && !override);
  return { required, explicit, production, overrideUsed: production && override && !explicit };
}

function _loud(event, message) {
  // Structured, to stderr, every time: an operator grepping job logs must see that this backup is plaintext.
  console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'WARN', event, message }));
}

/**
 * Backup-side resolution. Throws BackupCryptoError (before anything is written) on a policy/key violation.
 * @returns {{ encrypt: true, encKey: string, hmacKey: string } | { encrypt: false, overrideUsed: boolean }}
 */
function resolveBackupEncryption(env = process.env) {
  const policy = plaintextPolicy(env);
  const encKey = env.QODIQA_BACKUP_ENCRYPTION_KEY || '';
  const hmacKey = env.QODIQA_BACKUP_HMAC_KEY || '';
  if (!encKey) {
    if (policy.required) {
      throw new BackupCryptoError(
        `encryption is required (${policy.explicit ? 'QODIQA_BACKUP_REQUIRE_ENCRYPTION=true' : 'NODE_ENV=production'}) but QODIQA_BACKUP_ENCRYPTION_KEY is not set — refusing to write a plaintext DR backup; nothing was written`,
        'BACKUP_ENCRYPTION_REQUIRED');
    }
    if (policy.overrideUsed) {
      _loud('BACKUP_PLAINTEXT_OVERRIDE', 'QODIQA_BACKUP_ALLOW_PLAINTEXT=true under NODE_ENV=production: this DR backup holds every tenant\'s rows IN PLAINTEXT — throwaway targets only');
    } else {
      _loud('BACKUP_UNENCRYPTED', 'QODIQA_BACKUP_ENCRYPTION_KEY not set — this DR backup is stored in plaintext');
    }
    return { encrypt: false, overrideUsed: policy.overrideUsed };
  }
  if (_badKey(encKey)) {
    throw new BackupCryptoError('QODIQA_BACKUP_ENCRYPTION_KEY is a placeholder or shorter than 32 characters — refusing to encrypt with a guessable key', 'BACKUP_ENCRYPTION_KEY_INVALID');
  }
  if (!hmacKey) {
    throw new BackupCryptoError('QODIQA_BACKUP_ENCRYPTION_KEY is set but QODIQA_BACKUP_HMAC_KEY is not — an encrypted backup must be authenticated (encrypt-then-MAC)', 'BACKUP_ENCRYPTION_NEEDS_HMAC');
  }
  if (_badKey(hmacKey) || hmacKey === encKey) {
    throw new BackupCryptoError('QODIQA_BACKUP_HMAC_KEY is a placeholder, shorter than 32 characters, or equal to the encryption key — refusing to seal with it', 'BACKUP_HMAC_KEY_INVALID');
  }
  return { encrypt: true, encKey, hmacKey };
}

/** Manifest field recorded for an encrypted backup (no key material, no plaintext hashes). */
function encryptionManifestField() {
  return { scheme: SCHEME, seal: SEAL_SCHEME, sealFile: SEAL_FILE, keyEnv: 'QODIQA_BACKUP_ENCRYPTION_KEY', sealKeyEnv: 'QODIQA_BACKUP_HMAC_KEY' };
}

/**
 * Archive writer bound to one backup directory. Plaintext mode writes the bytes as before; encrypted mode writes only
 * `<fileName>.enc` and returns its ciphertext checksum/size for the manifest.
 */
function makeArchiveWriter(targetDir, enc) {
  return function writeArchive(fileName, data) {
    const plain = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
    if (!enc || !enc.encrypt) {
      fs.writeFileSync(path.join(targetDir, fileName), plain);
      return { archiveFile: fileName };
    }
    const ct = encryptBuffer(plain, enc.encKey);
    const archiveFile = `${fileName}.enc`;
    fs.writeFileSync(path.join(targetDir, archiveFile), ct, { mode: 0o600, flag: 'wx' });
    return { archiveFile, sha256: sha256Hex(ct), sizeBytes: ct.length };
  };
}

function writeSeal(backupDir, manifestBytes, hmacKey) {
  fs.writeFileSync(path.join(backupDir, SEAL_FILE), `${hmacHex(manifestBytes, hmacKey)}\n`, { mode: 0o600 });
}

/**
 * Restore/verify-side gate, given the RAW manifest bytes and the parsed manifest. Throws BackupCryptoError:
 *   BACKUP_PLAINTEXT_REFUSED   plaintext backup while policy requires encryption
 *   BACKUP_KEYS_MISSING        encrypted backup but QODIQA_BACKUP_ENCRYPTION_KEY / QODIQA_BACKUP_HMAC_KEY not set
 *   BACKUP_SEAL_MISSING / BACKUP_SEAL_MISMATCH
 *   BACKUP_ENCRYPTION_SCHEME_UNKNOWN
 */
function verifyBackupSeal(backupDir, rawManifest, manifest, env = process.env) {
  if (!manifest.encryption) {
    const policy = plaintextPolicy(env);
    if (policy.required) {
      throw new BackupCryptoError(
        `plaintext DR backup refused: encryption is required (${policy.explicit ? 'QODIQA_BACKUP_REQUIRE_ENCRYPTION=true' : 'NODE_ENV=production'}); only an encrypted, sealed backup is accepted`,
        'BACKUP_PLAINTEXT_REFUSED');
    }
    return { encrypted: false };
  }
  if (manifest.encryption.scheme !== SCHEME) {
    throw new BackupCryptoError(`unknown backup encryption scheme "${manifest.encryption.scheme}"`, 'BACKUP_ENCRYPTION_SCHEME_UNKNOWN');
  }
  const encKey = env.QODIQA_BACKUP_ENCRYPTION_KEY || '';
  const hmacKey = env.QODIQA_BACKUP_HMAC_KEY || '';
  if (!encKey || !hmacKey) {
    throw new BackupCryptoError('encrypted DR backup: QODIQA_BACKUP_ENCRYPTION_KEY and QODIQA_BACKUP_HMAC_KEY are both required to verify and read it', 'BACKUP_KEYS_MISSING');
  }
  const sealPath = path.join(backupDir, SEAL_FILE);
  if (!fs.existsSync(sealPath)) {
    throw new BackupCryptoError(`${SEAL_FILE} is missing — an encrypted backup without its seal is not trusted`, 'BACKUP_SEAL_MISSING');
  }
  const expected = fs.readFileSync(sealPath, 'utf8').trim();
  const actual = hmacHex(Buffer.from(rawManifest, 'utf8'), hmacKey);
  const ok = /^[0-9a-f]{64}$/.test(expected)
    && crypto.timingSafeEqual(Buffer.from(expected, 'utf8'), Buffer.from(actual, 'utf8'));
  if (!ok) {
    throw new BackupCryptoError('manifest seal mismatch — the manifest was altered, or QODIQA_BACKUP_HMAC_KEY is not the key it was sealed with', 'BACKUP_SEAL_MISMATCH');
  }
  return { encrypted: true };
}

/**
 * Read one archive's PLAINTEXT bytes. For an encrypted backup the ciphertext must match the (sealed) manifest's
 * sha256 before it is decrypted; an encrypted entry without a recorded checksum is refused.
 * @param {string} backupDir
 * @param {object|null} encryption  manifest.encryption
 * @param {{ archiveFile: string, sha256?: string }} entry
 */
function readArchive(backupDir, encryption, entry, env = process.env) {
  const buf = fs.readFileSync(path.join(backupDir, entry.archiveFile));
  if (!encryption) return buf;
  if (typeof entry.sha256 !== 'string') {
    throw new BackupCryptoError(`encrypted archive "${entry.archiveFile}" has no checksum in the manifest`, 'ARCHIVE_CHECKSUM_MISSING');
  }
  if (sha256Hex(buf) !== entry.sha256) {
    throw new BackupCryptoError(`checksum mismatch for encrypted archive "${entry.archiveFile}" — corrupted or tampered`, 'ARCHIVE_CHECKSUM_MISMATCH');
  }
  const encKey = env.QODIQA_BACKUP_ENCRYPTION_KEY || '';
  if (!encKey) throw new BackupCryptoError('QODIQA_BACKUP_ENCRYPTION_KEY is required to read an encrypted backup', 'BACKUP_KEYS_MISSING');
  return decryptBuffer(buf, encKey);
}

// ──: streaming archive I/O ───────────────────────────────────────────────────────────────────
// Same "Salted__" ‖ salt ‖ AES-256-CBC format as encryptBuffer (openssl enc decrypts it), processed in CHUNK_BYTES
// pieces so no component is ever held whole in memory (readFileSync/Buffer.concat capped every component at 2 GiB).
// The decrypt-back check of encryptBuffer is kept, streamed: a written archive is decrypted again from disk and its
// plaintext SHA-256 must equal the SHA-256 of the bytes that were read from the source.

const { forEachChunkSync, CHUNK_BYTES } = require('./checksum');

function _writeAllSync(fd, buf) {
  let off = 0;
  while (off < buf.length) off += fs.writeSync(fd, buf, off, buf.length - off);
}

/** Decrypt an archive file chunk by chunk, handing plaintext to onPlain; returns { plainSha256, plainBytes }. */
function _decryptFileChunked(archivePath, passphrase, onPlain) {
  const head = Buffer.alloc(16);
  const fd = fs.openSync(archivePath, 'r');
  let n;
  try { n = fs.readSync(fd, head, 0, 16, 0); } finally { fs.closeSync(fd); }
  if (n < 16 || !head.subarray(0, 8).equals(MAGIC)) {
    throw new BackupCryptoError('archive is not an openssl "Salted__" ciphertext', 'BACKUP_DECRYPT_FAILED');
  }
  const { key, iv } = _deriveKeyIv(passphrase, head.subarray(8, 16));
  const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const h = crypto.createHash('sha256');
  let plainBytes = 0;
  const emit = (b) => { if (b.length) { h.update(b); plainBytes += b.length; if (onPlain) onPlain(b); } };
  try {
    forEachChunkSync(archivePath, (c) => emit(d.update(c)), { start: 16 });
    emit(d.final());
  } catch (e) {
    if (e instanceof BackupCryptoError) throw e;
    throw new BackupCryptoError(`archive does not decrypt (wrong key or corrupt): ${e.message}`, 'BACKUP_DECRYPT_FAILED');
  }
  return { plainSha256: h.digest('hex'), plainBytes };
}

/**
 * Encrypt [start, start+length) of srcPath (default: the whole file) into a NEW file dstPath, then verify it by
 * decrypting it back. Returns the ciphertext's sha256/size (for the manifest) and the plaintext's.
 */
function encryptFileToArchive(srcPath, dstPath, passphrase, { start = 0, length = null } = {}) {
  const salt = crypto.randomBytes(8);
  const { key, iv } = _deriveKeyIv(passphrase, salt);
  const c = crypto.createCipheriv('aes-256-cbc', key, iv);
  const plainHash = crypto.createHash('sha256');
  const ctHash = crypto.createHash('sha256');
  let ctBytes = 0;
  const fd = fs.openSync(dstPath, 'wx', 0o600);
  const out = (b) => { if (b.length) { _writeAllSync(fd, b); ctHash.update(b); ctBytes += b.length; } };
  let plainBytes;
  try {
    out(Buffer.concat([MAGIC, salt]));
    plainBytes = forEachChunkSync(srcPath, (b) => { plainHash.update(b); out(c.update(b)); }, { start, length });
    out(c.final());
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  const plainSha256 = plainHash.digest('hex');
  const back = _decryptFileChunked(dstPath, passphrase, null);
  if (back.plainSha256 !== plainSha256 || back.plainBytes !== plainBytes) {
    throw new BackupCryptoError(`encrypted archive ${path.basename(dstPath)} does not decrypt back to its plaintext`, 'BACKUP_ENCRYPTION_FAILED');
  }
  return { sha256: ctHash.digest('hex'), sizeBytes: ctBytes, plainSha256, plainBytes };
}

/**
 * Encrypt a Readable (e.g. pg_dump's stdout) into a NEW file dstPath, streaming, then verify it by decrypting it back.
 * Without encryption (enc falsy) the bytes are written as they are. Resolves like encryptFileToArchive.
 */
function writeStreamToArchive(readable, dstPath, passphrase) {
  return new Promise((resolve, reject) => {
    let cipher = null;
    const plainHash = crypto.createHash('sha256');
    const ctHash = crypto.createHash('sha256');
    let plainBytes = 0; let ctBytes = 0;
    const ws = fs.createWriteStream(dstPath, { flags: 'wx', mode: 0o600 });
    let failed = false;
    const fail = (e) => { if (failed) return; failed = true; readable.destroy(); ws.destroy(); reject(e); };
    const write = (b) => { if (b.length) { ctHash.update(b); ctBytes += b.length; if (!ws.write(b)) readable.pause(); } };
    ws.on('drain', () => readable.resume());
    ws.on('error', fail);
    readable.on('error', fail);
    if (passphrase) {
      const salt = crypto.randomBytes(8);
      const { key, iv } = _deriveKeyIv(passphrase, salt);
      cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
      write(Buffer.concat([MAGIC, salt]));
    }
    readable.on('data', (b) => {
      plainHash.update(b); plainBytes += b.length;
      write(cipher ? cipher.update(b) : b);
    });
    readable.on('end', () => {
      if (failed) return;
      try { if (cipher) write(cipher.final()); } catch (e) { fail(e); return; }
      ws.end(() => {
        fs.open(dstPath, 'r', (oe, fd) => {
          if (oe) { fail(oe); return; }
          fs.fsync(fd, () => fs.close(fd, () => {
            const plainSha256 = plainHash.digest('hex');
            try {
              if (cipher) {
                const back = _decryptFileChunked(dstPath, passphrase, null);
                if (back.plainSha256 !== plainSha256 || back.plainBytes !== plainBytes) {
                  throw new BackupCryptoError(`encrypted archive ${path.basename(dstPath)} does not decrypt back to its plaintext`, 'BACKUP_ENCRYPTION_FAILED');
                }
              }
              resolve({ sha256: ctHash.digest('hex'), sizeBytes: ctBytes, plainSha256, plainBytes });
            } catch (e) { reject(e); }
          }));
        });
      });
    });
  });
}

/** Checksum (sealed manifest) then decrypt an archive to a NEW file, chunked. Plaintext archives are copied. */
function restoreArchiveToFile(backupDir, encryption, entry, dstPath, env = process.env) {
  const archivePath = path.join(backupDir, entry.archiveFile);
  if (!encryption) { fs.copyFileSync(archivePath, dstPath); return; }
  _checkArchiveChecksum(archivePath, entry);
  const encKey = env.QODIQA_BACKUP_ENCRYPTION_KEY || '';
  if (!encKey) throw new BackupCryptoError('QODIQA_BACKUP_ENCRYPTION_KEY is required to read an encrypted backup', 'BACKUP_KEYS_MISSING');
  const fd = fs.openSync(dstPath, 'w', 0o600);
  try {
    _decryptFileChunked(archivePath, encKey, (b) => _writeAllSync(fd, b));
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
}

function _checkArchiveChecksum(archivePath, entry) {
  if (typeof entry.sha256 !== 'string') {
    throw new BackupCryptoError(`encrypted archive "${entry.archiveFile}" has no checksum in the manifest`, 'ARCHIVE_CHECKSUM_MISSING');
  }
  const h = crypto.createHash('sha256');
  forEachChunkSync(archivePath, (b) => h.update(b));
  if (h.digest('hex') !== entry.sha256) {
    throw new BackupCryptoError(`checksum mismatch for encrypted archive "${entry.archiveFile}" — corrupted or tampered`, 'ARCHIVE_CHECKSUM_MISMATCH');
  }
}

/**
 * A Readable of an archive's PLAINTEXT (checksum verified first, then decrypted as it is read). For feeding
 * pg_restore / pg_restore --list without a plaintext copy on disk.
 */
function createArchivePlainStream(backupDir, encryption, entry, env = process.env) {
  const { Readable } = require('stream');
  const archivePath = path.join(backupDir, entry.archiveFile);
  if (!encryption) return fs.createReadStream(archivePath, { highWaterMark: CHUNK_BYTES });
  _checkArchiveChecksum(archivePath, entry);
  const encKey = env.QODIQA_BACKUP_ENCRYPTION_KEY || '';
  if (!encKey) throw new BackupCryptoError('QODIQA_BACKUP_ENCRYPTION_KEY is required to read an encrypted backup', 'BACKUP_KEYS_MISSING');
  const head = Buffer.alloc(16);
  const fd = fs.openSync(archivePath, 'r');
  try { fs.readSync(fd, head, 0, 16, 0); } finally { fs.closeSync(fd); }
  if (!head.subarray(0, 8).equals(MAGIC)) throw new BackupCryptoError('archive is not an openssl "Salted__" ciphertext', 'BACKUP_DECRYPT_FAILED');
  const { key, iv } = _deriveKeyIv(encKey, head.subarray(8, 16));
  const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const src = fs.createReadStream(archivePath, { start: 16, highWaterMark: CHUNK_BYTES });
  return Readable.from((async function* plain() {
    try {
      for await (const c of src) { const p = d.update(c); if (p.length) yield p; }
      const f = d.final(); if (f.length) yield f;
    } catch (e) {
      throw new BackupCryptoError(`archive does not decrypt (wrong key or corrupt): ${e.message}`, 'BACKUP_DECRYPT_FAILED');
    }
  })());
}

/**
 * The first line of an archive's plaintext (checksum verified first), reading only as far as the first newline —
 * the audit-base check needs the log's first entry, never the whole log.
 */
function readArchiveFirstLine(backupDir, encryption, entry, env = process.env) {
  const archivePath = path.join(backupDir, entry.archiveFile);
  const chunks = []; let found = false;
  const take = (b) => {
    if (found) return;
    const nl = b.indexOf(0x0a);
    if (nl >= 0) { chunks.push(Buffer.from(b.subarray(0, nl))); found = true; } else chunks.push(Buffer.from(b));
  };
  if (!encryption) {
    const fd = fs.openSync(archivePath, 'r');
    try {
      const buf = Buffer.alloc(65536); let pos = 0;
      while (!found) { const n = fs.readSync(fd, buf, 0, buf.length, pos); if (n <= 0) break; take(buf.subarray(0, n)); pos += n; }
    } finally { fs.closeSync(fd); }
  } else {
    _checkArchiveChecksum(archivePath, entry);
    const encKey = env.QODIQA_BACKUP_ENCRYPTION_KEY || '';
    if (!encKey) throw new BackupCryptoError('QODIQA_BACKUP_ENCRYPTION_KEY is required to read an encrypted backup', 'BACKUP_KEYS_MISSING');
    const head = Buffer.alloc(16);
    const fd = fs.openSync(archivePath, 'r');
    try {
      fs.readSync(fd, head, 0, 16, 0);
      if (!head.subarray(0, 8).equals(MAGIC)) throw new BackupCryptoError('archive is not an openssl "Salted__" ciphertext', 'BACKUP_DECRYPT_FAILED');
      const { key, iv } = _deriveKeyIv(encKey, head.subarray(8, 16));
      const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
      const buf = Buffer.alloc(65536); let pos = 16;
      for (;;) {
        if (found) break;
        const n = fs.readSync(fd, buf, 0, buf.length, pos);
        if (n <= 0) { take(d.final()); break; }
        take(d.update(buf.subarray(0, n))); pos += n;
      }
    } catch (e) {
      if (e instanceof BackupCryptoError) throw e;
      throw new BackupCryptoError(`archive does not decrypt (wrong key or corrupt): ${e.message}`, 'BACKUP_DECRYPT_FAILED');
    } finally { fs.closeSync(fd); }
  }
  const s = Buffer.concat(chunks).toString('utf8').trim();
  return s || null;
}

module.exports = {
  SCHEME, SEAL_FILE, ITERATIONS, BackupCryptoError,
  encryptBuffer, decryptBuffer, hmacHex, sha256Hex,
  plaintextPolicy, resolveBackupEncryption, encryptionManifestField, makeArchiveWriter, writeSeal,
  verifyBackupSeal, readArchive,
  encryptFileToArchive, writeStreamToArchive, restoreArchiveToFile, createArchivePlainStream, readArchiveFirstLine,
};
