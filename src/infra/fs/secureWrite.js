'use strict';

// (patch P1): one secure, durable
// writer for every key-material file (keys.json, key-archive.json, the
// transparency/checkpoint Ed25519 stores, mac-keys.json).
//
//   - The temp file is created EXCLUSIVELY ('wx') with mode 0o600 under a
//     unique name (<target>.<pid>.<random>.tmp). A fixed "<target>.tmp" name
//     let two writers (two processes on a shared keystore, or a CLI beside a
//     live server) interleave on the same temp file, and a stale temp file left
//     by a crash kept its old, wider mode when it was re-used.
//   - The data is fsync'ed before the rename, so a power loss cannot leave a
//     renamed-but-empty key file (the active private key exists only there).
//   - rename() over the target replaces the target's inode, so the target ends
//     up 0o600 even when an operator pre-created it 0644; the copy fallback
//     (Windows EPERM/EBUSY on rename) re-applies 0o600 explicitly.
//   - New parent directories are created 0o700; existing ones are left as-is.
//   - On POSIX the parent directory is fsync'ed (best effort) so the rename
//     itself is durable.
//
// Windows: mode bits are ignored by the OS — the file inherits the folder ACL
// ('s Windows half is an design decision: explicit ACL or "Windows is
// not a supported production platform").

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const FILE_MODE = 0o600;
const DIR_MODE  = 0o700;

function uniqueTempPath(target) {
  return `${target}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
}

function writeFileAtomicSecure(target, data) {
  const dir = path.dirname(target);
  fs.mkdirSync(dir, { recursive: true, mode: DIR_MODE });

  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
  const tmp = uniqueTempPath(target);
  const fd  = fs.openSync(tmp, 'wx', FILE_MODE);
  let written = false;
  try {
    let off = 0;
    while (off < buf.length) off += fs.writeSync(fd, buf, off, buf.length - off);
    fs.fsyncSync(fd);
    written = true;
  } finally {
    fs.closeSync(fd);
    if (!written) { try { fs.unlinkSync(tmp); } catch { /* best-effort cleanup of our own temp file */ } }
  }
  try { fs.chmodSync(tmp, FILE_MODE); } catch { /* win32: mode bits ignored */ }

  try {
    fs.renameSync(tmp, target);
  } catch {
    fs.copyFileSync(tmp, target);
    try { fs.chmodSync(target, FILE_MODE); } catch { /* win32: mode bits ignored */ }
    try { fs.unlinkSync(tmp); } catch { /* best-effort cleanup of our own temp file */ }
  }

  if (process.platform !== 'win32') {
    try { const d = fs.openSync(dir, 'r'); try { fs.fsyncSync(d); } finally { fs.closeSync(d); } } catch { /* best effort */ }
  }
}

module.exports = { writeFileAtomicSecure, uniqueTempPath, FILE_MODE, DIR_MODE };
