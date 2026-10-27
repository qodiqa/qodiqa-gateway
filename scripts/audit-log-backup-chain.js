'use strict';

/**
 * — helper for scripts/backup-audit-log.sh's INCREMENTAL mode (append-only audit log).
 *
 * The 5-minute audit-log backup used to copy, gzip and seal the WHOLE log every run (measured at 3.15 GB: 63 s per run,
 * 117 MB per copy, gateway segment p95 379 ms while it ran; 288 full copies a day kept for 90 days). The audit log is
 * append-only, so a run only needs the bytes appended since the previous run. This helper does the parts that need
 * byte-exact reasoning; the shell script keeps logging, alerting, metrics and the HMAC seal.
 *
 *   probe <log>                         → {size, prefix, firstLineSha, lastLineSha, ino}: `prefix` = bytes up to the last
 *                                          complete line ('\n'), the part that may be backed up (an in-flight append is
 *                                          not yet acknowledged)
 *   lineSha <log> <offset>              → sha256 of the complete line ending just before byte `offset`
 *   meta <out> <json>                   → write a run's metadata file (the shell seals it)
 *   wal-fit <log> <limit> <wal>         → does a copied WAL belong with the log prefix [0, limit)? (see walFit)
 *   check-chain <dir> <base-name>       → verify the metadata chain of one base: contiguous byte ranges, seq order, each
 *                                          meta's prevMetaSha256 = sha256 of the previous meta file, each data file's
 *                                          sha256 = the one recorded; prints {ok, segments, bytes} or {ok:false, error}
 *
 * Seals: every meta file is HMAC-sealed by the shell (meta.seal). A meta records the sha256 of its data file and of the
 * previous meta, so the sealed meta chain authenticates every data byte and the order — dropping, reordering, replacing
 * or truncating a segment in the middle is detected; dropping the NEWEST runs is detected by the staleness check (as
 * before) and, at boot, by the restored log's own anti-deletion checksum.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CHUNK = 65536;
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

function _readAt(fd, pos, len) {
  const b = Buffer.alloc(len);
  const n = fs.readSync(fd, b, 0, len, pos);
  return b.subarray(0, n);
}

/** Offset just past the last '\n' within the first `size` bytes (0 if none). */
function completeLinesPrefix(fd, size) {
  let end = size;
  while (end > 0) {
    const start = Math.max(0, end - CHUNK);
    const nl = _readAt(fd, start, end - start).lastIndexOf(0x0a);
    if (nl >= 0) return start + nl + 1;
    end = start;
  }
  return 0;
}

/** sha256 of the complete line that ends (with its '\n') just before `offset`; null when offset is 0. */
function lineShaBefore(fd, offset) {
  if (offset <= 0) return null;
  const parts = []; let end = offset - 1;   // byte offset-1 is the line's '\n'
  for (;;) {
    const start = Math.max(0, end - CHUNK);
    const b = _readAt(fd, start, end - start);
    const nl = b.lastIndexOf(0x0a);
    if (nl >= 0) { parts.unshift(b.subarray(nl + 1)); break; }
    parts.unshift(b);
    if (start === 0) break;
    end = start;
  }
  return sha256(Buffer.concat(parts));
}

function firstLineSha(fd, size) {
  const parts = []; let pos = 0;
  while (pos < size) {
    const b = _readAt(fd, pos, Math.min(CHUNK, size - pos));
    if (!b.length) break;
    const nl = b.indexOf(0x0a);
    if (nl >= 0) { parts.push(b.subarray(0, nl)); return sha256(Buffer.concat(parts)); }
    parts.push(b); pos += b.length;
  }
  return null;   // no complete first line yet
}

function probe(log) {
  const st = fs.statSync(log);
  const fd = fs.openSync(log, 'r');
  try {
    const prefix = completeLinesPrefix(fd, st.size);
    return { size: st.size, prefix, firstLineSha: firstLineSha(fd, prefix), lastLineSha: lineShaBefore(fd, prefix), ino: String(st.ino) };
  } finally { fs.closeSync(fd); }
}

function fileSha(p) {
  const h = crypto.createHash('sha256');
  const fd = fs.openSync(p, 'r');
  try { const b = Buffer.alloc(CHUNK); let pos = 0; for (;;) { const n = fs.readSync(fd, b, 0, CHUNK, pos); if (n <= 0) break; h.update(b.subarray(0, n)); pos += n; } }
  finally { fs.closeSync(fd); }
  return h.digest('hex');
}

/**
 * Does a copied WAL belong with the log prefix [0, limit)? The WAL is copied BEFORE the log is measured, and the log is
 * append-only, so its batch is either (a) not yet — or only partly — in the prefix: it continues the prefix's tail,
 * exactly what boot recovery (_recoverWalSync) replays, or (b) already wholly committed inside the prefix, with later
 * entries after it — restoring it then makes boot refuse ("the WAL batch does not continue the log"), and omitting it
 * loses nothing, since every entry is in the log. Anything else is a WAL from another log: an error, never guessed.
 *   → {disposition: 'empty'|'torn'|'continues'|'committed', entries}   (torn = unparseable last line; boot discards it)
 */
const WAL_SEARCH_MAX = 256 * 1024 * 1024;
function walFit(log, limit, walPath) { return walFitText(log, limit, fs.readFileSync(walPath, 'utf8')); }

/** walFit on WAL bytes already in memory. */
function walFitText(log, limit, text) {
  if (text.length === 0) return { disposition: 'empty', entries: 0 };
  if (!text.endsWith('\n')) {
    try { JSON.parse(text.slice(text.lastIndexOf('\n') + 1)); } catch { return { disposition: 'torn', entries: 0 }; }
  }
  const lines = (text.endsWith('\n') ? text.slice(0, -1) : text).split('\n');
  const wal = lines.map((l, i) => {
    let e; try { e = JSON.parse(l); } catch { throw new Error(`WAL line ${i + 1} is not valid JSON`); }
    if (typeof e.hash !== 'string' || typeof e.prevHash !== 'string') throw new Error(`WAL line ${i + 1} has no hash/prevHash`);
    if (i > 0 && e.prevHash !== wal_prev(lines, i)) throw new Error(`WAL entry ${i + 1} does not link to entry ${i}`);
    return e;
  });
  if (limit === 0) return { disposition: 'continues', entries: wal.length, alreadyInLog: 0 };   // empty log: boot replays from the chain start
  const fd = fs.openSync(log, 'r');
  try {
    // (a) the same tail test boot recovery applies, on the prefix
    const want = Math.min(limit, Buffer.byteLength(text, 'utf8') + 256 * 1024);
    const tail = _readAt(fd, limit - want, want).toString('utf8');
    const lastNl = tail.lastIndexOf('\n');
    let complete = lastNl >= 0 ? tail.slice(0, lastNl).split('\n') : [];
    if (want < limit) complete = complete.slice(1);
    const hashes = complete.map((l) => { try { return JSON.parse(l).hash ?? null; } catch { throw new Error('a complete line near the log tail is not valid JSON'); } });
    let k = 0;
    for (let c = Math.min(wal.length, hashes.length); c >= 1; c--) {
      if (hashes.slice(hashes.length - c).every((h, j) => h === wal[j].hash)) { k = c; break; }
    }
    const before = hashes.length - k - 1 >= 0 ? hashes[hashes.length - k - 1] : null;
    if (limit === 0 || before === null || before === wal[0].prevHash) return { disposition: 'continues', entries: wal.length, alreadyInLog: k };
    // (b) the whole batch, byte-exact and line-aligned, earlier in the prefix (searched back from the tail)
    const needle = Buffer.from(`\n${lines.join('\n')}\n`, 'utf8');
    let end = limit;
    while (end > 0 && limit - end < WAL_SEARCH_MAX) {
      const start = Math.max(0, end - CHUNK * 64);
      const lo = Math.max(0, start - needle.length);           // overlap so a match across chunk edges is found
      const at = _readAt(fd, lo, Math.min(limit, end + needle.length) - lo).lastIndexOf(needle);
      if (at >= 0) return { disposition: 'committed', entries: wal.length, offset: lo + at + 1 };
      end = start;
    }
    if (_readAt(fd, 0, needle.length - 1).equals(needle.subarray(1))) return { disposition: 'committed', entries: wal.length, offset: 0 };
    throw new Error(`the WAL batch (${wal.length} entries, expects ${wal[0].prevHash}) neither continues the log prefix nor is committed in its last ${WAL_SEARCH_MAX} bytes`);
  } finally { fs.closeSync(fd); }
}
function wal_prev(lines, i) { return JSON.parse(lines[i - 1]).hash; }

/** Metas of one base, in seq order: <base>.meta.json (seq 0) then <base>.seg-NNNNNN.meta.json. */
function chainMetas(dir, base) {
  const names = fs.readdirSync(dir).filter((f) => f === `${base}.meta.json` || (f.startsWith(`${base}.seg-`) && f.endsWith('.meta.json')));
  return names.map((f) => ({ file: f, meta: JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')) })).sort((a, b) => a.meta.seq - b.meta.seq);
}

function checkChain(dir, base) {
  const metas = chainMetas(dir, base);
  if (!metas.length || metas[0].meta.kind !== 'base' || metas[0].meta.seq !== 0) return { ok: false, error: `no base meta for ${base}` };
  let prevMetaSha = null; let to = 0;
  for (let i = 0; i < metas.length; i++) {
    const { file, meta } = metas[i];
    if (meta.seq !== i) return { ok: false, error: `sequence gap: expected seq ${i}, found ${meta.seq} (${file})` };
    if (meta.base !== base) return { ok: false, error: `${file} belongs to base ${meta.base}` };
    if (meta.from !== to) return { ok: false, error: `byte gap: ${file} starts at ${meta.from}, previous run ended at ${to}` };
    if (meta.to < meta.from) return { ok: false, error: `${file}: negative range` };
    if ((meta.prevMetaSha256 || null) !== prevMetaSha) return { ok: false, error: `${file}: previous-meta hash does not match — reordered or replaced run` };
    const data = path.join(dir, meta.dataFile);
    if (!fs.existsSync(data)) return { ok: false, error: `${file}: data file ${meta.dataFile} is missing` };
    if (fileSha(data) !== meta.dataSha256) return { ok: false, error: `${file}: data file ${meta.dataFile} does not match its recorded sha256` };
    prevMetaSha = fileSha(path.join(dir, file));
    to = meta.to;
  }
  return { ok: true, base, segments: metas.length - 1, bytes: to, lastMeta: metas[metas.length - 1].file, lastLineSha256: metas[metas.length - 1].meta.lastLineSha256 };
}

if (require.main === module) {
  const [cmd, a, b] = process.argv.slice(2);
  try {
    if (cmd === 'probe') process.stdout.write(JSON.stringify(probe(a)));
    else if (cmd === 'lineSha') { const fd = fs.openSync(a, 'r'); try { process.stdout.write(String(lineShaBefore(fd, Number(b)))); } finally { fs.closeSync(fd); } }
    else if (cmd === 'meta') fs.writeFileSync(a, `${JSON.stringify(JSON.parse(b), null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    else if (cmd === 'fileSha') process.stdout.write(fileSha(a));
    else if (cmd === 'wal-fit') process.stdout.write(JSON.stringify(walFit(a, Number(b), process.argv[5])));
    else if (cmd === 'check-chain') { const r = checkChain(a, b); process.stdout.write(JSON.stringify(r)); process.exitCode = r.ok ? 0 : 1; }
    else { console.error('usage: probe <log> | lineSha <log> <offset> | meta <out> <json> | fileSha <file> | check-chain <dir> <base> | wal-fit <log> <limit> <wal>'); process.exitCode = 2; }
  } catch (e) { console.error(`audit-log-backup-chain: ${e.message}`); process.exitCode = 1; }
}

module.exports = { probe, completeLinesPrefix, lineShaBefore, firstLineSha, checkChain, chainMetas, fileSha, walFit, walFitText };
