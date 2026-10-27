'use strict';

/**
 * Pilot backup window. A real-size hot DR backup raised the
 * gateway's 30-s segment p95 to 563–949 ms for ~2 min (0 errors; pilot-gates/runtime/dr-hot-load-rcsoak8), which
 * breaks the 200 ms per-segment capacity bar — so the heavy jobs must not run during contracted traffic.
 *
 * QODIQA_BACKUP_WINDOW_UTC="HH:MM-HH:MM" (UTC, end exclusive; may wrap midnight, e.g. "23:00-04:00"). When set, a
 * heavy backup job refuses to START outside it — loudly (non-zero exit, alert, failure metric), never a silent skip, so
 * a schedule that drifts out of the window is visible. Unset = no restriction (behaviour unchanged). A malformed value
 * is refused (fail closed) rather than ignored. QODIQA_BACKUP_WINDOW_OVERRIDE=true lets an operator run one backup
 * outside the window deliberately (e.g. before a risky change); it is logged.
 */

class BackupWindowError extends Error {
  constructor(message, code) { super(message); this.name = 'BackupWindowError'; this.code = code; }
}

function _minutes(hhmm) {
  const m = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(hhmm);
  return m ? Number(m[1]) * 60 + Number(m[2]) : null;
}

function parseWindow(spec) {
  const parts = String(spec).split('-');
  const start = parts.length === 2 ? _minutes(parts[0].trim()) : null;
  const end = parts.length === 2 ? _minutes(parts[1].trim()) : null;
  if (start === null || end === null || start === end) {
    throw new BackupWindowError(`QODIQA_BACKUP_WINDOW_UTC="${spec}" is not "HH:MM-HH:MM" with distinct start and end — refusing to run`, 'BACKUP_WINDOW_INVALID');
  }
  return { start, end };
}

function inWindow({ start, end }, date) {
  const now = date.getUTCHours() * 60 + date.getUTCMinutes();
  return start < end ? now >= start && now < end : now >= start || now < end;
}

/** Throws BackupWindowError when a window is configured and `date` is outside it (unless overridden). */
function assertInBackupWindow(env = process.env, date = new Date()) {
  const spec = env.QODIQA_BACKUP_WINDOW_UTC;
  if (!spec) return { restricted: false };
  const w = parseWindow(spec);
  if (inWindow(w, date)) return { restricted: true, inWindow: true, window: spec };
  if (env.QODIQA_BACKUP_WINDOW_OVERRIDE === 'true') {
    console.error(JSON.stringify({ ts: date.toISOString(), level: 'WARN', event: 'BACKUP_WINDOW_OVERRIDDEN', window: spec }));
    return { restricted: true, inWindow: false, overridden: true, window: spec };
  }
  throw new BackupWindowError(`outside the backup window ${spec} UTC (now ${date.toISOString()}) — backups are off-peak operations; nothing was written (QODIQA_BACKUP_WINDOW_OVERRIDE=true runs one deliberately)`, 'BACKUP_OUTSIDE_WINDOW');
}

module.exports = { assertInBackupWindow, parseWindow, inWindow, BackupWindowError };

if (require.main === module) {
  // CLI for the shell scripts: exit 0 inside (or unrestricted), 3 outside, 2 invalid — message on stderr.
  try { assertInBackupWindow(); process.exit(0); } catch (e) {
    console.error(e.message);
    process.exit(e.code === 'BACKUP_OUTSIDE_WINDOW' ? 3 : 2);
  }
}
