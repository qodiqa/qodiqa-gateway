'use strict';

/**
 * QODIQA DR RTO measurement harness.
 *
 * The published RTO figure (4 hours, docs/operations/disaster-recovery.md
 * §1) has always been a step-by-step time BUDGET, never a number produced
 * by timing a real or simulated drill — the only piece of the recovery
 * sequence that has ever had real timing data is the automated
 * backup -> restore -> validate cycle itself (scripts/dr/cycle.js, already
 * documented in docs/operations/backup-restore-validation.md §9.1).
 *
 * This harness turns the manual, blank-fill-in "Validation Checklist" in
 * disaster-recovery.md §13 into an actual timestamped record. A real drill
 * spans multiple, separate command invocations over potentially hours (an
 * operator runs `terraform apply`, waits, then marks a phase; runs a
 * restore, waits, then marks the next) — so state is persisted to a small
 * JSON file between invocations rather than held in one long-running
 * process.
 *
 * Usage:
 *   node scripts/dr/rtoHarness.js mark <phaseName> [--state <path>]
 *   node scripts/dr/rtoHarness.js cycle [--state <path>]   (runs the real,
 *       automated backup->restore->validate cycle via scripts/dr/cycle.js
 *       and records its actual measured duration as one phase, rather than
 *       guessing it)
 *   node scripts/dr/rtoHarness.js report [--state <path>] [--json]
 *   node scripts/dr/rtoHarness.js reset [--state <path>]
 *
 * Environment:
 *   QODIQA_RTO_STATE_FILE — default state file path (default:
 *     <os.tmpdir()>/qodiqa-rto-drill.json). Overridable per-call with
 *     --state so multiple drills can run independently.
 *
 * for the recommended phase names
 * (matching disaster-recovery.md §12's Recovery Sequence) and how to run a
 * drill end-to-end.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

function defaultStatePath() {
  return process.env.QODIQA_RTO_STATE_FILE || path.join(os.tmpdir(), 'qodiqa-rto-drill.json');
}

/** Pure: load marks from a state file. Returns [] if the file doesn't exist. */
function loadState(statePath) {
  try {
    const raw = fs.readFileSync(statePath, 'utf8');
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed.marks)) return [];
    return parsed.marks;
  } catch {
    return [];
  }
}

/** Persist marks to a state file, atomically (temp file + rename). */
function saveState(statePath, marks) {
  fs.mkdirSync(path.dirname(statePath), { recursive: true });
  const tmpPath = path.join(path.dirname(statePath), `.${path.basename(statePath)}.${process.pid}.tmp`);
  fs.writeFileSync(tmpPath, JSON.stringify({ marks }, null, 2), 'utf8');
  fs.renameSync(tmpPath, statePath);
}

/**
 * Pure: append a mark to an existing marks array without mutating it.
 * @param {Array<{phase: string, tsMs: number, extra?: object}>} marks
 * @param {string} phase
 * @param {number} tsMs
 * @param {object} [extra]
 */
function addMark(marks, phase, tsMs, extra) {
  if (!phase || typeof phase !== 'string') {
    throw new Error('phase name is required and must be a string');
  }
  if (!Number.isFinite(tsMs)) {
    throw new Error('tsMs must be a finite number');
  }
  return [...marks, { phase, tsMs, ...(extra ? { extra } : {}) }];
}

/**
 * Pure: turn an ordered list of marks into a report — per-phase duration
 * since the previous mark, duration since the first mark, and the total.
 * Marks are sorted by tsMs first so out-of-order recording (e.g. a mark
 * added from a retried/delayed command) never produces a negative duration.
 */
function computeDurations(marks) {
  if (marks.length === 0) {
    return { phases: [], totalMs: 0, startedAt: null, endedAt: null };
  }
  const sorted = [...marks].sort((a, b) => a.tsMs - b.tsMs);
  const startMs = sorted[0].tsMs;
  const phases = sorted.map((m, i) => ({
    phase: m.phase,
    tsMs: m.tsMs,
    sinceStartMs: m.tsMs - startMs,
    sincePreviousMs: i === 0 ? 0 : m.tsMs - sorted[i - 1].tsMs,
    ...(m.extra ? { extra: m.extra } : {}),
  }));
  const endMs = sorted[sorted.length - 1].tsMs;
  return {
    phases,
    totalMs: endMs - startMs,
    startedAt: new Date(startMs).toISOString(),
    endedAt: new Date(endMs).toISOString(),
  };
}

function _fmtDuration(ms) {
  const totalSeconds = Math.round(ms / 1000);
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = totalSeconds % 60;
  return `${h}h ${m}m ${s}s`;
}

/** Pure: render a computeDurations() result as a human-readable report. */
function formatReport(durations) {
  if (durations.phases.length === 0) {
    return 'No marks recorded yet. Use `mark <phaseName>` to record the first phase.';
  }
  const lines = [];
  lines.push('QODIQA DR RTO Drill Report');
  lines.push('='.repeat(40));
  lines.push(`Started: ${durations.startedAt}`);
  lines.push(`Ended:   ${durations.endedAt}`);
  lines.push(`Total:   ${_fmtDuration(durations.totalMs)} (${durations.totalMs}ms)`);
  lines.push('');
  lines.push('Phase-by-phase:');
  for (const p of durations.phases) {
    lines.push(
      `  [+${_fmtDuration(p.sinceStartMs).padEnd(12)}]  (+${_fmtDuration(p.sincePreviousMs)})  ${p.phase}`
        + (p.extra ? `  ${JSON.stringify(p.extra)}` : ''),
    );
  }
  return lines.join('\n');
}

module.exports = { defaultStatePath, loadState, saveState, addMark, computeDurations, formatReport };

if (require.main === module) {
  const args = process.argv.slice(2);
  const command = args[0];
  const stateFlagIdx = args.indexOf('--state');
  const statePath = stateFlagIdx !== -1 ? args[stateFlagIdx + 1] : defaultStatePath();

  function fail(message, code = 1) {
    console.error(JSON.stringify({ event: 'RTO_HARNESS_FAILED', error: message }, null, 2));
    process.exitCode = code;
  }

  (async () => {
    if (command === 'mark') {
      const phase = args[1];
      if (!phase || phase.startsWith('--')) {
        return fail('Usage: node scripts/dr/rtoHarness.js mark <phaseName> [--state <path>]', 2);
      }
      const marks = addMark(loadState(statePath), phase, Date.now());
      saveState(statePath, marks);
      console.log(JSON.stringify({ event: 'RTO_MARK_RECORDED', phase, statePath }, null, 2));
      return;
    }

    if (command === 'cycle') {
      // Runs the real, automated backup->restore->validate cycle and
      // records its ACTUAL measured duration and pass/fail as one phase —
      // this is the one part of a drill this environment can measure
      // directly rather than estimate.
      const { runCycle } = require('./cycle');
      let marks = addMark(loadState(statePath), 'AUTOMATED_CYCLE_START', Date.now());
      saveState(statePath, marks);
      try {
        const { passed, validation } = await runCycle();
        marks = addMark(loadState(statePath), 'AUTOMATED_CYCLE_END', Date.now(), {
          passed,
          overallValid: validation.overallValid,
        });
        saveState(statePath, marks);
        console.log(JSON.stringify({ event: 'RTO_AUTOMATED_CYCLE_COMPLETE', passed, statePath }, null, 2));
        if (!passed) process.exitCode = 1;
      } catch (err) {
        marks = addMark(loadState(statePath), 'AUTOMATED_CYCLE_ERROR', Date.now(), { error: err.message });
        saveState(statePath, marks);
        return fail(`Automated cycle errored: ${err.message}`);
      }
      return;
    }

    if (command === 'report') {
      const durations = computeDurations(loadState(statePath));
      if (args.includes('--json')) {
        console.log(JSON.stringify({ event: 'RTO_REPORT', statePath, ...durations }, null, 2));
      } else {
        console.log(formatReport(durations));
      }
      return;
    }

    if (command === 'reset') {
      saveState(statePath, []);
      console.log(JSON.stringify({ event: 'RTO_STATE_RESET', statePath }, null, 2));
      return;
    }

    fail(
      'Usage: node scripts/dr/rtoHarness.js <mark <phaseName>|cycle|report [--json]|reset> [--state <path>]',
      2,
    );
  })();
}
