'use strict';

/**
 * DR RTO measurement harness.
 *
 * Covers the pure phase/duration computation logic plus the real filesystem
 * state persistence (loadState/saveState), so this proves the harness
 * genuinely records and reconstructs a drill's timeline, not just that its
 * math is correct in isolation.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const { loadState, saveState, addMark, computeDurations, formatReport } = require('../../scripts/dr/rtoHarness');

describe('addMark (pure logic)', () => {
  test('appends without mutating the input array', () => {
    const marks = [{ phase: 'A', tsMs: 1000 }];
    const next = addMark(marks, 'B', 2000);
    expect(marks).toHaveLength(1);
    expect(next).toHaveLength(2);
    expect(next[1]).toEqual({ phase: 'B', tsMs: 2000 });
  });

  test('carries an extra payload when provided', () => {
    const next = addMark([], 'AUTOMATED_CYCLE_END', 5000, { passed: true });
    expect(next[0].extra).toEqual({ passed: true });
  });

  test('rejects a missing or non-string phase name', () => {
    expect(() => addMark([], '', 1000)).toThrow(/phase name/);
    expect(() => addMark([], null, 1000)).toThrow(/phase name/);
  });

  test('rejects a non-finite timestamp', () => {
    expect(() => addMark([], 'A', NaN)).toThrow(/tsMs/);
  });
});

describe('computeDurations (pure logic)', () => {
  test('returns an empty report for no marks', () => {
    const result = computeDurations([]);
    expect(result.phases).toEqual([]);
    expect(result.totalMs).toBe(0);
    expect(result.startedAt).toBeNull();
  });

  test('computes sinceStart and sincePrevious for a simple sequence', () => {
    const marks = [
      { phase: 'DISASTER_DECLARED', tsMs: 0 },
      { phase: 'INFRA_READY', tsMs: 10_000 },
      { phase: 'APP_STARTED', tsMs: 15_000 },
    ];
    const { phases, totalMs } = computeDurations(marks);
    expect(totalMs).toBe(15_000);
    expect(phases[0]).toMatchObject({ phase: 'DISASTER_DECLARED', sinceStartMs: 0, sincePreviousMs: 0 });
    expect(phases[1]).toMatchObject({ phase: 'INFRA_READY', sinceStartMs: 10_000, sincePreviousMs: 10_000 });
    expect(phases[2]).toMatchObject({ phase: 'APP_STARTED', sinceStartMs: 15_000, sincePreviousMs: 5_000 });
  });

  test('sorts out-of-order marks by timestamp so no duration goes negative', () => {
    const marks = [
      { phase: 'SECOND', tsMs: 5000 },
      { phase: 'FIRST', tsMs: 1000 },
    ];
    const { phases } = computeDurations(marks);
    expect(phases.map(p => p.phase)).toEqual(['FIRST', 'SECOND']);
    expect(phases.every(p => p.sincePreviousMs >= 0)).toBe(true);
  });

  test('a single mark has zero total duration', () => {
    const { phases, totalMs } = computeDurations([{ phase: 'ONLY', tsMs: 42 }]);
    expect(totalMs).toBe(0);
    expect(phases).toHaveLength(1);
  });
});

describe('formatReport (pure logic)', () => {
  test('reports "no marks" for an empty drill', () => {
    expect(formatReport(computeDurations([]))).toMatch(/No marks recorded/);
  });

  test('includes every phase name and the total duration for a real drill', () => {
    const durations = computeDurations([
      { phase: 'DISASTER_DECLARED', tsMs: 0 },
      { phase: 'RECOVERY_COMPLETE', tsMs: 3_600_000 },
    ]);
    const report = formatReport(durations);
    expect(report).toContain('DISASTER_DECLARED');
    expect(report).toContain('RECOVERY_COMPLETE');
    expect(report).toContain('1h 0m 0s');
  });
});

describe('loadState / saveState (real filesystem)', () => {
  let dir;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-rto-harness-test-'));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('loadState returns [] when the state file does not exist', () => {
    expect(loadState(path.join(dir, 'nope.json'))).toEqual([]);
  });

  test('round-trips marks through save then load', () => {
    const statePath = path.join(dir, 'drill.json');
    const marks = addMark(addMark([], 'A', 1000), 'B', 2000);
    saveState(statePath, marks);
    expect(loadState(statePath)).toEqual(marks);
  });

  test('loadState tolerates a corrupt state file by returning []', () => {
    const statePath = path.join(dir, 'corrupt.json');
    fs.writeFileSync(statePath, 'not valid json{{{', 'utf8');
    expect(loadState(statePath)).toEqual([]);
  });

  test('saveState creates intermediate directories', () => {
    const statePath = path.join(dir, 'nested', 'deep', 'drill.json');
    saveState(statePath, [{ phase: 'X', tsMs: 1 }]);
    expect(fs.existsSync(statePath)).toBe(true);
  });

  test('saveState overwrites atomically, never leaving a .tmp file behind', () => {
    const statePath = path.join(dir, 'drill.json');
    saveState(statePath, [{ phase: 'A', tsMs: 1 }]);
    saveState(statePath, [{ phase: 'A', tsMs: 1 }, { phase: 'B', tsMs: 2 }]);
    const files = fs.readdirSync(dir);
    expect(files).toEqual(['drill.json']);
    expect(loadState(statePath)).toHaveLength(2);
  });
});
