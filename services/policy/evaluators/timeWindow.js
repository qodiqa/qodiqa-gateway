'use strict';

const DAY_INDEX = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];
const VALID_DAYS = new Set(DAY_INDEX);

function parseHHMM(str) {
  const m = /^(\d{2}):(\d{2})$/.exec(str);
  if (!m) throw new Error(`Invalid time format (expected HH:MM): ${str}`);
  const h = parseInt(m[1], 10);
  const min = parseInt(m[2], 10);
  if (h < 0 || h > 23 || min < 0 || min > 59) throw new Error(`Out-of-range time: ${str}`);
  return h * 60 + min;
}

function validate(config) {
  if (!Array.isArray(config.allowedWindows) || config.allowedWindows.length === 0) {
    throw new Error('config.allowedWindows must be a non-empty array');
  }
  for (const w of config.allowedWindows) {
    if (!Array.isArray(w.days) || w.days.length === 0) {
      throw new Error('Each window must have a non-empty days array');
    }
    for (const d of w.days) {
      if (!VALID_DAYS.has(d)) throw new Error(`Invalid day: ${d}`);
    }
    const start = parseHHMM(w.start);
    const end   = parseHHMM(w.end);
    if (start >= end) throw new Error(`Window start must be before end: ${w.start} >= ${w.end}`);
  }
}

function preprocess(config) {
  return {
    ...config,
    _windows: config.allowedWindows.map(w => ({
      days:  new Set(w.days),
      start: parseHHMM(w.start),
      end:   parseHHMM(w.end),
    })),
  };
}

// Uses context.timestamp (Unix seconds), never Date.now() — deterministic.
function evaluate(context, config) {
  if (typeof context.timestamp !== 'number' || context.timestamp <= 0) {
    return { pass: false, reason: 'TIMESTAMP_MISSING' };
  }

  const date    = new Date(context.timestamp * 1000);
  const day     = DAY_INDEX[date.getUTCDay()];
  const minutes = date.getUTCHours() * 60 + date.getUTCMinutes();

  for (const w of config._windows) {
    if (w.days.has(day) && minutes >= w.start && minutes < w.end) {
      return { pass: true };
    }
  }

  return { pass: false, reason: 'OUTSIDE_TIME_WINDOW' };
}

module.exports = { validate, preprocess, evaluate };
