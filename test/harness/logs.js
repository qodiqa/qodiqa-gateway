'use strict';

/**
 * Log capture/parsing helpers built on top of helpers/filesystem.js's
 * writeLog(). Test scripts get a spawned-process handle from
 * helpers/server.js (which already captures combined stdout/stderr); this
 * module is just the "persist it to test/acceptance/logs/ with the right
 * name" and "parse the newline-delimited JSON log events" step.
 */

const { writeLog } = require('./filesystem');

/**
 * Persists a spawned process's captured output to
 * test/acceptance/logs/<filename>, returning the repo-relative path.
 *
 * @param {string} filename e.g. "AT-002-startup.log"
 * @param {{ getOutput(): string }} handle  from helpers/process.js spawnCapturing()
 */
function saveProcessLog(filename, handle) {
  return writeLog(filename, handle.getOutput());
}

/**
 * Parses newline-delimited JSON log events (services/logger.js's format)
 * out of a captured output string, silently skipping any non-JSON line
 * (banners, plain-text messages from scripts/bootstrap-dev.js, etc.).
 *
 * @param {string} output
 * @returns {object[]} parsed event records, in original order
 */
function parseEvents(output) {
  const events = [];
  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === 'object') {
        // (post-dates this framework's last full run) renamed the
        // canonical envelope fields level→severity and event→eventType
        // (services/logger.js emit()). Every acceptance script matches the
        // original names, so alias them here — one normalization point —
        // rather than editing ~100 case scripts. Records that already carry
        // level/event (none today) are left untouched.
        if (parsed.event === undefined && parsed.eventType !== undefined) parsed.event = parsed.eventType;
        if (parsed.level === undefined && parsed.severity  !== undefined) parsed.level = parsed.severity;
        events.push(parsed);
      }
    } catch {
      // not a JSON log line — plain-text banner/diagnostic output, ignored
    }
  }
  return events;
}

function findEvent(output, eventName) {
  return parseEvents(output).find((e) => e.event === eventName);
}

function eventOrder(output, eventNames) {
  const events = parseEvents(output);
  const indices = eventNames.map((name) => events.findIndex((e) => e.event === name));
  return { indices, events };
}

/**
 * Extracts the per-identity signing API key printed by
 * scripts/lib/devEnvironment.js's development banner from a captured
 * startBootstrapped() output. Returns null if no banner is present (e.g.
 * output from a startRaw() spawn).
 *
 * TRUST-1 remediation: this used to extract a bare 64-hex shared
 * QODIQA_SIGN_TOKEN. It now extracts an `sk_`-prefixed per-identity signing
 * API key (see src/core/signing/signingIdentityStore.js) — same call sites,
 * same banner location, different credential shape.
 */
function extractSignToken(output) {
  const m = output.match(/Signing API Key \(identity: [^)]*\):\n(sk_[0-9a-f]{64})/);
  return m ? m[1] : null;
}

module.exports = { saveProcessLog, parseEvents, findEvent, eventOrder, extractSignToken };
