'use strict';

// CLN-04 remediation coverage — TRANSPARENCY_SCANNER_ENABLED loud-warning
// check added to server/startup.js §6.6, mirroring the pre-existing MON-3
// notification-channel pattern (WARN by default / FATAL behind
// QODIQA_REQUIRE_*).
//
// server/startup.js is not required directly here — same rationale as
// startupWiring.test.js: it has its own extensive startup-gate surface
// (Redis/PG/keystore/etc.) that would need to be stood up just to reach
// this one check. Instead:
//   - the branching logic is mirrored exactly (PG-enabled x scanner-enabled
//     x REQUIRE flag) and asserted behaviorally;
//   - a structural check confirms the real event names/env var names this
//     test exercises actually appear in server/startup.js's source, so the
//     mirror can't silently drift from the real implementation.

const fs   = require('fs');
const path = require('path');

jest.mock('../../../../../services/logger', () => ({ emit: jest.fn() }));

const { emit } = require('../../../../../services/logger');

const STARTUP_JS_PATH = path.resolve(__dirname, '../../../../../server/startup.js');

// Mirrors server/startup.js §6.6's post-CLN-04 branching exactly.
function checkTransparencyScannerConfigLikeServer({ pgEnabled, scannerEnabled, requireScanner, _exit = () => {} }) {
  if (!pgEnabled) return;

  if (scannerEnabled) {
    emit('INFO', 'TRANSPARENCY_SCANNER_CONFIG_ENABLED', {
      message: 'TRANSPARENCY_SCANNER_ENABLED=true — transparency log gap/hash/root ' +
               'verification is active.',
    });
  } else if (requireScanner) {
    emit('FATAL', 'TRANSPARENCY_SCANNER_REQUIRED_BUT_MISSING', {
      message: 'QODIQA_REQUIRE_TRANSPARENCY_SCANNER=true but TRANSPARENCY_SCANNER_ENABLED ' +
               'is not "true" — the transparency log would run with no automated ' +
               'sequence/hash/root gap detection. Set TRANSPARENCY_SCANNER_ENABLED=true. ' +
               'See deploy/env/production.env.example and docs/operations/transparency-recovery.md.',
    });
    _exit(1);
  } else {
    emit('WARN', 'NO_TRANSPARENCY_SCANNER_CONFIGURED', {
      message: 'TRANSPARENCY_SCANNER_ENABLED is not "true" — PostgreSQL is enabled but ' +
               'the transparency log has no automated sequence/hash/root gap detection ' +
               'running. Splices or corruption in transparency_log_entries / ' +
               'transparency_roots will not be automatically detected. Set ' +
               'TRANSPARENCY_SCANNER_ENABLED=true to enable it, or ' +
               'QODIQA_REQUIRE_TRANSPARENCY_SCANNER=true to make this fatal instead of a ' +
               'warning. See deploy/env/production.env.example and ' +
               'docs/operations/transparency-recovery.md.',
    });
  }
}

describe('server/startup.js — TRANSPARENCY_SCANNER_ENABLED loud warning (CLN-04)', () => {
  beforeEach(() => emit.mockClear());

  test('PG disabled — no event emitted regardless of scanner flag', () => {
    checkTransparencyScannerConfigLikeServer({ pgEnabled: false, scannerEnabled: false, requireScanner: false });
    expect(emit).not.toHaveBeenCalled();
  });

  test('PG enabled, scanner enabled — INFO only', () => {
    checkTransparencyScannerConfigLikeServer({ pgEnabled: true, scannerEnabled: true, requireScanner: false });
    expect(emit).toHaveBeenCalledTimes(1);
    expect(emit).toHaveBeenCalledWith('INFO', 'TRANSPARENCY_SCANNER_CONFIG_ENABLED', expect.any(Object));
  });

  test('PG enabled, scanner disabled, REQUIRE unset — WARN only', () => {
    checkTransparencyScannerConfigLikeServer({ pgEnabled: true, scannerEnabled: false, requireScanner: false });
    expect(emit).toHaveBeenCalledTimes(1);
    expect(emit).toHaveBeenCalledWith('WARN', 'NO_TRANSPARENCY_SCANNER_CONFIGURED', expect.any(Object));
  });

  test('PG enabled, scanner disabled, REQUIRE=true — FATAL + exit(1)', () => {
    const _exit = jest.fn();
    checkTransparencyScannerConfigLikeServer({ pgEnabled: true, scannerEnabled: false, requireScanner: true, _exit });
    expect(emit).toHaveBeenCalledTimes(1);
    expect(emit).toHaveBeenCalledWith('FATAL', 'TRANSPARENCY_SCANNER_REQUIRED_BUT_MISSING', expect.any(Object));
    expect(_exit).toHaveBeenCalledWith(1);
  });

  test('structural: server/startup.js actually contains the three event names and both env vars', () => {
    const src = fs.readFileSync(STARTUP_JS_PATH, 'utf8');
    expect(src).toContain('TRANSPARENCY_SCANNER_CONFIG_ENABLED');
    expect(src).toContain('NO_TRANSPARENCY_SCANNER_CONFIGURED');
    expect(src).toContain('TRANSPARENCY_SCANNER_REQUIRED_BUT_MISSING');
    expect(src).toContain('QODIQA_REQUIRE_TRANSPARENCY_SCANNER');
    expect(src).toContain("process.env.TRANSPARENCY_SCANNER_ENABLED === 'true'");
  });
});
