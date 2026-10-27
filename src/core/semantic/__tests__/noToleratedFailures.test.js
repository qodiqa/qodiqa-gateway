'use strict';

/**
 * Anti-Regression Guard — "no silent gaps" (TEST-3 remediation requirement #10)
 *
 * TEST-3's root cause was not a bug in a classifier — it was a test suite
 * that had been deliberately calibrated to *accept* a known-exploitable
 * detection failure (a DETECTION_BASELINE of 0 for categories had
 * already confirmed bypassable) rather than catch it. Closing the detection
 * gap (see textSignals.js, i18nSignals.js, and the classifier changes) does
 * not, by itself, stop a future editor from reintroducing the same failure
 * mode — quietly lowering a baseline, marking a case `skip: true`, or
 * wrapping a known miss in a comment instead of fixing it. This file is the
 * static guard against that regression path: it scans the actual source of
 * the confirmed-exploit corpus and its two consuming test suites for the
 * vocabulary of "we know this fails and we're OK with it," and independently
 * re-derives the invariant that the four confirmed-exploit categories carry
 *
 * This is deliberately implemented as source-text scanning rather than only
 * runtime assertions: a hardcoded `expectedMiss: true` field or a
 * `test.skip(...)` call doesn't fail at runtime by itself — it just quietly
 * stops testing something. A text-level scan catches the pattern itself,
 * not just its runtime symptom.
 */

const fs = require('fs');
const path = require('path');

const GUARDED_FILES = [
  path.join(__dirname, '..', 'fixtures', 'redTeamCorpus.js'),
  path.join(__dirname, '..', 'fixtures', 'confirmedExploitsCorpus.js'),
  path.join(__dirname, 'semanticRedTeam.test.js'),
  path.join(__dirname, 'confirmedExploits.regression.test.js'),
];

// Vocabulary TEST-3 named explicitly, plus the jest mechanisms that achieve
// the same silent-disable effect without using any of those words.
const BANNED_TOKEN_PATTERNS = [
  /expectedDetection\s*[:=]\s*false/i,
  /\ballowFailure\b/i,
  /\bexpectedMiss\b/i,
  /\btoleratedFailure\b/i,
  /\binformationalOnly\b/i,
  /\bwarningOnly\b/i,
  /\bknown limitation\b/i,
  /\btemporary exception\b/i,
  /\bTODO\b/,
  /\bFIXME\b/,
  /\.skip\s*\(/,
  /\bxdescribe\s*\(/,
  /\bxtest\s*\(/,
  /\bxit\s*\(/,
  /\bskip\s*:\s*true\b/i,
  /\bdisabled\s*:\s*true\b/i,
];

describe('Anti-Regression Guard — no tolerated-failure vocabulary in the confirmed-exploit test surface', () => {
  test.each(GUARDED_FILES.map((f) => [path.relative(process.cwd(), f), f]))(
    '%s contains no banned tolerated-failure pattern',
    (_label, filePath) => {
      const source = fs.readFileSync(filePath, 'utf8');
      const hits = BANNED_TOKEN_PATTERNS
        .map((pattern) => ({ pattern: pattern.toString(), match: source.match(pattern) }))
        .filter((r) => r.match);
      expect(hits).toEqual([]);
    },
  );
});

describe('Anti-Regression Guard — confirmed-exploit categories cannot silently shrink', () => {
  // Re-require fresh (not mocked) so this test independently re-verifies
  // the same invariant semanticRedTeam.test.js enforces at runtime — this
  // file exists precisely so that invariant has two independent guards.
  const { cases, MANDATORY_CATEGORIES } = require('../fixtures/confirmedExploitsCorpus');
  const corpus = require('../fixtures/redTeamCorpus');

  const EXPECTED_MANDATORY_CATEGORIES = [
    'BASE64_ENCODED_PROMPTS',
    'UNICODE_OBFUSCATION',
    'MULTILINGUAL_ATTACKS',
    'MIXED_LANGUAGE_ATTACKS',
    // follow-up remediation: hex/Unicode-escape/duplication/
    // fragmentation/emoji-insertion bypass classes confirmed live after the
    // first pass — added here deliberately, not a narrowing.
    'HEX_ENCODED_PROMPTS',
    'UNICODE_ESCAPE_PROMPTS',
    'CHARACTER_REPETITION_EVASION',
    'FRAGMENTED_KEYWORD_EVASION',
    'EMOJI_INSERTION_EVASION',
  ];

  test('MANDATORY_CATEGORIES has not been quietly emptied or narrowed', () => {
    expect([...MANDATORY_CATEGORIES].sort()).toEqual([...EXPECTED_MANDATORY_CATEGORIES].sort());
  });

  test('the confirmed-exploit corpus has not shrunk below its current floor of 56 cases', () => {
    // A minimum, not an exact match — the corpus is expected to grow as new
    // exploits are confirmed (remediation requirement #3), never to shrink.
    // Raised from 37 to 56 by the follow-up remediation's 19 new cases.
    expect(cases.length).toBeGreaterThanOrEqual(56);
  });

  test('every mandatory category has nonzero coverage in both the regression corpus and its source category', () => {
    for (const category of MANDATORY_CATEGORIES) {
      const count = cases.filter((c) => c.category === category).length;
      expect(count).toBeGreaterThan(0);
      // The underlying red-team corpus for this category must also still
      // exist and be non-empty — deleting the source category out from
      // under the regression corpus would otherwise go unnoticed.
      expect(corpus.attacks[category] && corpus.attacks[category].length).toBeGreaterThan(0);
    }
  });

  test('no confirmed-exploit case can be individually disabled via a skip/disabled/known-limitation field', () => {
    for (const c of cases) {
      expect(c.skip).not.toBe(true);
      expect(c.disabled).not.toBe(true);
      expect(c.expectedMiss).not.toBe(true);
      expect(c.toleratedFailure).not.toBe(true);
    }
  });
});
