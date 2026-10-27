'use strict';

/**
 * scripts/onboarding-contract-check.js — regression coverage.
 *
 * root cause: aiChat.js has several literal `res.status(200).json(`
 * call sites (streaming pre-block BLOCK responses, artifact-decode BLOCK
 * responses, and the actual EXECUTE response, in that file order) —
 * `propsAt()`'s plain first-match `.exec()` silently picked up the FIRST
 * one (a BLOCK shape), not the intended EXECUTE response, which made this
 * check report docs/guides/quickstart.md's correct EXECUTE documentation as drift in a
 * confusing direction. Fixed with `propsAtMatching()`, which requires the
 * matched object to itself declare a specific key/value pair.
 *
 * OCC-01 — propsAtMatching() picks the EXECUTE-shaped object out of a
 *          synthetic source with multiple literal-200 call sites, mirroring
 *          aiChat.js's exact structure (BLOCK object first, EXECUTE second).
 * OCC-02 — negative control: propsAt() (the old, unfixed function) on the
 *          IDENTICAL fixture returns the wrong (BLOCK-shaped) object —
 *          proving OCC-01 isn't passing by accident and reproducing the
 *          exact pre-fix defect.
 * OCC-03 — propsAtMatching() throws a clear error if no object satisfies
 *          the predicate, rather than silently returning a wrong match.
 * OCC-04 — buildAiChatLiveTrees(), run against the REAL current
 *          src/api/routes/aiChat.js, extracts the true EXECUTE fields
 *          (response/artifactId/keyId/transparency/decision/reason/
 *          requestId) and specifically does NOT extract `details` (the
 *          BLOCK-only field that leaked through before this fix) — pins
 *          the fix against real source, not just a synthetic fixture.
 * OCC-05 — end-to-end: the full checker (buildAiChatLiveTrees() +
 *          buildDocJson() + report()) finds zero drift for the chat
 *          EXECUTE response against the real, current docs/guides/quickstart.md.
 */

const {
  propsAt,
  propsAtMatching,
  buildAiChatLiveTrees,
  buildDocJson,
  diffTrees,
  docTreeFromJson,
} = require('../onboarding-contract-check');

// Mirrors aiChat.js's real structure closely enough to reproduce the
// defect: a BLOCK-shaped `res.status(200).json(` call textually BEFORE the
// EXECUTE-shaped one, both using a literal `200`.
const MULTI_CALL_SITE_FIXTURE = `
function _enforceAndStream(res) {
  if (blocked) {
    return res.status(200).json({
      decision: 'BLOCK', reason: enforcement.reason, details: enforcement.details, requestId: reqId,
    });
  }
}

module.exports = function createRouter() {
  return function handler(req, res) {
    if (someOtherBlock) {
      return res.status(200).json({ decision: 'BLOCK', reason: 'MISSING_ARTIFACT', details: {}, requestId: reqId });
    }

    return res.status(200).json({
      decision:   'EXECUTE',
      reason:     'ALL_CHECKS_PASSED',
      response:   result.response,
      artifactId: result.artifactId,
      keyId:      result.keyId,
      requestId:  reqId,
      transparency: result.transparency,
    });
  };
};
`;

describe('scripts/onboarding-contract-check — propsAtMatching', () => {
  test('OCC-01. picks the EXECUTE-shaped object out of multiple literal-200 call sites', () => {
    const props = propsAtMatching(MULTI_CALL_SITE_FIXTURE, /return res\.status\(200\)\.json\(/, 'decision', 'EXECUTE');
    const keys = props.map((p) => p.key).sort();
    expect(keys).toEqual(['artifactId', 'decision', 'keyId', 'reason', 'requestId', 'response', 'transparency'].sort());
    expect(keys).not.toContain('details');
  });

  test('OCC-02. negative control: the OLD propsAt() picks the wrong (first, BLOCK-shaped) object on the identical fixture', () => {
    const props = propsAt(MULTI_CALL_SITE_FIXTURE, /return res\.status\(200\)\.json\(/);
    const keys = props.map((p) => p.key).sort();
    // This is the exact pre-fix defect: propsAt() finds the FIRST literal-200
    // call site (the streaming BLOCK response), not the EXECUTE one.
    expect(keys).toEqual(['decision', 'details', 'reason', 'requestId'].sort());
    expect(keys).not.toContain('response');
    expect(keys).not.toContain('artifactId');
  });

  test('OCC-03. throws a clear error when no object satisfies the predicate', () => {
    expect(() =>
      propsAtMatching(MULTI_CALL_SITE_FIXTURE, /return res\.status\(200\)\.json\(/, 'decision', 'NEVER_MATCHES')
    ).toThrow(/no object with decision: 'NEVER_MATCHES' found/);
  });
});

describe('scripts/onboarding-contract-check — buildAiChatLiveTrees against real aiChat.js', () => {
  test('OCC-04. extracts the true EXECUTE response shape, not a BLOCK shape', () => {
    const { responseTree } = buildAiChatLiveTrees();
    const keys = Object.keys(responseTree).sort();
    expect(keys).toEqual(
      // aiDisclosure is part of every EXECUTE response.
      ['decision', 'reason', 'response', 'artifactId', 'keyId', 'requestId', 'transparency', 'aiDisclosure'].sort()
    );
    // The exact field that leaked through from the wrong (BLOCK) object
    // before this fix — must never reappear in the EXECUTE tree.
    expect(keys).not.toContain('details');
  });
});

describe('scripts/onboarding-contract-check — end to end against the real repo', () => {
  test('OCC-05. zero drift between the real docs/guides/quickstart.md and the real live handlers for the chat EXECUTE response', () => {
    const { responseTree } = buildAiChatLiveTrees();
    const { chatResponseJson } = buildDocJson();

    const diff = { documentedNotInLive: [], requiredNotDocumented: [] };
    diffTrees(responseTree, docTreeFromJson(chatResponseJson), '', diff);

    expect(diff.documentedNotInLive).toEqual([]);
    expect(diff.requiredNotDocumented).toEqual([]);
  });
});
