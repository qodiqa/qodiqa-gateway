'use strict';

const { defineClassifier } = require('../baseClassifier');
const { SEMANTIC_REASONS, SEVERITY } = require('../../reasons');

/**
 * Detects requests that explicitly acknowledge lacking authorization for a
 * tool/API/function and ask for it anyway — "use a tool you weren't given",
 * "beyond its intended/authorized scope", or chaining one tool's output to
 * reach a resource the requester "wasn't given/authorized". Distinct from
 * toolAbuse.js, which targets MISUSING a tool's capability (destructive
 * actions, invoking privileged/admin functions, self-granting privilege) —
 * a different concept from explicitly REQUESTING access one is known to
 * lack authorization for.
 *
 * Split from toolAbuse.js: these three signals originally lived in
 * toolAbuse.js, but defineClassifier()'s
 * one-reason-per-classifier-file contract meant that file could only ever
 * report TOOL_ABUSE_ATTEMPT — even for a prompt precision-tuned to fire
 * only these three "lacks authorization" signals, never the dedicated
 * SEMANTIC_REASONS.UNAUTHORIZED_TOOL_REQUEST code that already existed in
 * the taxonomy for exactly this scenario. Split into this sibling file
 * (same signal patterns and weights, unchanged — moved, not rewritten) so
 * the reason now correctly reflects which classifier actually fired.
 * Regex text, weights, and tags are byte-for-byte identical to their prior
 * home in toolAbuse.js; only the module boundary and `reason` changed.
 *
 * set was finalized, zero co-occurrences found. These three signals are full
 * phrase-level template matches (not composed with a bare-verb structural
 * check the way toolAbuse.js's direct_invocation_by_identifier is), so no
 * analogous CAL-01-style low-weight bare-signal mitigation is needed here.
 */
const SIGNALS = [
  { pattern: /\buse (a |the )?tool (you (are|were) not|without being) (given|granted|authorized)\b/, weight: 0.40, tag: 'unauthorized_tool_phrase' },
  // Broadens unauthorized_tool_phrase's narrow "use a tool you weren't
  // given" template to general beyond/outside-scope framing.
  { pattern: /\b(use|call) (this |the )?(tool|api|function|endpoint) (beyond|outside) (its |your |the )?(intended|permitted|allowed|authorized) (scope|range|purpose|use)\b/, weight: 0.40, tag: 'tool_scope_escalation' },
  // Sequencing language — one tool call's output deliberately chained into
  // reaching a second, unauthorized resource.
  { pattern: /\buse (its|the|that) (output|result|response) to (access|reach|obtain|retrieve|call) .{0,40}\byou (weren'?t|were not|aren'?t|are not) (given|granted|authorized)\b/, weight: 0.45, tag: 'chained_tool_escalation' },
];

module.exports = defineClassifier({
  id: 'unauthorized-tool-request',
  reason: SEMANTIC_REASONS.UNAUTHORIZED_TOOL_REQUEST,
  severity: SEVERITY.HIGH,
  signals: SIGNALS,
});
