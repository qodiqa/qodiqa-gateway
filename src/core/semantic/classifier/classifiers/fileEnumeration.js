'use strict';

const { defineClassifier } = require('../baseClassifier');
const { coOccurs } = require('../../textSignals');
const { SEMANTIC_REASONS, SEVERITY } = require('../../reasons');

/**
 * Detects attempts to have the model enumerate, traverse, or dump the
 * contents of a filesystem/directory the requester has no legitimate,
 * scoped view into — distinct from toolAbuse.js (invoking a tool outside
 * authorization) and dataExfiltration.js (sending already-obtained data
 * externally); this classifier is specifically about eliciting the
 * listing/traversal/contents-dump in the first place.
 *
 * Taxonomy:
 * SEMANTIC_REASONS.FILE_SYSTEM_ENUMERATION already existed in reasons.js
 * with no bundled classifier (see docs/architecture/content-screening.md's own
 * "no bundled classifier" list) — reused directly, no taxonomy extension
 * needed. Unlike the paraphrase/roleplay classifiers (which had no existing reason,
 * forcing an evasion_technique metadata-field carry), that precedent simply
 * doesn't apply here: the taxonomy already anticipated this classifier.
 *
 * Four pattern classes, each threat-model-derived (technique class, not
 * corpus phrasing):
 *   - unscoped_enumeration_imperative: "list every file ON THE SERVER" —
 *     the system-wide/unscoped qualifier is mandatory in the pattern (not
 *     optional), which is what distinguishes it from a legitimate, scoped
 *     "list the files in my project" — that never matches this signal.
 *   - path-traversal primitives (TRAVERSAL_PRIMITIVE) co-occurring with an
 *     access verb: the syntactic signature of a traversal attempt (literal
 *     "../../", or a sensitive absolute root path), not the topic of the
 *     sentence — a security-education question that merely discusses path
 *     traversal as a concept contains neither the literal syntax nor an
 *     access verb next to it.
 *   - sensitive-path targeting (SENSITIVE_PATH) co-occurring with an access
 *     verb: canonical known-sensitive locations (.env, SSH keys,
 *     /etc/shadow, credential stores) combined with a read/dump verb.
 *   - bulk_dump_framing / directory_tree_walk: recursive/bulk-dump
 *     framing, distinct from a single-file read request.
 *
 * zero hits/co-occurrences for every pattern below, including specifically
 * traversal prevented" quoted-control items — this classifier's flagged
 * overall): every declared signal requires an imperative-verb-adjacent
 * structure with a mandatory scope/syntax/sensitivity qualifier, which the
 * ASVS template's 3rd-person, quoted, nominal phrasing ("Directory listing
 * disabled") never satisfies — it names no verb, no object, no literal
 * traversal syntax, and no sensitive-path token. TRAVERSAL_PRIMITIVE and
 * SENSITIVE_PATH are deliberately NOT declared as their own low-weight bare
 * signals (unlike ACCESS_VERB below) — a benign question that merely
 * mentions "../" syntax or ".env files" educationally is a plausible
 * legitimate collision (same reasoning as toolAbuse.js's IDENTIFIER_TOKEN
 * and policyBypass.js's CONSTRAINT_NEGATION exclusions); they only ever
 * contribute via the structural coOccurs proximity check in refine().
 * ACCESS_VERB alone (read/access/open/show/reveal/dump/output/retrieve/
 * fetch/print/display/cat) is common in wholly unrelated benign text, so it
 * is declared at CAL-01-style low weight (0.15) — never solo-triggers WARN.
 */
const ACCESS_VERB = /\b(read|access|open|show|reveal|dump|output|retrieve|fetch|print|display|cat)\b/;
const TRAVERSAL_PRIMITIVE = /\.\.[/\\](?:\.\.[/\\])+|\/etc\/|\/root\/|c:\\windows|c:\\users/;
const SENSITIVE_PATH = /\b(\.env|id_rsa|id_ed25519|authorized_keys|ssh private key|credentials file|shadow file)\b|\/etc\/(shadow|passwd)\b|\.aws\/credentials/;

const SIGNALS = [
  // Enumeration imperative + mandatory unscoped/system-wide qualifier — the
  // qualifier is NOT optional, so a legitimate "list all files in my
  // project" never matches this shape.
  { pattern: /\b(list|show|enumerate|display)( me| us)? (all|every) (files?|directories|folders) (on (the )?(server|system|disk|machine)|in (the )?(filesystem|file system)|on this (server|system|machine))\b/, weight: 0.40, tag: 'unscoped_enumeration_imperative' },
  // Recursive/bulk-dump framing.
  { pattern: /\b(dump|output|show) (the )?(entire )?contents? of (every|all) files? in\b/, weight: 0.45, tag: 'bulk_dump_framing' },
  { pattern: /\bwalk (the )?directory tree and (show|list|dump)\b/, weight: 0.40, tag: 'directory_tree_walk' },
  // Bare-keyword half of the traversal/sensitive-path structural checks
  // below — CAL-01 style: alone, an access verb is common in wholly
  // unrelated benign text, so this stays far below WARN on its own.
  { pattern: ACCESS_VERB, weight: 0.15, tag: 'access_verb_bare' },
];

module.exports = defineClassifier({
  id: 'file-enumeration',
  reason: SEMANTIC_REASONS.FILE_SYSTEM_ENUMERATION,
  severity: SEVERITY.HIGH,
  signals: SIGNALS,
  refine(text, base) {
    let confidence = base.confidence;
    if (coOccurs(text, TRAVERSAL_PRIMITIVE, ACCESS_VERB, 80)) {
      confidence = Math.min(1, confidence + 0.45);
    }
    if (coOccurs(text, SENSITIVE_PATH, ACCESS_VERB, 80)) {
      confidence = Math.min(1, confidence + 0.45);
    }
    return { confidence, matched: base.matched };
  },
});
