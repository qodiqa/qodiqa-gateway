'use strict';

/**
 * Shared, deterministic text-analysis primitives for semantic classifiers.
 *
 * Every classifier in classifier/classifiers/ is declarative: it supplies a
 * set of weighted signals (not a single pattern) and this module scores them.
 * This is the piece that keeps the engine from degenerating into "keyword
 * list = malicious": no single signal alone determines a verdict — matched
 * signals combine probabilistically (see scoreSignals), and classifiers can
 * layer structural refinements (see coOccurs) on top, such as requiring an
 * override verb and a security-control noun to appear near each other rather
 * than anywhere in the text independently.
 *
 * Nothing here calls an external model or service — every function is a pure,
 * synchronous function of its input string, which is what makes the engine's
 * final decision deterministic and reproducible (see src/core/semantic/index.js).
 *
 * TEST-3 / remediation (encode-and-rescan + confusable folding):
 * demonstrated that literal English-phrase regexes are trivially
 * bypassed by base64 encoding ("no classifier decodes embedded base64") and
 * cross-script homoglyph substitution ("NFKC does not collapse cross-script
 * homoglyphs (Cyrillic а/е/о survive NFKC unchanged from Latin a/e/o)").
 * normalize() below now performs a bounded decode-and-rescan pass (base64 /
 * hex / URL-encoding / HTML entities / Unicode escapes, recursively, so
 * nested encodings are also unwrapped), folds common Cyrillic/Greek
 * confusables plus Latin diacritics, strips pictographic (emoji) evasion
 * characters, collapses character-repetition evasion, and reconstructs a
 * curated set of high-signal attack keywords that have been split apart by
 * inserted whitespace/punctuation — before any pattern is evaluated. This is
 * a single shared normalization change, not a per-classifier patch, so every
 * existing and future classifier benefits without modification.
 *
 * follow-up remediation (fragmentation/duplication/hex/unicode-escape):
 * closes the remaining bypass classes confirmed live after the first pass —
 * hex-encoded payloads, literal `\uXXXX`/`\xXX` escape sequences, character-
 * duplication ("deeeellleeettteeee"), emoji-interleaved keywords, and
 * keywords fragmented by punctuation/whitespace ("d.e.l.e.t.e",
 * "d-e-l-e-t-e", "d_e_l_e_t_e", "d e l e t e", or an arbitrary two-piece
 * split such as "ig nore"). All of it is deterministic, synchronous,
 * dictionary-bounded (not generic NLP/ML), and additive: it never mutates
 * the caller's original string, only the copy used for signal scoring.
 */

// Zero-width and bidi control characters are a known lexical-scanner evasion
// technique (e.g. inserting U+200B between letters of a flagged word). They
// carry no legitimate meaning in a plain-text prompt, so they are stripped
// before any pattern is evaluated, not treated as a signal themselves.
const EVASION_CHARS = /[​-‏‪-‮⁠﻿]/g;
// Non-global mirror of EVASION_CHARS for presence checks: `.test()` on a
// global-flag regex mutates its `lastIndex`, which would corrupt later calls
// against that same shared instance (see the follow-up note on
// analyzeNormalization() below). This copy is only ever used with `.test()`.
const EVASION_CHARS_PRESENT = new RegExp(EVASION_CHARS.source);

// Emoji/pictographic characters used the same way — inserted between the
// letters of a flagged word so a literal-phrase regex no longer matches
// (e.g. "i🔥g🔥n🔥o🔥r🔥e"). \p{Extended_Pictographic} covers the emoji block
// plus dingbats/symbols commonly used this way, without touching ordinary
// punctuation or any script's letters, so genuine emoji use in benign text
// (a normal "🎉" at the end of a sentence) is simply removed, not treated as
// suspicious in itself — only its role as an inter-letter separator matters,
// and that is what the reconstruction pass below defeats.
const PICTOGRAPHIC_CHARS = /\p{Extended_Pictographic}/gu;
// Non-global mirror for presence checks — see EVASION_CHARS_PRESENT above.
const PICTOGRAPHIC_CHARS_PRESENT = new RegExp(PICTOGRAPHIC_CHARS.source, 'u');

// Cross-script confusables used in homoglyph-substitution attacks:
// visually identical or near-identical Cyrillic/Greek characters standing in
// for their Latin lookalikes so a literal English-phrase regex no longer
// matches (e.g. "hаve" with Cyrillic а, U+0430, instead of Latin a). Folding
// these to their Latin equivalent before matching closes that bypass for
// every classifier at once. Deliberately limited to characters that are true
// visual confusables of common Latin letters used in attack-phrase
// vocabulary — not a full confusables-table import — to avoid corrupting
// legitimate Cyrillic/Greek text (e.g. a Russian-language benign question)
// any more than swapping a handful of letters for their Latin twins already
// would; genuine Cyrillic/Greek attack phrases are separately handled by the
// multilingual signals in i18nSignals.js, not by this folding step.
const CONFUSABLES = Object.freeze({
  // Cyrillic → Latin
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
  'х': 'x', 'у': 'y', 'і': 'i', 'ѕ': 's', 'ј': 'j',
  'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ѡ': 'w', 'ґ': 'r',
  // Greek → Latin
  'α': 'a', 'ο': 'o', 'ρ': 'p', 'υ': 'y', 'χ': 'x',
  'ι': 'i', 'κ': 'k', 'ν': 'v', 'β': 'b',
  // IPA/phonetic-extension small-capital letters that NFKC does not fold to
  // their plain-Latin base (distinct codepoints, not compatibility
  // decompositions) but that superscript/small-caps obfuscation schemes
  // leave behind after NFKC resolves the surrounding superscript letters —
  // e.g. U+1DA6 MODIFIER LETTER SMALL CAPITAL I decomposes under NFKC to
  // U+026A LATIN LETTER SMALL CAPITAL I, not to plain "i".
  'ɪ': 'i', 'ʟ': 'l', 'ʀ': 'r', 'ɴ': 'n', 'ʜ': 'h',
});

// Folding is scoped to individual word tokens, and only applied to a token
// that mixes Latin letters with confusable Cyrillic/Greek ones — the actual
// signature of a homoglyph-substitution attack (a handful of foreign
// lookalikes swapped into an otherwise-Latin word, e.g. "Ignоrе" with
// Cyrillic о/е). An unmixed, all-Cyrillic/Greek token is left untouched:
// folding it would corrupt genuine non-English text (e.g. a real Russian
// sentence) into a garbled Latin/Cyrillic hybrid that matches neither the
// English signals nor the multilingual signals in i18nSignals.js.
// Combining Diacritical Marks block (U+0300-U+036F) — covers Latin accents
// (é, ș, ü, ...) but is also produced by NFKD-decomposing certain non-Latin
// precomposed characters that happen to reuse marks from this same block
// (e.g. Cyrillic й/Й, U+0439/U+0419, decomposes to и/И + U+0306 COMBINING
// BREVE). A blanket strip of the whole block therefore corrupts genuine
// Cyrillic text (й -> и) in addition to folding Latin accents. Scoping the
// strip to marks that directly follow an ASCII Latin base letter avoids
// that: Latin diacritics are still folded (helping match unaccented Latin
// signals against accented input), while a mark following a non-Latin base
// letter is left alone so the later NFC pass can recompose it correctly.
const COMBINING_MARK = /[̀-ͯ]/;

function stripLatinDiacritics(text) {
  let out = '';
  let prevIsAsciiLatin = false;
  for (const ch of text) {
    if (COMBINING_MARK.test(ch)) {
      if (prevIsAsciiLatin) continue; // drop: Latin diacritic
      out += ch; // keep: belongs to a non-Latin base, recomposed below
      continue;
    }
    out += ch;
    prevIsAsciiLatin = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
  }
  return out;
}

/**
 * Case-preserving confusable fold —.
 *
 * CONFUSABLES is written with lowercase keys only ('е' -> 'e'), which is
 * safe for the primary pipeline because that pipeline case-folds BEFORE
 * folding confusables (see normalizeWithMeta()'s own comment on why that
 * ordering matters). The case-preserved variant cannot case-fold first —
 * preserving case is its entire purpose — so it would otherwise miss every
 * uppercase homoglyph and hand a silently unfolded string to the
 * case-shape detection that depends on it.
 *
 * Resolution: look the character up as written; failing that, look up its
 * lowercase form and restore the original case on the replacement. No
 * second, hand-maintained uppercase table is needed now or for any script
 * added to CONFUSABLES later — the same reasoning the primary pipeline
 * already applies, reached by the other direction.
 *
 * foldConfusables() itself is deliberately NOT modified: it only ever
 * receives already-lowercased text, so its behaviour is unchanged and the
 * primary decision path is untouched.
 */
function foldConfusablePreservingCase(ch) {
  const direct = CONFUSABLES[ch];
  if (direct) return direct;
  const lower = ch.toLowerCase();
  if (lower === ch) return ch;
  const folded = CONFUSABLES[lower];
  return folded ? folded.toUpperCase() : ch;
}

function foldConfusablesPreservingCase(text) {
  return text.replace(/[\p{L}\p{M}]+/gu, (word) => {
    let hasLatin = false;
    let hasConfusable = false;
    for (const ch of word) {
      if (CONFUSABLES[ch] || (ch.toLowerCase() !== ch && CONFUSABLES[ch.toLowerCase()])) hasConfusable = true;
      else if (ch >= 'a' && ch <= 'z') hasLatin = true;
      else if (ch >= 'A' && ch <= 'Z') hasLatin = true;
    }
    if (!hasLatin || !hasConfusable) return word;
    let out = '';
    for (const ch of word) out += foldConfusablePreservingCase(ch);
    return out;
  });
}

function foldConfusables(text) {
  return text.replace(/[\p{L}\p{M}]+/gu, (word) => {
    let hasLatin = false;
    let hasConfusable = false;
    for (const ch of word) {
      if (CONFUSABLES[ch]) hasConfusable = true;
      else if (ch >= 'a' && ch <= 'z') hasLatin = true;
      else if (ch >= 'A' && ch <= 'Z') hasLatin = true;
    }
    if (!hasLatin || !hasConfusable) return word;
    let out = '';
    for (const ch of word) out += CONFUSABLES[ch] || ch;
    return out;
  });
}

// ── Decode-and-rescan ──

const BASE64_CANDIDATE = /[A-Za-z0-9+/_-]{20,}={0,2}/g;

// Security limits: bound decode
// depth, per-call candidate count, and total expansion size so a
// pathological input cannot force unbounded or superlinear work. These are
// deliberately generous relative to the 32KB request-body cap already
// enforced in src/validation/schemas/aiChat.schema.js — this is defense in
// depth for this module in isolation, not the primary size control.
const MAX_DECODE_DEPTH = 3;
const MAX_CANDIDATES_PER_PASS = 50;
const MAX_EXPANSION_MULTIPLE = 5;
// Comfortably above the 32KB request-body cap enforced upstream
// (src/validation/schemas/aiChat.schema.js), so this never truncates a
// legitimate in-policy prompt — it exists purely to bound the cost of any
// input that reaches this module by some future or alternate path.
const MAX_NORMALIZE_INPUT_LENGTH = 40000;
// Absolute ceiling on the fully decode-expanded text, independent of the
// per-level MAX_EXPANSION_MULTIPLE multiplier — bounds worst-case nested-
// encoding blowup (MAX_EXPANSION_MULTIPLE ** MAX_DECODE_DEPTH) to a fixed,
// small multiple of the input cap rather than letting it compound unbounded.
const MAX_TOTAL_NORMALIZE_LENGTH = 200000;

/**
 * Shared validation for a candidate decoded byte sequence: must be valid
 * UTF-8, of meaningful length, and mostly printable text. This is what keeps
 * every decoder below from firing on arbitrary binary garbage or on
 * non-encoded tokens that merely happen to be decodable (a random 24-char
 * hex string, an opaque ID) without producing readable instructions.
 */
function isMeaningfulPlainText(decoded) {
  if (decoded.includes('�')) return false; // invalid UTF-8
  if (decoded.length < 6) return false;
  const printable = decoded.replace(/[^\x20-\x7E\s]/g, '').length;
  return printable / decoded.length >= 0.85;
}

/**
 * Attempt to decode `candidate` as base64 (standard or URL-safe alphabet)
 * and validate that it round-trips and decodes to mostly-printable text —
 * this is what keeps the decoder from firing on arbitrary long alphanumeric
 * tokens (API keys, hashes, IDs) that are not actually base64-encoded
 * instructions: a non-base64 token will not round-trip cleanly, and binary
 * garbage will fail the printable-ratio check.
 */
function tryBase64Decode(candidate) {
  if (candidate.length < 20) return null;
  const std = candidate.replace(/-/g, '+').replace(/_/g, '/');
  const padded = std + '='.repeat((4 - (std.length % 4)) % 4);
  let buf;
  try {
    buf = Buffer.from(padded, 'base64');
  } catch {
    return null;
  }
  if (!buf.length) return null;
  const roundTrip = buf.toString('base64').replace(/=+$/, '');
  if (roundTrip !== std.replace(/=+$/, '')) return null;

  const decoded = buf.toString('utf8');
  return isMeaningfulPlainText(decoded) ? decoded : null;
}

// Hex candidates: an even-length run of hex digits, optionally separated by
// single spaces or "0x" byte prefixes (e.g. "0x69 0x67 0x6e ..."). Minimum
// group count (6 bytes / 12 hex chars) matches isMeaningfulPlainText()'s own
// length floor below — no point admitting shorter candidates that could
// never pass it, and this is short enough to still catch a single hex-
// encoded keyword like "delete" or "sudo", not just full phrases.
const HEX_CANDIDATE = /(?:0x)?[0-9A-Fa-f]{2}(?:[ ]?(?:0x)?[0-9A-Fa-f]{2}){5,}/g;

function tryHexDecode(candidate) {
  const cleaned = candidate.replace(/0x/gi, '').replace(/\s+/g, '');
  if (cleaned.length < 16 || cleaned.length % 2 !== 0) return null;
  if (!/^[0-9A-Fa-f]+$/.test(cleaned)) return null;
  let buf;
  try {
    buf = Buffer.from(cleaned, 'hex');
  } catch {
    return null;
  }
  if (!buf.length) return null;
  const decoded = buf.toString('utf8');
  return isMeaningfulPlainText(decoded) ? decoded : null;
}

function decodeUrlEncoding(text) {
  if (!/%[0-9A-Fa-f]{2}/.test(text)) return null;
  try {
    const decoded = decodeURIComponent(text);
    return decoded !== text ? decoded : null;
  } catch {
    return null;
  }
}

const HTML_NAMED_ENTITIES = Object.freeze({
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ',
});

function decodeHtmlEntities(text) {
  if (!/&(#\d+|#x[0-9a-f]+|[a-z]+);/i.test(text)) return null;
  const decoded = text.replace(/&(#\d+|#x[0-9a-f]+|[a-z]+);/gi, (whole, ent) => {
    if (ent[0] === '#') {
      const isHex = ent[1] === 'x' || ent[1] === 'X';
      const code = isHex ? parseInt(ent.slice(2), 16) : parseInt(ent.slice(1), 10);
      return Number.isFinite(code) && code >= 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
    }
    const key = ent.toLowerCase();
    return HTML_NAMED_ENTITIES[key] || whole;
  });
  return decoded !== text ? decoded : null;
}

// Literal Unicode/hex escape sequences typed as text — not actual Unicode
// codepoints, but the source-code-style escape spelling of one (e.g. a
// prompt containing the literal six characters `\`, `u`, `0`, `0`, `6`, `9`
// instead of the character "i"). A regex/keyword classifier scanning the raw
// characters never sees "i" here unless this is decoded first.
const UNICODE_ESCAPE = /\\u\{([0-9A-Fa-f]{1,6})\}|\\u([0-9A-Fa-f]{4})|\\x([0-9A-Fa-f]{2})/g;

function decodeUnicodeEscapes(text) {
  if (!UNICODE_ESCAPE.test(text)) return null;
  UNICODE_ESCAPE.lastIndex = 0;
  const decoded = text.replace(UNICODE_ESCAPE, (whole, braced, u4, x2) => {
    const code = parseInt(braced || u4 || x2, 16);
    if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return whole;
    try {
      return String.fromCodePoint(code);
    } catch {
      return whole;
    }
  });
  return decoded !== text ? decoded : null;
}

const EMPTY_DECODE_FLAGS = Object.freeze({ base64: false, hex: false, url: false, html: false, unicodeEscape: false });

function mergeDecodeFlags(a, b) {
  return {
    base64: a.base64 || b.base64,
    hex: a.hex || b.hex,
    url: a.url || b.url,
    html: a.html || b.html,
    unicodeEscape: a.unicodeEscape || b.unicodeEscape,
  };
}

/**
 * Returns { text, flags } instead of a bare string so callers (specifically
 * analyzeNormalization()) can report *which* decoders actually contributed —
 * derived from the real decode attempts here, not by re-scanning the input
 * with a second, separate pattern afterward (which would risk drifting from
 * what was actually decoded, and would require re-using the same global-flag
 * regexes with `.test()`, mutating their `lastIndex` for later calls).
 */
function expandEncodedContent(rawText, depth = 0) {
  if (depth >= MAX_DECODE_DEPTH || typeof rawText !== 'string' || !rawText) {
    return { text: '', flags: EMPTY_DECODE_FLAGS };
  }

  const found = [];
  let flags = EMPTY_DECODE_FLAGS;

  const b64Candidates = (rawText.match(BASE64_CANDIDATE) || []).slice(0, MAX_CANDIDATES_PER_PASS);
  for (const candidate of b64Candidates) {
    const decoded = tryBase64Decode(candidate);
    if (decoded) { found.push(decoded); flags = { ...flags, base64: true }; }
  }

  const hexCandidates = (rawText.match(HEX_CANDIDATE) || []).slice(0, MAX_CANDIDATES_PER_PASS);
  for (const candidate of hexCandidates) {
    const decoded = tryHexDecode(candidate);
    if (decoded) { found.push(decoded); flags = { ...flags, hex: true }; }
  }

  const urlDecoded = decodeUrlEncoding(rawText);
  if (urlDecoded) { found.push(urlDecoded); flags = { ...flags, url: true }; }

  const htmlDecoded = decodeHtmlEntities(rawText);
  if (htmlDecoded) { found.push(htmlDecoded); flags = { ...flags, html: true }; }

  const escapeDecoded = decodeUnicodeEscapes(rawText);
  if (escapeDecoded) { found.push(escapeDecoded); flags = { ...flags, unicodeEscape: true }; }

  if (!found.length) return { text: '', flags };

  const cap = rawText.length * MAX_EXPANSION_MULTIPLE;
  let expanded = found.join(' ');
  for (const piece of found) {
    if (expanded.length >= cap) break;
    const nested = expandEncodedContent(piece, depth + 1);
    if (nested.text) expanded += ' ' + nested.text;
    flags = mergeDecodeFlags(flags, nested.flags);
  }
  const text = expanded.length > cap ? expanded.slice(0, cap) : expanded;
  return { text, flags };
}

/**
 * SUBSTITUTING decoder —. Purely additive: nothing above or below this
 * function is modified, `normalize()` is untouched, and no existing caller
 * reaches this code.
 *
 * WHY A SECOND SHAPE OF THE SAME OPERATION. expandEncodedContent() above
 * APPENDS what it decodes (`${truncated} ${decodedExtra}`), which is right for
 * a scanner: a regex wants to see both the original surface and the payload,
 * and carrying the undecoded blob along costs a pattern match nothing.
 *
 * It is wrong for a representation model, and measured how wrong.
 * Feeding normalize()'s appended form to the embedding gates turned the frozen
 * them a `B64SRC:` hard negative, i.e. ordinary text that legitimately contains
 * a base64 blob. Removing the blob and scoring only the decoded content
 * returned all 13 to ALLOW, with v9 falling consistently (0.758->0.675,
 * 0.697->0.590, 0.690->0.565, 0.531->0.384, 0.498->0.261) and FT-3 going from
 * fired to not fired. The retained blob was the cause, not the payload: it is
 * high-entropy noise that drags both the embedding and v9's own surface
 * features (digit ratio, non-alphanumeric ratio, log length) out of the
 * distribution their thresholds were calibrated against.
 *
 * The same substitution IMPROVES the adversarial side rather than trading
 * because the payload is no longer diluted by the blob it arrived in.
 *
 * So: one decoder implementation, two composition rules, each matched to what
 * consumes it. The bounds (depth, candidate count, total length) are the same
 * constants the appending path uses, so neither can be tightened without the
 * other noticing.
 *
 * @param {string} rawText
 * @returns {string} the text with every decodable encoded segment REPLACED by
 *   its plaintext. Returns the input unchanged when nothing decodes.
 */
function substituteEncodedContent(rawText) {
  if (typeof rawText !== 'string' || !rawText) return '';

  let text = rawText.length > MAX_NORMALIZE_INPUT_LENGTH
    ? rawText.slice(0, MAX_NORMALIZE_INPUT_LENGTH)
    : rawText;

  for (let depth = 0; depth < MAX_DECODE_DEPTH; depth++) {
    const before = text;

    // Whole-text decoders first: these are already substitutions by nature —
    // decodeURIComponent and the entity/escape replacers rewrite in place.
    const url = decodeUrlEncoding(text);
    if (url) text = url;
    const html = decodeHtmlEntities(text);
    if (html) text = html;
    const esc = decodeUnicodeEscapes(text);
    if (esc) text = esc;

    // Segment decoders: replace the matched blob with its plaintext instead of
    // appending it. Capped per pass exactly as expandEncodedContent() caps its
    // own candidate list.
    let b64Used = 0;
    text = text.replace(BASE64_CANDIDATE, (candidate) => {
      if (b64Used >= MAX_CANDIDATES_PER_PASS) return candidate;
      const decoded = tryBase64Decode(candidate);
      if (!decoded) return candidate;
      b64Used += 1;
      return decoded;
    });

    let hexUsed = 0;
    text = text.replace(HEX_CANDIDATE, (candidate) => {
      if (hexUsed >= MAX_CANDIDATES_PER_PASS) return candidate;
      const decoded = tryHexDecode(candidate);
      if (!decoded) return candidate;
      hexUsed += 1;
      return decoded;
    });

    if (text === before) break; // fixed point: nothing further decodes
    if (text.length > MAX_TOTAL_NORMALIZE_LENGTH) {
      text = text.slice(0, MAX_TOTAL_NORMALIZE_LENGTH);
      break;
    }
  }

  return text;
}

// ── Character-repetition collapse ──
//
// Three-or-more identical consecutive letters is a duplication-for-evasion
// signature, not something ordinary prose or any language in scope produces
// (the longest legitimate same-letter run in English/Romanian/French/etc. is
// 2 — "committee", "Mississippi", "voiture" have no run of 3). Collapsing
// runs of 3+ down to a single instance is therefore safe for legitimate text
// while defeating "deeeellleeettteeee" -> "delete".
const REPEATED_CHAR = /(\p{L})\1{2,}/gu;

function collapseRepeatedChars(text) {
  return text.replace(REPEATED_CHAR, '$1');
}

// ── Fragmented-keyword reconstruction (follow-up: punctuation/whitespace-
// spelled and arbitrarily-split keywords) ──
//
// A small, curated set of the highest-signal attack-vocabulary terms already
// referenced (in contiguous form) by this engine's classifiers. Each entry
// is matched via a bounded "fuzzy" pattern that tolerates a short run of
// separator characters between every letter, then rewritten to its plain
// canonical spelling. This is what turns "d.e.l.e.t.e", "d-e-l-e-t-e",
// "d_e_l_e_t_e", "d e l e t e", and an arbitrary split like "ig nore" or
// "igno re" into a form the classifiers' existing phrase regexes can match —
// the separator may legally fall at any single letter boundary (including
// just one), so a two-fragment split is defeated the same way full
// letter-by-letter spelling is.
//
// Deliberately dictionary-bounded rather than a generic "join any adjacent
// short tokens" transform: blindly merging arbitrary tokens would corrupt
// ordinary short-token prose (initials, "e.g.", "i.e.") into false signal
// matches. Restricting reconstruction to this fixed vocabulary keeps that
// blast radius to "a benign sentence coincidentally spells out one of these
// ~40 specific words letter-by-letter with punctuation between," which does
// not happen in normal writing. Ambiguous common words that collide with
// ordinary names/usage (e.g. "dan" — see jailbreak.js's CAL-03 note) are
// deliberately excluded.
const KEYWORD_DICTIONARY = Object.freeze([
  'ignore', 'disregard', 'override', 'bypass', 'circumvent', 'jailbreak',
  'unrestricted', 'unfiltered', 'unlock', 'delete', 'extract', 'exfiltrate',
  'reveal', 'credentials', 'password', 'sudo', 'disable', 'suppress',
  'confidential', 'malware', 'exploit', 'vulnerability', 'illegal', 'hack',
  'secret', 'forget', 'pretend', 'hypothetical', 'authorized', 'developer',
  'unlocked', 'liberated', 'previous instructions', 'system prompt',
  'security controls', 'safety guidelines', 'signing token', 'private key',
  'access token', 'environment variables',
]);

// Space, hyphen, underscore, dot, comma, semicolon, colon, pipe — up to two
// in a row. Deliberately excludes letters/digits (so it can never "skip
// over" unrelated real content) and is capped at 2 to keep proximity tight
// (long runs of punctuation between letters stop matching, which is fine —
// that stretches well past what any of the evasion examples in scope need).
const FRAGMENT_SEP = '[\\s\\-_.,;:|]{0,2}';
// Separator allowed *between repeats of the same letter* (see
// buildFragmentPattern) — deliberately excludes whitespace and is capped at
// 1, unlike FRAGMENT_SEP above. A bare space is the ordinary boundary
// between two different words, not a duplication-evasion gap; allowing it
// here let a trailing repeated letter of one word (e.g. the second "s" in
// "bypass") chain across the space into an unrelated following word that
// happened to start with the same letter (e.g. "security"), corrupting the
// match. Punctuation-only, max 1, still covers the in-scope duplication
// examples ("d.e.e.e.l.e.t.e") without that cross-word risk.
const REPEAT_SEP = '[\\-_.,;:|]{0,1}';

/**
 * Collapses consecutive duplicate characters to one, e.g. ['b','y','p','a',
 * 's','s'] -> ['b','y','p','a','s']. Used so a canonical word with a
 * legitimate doubled letter (e.g. "bypass") produces one pattern position
 * for that letter, quantified with `+` (see buildFragmentPattern) rather
 * than requiring exactly two — which would otherwise fail to match after
 * collapseRepeatedChars() has already reduced a 3+ duplication-evasion run
 * down to fewer occurrences than the correct spelling has (e.g. "bypasss"
 * legitimately collapses to "bypas", one s short of "bypass").
 */
function dedupeConsecutive(chars) {
  const out = [];
  for (const ch of chars) {
    if (out.length && out[out.length - 1] === ch) continue;
    out.push(ch);
  }
  return out;
}

function buildFragmentPattern(canonical) {
  const letters = dedupeConsecutive(Array.from(canonical.replace(/\s+/g, '')));
  // Each letter position matches one-or-more occurrences of that letter,
  // each optionally separated by the same bounded separator class — not
  // just a plain `+` (which only absorbs *contiguous* repeats). This is
  // what additionally defeats a keyword that is simultaneously duplicated
  // and punctuation-fragmented, e.g. "d.e.e.e.l.e.t.e" (three separated
  // "e"s, not one contiguous run collapseRepeatedChars() would have already
  // handled). The repeat count and the separator length are both bounded
  // (by input length and {0,2} respectively), so this stays linear-ish with
  // no nested unbounded quantifiers — not a ReDoS risk.
  const escaped = letters.map((ch) => {
    const e = ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return `${e}(?:${REPEAT_SEP}${e})*`;
  });
  return new RegExp(`\\b${escaped.join(FRAGMENT_SEP)}\\b`, 'giu');
}

// Longest letter-count first, so a multi-word phrase is reconstructed before
// any shorter entry that could otherwise partially match inside it.
const FRAGMENT_PATTERNS = KEYWORD_DICTIONARY
  .slice()
  .sort((a, b) => b.replace(/\s+/g, '').length - a.replace(/\s+/g, '').length)
  .map((canonical) => ({ canonical, pattern: buildFragmentPattern(canonical) }));

function reconstructFragmentedKeywords(text) {
  let out = text;
  let changed = false;
  for (const { canonical, pattern } of FRAGMENT_PATTERNS) {
    pattern.lastIndex = 0;
    if (!pattern.test(out)) continue;
    const before = out;
    pattern.lastIndex = 0;
    out = out.replace(pattern, canonical);
    // A dictionary word that already appears in plain contiguous form is a
    // no-op replace (canonical -> canonical) — only count this as
    // "reconstruction" when the fragmented/separated spelling actually
    // changed the text, not merely because the word is present.
    if (out !== before) changed = true;
  }
  return { text: out, changed };
}

/**
 * The transformation sequence itself, extracted so the
 * lowercased and case-preserved variants execute the SAME steps in the SAME
 * order rather than existing as two hand-maintained copies.
 *
 * With preserveCase=false the behaviour is byte-for-byte what it was before
 * the two `toLowerCase()` calls are exactly where they were, and the
 * intermediates the caller needs for `meta` are returned unchanged.
 *
 * The original ordering comment, still load-bearing, is preserved verbatim:
 *
 *   Case-fold before the confusable lookup, not after (as before this fix).
 *   CONFUSABLES only lists one, lowercase entry per confusable character
 *   (e.g. 'е' -> 'e'); an uppercase or capitalized confusable (Cyrillic
 *   capital 'Е') used to miss the lookup entirely and then get case-folded
 *   *within its own script* by the later toLowerCase() call, never
 *   converging to Latin and silently defeating the fold for any capitalized
 *   or all-caps homoglyph attack. Case-folding first means every confusable
 *   reaches foldConfusables() in the same case its table key is written in,
 *   for any script — no second, hand-maintained uppercase entry is needed
 *   per character, now or for any script added to the table later.
 *
 * The preserveCase=true branch cannot case-fold first without defeating its
 * own purpose, so it reaches the same guarantee through
 * foldConfusablesPreservingCase() instead — see that function's header. A
 * capitalized homoglyph is folded on BOTH paths; neither is weaker.
 */
function runPipeline(combined, preserveCase) {
  const nfkc = combined.normalize('NFKC');
  const caseFoldedForConfusables = preserveCase ? nfkc : nfkc.toLowerCase();
  const confusablesFolded = preserveCase
    ? foldConfusablesPreservingCase(caseFoldedForConfusables)
    : foldConfusables(caseFoldedForConfusables);
  const evasionStripped = confusablesFolded
    .replace(EVASION_CHARS, '')
    .replace(PICTOGRAPHIC_CHARS, '');
  const decomposed = evasionStripped.normalize('NFKD');

  // Recompose after the Latin-scoped diacritic strip: NFKD decomposes any
  // precomposed character built from a base + combining mark, Latin or not
  // (Japanese dakuten kana, Cyrillic й, ...). stripLatinDiacritics() only
  // removes marks that fold a Latin accent; everything else survives to be
  // recomposed back into its original precomposed form here.
  const recomposed = stripLatinDiacritics(decomposed).normalize('NFC');
  const lowered = preserveCase ? recomposed : recomposed.toLowerCase();

  const repetitionCollapsed = collapseRepeatedChars(lowered);

  // Fragment reconstruction is deliberately SKIPPED on the case-preserved
  // path. buildFragmentPattern() compiles its patterns case-insensitively
  // ('giu') and replaces every match with the dictionary's canonical form,
  // which is lowercase by construction — so running it here would rewrite
  // "DELETE" to "delete" and silently reintroduce exactly the case loss this
  // variant exists to avoid. Verified by a test in
  // __tests__/casePreservedNormalization.test.js rather than assumed.
  //
  // The cost is explicit and accepted: a camelCase identifier that is ALSO
  // punctuation-fragmented ("d.e.l.e.t.eUser") is not reconstructed on this
  // path, so the camelCase branch will not see it. The primary lowercase
  // path still reconstructs it and every one of the 62 signal patterns still
  // benefits — only the narrow case-shape branch forgoes it. Reconstruction
  // that preserved case would need a case-restoring replace, which is its
  // own change and is not smuggled in here.
  const { text: reconstructed, changed: fragmentsReconstructed } = preserveCase
    ? { text: repetitionCollapsed, changed: false }
    : reconstructFragmentedKeywords(repetitionCollapsed);

  const normalized = reconstructed.replace(/\s+/g, ' ').trim();

  return {
    caseFoldedForConfusables, confusablesFolded, lowered,
    repetitionCollapsed, fragmentsReconstructed, normalized,
  };
}

/**
 * Core normalization pipeline, instrumented with which steps actually fired
 * — shared by normalize() (returns just the text, used for signal scoring)
 * and analyzeNormalization() (returns audit-safe metadata about what
 * changed, never the text itself). Keeping one implementation avoids the two
 * ever silently drifting apart.
 *
 * additionally returns `normalizedCased`: the identical
 * pipeline with both case folds skipped, for the narrow set of detections
 * that need case SHAPE (camelCase identifiers). Additive only — `normalized`
 * is unchanged and remains what every existing signal pattern reads.
 */
function normalizeWithMeta(text) {
  if (typeof text !== 'string' || !text) {
    return { normalized: '', normalizedCased: '', meta: { changed: false } };
  }

  const truncated = text.length > MAX_NORMALIZE_INPUT_LENGTH
    ? text.slice(0, MAX_NORMALIZE_INPUT_LENGTH)
    : text;

  const { text: decodedExtra, flags: decodeFlags } = expandEncodedContent(truncated);
  let combined = decodedExtra ? `${truncated} ${decodedExtra}` : truncated;
  if (combined.length > MAX_TOTAL_NORMALIZE_LENGTH) {
    combined = combined.slice(0, MAX_TOTAL_NORMALIZE_LENGTH);
  }

  const lower = runPipeline(combined, false);
  const {
    caseFoldedForConfusables, confusablesFolded, lowered,
    repetitionCollapsed, fragmentsReconstructed, normalized,
  } = lower;

  // the same pipeline with both case folds skipped. Runs
  // through runPipeline() rather than a hand-copied second pass precisely so
  // the two can never silently drift, which is this module's own stated
  // reason for having one normalizeWithMeta() behind normalize() and
  // analyzeNormalization().
  //
  // This is ADDITIVE. `normalized` above is byte-identical to what it was
  // every one of the engine's 62 signal patterns still reads it,
  // and no classifier sees `normalizedCased` unless it deliberately opts in
  // (today: toolAbuse.js's identifier co-occurrence, the one detection whose
  // dead camelCase branch motivated this change).
  //
  // Known and deliberate difference beyond letter case: FRAGMENT_PATTERNS
  // and the repetition collapse are written against lowercase text, so
  // fragment reconstruction generally does not fire on this variant. That
  // means `normalizedCased.toLowerCase()` is NOT guaranteed equal to
  // `normalized`, and character offsets are NOT guaranteed to correspond.
  // Any consumer must therefore evaluate a proximity/co-occurrence check
  // entirely WITHIN one of the two strings, never by mixing offsets across
  // them — see toolAbuse.js's refine(), which does exactly that.
  const normalizedCased = runPipeline(combined, true).normalized;

  // Baseline applies only routine case/whitespace folding (never itself
  // "suspicious"), so `changed` reports whether anything beyond that
  // happened — decoding, folding, collapsing, or reconstruction — rather
  // than firing on every prompt with a double space or trailing newline.
  const baseline = text.toLowerCase().replace(/\s+/g, ' ').trim();

  return {
    normalized,
    normalizedCased,
    meta: {
      changed: normalized !== baseline,
      truncated: truncated.length !== text.length,
      base64Decoded: decodeFlags.base64,
      hexDecoded: decodeFlags.hex,
      urlDecoded: decodeFlags.url,
      htmlEntityDecoded: decodeFlags.html,
      unicodeEscapeDecoded: decodeFlags.unicodeEscape,
      homoglyphFolded: confusablesFolded !== caseFoldedForConfusables,
      pictographicStripped: PICTOGRAPHIC_CHARS_PRESENT.test(confusablesFolded),
      // Tested against confusablesFolded (the final decoded text right
      // before the strip below runs), not the original pre-decode input —
      // an evasion character embedded only inside a decoded payload (e.g.
      // base64) is stripped from the text actually used for scoring, and
      // the metadata must say so, matching how pictographicStripped above
      // already tests the same post-decode variable.
      evasionCharsStripped: EVASION_CHARS_PRESENT.test(confusablesFolded),
      repetitionCollapsed: repetitionCollapsed !== lowered,
      fragmentsReconstructed,
    },
  };
}

/**
 * Normalize text for signal matching: decode-and-rescan of embedded
 * encodings (base64, hex, URL, HTML entities, Unicode escapes), Unicode NFKC
 * normalization (collapses many homoglyph/compatibility variants),
 * cross-script confusable folding, evasion-character (zero-width/bidi/
 * pictographic) stripping, diacritic folding, character-repetition collapse,
 * fragmented-keyword reconstruction, lowercasing, and whitespace collapsing.
 */
function normalize(text) {
  return normalizeWithMeta(text).normalized;
}

/**
 * Case-preserving counterpart of normalize() —. Same pipeline,
 * same evasion/homoglyph/diacritic handling, letter case retained.
 *
 * Use ONLY where the detection genuinely depends on case shape (today:
 * camelCase identifier recognition). Everything else must keep reading
 * normalize(), whose lowercased output all 62 of the engine's signal
 * patterns are written against.
 */
function normalizeCased(text) {
  return normalizeWithMeta(text).normalizedCased;
}

/**
 * Audit-safe metadata describing which normalization steps fired for a given
 * request — never the raw or decoded text itself (semantic evidence must
 * never carry verbatim prompt content into the audit trail, matching the
 * rest of this engine's evidence model and
 * classifier/baseClassifier.js). Intended to be computed once per request
 * and attached to evidence only when something actually changed.
 */
function analyzeNormalization(text) {
  const { meta } = normalizeWithMeta(text);
  return meta;
}

/**
 * Score a normalized text against a set of weighted signals.
 *
 * @param {string} normalizedText
 * @param {Array<{ pattern: RegExp, weight: number, tag: string }>} signals
 * @returns {{ confidence: number, matched: Array<{tag:string, weight:number, index:number}> }}
 *
 * Matched signals are combined via a probabilistic-OR (noisy-OR):
 *   confidence = 1 - Π(1 - weight_i)
 * so several weak, independent indicators can still add up to a confident
 * detection, while a single strong (high-weight) signal can also reach high
 * confidence on its own — neither a naive sum (which can blow past 1 and
 * over-rewards repetition) nor a bare max (which is equivalent to single-
 * pattern matching) has that property.
 */
function scoreSignals(normalizedText, signals) {
  const matched = [];
  for (const signal of signals) {
    const m = normalizedText.match(signal.pattern);
    if (m) matched.push({ tag: signal.tag, weight: signal.weight, index: m.index ?? 0 });
  }
  if (!matched.length) return { confidence: 0, matched: [] };
  const confidence = 1 - matched.reduce((acc, s) => acc * (1 - s.weight), 1);
  return { confidence: Math.min(1, confidence), matched };
}

// ── clause-aware co-occurrence gate (kill-switched, defaults OFF) ──
//
// established that
// coOccurs()'s pure character-offset proximity check can combine two
// independently-valid signal matches that belong to semantically separate
// quoted examples, parenthetical asides, or table rows — e.g. two unrelated
// example attack phrases quoted next to each other in documentation. This
// gate adds ONE additional, restrictive condition — the two matches must
// share the same clause/context span — without altering any verb/noun
// regex, the caller-supplied proximity window, normalization, or any
// classifier's own vocabulary. It can only WITHHOLD an existing
// co-occurrence result, never grant one proximity alone did not already
// produce (verified structurally and empirically in 0 new matches
// in every tested variant) — see coOccurs()'s own short-circuit below.
//
// Boundary rules (H24-validated). Deliberately EXCLUDES ':' and ',' as
// split points: formally falsified colon as a universal boundary — it
// destroys a legitimate detection where one verb governs a comma-separated
// object list introduced by a colon (e.g. "Bypass: identity verification,
// artifact validation, ..."). Only these characters carry boundary meaning:
//   - '"' toggles a quoted-content span (quote boundary)
//   - '(' / ')' each toggle their own parenthetical span
//   - '|' is an unconditional hard split (table-cell boundary)
//   - '.', '!', '?', ';' are hard splits OUTSIDE any quote/parenthetical
//     (sentence/clause boundary)
const CLAUSE_GATE_TOGGLE_CHARS = ['"', '(', ')'];
const CLAUSE_GATE_HARD_SPLIT_CHARS = ['.', '!', '?', ';', '|'];

/**
 * Splits `text` into clause/context spans using only the boundary characters
 * above. Pure function of the input string — no external state, no I/O.
 */
function computeClauseSpans(text) {
  const spans = [];
  let start = 0;
  const toggleState = { '"': false, '(': false, ')': false };
  const anyToggleActive = () => toggleState['"'] || toggleState['('] || toggleState[')'];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (CLAUSE_GATE_TOGGLE_CHARS.includes(ch)) {
      spans.push({ start, end: i });
      start = i;
      toggleState[ch] = !toggleState[ch];
      continue;
    }
    if (!anyToggleActive() && CLAUSE_GATE_HARD_SPLIT_CHARS.includes(ch)) {
      spans.push({ start, end: i + 1 });
      start = i + 1;
    }
  }
  if (start < text.length) spans.push({ start, end: text.length });
  return spans;
}

/**
 * SAME if both indices fall in the identical span, DIFFERENT if they fall in
 * two distinct, fully-computed spans, AMBIGUOUS if either index cannot be
 * located in any span at all (should not occur for indices returned by a
 * successful String.match() against the same text the spans were computed
 * from, but guarded rather than assumed).
 */
function sameClause(indexA, indexB, spans) {
  const spanOf = (idx) => spans.findIndex((s) => idx >= s.start && idx < s.end);
  const a = spanOf(indexA);
  const b = spanOf(indexB);
  if (a === -1 || b === -1) return 'AMBIGUOUS';
  return a === b ? 'SAME' : 'DIFFERENT';
}

/**
 * True if patternA and patternB both match within `windowChars` of each
 * other in normalizedText. Used to require structural proximity (e.g. an
 * override verb near a security-control noun) rather than mere co-presence
 * anywhere in a long prompt.
 *
 * when QODIQA_SEM_CLAUSE_GATE_ENABLED is exactly the literal string
 * "true" (defaults OFF — every other value, including unset, preserves the
 * pre-H26 behavior byte-for-byte), an additional SAME_CLAUSE requirement is
 * applied on top of the existing proximity check. AMBIGUOUS is treated
 * identically to DIFFERENT (withholds the co-occurrence result) — this
 * withholds only this function's own boolean contribution to whichever
 * classifier's refine() called it; it never touches that classifier's base
 * signal weights, any other classifier, or the request as a whole.
 */
function coOccurs(normalizedText, patternA, patternB, windowChars = 160) {
  const a = normalizedText.match(patternA);
  const b = normalizedText.match(patternB);
  if (!a || !b) return false;
  const withinWindow = Math.abs((a.index ?? 0) - (b.index ?? 0)) <= windowChars;
  if (!withinWindow) return false;
  if (process.env.QODIQA_SEM_CLAUSE_GATE_ENABLED !== 'true') return true;
  const spans = computeClauseSpans(normalizedText);
  return sameClause(a.index ?? 0, b.index ?? 0, spans) === 'SAME';
}

/** Convenience: does `tag` appear among a scoreSignals() matched array? */
function hasTag(matched, tag) {
  return matched.some((m) => m.tag === tag);
}

module.exports = {
  normalize, normalizeCased, analyzeNormalization, scoreSignals, coOccurs, hasTag,
  // additive. See its own header for why the embedding path needs a
  // substituting composition of the SAME decoders normalize() already uses,
  // and why sharing the decoders rather than copying them is the point.
  substituteEncodedContent,
  // additive. inputNormalization.js's whitespace-tolerant base64
  // candidate reuses this exact decode-and-validate pair (round-trip +
  // span is held to the identical acceptance bar as a contiguous one.
  tryBase64Decode,
  isMeaningfulPlainText,
  // additive. Exported so the clause-span primitive itself can be unit
  // tested directly (matching this file's own existing convention of testing
  // primitives like tryBase64Decode/isMeaningfulPlainText in isolation),
  // independent of coOccurs()'s own kill-switch and window logic.
  computeClauseSpans,
  sameClause,
};
